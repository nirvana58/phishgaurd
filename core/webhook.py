"""
core/discord_webhook.py

Discord notification system.

Sends a formatted embed to a Discord channel via incoming webhook
whenever a scan completes with a verdict that meets or exceeds the
configured threshold.

Environment variables:
  DISCORD_WEBHOOK_URL           Discord "incoming webhook" URL
  DISCORD_WEBHOOK_ON_SUSPICIOUS Also fire for SUSPICIOUS (default: false)
  DISCORD_WEBHOOK_TIMEOUT       Request timeout in seconds (default: 10)
  DISCORD_MENTION_ROLE_ID       Optional role ID to @mention on MALICIOUS

Setup (Discord side):
  1. Server Settings -> Integrations -> Webhooks -> New Webhook
  2. Pick the channel, copy the "Webhook URL"
  3. Set DISCORD_WEBHOOK_URL to that value

Fire-and-forget:
  Calls are non-blocking. A failure (timeout, 4xx, 5xx) is logged but
  never fails the scan or the report. One retry on failure.
"""

import json
import os

import httpx

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
DISCORD_ON_SUSPICIOUS = os.getenv("DISCORD_WEBHOOK_ON_SUSPICIOUS", "false").lower() == "true"
DISCORD_TIMEOUT = float(os.getenv("DISCORD_WEBHOOK_TIMEOUT", "10"))
DISCORD_MENTION_ROLE_ID = os.getenv("DISCORD_MENTION_ROLE_ID", "").strip()

_TRIGGER_VERDICTS = {"MALICIOUS"}
if DISCORD_ON_SUSPICIOUS:
    _TRIGGER_VERDICTS.add("SUSPICIOUS")

# Decimal color codes (Discord embeds want int, not hex string)
_COLORS = {
    "MALICIOUS":  0xD1366B,  # matches your project's red accent
    "SUSPICIOUS": 0xE8A33D,
    "CLEAN":      0x3DDC97,
    "UNKNOWN":    0x6E7681,
}

_EMOJI = {
    "MALICIOUS":  "🛑",
    "SUSPICIOUS": "⚠️",
    "CLEAN":      "✅",
    "UNKNOWN":    "❔",
}


def _should_fire(verdict: str) -> bool:
    return bool(DISCORD_WEBHOOK_URL) and verdict in _TRIGGER_VERDICTS


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _domain_from_url(url: str) -> str:
    try:
        from urllib.parse import urlparse
        netloc = urlparse(url).netloc
        return netloc.split("@")[-1].split(":")[0] or url
    except Exception:
        return url


def _build_embed(scan_id: str, result: dict) -> dict:
    verdict_block = result.get("verdict", {})
    verdict        = verdict_block.get("verdict", "UNKNOWN")
    confidence     = verdict_block.get("confidence", "UNKNOWN")
    reasons        = verdict_block.get("reasons", []) or []
    ml             = result.get("ml", {})
    chain          = result.get("redirect_chain", {})
    vt             = result.get("virustotal", {})
    gsb            = result.get("safe_browsing", {})
    urlhaus        = result.get("urlhaus", {})
    whois          = result.get("whois", {})

    url        = result.get("url", "")
    final_url  = chain.get("final_url", url)
    hop_count  = chain.get("hop_count", 0)
    shorteners = chain.get("shorteners_found", []) or []
    scanned_at = result.get("scanned_at", "")
    domain     = _domain_from_url(final_url or url)

    fields = [
        {"name": "Confidence", "value": confidence, "inline": True},
        {"name": "Verdict", "value": verdict, "inline": True},
        {"name": "Scan ID", "value": f"`{scan_id[:8]}`", "inline": True},
    ]

    # ── Original vs final URL (only shown separately if they differ) ──────────
    fields.append({
        "name": "Scanned URL",
        "value": f"```{_truncate(url, 500)}```",
        "inline": False,
    })
    if final_url and final_url != url:
        redirect_note = f"```{_truncate(final_url, 500)}```"
        hop_note = f"{hop_count} hop{'s' if hop_count != 1 else ''}"
        if shorteners:
            hop_note += f" · shortener(s): {', '.join(shorteners)}"
        fields.append({
            "name": f"Final URL ({hop_note})",
            "value": redirect_note,
            "inline": False,
        })

    if reasons:
        fields.append({
            "name": f"Reasons ({len(reasons)})",
            "value": _truncate("\n".join(f"• {r}" for r in reasons[:8]), 1024),
            "inline": False,
        })

    # ── VirusTotal ──────────────────────────────────────────────────────────
    if vt.get("available"):
        malicious  = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        harmless   = vt.get("harmless", 0)
        undetected = vt.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected
        fields.append({
            "name": "🔍 VirusTotal",
            "value": (
                f"**{malicious}**/{total or '?'} engines flagged malicious\n"
                f"suspicious: {suspicious} · harmless: {harmless} · undetected: {undetected}"
            ),
            "inline": True,
        })

    # ── Google Safe Browsing ───────────────────────────────────────────────
    if gsb.get("available"):
        is_threat = gsb.get("is_threat", False)
        threat_types = ", ".join(gsb.get("threat_types", [])) or "none"
        fields.append({
            "name": "🛡️ Safe Browsing",
            "value": f"threat: **{is_threat}**\ntypes: {threat_types}",
            "inline": True,
        })

    # ── URLhaus ─────────────────────────────────────────────────────────────
    url_lookup  = urlhaus.get("url_lookup", {}) or {}
    host_lookup = urlhaus.get("host_lookup", {}) or {}
    if url_lookup.get("found") or host_lookup.get("found"):
        lines = []
        if url_lookup.get("found"):
            tags = ", ".join(url_lookup.get("tags", [])) or "none"
            lines.append(
                f"URL status: **{url_lookup.get('url_status')}** "
                f"(threat: {url_lookup.get('threat')})\ntags: {tags}"
            )
        if host_lookup.get("found"):
            lines.append(f"host has {host_lookup.get('url_count', 0)} known malicious URL(s)")
        fields.append({
            "name": "🧬 URLhaus",
            "value": _truncate("\n".join(lines), 1024),
            "inline": True,
        })

    # ── WHOIS ───────────────────────────────────────────────────────────────
    if whois.get("available"):
        age = whois.get("age_days")
        lines = [
            f"domain: {whois.get('domain', domain)}",
            f"age: {age if age is not None else 'unknown'} days"
            + (" 🆕 newly registered" if whois.get("is_new_domain") else ""),
        ]
        if whois.get("registrar"):
            lines.append(f"registrar: {whois.get('registrar')}")
        if whois.get("country"):
            lines.append(f"country: {whois.get('country')}")
        fields.append({
            "name": "📇 WHOIS",
            "value": _truncate("\n".join(lines), 1024),
            "inline": True,
        })

    # ── ML models ───────────────────────────────────────────────────────────
    if ml.get("available"):
        kmeans = ml.get("kmeans", {}) or {}
        som    = ml.get("som", {}) or {}
        fields.append({
            "name": "🤖 ML Detection",
            "value": (
                f"combined score: **{ml.get('combined_score', 0.0):.2f}**\n"
                f"k-means: {kmeans.get('anomaly_score', 0.0):.2f} · "
                f"SOM: {som.get('anomaly_score', 0.0):.2f}\n"
                f"models agree: {ml.get('models_agree', False)} "
                f"(v{ml.get('model_version', 'none')})"
            ),
            "inline": True,
        })

    embed = {
        "author": {"name": "PhishGuard Scan Report"},
        "title": f"{_EMOJI.get(verdict, '')} {verdict} — {_truncate(domain, 180)}",
        "url": final_url if final_url.startswith(("http://", "https://")) else None,
        "color": _COLORS.get(verdict, _COLORS["UNKNOWN"]),
        "thumbnail": {"url": f"https://www.google.com/s2/favicons?domain={domain}&sz=128"},
        "fields": fields,
        "footer": {"text": f"PhishGuard · scan {scan_id[:8]}"},
    }
    if scanned_at:
        embed["timestamp"] = scanned_at

    # Discord rejects "url": None — strip it if unset
    if embed["url"] is None:
        del embed["url"]

    return embed


def _build_payload(scan_id: str, result: dict) -> dict:
    verdict = result.get("verdict", {}).get("verdict", "UNKNOWN")
    content = None
    if verdict == "MALICIOUS" and DISCORD_MENTION_ROLE_ID:
        content = f"<@&{DISCORD_MENTION_ROLE_ID}>"

    payload = {"embeds": [_build_embed(scan_id, result)]}
    if content:
        payload["content"] = content
    return payload


async def send_discord_webhook(scan_id: str, result: dict) -> bool:
    """
    Fire a Discord notification for a completed scan.

    Args:
        scan_id: UUID of the scan.
        result:  Full result dict from scanner.py.

    Returns:
        True if the message was posted successfully, False otherwise.
        Never raises — failures are logged and swallowed.
    """
    verdict = result.get("verdict", {}).get("verdict", "")
    if not _should_fire(verdict):
        return False

    payload = _build_payload(scan_id, result)
    payload_bytes = json.dumps(payload, default=str).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "PhishGuard/1.0",
    }

    for attempt in range(1, 3):
        try:
            async with httpx.AsyncClient(timeout=DISCORD_TIMEOUT) as client:
                resp = await client.post(
                    DISCORD_WEBHOOK_URL,
                    content=payload_bytes,
                    headers=headers,
                )
            # Discord returns 204 No Content on success
            if resp.status_code < 400:
                print(f"[discord] Sent  scan={scan_id[:8]}  verdict={verdict}"
                      f"  status={resp.status_code}")
                return True
            elif resp.status_code == 429:
                # Rate limited — Discord tells us how long to wait
                retry_after = resp.json().get("retry_after", 2)
                print(f"[discord] Rate limited, retry_after={retry_after}s")
                import asyncio
                await asyncio.sleep(float(retry_after))
                continue
            else:
                print(f"[discord] Attempt {attempt} failed  "
                      f"status={resp.status_code}  body={resp.text[:200]}")
        except httpx.TimeoutException:
            print(f"[discord] Attempt {attempt} timed out")
        except Exception as e:
            print(f"[discord] Attempt {attempt} error: {e}")

        if attempt < 2:
            import asyncio
            await asyncio.sleep(2)

    print(f"[discord] All attempts failed for scan {scan_id[:8]} — giving up.")
    return False