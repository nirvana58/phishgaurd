"""
core/redirect_chain.py

Async redirect chain tracer.

Most phishing and malware URLs don't serve content directly — they pass
through URL shorteners, cloaking layers, or affiliate redirect chains
before landing on the malicious page. This module traces the full chain
so the scanner can:

  1. See every intermediate URL (and flag any that are in URLhaus)
  2. Identify the actual landing URL (the one that serves content)
  3. Detect URL shorteners being used as obfuscation
  4. Show the full chain in reports for human review

Implementation:
  - Uses HEAD requests per hop (no body download)
  - Falls back to GET with stream=True if server rejects HEAD
  - Hard limit of MAX_HOPS to prevent infinite loops
  - Per-hop timeout so slow redirectors don't hang the scan
  - Deduplication: if a URL repeats, the loop is broken immediately
  - Runs concurrently with VT/GSB/URLhaus/WHOIS via asyncio.gather
    in scanner.py — adds zero serial latency to the scan
"""

import asyncio
from urllib.parse import urlparse, urljoin

import httpx

MAX_HOPS    = 12     # stop after this many redirects
HOP_TIMEOUT = 6.0   # seconds per hop request

# Known URL shortener domains — flagged in reports as obfuscation indicators
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "rb.gy", "cutt.ly", "is.gd", "v.gd", "tiny.cc",
    "tr.im", "snip.ly", "rebrand.ly", "bl.ink", "clck.ru", "3.ly",
    "s.id", "shorturl.at",
}

_TRACE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; url-threat-scanner/1.0)",
    "Accept":     "*/*",
}


def _registrable_domain(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ""


async def _head_or_get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    """
    Try HEAD first (no body). Fall back to GET with stream if HEAD is
    rejected (405 Method Not Allowed) or gives no Location header.
    """
    try:
        resp = await client.head(url, timeout=HOP_TIMEOUT, follow_redirects=False)
        if resp.status_code not in (405, 501):
            return resp
    except Exception:
        pass

    try:
        async with client.stream("GET", url, timeout=HOP_TIMEOUT,
                                 follow_redirects=False) as resp:
            # Don't read the body — we only need headers
            return resp
    except Exception:
        return None


async def trace_redirects(url: str) -> dict:
    """
    Follow the redirect chain for a URL.

    Returns:
    {
        "original_url":  str,
        "final_url":     str,          # URL after all redirects
        "hops":          list[dict],   # one entry per hop
        "hop_count":     int,
        "is_shortened":  bool,         # True if any hop is a known shortener
        "shorteners_found": list[str], # which shortener domains appeared
        "error":         str | None,
    }

    Each hop dict:
    {
        "url":         str,
        "status_code": int,
        "redirect_to": str | None,    # Location header value, resolved
        "server":      str | None,    # Server header
        "is_shortener": bool,
    }
    """
    original_url = url.strip()
    if not original_url:
        return {
            "original_url": original_url, "final_url": original_url,
            "hops": [], "hop_count": 0,
            "is_shortened": False, "shorteners_found": [],
            "error": "empty URL",
        }

    # Ensure scheme present
    if not original_url.startswith(("http://", "https://")):
        original_url = f"https://{original_url}"

    hops: list[dict] = []
    seen_urls: set[str] = set()
    current_url = original_url
    shorteners_found: list[str] = []
    last_error: str | None = None

    async with httpx.AsyncClient(
        headers=_TRACE_HEADERS,
        verify=False,       # some malicious sites have invalid certs — still trace them
    ) as client:
        for _ in range(MAX_HOPS):
            if current_url in seen_urls:
                last_error = "redirect loop detected"
                break
            seen_urls.add(current_url)

            resp = await _head_or_get(client, current_url)

            if resp is None:
                last_error = f"request failed for {current_url[:80]}"
                break

            # Resolve Location header to absolute URL
            redirect_to: str | None = None
            if resp.status_code in range(300, 400):
                loc = resp.headers.get("location", "").strip()
                if loc:
                    redirect_to = urljoin(current_url, loc)

            domain = _registrable_domain(current_url)
            is_shortener = domain in URL_SHORTENERS
            if is_shortener and domain not in shorteners_found:
                shorteners_found.append(domain)

            hops.append({
                "url":          current_url,
                "status_code":  resp.status_code,
                "redirect_to":  redirect_to,
                "server":       resp.headers.get("server"),
                "content_type": resp.headers.get("content-type", "").split(";")[0].strip(),
                "is_shortener": is_shortener,
            })

            if redirect_to:
                current_url = redirect_to
            else:
                break   # No more redirects

    final_url = hops[-1]["redirect_to"] or hops[-1]["url"] if hops else original_url

    return {
        "original_url":    original_url,
        "final_url":       final_url,
        "hops":            hops,
        "hop_count":       len(hops),
        "is_shortened":    len(shorteners_found) > 0,
        "shorteners_found": shorteners_found,
        "error":           last_error,
    }


def redirect_chain_signals(chain: dict) -> list[str]:
    """
    Extract human-readable risk signals from a redirect chain result.
    Returns [] if chain tracing failed — never affects verdict alone.
    """
    signals = []
    if not chain or chain.get("error") == "empty URL":
        return signals

    hops = chain.get("hops", [])
    hop_count = chain.get("hop_count", 0)

    if hop_count > 3:
        signals.append(
            f"URL passes through {hop_count} redirects before reaching destination "
            f"— common obfuscation technique"
        )

    shorteners = chain.get("shorteners_found", [])
    if shorteners:
        signals.append(
            f"URL shortener(s) detected in redirect chain: "
            f"{', '.join(shorteners)} — masks true destination"
        )

    # Check for protocol downgrade (HTTPS → HTTP)
    https_to_http = any(
        h["url"].startswith("https://") and
        (h.get("redirect_to") or "").startswith("http://")
        for h in hops
    )
    if https_to_http:
        signals.append("Redirect chain downgrades from HTTPS to HTTP")

    # Check if final URL domain differs from original
    original_domain = _registrable_domain(chain.get("original_url", ""))
    final_domain    = _registrable_domain(chain.get("final_url", ""))
    if original_domain and final_domain and original_domain != final_domain:
        signals.append(
            f"Final destination domain ({final_domain}) differs from "
            f"submitted domain ({original_domain})"
        )

    return signals
