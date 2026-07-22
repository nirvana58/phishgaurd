"""
core/urlhaus.py

URLhaus threat intelligence integration.
URLhaus (https://urlhaus.abuse.ch/) is maintained by abuse.ch and tracks
malicious URLs used for malware distribution in real time.

WHY URLHAUS IN ADDITION TO VIRUSTOTAL:
  VirusTotal checks against 70+ AV engines — good at detecting known malware.
  URLhaus specifically tracks active malware-distribution URLs and C2 servers,
  often catching them *before* AV engines pick them up. The two complement
  each other: VirusTotal for breadth, URLhaus for speed on active threats.

API:
  Free, no API key required.
  Uses POST with application/x-www-form-urlencoded (not JSON).
  Base URL: https://urlhaus-api.abuse.ch/v1/

ENDPOINTS USED:
  POST /url/   — look up a specific URL
  POST /host/  — look up a host/domain (all known malicious URLs on it)

CACHING:
  Results cached in-process for 30 minutes per URL and per host.
  URLhaus data changes frequently (URLs go online/offline) so TTL is
  shorter than WHOIS (1hr).

RATE LIMITS:
  URLhaus asks users not to hammer the API. The 30-minute cache and
  one-per-scan design means we stay well within acceptable use.
"""

import asyncio
import time
from urllib.parse import urlparse

import httpx

URLHAUS_BASE    = "https://urlhaus-api.abuse.ch/v1"
REQUEST_TIMEOUT = 12.0
CACHE_TTL       = 1800   # 30 minutes

_URL_CACHE:  dict[str, tuple[dict, float]] = {}
_HOST_CACHE: dict[str, tuple[dict, float]] = {}

_HEADERS = {
    "User-Agent":   "url-threat-scanner/1.0 (security research)",
    "Accept":       "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
}


# ── URL lookup ─────────────────────────────────────────────────────────────────

async def lookup_url(url: str) -> dict:
    """
    Look up a specific URL in the URLhaus database.

    query_status values:
      "is_malware"  — URL is listed as malicious
      "no_results"  — URL not in URLhaus database
      "invalid_url" — URL failed validation

    Returns a structured dict — never raises.
    """
    url = url.strip()
    if not url:
        return {"available": False, "reason": "empty URL"}

    # Cache hit
    cached = _URL_CACHE.get(url)
    if cached:
        result, ts = cached
        if time.time() - ts < CACHE_TTL:
            return {**result, "cached": True}

    try:
        async with httpx.AsyncClient(
            headers=_HEADERS,
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = await client.post(
                f"{URLHAUS_BASE}/url/",
                data={"url": url},
            )

        if resp.status_code != 200:
            result = {
                "available": False,
                "reason": f"URLhaus returned HTTP {resp.status_code}",
            }
            _URL_CACHE[url] = (result, time.time())
            return result

        data = resp.json()
        status = data.get("query_status", "")

        if status == "no_results":
            result = {
                "available": True,
                "found":     False,
                "url_status": None,
                "threat":    None,
                "tags":      [],
                "date_added": None,
                "blacklists": {},
                "urlhaus_reference": None,
                "reporter": None,
                "query_status": status,
            }

        elif status in ("is_malware", "is_phishing"):
            blacklists = data.get("blacklists") or {}
            result = {
                "available":         True,
                "found":             True,
                "url_status":        data.get("url_status"),       # "online" | "offline"
                "threat":            data.get("threat"),           # "malware_download" etc.
                "tags":              data.get("tags") or [],       # malware family tags
                "date_added":        data.get("date_added"),
                "urlhaus_reference": data.get("urlhaus_reference"),
                "reporter":          data.get("reporter"),
                "blacklists":        {
                    "spamhaus_dbl": blacklists.get("spamhaus_dbl", "not listed"),
                    "surbl":        blacklists.get("surbl", "not listed"),
                },
                "query_status": status,
            }

        else:
            result = {
                "available": False,
                "reason": f"unexpected query_status: {status!r}",
            }

    except httpx.TimeoutException:
        result = {"available": False, "reason": "URLhaus request timed out"}
    except Exception as e:
        result = {"available": False, "reason": str(e)[:120]}

    _URL_CACHE[url] = (result, time.time())
    return result


# ── Host lookup ────────────────────────────────────────────────────────────────

async def lookup_host(url: str) -> dict:
    """
    Look up the host/domain of a URL in URLhaus.
    Returns the count of known malicious URLs on that host and
    blacklist status even for URLs not individually listed.

    query_status values:
      "is_host"    — host has known malicious URLs
      "no_results" — host not in URLhaus database
    """
    try:
        target = url if "://" in url else f"http://{url}"
        host   = urlparse(target).hostname or ""
    except Exception:
        return {"available": False, "reason": "could not parse host from URL"}

    if not host:
        return {"available": False, "reason": "empty host"}

    # Use registrable domain (strip subdomains for host lookup)
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

    cached = _HOST_CACHE.get(domain)
    if cached:
        result, ts = cached
        if time.time() - ts < CACHE_TTL:
            return {**result, "cached": True}

    try:
        async with httpx.AsyncClient(
            headers=_HEADERS,
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = await client.post(
                f"{URLHAUS_BASE}/host/",
                data={"host": domain},
            )

        if resp.status_code != 200:
            result = {"available": False, "reason": f"HTTP {resp.status_code}"}
            _HOST_CACHE[domain] = (result, time.time())
            return result

        data = resp.json()
        status = data.get("query_status", "")

        if status == "no_results":
            result = {
                "available":   True,
                "found":       False,
                "host":        domain,
                "url_count":   0,
                "blacklists":  {},
                "urlhaus_reference": None,
                "query_status": status,
            }

        elif status == "is_host":
            blacklists = data.get("blacklists") or {}
            # Summarise the URLs list (can be very long) — just keep counts
            urls_list  = data.get("urls") or []
            online  = sum(1 for u in urls_list if u.get("url_status") == "online")
            offline = sum(1 for u in urls_list if u.get("url_status") == "offline")
            # Collect unique tags/threats
            all_tags    = sorted(set(
                t for u in urls_list for t in (u.get("tags") or [])
            ))
            all_threats = sorted(set(
                u.get("threat") for u in urls_list if u.get("threat")
            ))

            result = {
                "available":         True,
                "found":             True,
                "host":              domain,
                "url_count":         data.get("url_count", len(urls_list)),
                "urls_online":       online,
                "urls_offline":      offline,
                "tags":              all_tags,
                "threats":           all_threats,
                "blacklists": {
                    "spamhaus_dbl": blacklists.get("spamhaus_dbl", "not listed"),
                    "surbl":        blacklists.get("surbl", "not listed"),
                },
                "urlhaus_reference": data.get("urlhaus_reference"),
                "query_status": status,
            }

        else:
            result = {"available": False, "reason": f"unexpected status: {status!r}"}

    except httpx.TimeoutException:
        result = {"available": False, "reason": "URLhaus host lookup timed out"}
    except Exception as e:
        result = {"available": False, "reason": str(e)[:120]}

    _HOST_CACHE[domain] = (result, time.time())
    return result


# ── Combined scan ──────────────────────────────────────────────────────────────

async def urlhaus_scan(url: str) -> dict:
    """
    Run both URL and host lookups concurrently and merge the results
    into a single dict that scanner.py stores in result["urlhaus"].
    """
    url_result, host_result = await asyncio.gather(
        lookup_url(url),
        lookup_host(url),
    )
    return {
        "url_lookup":  url_result,
        "host_lookup": host_result,
    }


def urlhaus_risk_signals(urlhaus_result: dict) -> list[str]:
    """
    Extract human-readable risk signals from a combined urlhaus_scan result.
    Returns [] if the API was unavailable — never crashes the verdict engine.
    """
    signals = []
    url_r  = urlhaus_result.get("url_lookup",  {})
    host_r = urlhaus_result.get("host_lookup", {})

    # URL-level signals
    if url_r.get("available") and url_r.get("found"):
        status = url_r.get("url_status", "")
        threat = url_r.get("threat", "")
        tags   = url_r.get("tags", [])
        tag_str = f" ({', '.join(tags[:3])})" if tags else ""

        if status == "online":
            signals.append(
                f"URLhaus: URL is ACTIVELY ONLINE and listed as {threat or 'malicious'}{tag_str}"
            )
        else:
            signals.append(
                f"URLhaus: URL was listed as {threat or 'malicious'}{tag_str} "
                f"(currently {status or 'unknown status'})"
            )

        bls = url_r.get("blacklists", {})
        if bls.get("spamhaus_dbl") not in (None, "not listed"):
            signals.append(f"Spamhaus DBL listed: {bls['spamhaus_dbl']}")
        if bls.get("surbl") not in (None, "not listed"):
            signals.append(f"SURBL listed: {bls['surbl']}")

    # Host-level signals (even if this exact URL isn't listed)
    if host_r.get("available") and host_r.get("found"):
        count   = host_r.get("url_count", 0)
        online  = host_r.get("urls_online", 0)
        threats = host_r.get("threats", [])
        t_str   = f" ({', '.join(threats[:2])})" if threats else ""
        if not url_r.get("found"):   # only add if URL wasn't already flagged
            signals.append(
                f"URLhaus: Host has {count} malicious URL(s) in database "
                f"({online} currently online){t_str}"
            )

    return signals
