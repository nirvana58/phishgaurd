"""
core/whois_lookup.py

Domain intelligence via RDAP (Registration Data Access Protocol).

WHY RDAP INSTEAD OF WHOIS:
  Classic WHOIS uses raw TCP port 43 — frequently blocked by ISPs,
  corporate firewalls, and cloud providers. RDAP is the ICANN-standardised
  replacement that runs over HTTPS (port 443, always open), returns
  structured JSON (no text parsing needed), and has the same data.

LOOKUP CHAIN (tried in order, first success wins):
  1. rdap.org          — public RDAP aggregator, handles all TLDs
  2. rdap.iana.org     — IANA's own RDAP bootstrap
  3. Verisign RDAP     — for .com / .net domains specifically
  4. python-whois      — port 43 fallback (works if port is open)

CACHING:
  Results are cached in-process per registrable domain for 1 hour.
  Batch scans hitting the same domain never make duplicate queries.

USAGE:
  from core.whois_lookup import whois_lookup, whois_risk_signals
  result = await whois_lookup("http://paypa1.com/login")
"""

import asyncio
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

# ── Cache ──────────────────────────────────────────────────────────────────────
_WHOIS_CACHE: dict[str, tuple[dict, float]] = {}
_CACHE_TTL    = 3600     # 1 hour
LOOKUP_TIMEOUT = 20.0    # seconds per RDAP request
NEW_DOMAIN_DAYS = 30

# RDAP servers to try in order
_RDAP_SERVERS = [
    "https://rdap.org/domain/{domain}",
    "https://www.rdap.net/domain/{domain}",
    "https://rdap.iana.org/domain/{domain}",
    "https://rdap.verisign.com/com/v1/domain/{domain}",   # .com / .net
]

_RDAP_HEADERS = {
    "User-Agent":   "url-threat-scanner/1.0 (security research tool)",
    "Accept":       "application/rdap+json, application/json;q=0.9, */*;q=0.8",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _registrable_domain(host: str) -> str:
    if not host:
        return ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _parse_date(val) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.replace(tzinfo=timezone.utc) if val.tzinfo is None else val
    if isinstance(val, str):
        val = val.strip()
        # Strip timezone suffixes so strptime sees a clean datetime
        for suffix in ("+00:00", "Z"):
            if val.endswith(suffix):
                val = val[:-len(suffix)]
        # Remove microseconds
        if "." in val:
            val = val[:val.index(".")]
        for fmt in (
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d-%b-%Y",
        ):
            try:
                return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _days_since(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    return max(0, (datetime.now(timezone.utc) - dt).days)


def _days_until(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    return (dt - datetime.now(timezone.utc)).days


def _clean(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return None
    return str(val).strip()[:100] or None


# ── RDAP response parser ───────────────────────────────────────────────────────

def _parse_rdap_response(data: dict, domain: str) -> dict:
    """
    Parse an RDAP JSON response into our standard result dict.
    RDAP spec: RFC 7483 / RFC 9083
    """
    # Events → dates
    events: dict[str, str] = {}
    for ev in data.get("events", []):
        action = ev.get("eventAction", "").lower()
        date   = ev.get("eventDate", "")
        if date:
            events[action] = date

    creation   = _parse_date(
        events.get("registration") or events.get("domain registration")
    )
    expiration = _parse_date(
        events.get("expiration") or events.get("domain expiration")
    )
    updated    = _parse_date(
        events.get("last changed") or events.get("last update of rdap database")
    )

    age_days    = _days_since(creation)
    expiry_days = _days_until(expiration)

    # Registrar + country from entities
    registrar = None
    country   = None

    for entity in data.get("entities", []):
        roles = [r.lower() for r in entity.get("roles", [])]

        if "registrar" in roles and registrar is None:
            # Try vcardArray first
            vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
            for item in vcard:
                if isinstance(item, list) and item and item[0] == "fn":
                    registrar = _clean(item[3] if len(item) > 3 else None)
                    break
            # Fallback: publicIds
            if not registrar:
                for pid in entity.get("publicIds", []):
                    if pid.get("type") == "IANA Registrar ID":
                        registrar = _clean(entity.get("handle"))

        if "registrant" in roles and country is None:
            vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
            for item in vcard:
                if isinstance(item, list) and item and item[0] == "adr":
                    params = item[1] if len(item) > 1 else {}
                    addr   = item[3] if len(item) > 3 else []
                    if isinstance(addr, list) and len(addr) >= 7:
                        country = _clean(addr[6])
                    elif isinstance(params, dict):
                        country = _clean(params.get("cc") or params.get("country"))
                    break

    # Name servers
    ns_list  = data.get("nameservers", [])
    ns_count = len(set(
        n.get("ldhName", "").lower().rstrip(".")
        for n in ns_list
        if isinstance(n, dict)
    ))

    # Status
    status_list = data.get("status", [])
    if isinstance(status_list, str):
        status_list = [status_list]

    return {
        "available":       True,
        "domain":          domain,
        "registrar":       registrar,
        "country":         country,
        "creation_date":   creation.isoformat()   if creation   else None,
        "expiration_date": expiration.isoformat() if expiration else None,
        "updated_date":    updated.isoformat()    if updated    else None,
        "age_days":        age_days,
        "expiry_days":     expiry_days,
        "ns_count":        ns_count,
        "statuses":        status_list,
        "is_new_domain":   (age_days is not None and age_days < NEW_DOMAIN_DAYS),
        "expiring_soon":   (expiry_days is not None and 0 <= expiry_days < 30),
        "is_ip_host":      False,
        "source":          "rdap",
    }


# ── RDAP query ─────────────────────────────────────────────────────────────────

async def _query_rdap(domain: str) -> dict:
    """
    Try each RDAP server in _RDAP_SERVERS until one returns 200.
    All use HTTPS (port 443) — no port 43 dependency.
    """
    last_error = "all RDAP servers unreachable"

    async with httpx.AsyncClient(
        headers=_RDAP_HEADERS,
        timeout=LOOKUP_TIMEOUT,
        follow_redirects=True,
    ) as client:
        for template in _RDAP_SERVERS:
            url = template.format(domain=domain)
            try:
                resp = await client.get(url)

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        return _parse_rdap_response(data, domain)
                    except Exception as e:
                        last_error = f"RDAP JSON parse error: {e}"
                        continue

                elif resp.status_code == 404:
                    return {
                        "available": False,
                        "reason": "domain not found in RDAP registry (may be newly registered or invalid)",
                    }

                elif resp.status_code == 429:
                    last_error = "RDAP rate limit hit — try again later"
                    # Still try next server
                    continue

                else:
                    last_error = f"{url.split('/')[2]} returned HTTP {resp.status_code}"

            except httpx.TimeoutException:
                last_error = f"{url.split('/')[2]} timed out"
            except httpx.ConnectError:
                last_error = f"{url.split('/')[2]} unreachable"
            except Exception as e:
                last_error = str(e)[:100]

    return {"available": False, "reason": last_error}


# ── python-whois fallback (port 43) ───────────────────────────────────────────

def _query_port43_sync(domain: str) -> dict:
    """
    Synchronous fallback using python-whois (port 43).
    Only used if all RDAP servers fail.
    """
    try:
        import whois as _w

        # python-whois: whois.whois()
        if callable(getattr(_w, "whois", None)):
            w = _w.whois(domain)
            if not w or not getattr(w, "domain_name", None):
                return {"available": False, "reason": "empty WHOIS response"}

            creation   = _parse_date(w.creation_date)
            expiration = _parse_date(w.expiration_date)
            updated    = _parse_date(w.updated_date)
            age_days   = _days_since(creation)
            expiry_days = _days_until(expiration)
            registrar  = _clean(w.registrar)
            country    = _clean(getattr(w, "country", None))
            ns         = w.name_servers or []
            if isinstance(ns, str):
                ns = [ns]
            ns_count = len(set(n.lower().rstrip(".") for n in ns))

            return {
                "available":       True,
                "domain":          domain,
                "registrar":       registrar,
                "country":         country,
                "creation_date":   creation.isoformat()   if creation   else None,
                "expiration_date": expiration.isoformat() if expiration else None,
                "updated_date":    updated.isoformat()    if updated    else None,
                "age_days":        age_days,
                "expiry_days":     expiry_days,
                "ns_count":        ns_count,
                "is_new_domain":   (age_days is not None and age_days < NEW_DOMAIN_DAYS),
                "expiring_soon":   (expiry_days is not None and 0 <= expiry_days < 30),
                "is_ip_host":      False,
                "source":          "whois-port43",
            }

        # whois package: whois.query()
        elif callable(getattr(_w, "query", None)):
            w = _w.query(domain)
            if not w:
                return {"available": False, "reason": "empty WHOIS response"}
            creation   = _parse_date(getattr(w, "creation_date", None))
            expiration = _parse_date(getattr(w, "expiration_date", None))
            age_days   = _days_since(creation)
            expiry_days = _days_until(expiration)
            return {
                "available":       True,
                "domain":          domain,
                "registrar":       _clean(getattr(w, "registrar", None)),
                "country":         _clean(getattr(w, "registrant_country", None)),
                "creation_date":   creation.isoformat()   if creation   else None,
                "expiration_date": expiration.isoformat() if expiration else None,
                "updated_date":    None,
                "age_days":        age_days,
                "expiry_days":     expiry_days,
                "ns_count":        len(getattr(w, "name_servers", None) or []),
                "is_new_domain":   (age_days is not None and age_days < NEW_DOMAIN_DAYS),
                "expiring_soon":   (expiry_days is not None and 0 <= expiry_days < 30),
                "is_ip_host":      False,
                "source":          "whois-port43",
            }

        return {"available": False, "reason": "no compatible whois package found"}

    except Exception as e:
        err = str(e).lower()
        if "timed out" in err or "timeout" in err:
            return {"available": False, "reason": "port 43 blocked or timed out"}
        if "connection refused" in err:
            return {"available": False, "reason": "port 43 connection refused"}
        return {"available": False, "reason": str(e)[:120]}


# ── Public async API ───────────────────────────────────────────────────────────

async def whois_lookup(url: str) -> dict:
    """
    Full domain intelligence lookup for any URL.

    Flow:
      1. Extract registrable domain from URL
      2. Check in-process cache (1h TTL)
      3. Try RDAP over HTTPS (multiple servers, no port 43)
      4. If all RDAP servers fail → fallback to python-whois (port 43)
      5. Cache and return result
    """
    # Parse host
    try:
        target = url if "://" in url else f"http://{url}"
        host   = urlparse(target).hostname or ""
    except Exception:
        return {"available": False, "reason": "could not parse URL"}

    # IP host
    import re
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-fA-F:]+\]?$", host):
        return {
            "available":  True,
            "domain":     host,
            "is_ip_host": True,
            "age_days":   None,
            "registrar":  None,
            "country":    None,
            "ns_count":   0,
            "is_new_domain": False,
            "expiring_soon": False,
        }

    domain = _registrable_domain(host)
    if not domain:
        return {"available": False, "reason": "could not extract domain"}

    # Cache hit
    cached = _WHOIS_CACHE.get(domain)
    if cached:
        result, ts = cached
        if time.time() - ts < _CACHE_TTL:
            return {**result, "cached": True}

    # 1. Try RDAP (HTTPS — no port 43)
    try:
        result = await asyncio.wait_for(_query_rdap(domain), timeout=LOOKUP_TIMEOUT + 5)
    except asyncio.TimeoutError:
        result = {"available": False, "reason": "all RDAP servers timed out"}
    except Exception as e:
        result = {"available": False, "reason": f"RDAP error: {e}"}

    # 2. Fallback: python-whois port 43 (if RDAP completely failed)
    if not result.get("available"):
        try:
            port43 = await asyncio.wait_for(
                asyncio.to_thread(_query_port43_sync, domain),
                timeout=LOOKUP_TIMEOUT,
            )
            if port43.get("available"):
                result = port43
        except Exception:
            pass  # Keep the RDAP error — it's more informative

    _WHOIS_CACHE[domain] = (result, time.time())
    return result


def whois_risk_signals(whois_result: dict) -> list[str]:
    """
    Extract human-readable risk signals from a WHOIS result.
    Returns [] if WHOIS unavailable — a failed lookup never
    changes the verdict on its own.
    """
    if not whois_result.get("available") or whois_result.get("is_ip_host"):
        return []

    signals = []
    age = whois_result.get("age_days")

    if whois_result.get("is_new_domain") and age is not None:
        signals.append(
            f"Newly registered domain ({age} day(s) old — strong phishing indicator)"
        )
    elif age is not None and age < 90:
        signals.append(f"Domain is less than 90 days old ({age} days)")

    if whois_result.get("expiring_soon"):
        days = whois_result.get("expiry_days", 0)
        signals.append(f"Domain expiring in {days} day(s)")

    if whois_result.get("ns_count") == 1:
        signals.append("Only 1 name server — unusual for legitimate domains")

    return signals