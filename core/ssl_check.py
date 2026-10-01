"""
core/ssl_check.py

Async SSL certificate inspection. Pure Python stdlib — no extra dependencies.

Extracts from every HTTPS URL:
  - Certificate validity (passes / fails chain verification)
  - Issuer name + organisation
  - Subject common name
  - Certificate age in days (newly issued certs are a phishing indicator)
  - Days until expiry
  - Whether the cert is self-signed
  - Whether it's expired
  - Subject Alternative Name (SAN) count
  - Wildcard certificate detection

For HTTP URLs (no TLS), returns is_http=True with no cert data — the
absence of HTTPS is itself surfaced as a signal in the report.

Risk signals produced:
  - Expired certificate            → high severity
  - Self-signed certificate        → suspicious
  - Cert issued < 5 days ago       → phishing indicator (paired with domain
                                      age via scanner.py's corroboration
                                      check, since even a tight threshold
                                      carries some routine-renewal noise)
  - Cert expires in < 7 days       → warning
  - Cert/hostname mismatch         → suspicious

Runs concurrently with VT/GSB/URLhaus/WHOIS via asyncio.gather in scanner.py.
"""

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

CERT_TIMEOUT   = 8.0    # seconds for TCP + TLS handshake
# NOTE: Let's Encrypt / ZeroSSL certs are valid 90 days and standard clients
# (e.g. certbot) renew once 30 days remain -- i.e. at day 60 of the cert's
# life. In steady state that means a routinely-renewed, completely ordinary
# HTTPS site sits under 30 days old roughly HALF the time, purely from
# automatic renewal. A 30-day threshold therefore flags ~50% of normal,
# long-established sites as "newly issued". Tightened to 5 days, which
# only catches genuinely implausible freshness (a cert issued days ago is
# very unlikely to be routine renewal noise) while still catching the
# classic "domain + cert stood up together for a campaign" pattern. Even
# at this threshold this signal alone is weak (~8% baseline false-positive
# rate against normal renewal timing) -- scanner.py additionally requires
# corroboration before letting this signal alone drive a SUSPICIOUS verdict.
NEW_CERT_DAYS  = 5
EXPIRY_WARN    = 7      # flag certs expiring within this many days


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_ssl_date(val: str) -> Optional[datetime]:
    """Parse 'Jun  1 00:00:00 2026 GMT' format returned by getpeercert()."""
    if not val:
        return None
    try:
        return datetime.strptime(val.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(val.strip(), "%b  %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _extract_cn(rdns_tuple) -> Optional[str]:
    """Extract commonName from a nested RDN tuple from getpeercert()."""
    if not rdns_tuple:
        return None
    for rdn in rdns_tuple:
        for attr, val in rdn:
            if attr == "commonName":
                return val
    return None


def _extract_org(rdns_tuple) -> Optional[str]:
    """Extract organizationName from a nested RDN tuple."""
    if not rdns_tuple:
        return None
    for rdn in rdns_tuple:
        for attr, val in rdn:
            if attr == "organizationName":
                return val
    return None


def _days_since(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    return max(0, (datetime.now(timezone.utc) - dt).days)


def _days_until(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    return (dt - datetime.now(timezone.utc)).days


# ── Core cert fetch ────────────────────────────────────────────────────────────

def _fetch_cert_verified(hostname: str, port: int) -> tuple[dict, bool, str | None]:
    """
    Attempt to fetch cert with full chain verification.
    Returns (cert_dict, verified=True, error=None) on success.
    Returns ({}, False, error_msg) on failure.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=CERT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                return tls.getpeercert(), True, None
    except ssl.SSLCertVerificationError as e:
        return {}, False, str(e)
    except ssl.SSLError as e:
        return {}, False, str(e)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {}, False, str(e)


def _fetch_cert_unverified(hostname: str, port: int) -> tuple[dict, str | None]:
    """
    Fetch cert without chain verification (for self-signed or expired certs).
    Uses CERT_OPTIONAL so getpeercert() still returns the cert dict.
    Returns (cert_dict, error) — cert_dict may be empty.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_OPTIONAL
    try:
        with socket.create_connection((hostname, port), timeout=CERT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                return tls.getpeercert() or {}, None
    except Exception as e:
        return {}, str(e)


def _parse_cert(cert: dict, verified: bool, verify_error: str | None) -> dict:
    """Turn a getpeercert() dict into our structured result."""
    subject_tuple = cert.get("subject", ())
    issuer_tuple  = cert.get("issuer", ())

    subject_cn = _extract_cn(subject_tuple)
    issuer_cn  = _extract_cn(issuer_tuple)
    issuer_org = _extract_org(issuer_tuple)

    not_before = _parse_ssl_date(cert.get("notBefore"))
    not_after  = _parse_ssl_date(cert.get("notAfter"))

    cert_age_days  = _days_since(not_before)
    expiry_days    = _days_until(not_after)
    is_expired     = (expiry_days is not None and expiry_days < 0)
    is_self_signed = bool(subject_cn and issuer_cn and subject_cn == issuer_cn)
    is_new_cert    = (cert_age_days is not None and cert_age_days < NEW_CERT_DAYS)
    expiring_soon  = (expiry_days is not None and 0 <= expiry_days < EXPIRY_WARN)

    # Subject Alternative Names
    san_list = cert.get("subjectAltName", [])
    san_dns   = [v for t, v in san_list if t == "DNS"]
    san_count = len(san_dns)
    is_wildcard = any(v.startswith("*.") for v in san_dns)

    # Free / cheap CA detection (common in phishing but NOT a hard signal)
    free_cas = {"Let's Encrypt", "ZeroSSL", "Buypass", "R3", "E1", "E2"}
    is_free_ca = bool(issuer_cn and any(ca in issuer_cn for ca in free_cas))

    return {
        "available":          True,
        "is_http":            False,
        "verified":           verified,
        "verify_error":       verify_error,
        "subject_cn":         subject_cn,
        "issuer_cn":          issuer_cn,
        "issuer_org":         issuer_org,
        "not_before":         not_before.isoformat()  if not_before else None,
        "not_after":          not_after.isoformat()   if not_after  else None,
        "cert_age_days":      cert_age_days,
        "expiry_days":        expiry_days,
        "is_expired":         is_expired,
        "is_self_signed":     is_self_signed,
        "is_new_cert":        is_new_cert,
        "expiring_soon":      expiring_soon,
        "san_count":          san_count,
        "san_dns":            san_dns[:10],
        "is_wildcard":        is_wildcard,
        "is_free_ca":         is_free_ca,
        "version":            cert.get("version"),
    }


def _do_ssl_check(hostname: str, port: int) -> dict:
    """
    Synchronous SSL check. Called via asyncio.to_thread().

    Try order:
      1. Full verification → cert + verified=True
      2. If verification fails → unverified fetch to still get cert data
         (lets us detect self-signed, expired, etc. and show them in report)
    """
    # Attempt 1: full verification
    cert, verified, err = _fetch_cert_verified(hostname, port)

    if cert:
        return _parse_cert(cert, verified=True, verify_error=None)

    # Attempt 2: unverified (for self-signed / expired / chain issues)
    cert2, err2 = _fetch_cert_unverified(hostname, port)
    if cert2:
        return _parse_cert(cert2, verified=False, verify_error=err)

    # Both attempts failed
    return {
        "available":  False,
        "is_http":    False,
        "error":      err or err2 or "SSL handshake failed",
    }


# ── Public async API ───────────────────────────────────────────────────────────

async def ssl_check(url: str) -> dict:
    """
    Async SSL certificate inspection for a URL.
    Returns a structured dict — never raises.

    For HTTP URLs (no TLS), returns {"available": True, "is_http": True}.
    For HTTPS URLs, returns full cert info (see _parse_cert).
    On any error returns {"available": False, "error": "..."}.
    """
    try:
        target   = url if "://" in url else f"http://{url}"
        parsed   = urlparse(target)
        scheme   = parsed.scheme.lower()
        hostname = parsed.hostname or ""
        port     = parsed.port or (443 if scheme == "https" else 80)
    except Exception as e:
        return {"available": False, "is_http": False, "error": str(e)}

    if not hostname:
        return {"available": False, "is_http": False, "error": "empty hostname"}

    # HTTP — no TLS, note it and return
    if scheme != "https":
        return {
            "available": True,
            "is_http":   True,
            "error":     None,
        }

    # HTTPS — run SSL check in thread (blocking socket I/O)
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_do_ssl_check, hostname, port),
            timeout=CERT_TIMEOUT + 4,
        )
        return result
    except asyncio.TimeoutError:
        return {"available": False, "is_http": False,
                "error": f"SSL check timed out after {CERT_TIMEOUT}s"}
    except Exception as e:
        return {"available": False, "is_http": False, "error": str(e)}


def ssl_risk_signals(ssl_result: dict) -> list[str]:
    """
    Extract human-readable risk signals from an SSL check result.
    Returns [] if SSL unavailable — never crashes the verdict engine.
    """
    signals = []

    if not ssl_result.get("available"):
        return signals

    if ssl_result.get("is_http"):
        signals.append("No HTTPS — connection is unencrypted")
        return signals

    if ssl_result.get("is_expired"):
        days = abs(ssl_result.get("expiry_days", 0))
        signals.append(f"SSL certificate is EXPIRED ({days} day(s) ago)")

    if ssl_result.get("is_self_signed"):
        signals.append(
            f"Self-signed certificate — not trusted by any CA "
            f"(issuer: {ssl_result.get('issuer_cn', '?')})"
        )

    if not ssl_result.get("verified") and not ssl_result.get("is_self_signed"):
        err = ssl_result.get("verify_error", "")
        signals.append(f"Certificate verification failed: {err[:80]}")

    if ssl_result.get("is_new_cert"):
        age = ssl_result.get("cert_age_days", 0)
        signals.append(
            f"Certificate issued only {age} day(s) ago — "
            f"newly issued certs are common in phishing campaigns"
        )

    if ssl_result.get("expiring_soon") and not ssl_result.get("is_expired"):
        days = ssl_result.get("expiry_days", 0)
        signals.append(f"Certificate expires in {days} day(s)")

    return signals