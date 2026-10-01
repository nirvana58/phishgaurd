"""
core/brand_protection.py

Two related detection features, both aimed at the brand-impersonation /
lookalike-domain attack pattern that current threat reporting (APWG Q1 2026,
via ZeroFox data) shows is the single largest category of social-media
phishing threats (43.8% impersonation), with finance, retail, and federal
government brands most heavily spoofed:

  1. Homograph / punycode (IDN spoofing) detection
     Catches domains using punycode-encoded internationalized characters
     (xn-- prefix) or mixed-script/confusable-character substitution to
     visually impersonate a legitimate ASCII domain
     (e.g. "аpple.com" using Cyrillic а instead of Latin a).

  2. Typosquatting / combosquatting distance check
     Flags domains that are suspiciously close (by edit distance) to a
     known, popular brand domain, or that embed a brand name alongside
     common phishing-suffix words ("-secure", "-support", "-login", etc).

Both functions return a result dict, plus a companion `*_risk_signals()`
function that formats findings into the same list[str] shape used by
whois_risk_signals() / ssl_risk_signals() / urlhaus_risk_signals(), so they
drop straight into scanner.py's `all_extra` signal aggregation:

    from core.brand_protection import (
        check_homograph, homograph_risk_signals,
        check_typosquat, typosquat_risk_signals,
    )
    ...
    homograph_result  = check_homograph(url)
    typosquat_result  = check_typosquat(url, known_brand_domains=BRAND_LIST)
    all_extra = (chain_signals + urlhaus_signals + ssl_signals + whois_signals
                 + homograph_risk_signals(homograph_result)
                 + typosquat_risk_signals(typosquat_result))
"""

import unicodedata
from urllib.parse import urlparse

# ── Homograph / confusable character detection ─────────────────────────────

# Common Cyrillic/Greek characters visually confusable with Latin letters,
# frequently used in real-world homograph phishing (e.g. the well-known
# "xn--80ak6aa92e.com" apple.com proof-of-concept from 2017).
# Mapping: confusable char -> the Latin letter it impersonates.
CONFUSABLE_MAP = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ѕ": "s", "һ": "h", "ј": "j", "ԁ": "d",
    "ç": "c",  # not cyrillic but included as a common trick char
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "υ": "y", "ι": "i",
}

CONFUSABLE_CHARS = set(CONFUSABLE_MAP.keys())


def _get_hostname(url_or_domain: str) -> str:
    """Extract bare hostname whether given a full URL or a bare domain."""
    if "://" in url_or_domain:
        host = urlparse(url_or_domain).netloc
    else:
        host = url_or_domain
    if host.startswith("www."):
        host = host[4:]
    return host.strip().lower()


def _script_of(char: str) -> str:
    """Rough script classification via unicodedata name - good enough to
    distinguish Latin vs Cyrillic vs Greek without a full ICU dependency."""
    try:
        name = unicodedata.name(char)
    except ValueError:
        return "UNKNOWN"
    if "CYRILLIC" in name:
        return "CYRILLIC"
    if "GREEK" in name:
        return "GREEK"
    if "LATIN" in name or char.isascii():
        return "LATIN"
    return "OTHER"


def check_homograph(url_or_domain: str) -> dict:
    """
    Detects punycode encoding and mixed-script / confusable-character use
    in a domain - both are strong indicators of visual brand impersonation
    rather than a coincidentally similar-looking legitimate domain.
    """
    host = _get_hostname(url_or_domain)
    labels = host.split(".")

    is_punycode = any(label.startswith("xn--") for label in labels)

    # Decode punycode labels to their actual unicode form for inspection,
    # since "xn--80ak6aa92e" alone doesn't tell us what it visually renders as.
    decoded_labels = []
    for label in labels:
        if label.startswith("xn--"):
            try:
                decoded_labels.append(label.encode("ascii").decode("idna"))
            except Exception:
                decoded_labels.append(label)  # decode failed, keep raw
        else:
            decoded_labels.append(label)
    decoded_host = ".".join(decoded_labels)

    confusable_chars_found = [c for c in decoded_host if c in CONFUSABLE_CHARS]

    scripts_present = {_script_of(c) for c in decoded_host if c.isalpha()}
    scripts_present.discard("UNKNOWN")
    is_mixed_script = len([s for s in scripts_present if s != "OTHER"]) > 1

    # Build the "what this would look like impersonating" string, useful
    # for showing analysts/users what the confusable chars resolve to.
    latin_lookalike = "".join(CONFUSABLE_MAP.get(c, c) for c in decoded_host)

    return {
        "hostname": host,
        "decoded_hostname": decoded_host,
        "is_punycode": is_punycode,
        "is_mixed_script": is_mixed_script,
        "scripts_present": sorted(scripts_present),
        "confusable_char_count": len(confusable_chars_found),
        "confusable_chars": confusable_chars_found,
        "latin_lookalike": latin_lookalike if confusable_chars_found else None,
    }


def homograph_risk_signals(result: dict) -> list[str]:
    signals = []
    if result.get("is_punycode"):
        signals.append(
            f"Punycode-encoded domain (xn--) - decodes to '{result.get('decoded_hostname')}'"
        )
    if result.get("is_mixed_script"):
        scripts = ", ".join(result.get("scripts_present", []))
        signals.append(f"Mixed-script hostname ({scripts}) - possible homograph spoofing")
    if result.get("confusable_char_count", 0) > 0:
        signals.append(
            f"{result['confusable_char_count']} confusable character(s) found - "
            f"visually resembles '{result.get('latin_lookalike')}'"
        )
    return signals


# ── Typosquatting / combosquatting detection ────────────────────────────────

COMBOSQUAT_SUFFIXES = [
    "secure", "support", "login", "verify", "account", "update",
    "confirm", "billing", "help", "service", "portal", "auth",
    "signin", "security", "alert", "recovery",
]

# Edit distance <= this value from a known brand domain is flagged.
# 1-2 catches character swaps/insertions/deletions (paypa1, paypall,
# paypal-l) without producing excessive false positives on genuinely
# unrelated short domains.
TYPOSQUAT_MAX_DISTANCE = 2

# Below this domain length, edit-distance comparison gets noisy (e.g. "cnn.com"
# vs "cnp.com" is distance 1 but likely unrelated) - require combosquat
# pattern matching instead for very short domains.
MIN_DOMAIN_LENGTH_FOR_DISTANCE_CHECK = 6


def _levenshtein(a: str, b: str) -> int:
    """Standard DP edit distance, no external dependency required."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                prev_row[j] + 1,       # deletion
                curr_row[j - 1] + 1,   # insertion
                prev_row[j - 1] + cost,  # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


def _strip_tld(domain: str) -> str:
    """Return just the registrable label (drop the TLD) for comparison,
    e.g. 'paypal.com' -> 'paypal'. Good enough for common gTLDs; doesn't
    handle multi-part TLDs like co.uk specially, which is an acceptable
    simplification for this heuristic feature."""
    parts = domain.split(".")
    return parts[0] if len(parts) >= 2 else domain


def check_typosquat(url_or_domain: str, known_brand_domains: list[str]) -> dict:
    """
    Compares the scanned domain against a list of known/popular brand
    domains (e.g. pulled from your Tranco/Majestic top-N benign pool) and
    flags close matches by edit distance, plus brand-name + suspicious-suffix
    combosquatting patterns (e.g. "paypal-secure-login.com").

    known_brand_domains: list of bare domains, e.g. ["paypal.com", "google.com", ...]
    """
    host = _get_hostname(url_or_domain)
    host_label = _strip_tld(host)

    best_match = None
    best_distance = None

    if len(host_label) >= MIN_DOMAIN_LENGTH_FOR_DISTANCE_CHECK:
        for brand_domain in known_brand_domains:
            brand_label = _strip_tld(_get_hostname(brand_domain))
            if brand_label == host_label:
                continue  # exact match to a known brand - not typosquatting, it IS the brand
            if abs(len(brand_label) - len(host_label)) > TYPOSQUAT_MAX_DISTANCE:
                continue  # length gap alone rules out being within distance threshold
            dist = _levenshtein(host_label, brand_label)
            if best_distance is None or dist < best_distance:
                best_distance = dist
                best_match = brand_domain

    is_close_match = (
        best_distance is not None and best_distance <= TYPOSQUAT_MAX_DISTANCE
    )

    # Combosquat pattern: known brand name embedded as a substring, combined
    # with a common phishing-suffix word (independent of edit distance -
    # catches "paypal-secure-login.com" which is edit-distance-far from
    # "paypal.com" but obviously impersonating it).
    combosquat_brand = None
    combosquat_suffix = None
    for brand_domain in known_brand_domains:
        brand_label = _strip_tld(_get_hostname(brand_domain))
        if len(brand_label) < 4:
            continue  # skip very short brand names, too noisy to substring-match
        if brand_label != host_label and brand_label in host_label:
            for suffix in COMBOSQUAT_SUFFIXES:
                if suffix in host_label:
                    combosquat_brand = brand_domain
                    combosquat_suffix = suffix
                    break
        if combosquat_brand:
            break

    return {
        "hostname": host,
        "closest_brand_match": best_match,
        "edit_distance": best_distance,
        "is_close_typosquat": is_close_match,
        "is_combosquat_pattern": combosquat_brand is not None,
        "combosquat_brand": combosquat_brand,
        "combosquat_suffix": combosquat_suffix,
    }


def typosquat_risk_signals(result: dict) -> list[str]:
    signals = []
    if result.get("is_close_typosquat"):
        signals.append(
            f"Domain is edit-distance {result['edit_distance']} from known brand "
            f"'{result['closest_brand_match']}' - possible typosquatting"
        )
    if result.get("is_combosquat_pattern"):
        signals.append(
            f"Domain embeds brand name '{result['combosquat_brand']}' alongside "
            f"suspicious term '{result['combosquat_suffix']}' - possible combosquatting"
        )
    return signals
