"""
core/features.py

Shared feature-extraction module. Used by BOTH the live server (scanner.py)
and the offline training script (training/train.py) — must have NO dependency
on FastAPI, SQLModel, or anything training/server-specific. Pure function in,
numeric vector out.

Two tiers of features:
  1. Lexical/structural — synchronous, no network call, near-instant.
     This is FEATURE_VECTOR_LENGTH and what K-means/SOM are trained on for v1.
  2. WHOIS/domain-age — requires a network lookup. Kept as a separate async
     function so the scanner can decide whether to include it (and so training
     doesn't need to do live WHOIS lookups for every historical row). Not part
     of the core vector yet — wire in later as v2 once we decide how to handle
     missing/failed lookups in the vector.

Vector order is fixed and must never change without bumping a model version,
since K-means/SOM are trained on positional meaning.

Scaling/normalization is intentionally NOT done here. This module only ever
turns a URL into a raw numeric vector. The scaler (e.g. sklearn StandardScaler)
is fit once during offline training (training/train.py) and saved as an
artifact; core/models.py loads that same fitted scaler at scan time and
applies it before feeding vectors into K-means/SOM. Keeping fit-vs-apply
strictly separated this way avoids train/serve skew.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse

# Fixed order — DO NOT reorder without retraining models from scratch.
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_subdomains",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "digit_ratio",
    "special_char_ratio",
    "shannon_entropy",
    "has_at_symbol",
    "has_ip_host",
    "is_https",
    "suspicious_tld",
    "num_query_params",
    "typosquat_distance",
]

FEATURE_VECTOR_LENGTH = len(FEATURE_NAMES)

# Small curated list — extend as needed. Used for both the suspicious-TLD
# flag and as the comparison set for typosquat distance.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "club", "work", "support",
    "click", "country", "gq", "tk", "ml", "cf", "ga",
}

POPULAR_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "paypal.com", "instagram.com", "netflix.com",
    "linkedin.com", "github.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "ebay.com", "twitter.com", "yahoo.com",
]

IP_HOST_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-fA-F:]+\]?$"
)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string, 0 if empty."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _levenshtein(a: str, b: str) -> int:
    """Standard edit distance, no external deps."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                prev_row[j] + 1,        # deletion
                curr_row[j - 1] + 1,    # insertion
                prev_row[j - 1] + cost  # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


def _registrable_domain(host: str) -> str:
    """Naive registrable-domain extraction: last two dot-separated labels.
    e.g. 'login.account-verify.paypal.com.xyz' -> 'com.xyz' is WRONG for
    multi-part TLDs (co.uk, com.au, etc.) — a proper implementation needs
    the public suffix list (the `tldextract` package). Flagging this as a
    known limitation rather than adding a dependency at this stage; revisit
    if multi-part-TLD false positives/negatives show up in testing."""
    if not host:
        return ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _min_typosquat_distance(host: str) -> int:
    """Smallest edit distance between this URL's REGISTRABLE domain (not the
    full host — subdomains stripped) and any popular domain. Comparing the
    registrable domain instead of the full host avoids the distance being
    inflated by subdomain noise like 'login.account-verify.paypal.com',
    which should compare near-identically to 'paypal.com' rather than being
    penalized for length. Small (but nonzero) distance is the typosquat
    signal; 0 means an exact match to a known popular domain (not inherently
    malicious on its own, just informative — e.g. legitimate paypal.com)."""
    domain = _registrable_domain(host)
    if not domain:
        return max(len(d) for d in POPULAR_DOMAINS)
    return min(_levenshtein(domain, d) for d in POPULAR_DOMAINS)


def _suspicious_tld(domain: str) -> int:
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    return 1 if tld in SUSPICIOUS_TLDS else 0


def _is_ip_host(host: str) -> int:
    return 1 if IP_HOST_RE.match(host or "") else 0


def extract_features(url: str) -> list[float]:
    """
    Main entry point. Takes a raw URL string, returns a fixed-length
    numeric feature vector in FEATURE_NAMES order.

    Does NOT normalize/scale — that happens downstream (training script
    fits a scaler; live scoring reuses the same fitted scaler artifact).
    Does NOT raise on malformed URLs — returns a best-effort vector so a
    single bad input can't crash the scan worker; malformed/unparsable
    fields just fall back to 0 / empty-string defaults.
    """
    url = (url or "").strip()

    # Be forgiving: prepend a scheme if missing so urlparse behaves.
    parse_target = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url) else f"http://{url}"

    try:
        parsed = urlparse(parse_target)
    except ValueError:
        parsed = urlparse("http://")

    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    domain_parts = host.split(".") if host else []
    # crude subdomain count: anything beyond "domain.tld" is a subdomain level
    num_subdomains = max(0, len(domain_parts) - 2)

    digits = sum(c.isdigit() for c in url)
    specials = sum(not c.isalnum() for c in url)
    url_len = len(url) or 1  # avoid div-by-zero below

    query_params = [p for p in query.split("&") if p] if query else []

    vector = [
        len(url),                                   # url_length
        len(host),                                  # domain_length
        len(path),                                  # path_length
        len(query),                                 # query_length
        num_subdomains,                             # num_subdomains
        url.count("."),                             # num_dots
        url.count("-"),                             # num_hyphens
        digits,                                      # num_digits
        digits / url_len,                            # digit_ratio
        specials / url_len,                           # special_char_ratio
        _shannon_entropy(url),                         # shannon_entropy
        1 if "@" in url else 0,                          # has_at_symbol
        _is_ip_host(host),                                # has_ip_host
        1 if parsed.scheme == "https" else 0,               # is_https
        _suspicious_tld(host),                                # suspicious_tld
        len(query_params),                                      # num_query_params
        _min_typosquat_distance(host),                            # typosquat_distance
    ]

    assert len(vector) == FEATURE_VECTOR_LENGTH, "vector length drifted from FEATURE_NAMES"
    return vector


def extract_features_dict(url: str) -> dict[str, float]:
    """Same as extract_features but returns a name->value dict.
    Handy for the report generator / debugging — not used by the models."""
    return dict(zip(FEATURE_NAMES, extract_features(url)))


# --- Tier 2: network-dependent feature (not yet part of the core vector) ---

async def get_domain_age_days(host: str) -> float | None:
    """
    Async WHOIS lookup -> domain age in days, or None if lookup fails.
    Kept separate from extract_features() on purpose:
      - it's a network call (slow, can fail/timeout)
      - training script can't run this for every historical row without
        hammering WHOIS servers
    Scanner.py decides if/when to call this and how to fold a None into
    the eventual feature set (e.g. impute with median age at training time).
    Left as a stub until we wire in a WHOIS library (e.g. `whois` or
    `aiowhois`) — implement when we get to scanner.py.
    """
    raise NotImplementedError("Wire in once we build scanner.py")


if __name__ == "__main__":
    # quick manual sanity check
    samples = [
        "https://www.google.com/search?q=test",
        "http://192.168.1.1/login",
        "http://g00gle.com-secure-login.tk/verify?id=12345",
        "paypal.com.account-verify.xyz/login",
    ]
    for s in samples:
        print(s)
        for name, val in extract_features_dict(s).items():
            print(f"  {name:22s} {val}")
        print()
