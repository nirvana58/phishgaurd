"""
server/scanner.py

Scan orchestrator. Called by the queue worker for each job.

Pipeline per URL:
  1. Feature extraction          (core/features.py  — sync, instant)
  2. ML anomaly scoring          (core/models.py    — sync, instant)
  3. External threat intel       (VirusTotal + Google Safe Browsing — async, concurrent)
  4. Aggregate all signals into a single result dict

The result dict is what gets stored as result_json in scan_jobs and later
handed to the report generator.

Environment variables needed (put in .env at project root):
  VIRUSTOTAL_API_KEY
  GOOGLE_SAFE_BROWSING_API_KEY
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

import httpx

from core.features import extract_features, extract_features_dict, FEATURE_NAMES
from core.models import ModelStore, AnomalyResult
from core.whois_lookup import whois_lookup, whois_risk_signals
from core.urlhaus import urlhaus_scan, urlhaus_risk_signals

# Anomaly thresholds — values in normalised score space.
# > 1.0 = notably outside the trained distribution.
# Tunable later from the admin panel; hardcoded here for now.
KMEANS_THRESHOLD = 1.0
SOM_THRESHOLD = 1.0

# Combined score above which we declare the URL suspicious from ML alone
# (external APIs can still override either direction).
ML_SUSPICIOUS_THRESHOLD = 0.8

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

REQUEST_TIMEOUT = 15.0   # seconds per external API call


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def _query_virustotal(url: str, client: httpx.AsyncClient) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "VIRUSTOTAL_API_KEY not set"}

    import base64
    # VT v3: URL ID = url-safe base64 of the URL (no padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        resp = await client.get(
            f"{VIRUSTOTAL_URL}/{url_id}",
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            # URL not in VT yet — submit it, note as pending (VT free tier
            # often needs a second poll; we just record not-found for now)
            return {"available": True, "status": "not_found", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}

        if resp.status_code != 200:
            return {"available": False, "reason": f"HTTP {resp.status_code}"}

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "available": True,
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except httpx.TimeoutException:
        return {"available": False, "reason": "timeout"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


# ── Google Safe Browsing ──────────────────────────────────────────────────────

async def _query_safe_browsing(url: str, client: httpx.AsyncClient) -> dict:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "GOOGLE_SAFE_BROWSING_API_KEY not set"}

    payload = {
        "client": {"clientId": "url-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = await client.post(
            f"{SAFE_BROWSING_URL}?key={api_key}",
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return {"available": False, "reason": f"HTTP {resp.status_code}"}

        data = resp.json()
        matches = data.get("matches", [])
        return {
            "available": True,
            "is_threat": len(matches) > 0,
            "threat_types": list({m.get("threatType") for m in matches}),
        }
    except httpx.TimeoutException:
        return {"available": False, "reason": "timeout"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


# ── Verdict logic ─────────────────────────────────────────────────────────────

def _compute_verdict(
    ml_combined_score: float,
    ml_agree: bool,
    vt: dict,
    gsb: dict,
    extra_signals: list[str] | None = None,
) -> dict:
    """
    Combine signals from ML, VirusTotal, Safe Browsing, and WHOIS.

    Priority:
      1. Safe Browsing flags it → MALICIOUS (real-time, high authority)
      2. VT >= 3 malicious detections → MALICIOUS
      3. VT 1-2 malicious OR ML agrees above threshold → SUSPICIOUS
      4. ML combined score alone above threshold → SUSPICIOUS (low confidence)
      5. WHOIS: newly registered domain → SUSPICIOUS if no other signals
      6. Otherwise → SAFE
    """
    reasons = list(extra_signals or [])

    if gsb.get("available") and gsb.get("is_threat"):
        reasons.append(f"Google Safe Browsing flagged: {', '.join(gsb.get('threat_types', []))}")
        return {"verdict": "MALICIOUS", "confidence": "HIGH", "reasons": reasons}

    # URLhaus: if any reason mentions an actively-online malicious URL → MALICIOUS
    for sig in reasons:
        if "ACTIVELY ONLINE" in sig:
            return {"verdict": "MALICIOUS", "confidence": "HIGH", "reasons": reasons}

    if vt.get("available") and vt.get("status") == "found":
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        if mal >= 3:
            reasons.append(f"VirusTotal: {mal} engines flagged as malicious")
            return {"verdict": "MALICIOUS", "confidence": "HIGH", "reasons": reasons}
        if mal > 0:
            reasons.append(f"VirusTotal: {mal} engine(s) flagged as malicious")
        if sus > 0:
            reasons.append(f"VirusTotal: {sus} engine(s) flagged as suspicious")

    if ml_agree and ml_combined_score > ML_SUSPICIOUS_THRESHOLD:
        reasons.append(
            f"ML models agree: anomaly score {ml_combined_score:.3f} "
            f"(threshold {ML_SUSPICIOUS_THRESHOLD})"
        )
        confidence = "MEDIUM" if ml_combined_score < 1.5 else "HIGH"
        return {"verdict": "SUSPICIOUS", "confidence": confidence, "reasons": reasons}

    if ml_combined_score > ML_SUSPICIOUS_THRESHOLD:
        reasons.append(
            f"ML anomaly score {ml_combined_score:.3f} above threshold "
            "(models disagree — treat as low confidence)"
        )
        return {"verdict": "SUSPICIOUS", "confidence": "LOW", "reasons": reasons}

    if reasons and any(
        "malicious" in r.lower() or "engine" in r.lower() for r in reasons
    ):
        return {"verdict": "SUSPICIOUS", "confidence": "LOW", "reasons": reasons}

    if reasons:  # WHOIS-only signals
        reasons_out = reasons[:]
        reasons_out.append("No direct threat detections — WHOIS signals only")
        return {"verdict": "SUSPICIOUS", "confidence": "LOW", "reasons": reasons_out}

    reasons.append("No threat signals detected")
    return {"verdict": "SAFE", "confidence": "HIGH", "reasons": reasons}


# ── Main scan function ────────────────────────────────────────────────────────

async def scan_url(
    url: str,
    model_store: ModelStore,
    use_llm: bool = False,
) -> dict:
    """
    Full scan pipeline. Returns a structured result dict ready to be
    stored as result_json and passed to the report generator.
    """
    scanned_at = datetime.now(timezone.utc).isoformat()

    # 1. Feature extraction (sync — fast)
    raw_vector = extract_features(url)
    features_named = extract_features_dict(url)

    # 2. ML scoring (sync — in-process, instant)
    try:
        ml_result = model_store.score_dict(
            raw_vector,
            kmeans_threshold=KMEANS_THRESHOLD,
            som_threshold=SOM_THRESHOLD,
        )
        ml_available = True
    except Exception as e:
        ml_result = {}
        ml_available = False
        ml_error = str(e)

    # 3. External threat intel + WHOIS + URLhaus (all concurrent)
    async with httpx.AsyncClient() as client:
        vt_result, gsb_result, whois_result, urlhaus_result = await asyncio.gather(
            _query_virustotal(url, client),
            _query_safe_browsing(url, client),
            whois_lookup(url),
            urlhaus_scan(url),
        )

    # 4. Verdict
    ml_score = ml_result.get("combined_score", 0.0) if ml_available else 0.0
    ml_agree = ml_result.get("models_agree", False) if ml_available else False

    # Combine WHOIS + URLhaus signals before verdict
    whois_signals   = whois_risk_signals(whois_result)
    urlhaus_signals = urlhaus_risk_signals(urlhaus_result)
    all_extra_signals = urlhaus_signals + whois_signals   # URLhaus first (higher authority)
    verdict = _compute_verdict(ml_score, ml_agree, vt_result, gsb_result, all_extra_signals)

    # 5. Assemble result
    result = {
        "url": url,
        "scanned_at": scanned_at,
        "verdict": verdict,
        "ml": {
            "available": ml_available,
            **(ml_result if ml_available else {"error": ml_error if not ml_available else ""}),
        },
        "virustotal":    vt_result,
        "safe_browsing": gsb_result,
        "whois":         whois_result,
        "urlhaus":       urlhaus_result,
        "features":     features_named,
        "use_llm":      use_llm,
    }

    return result, raw_vector