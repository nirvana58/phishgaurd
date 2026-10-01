"""
server/scanner.py

Scan orchestrator. Called by the queue worker for each job.

Pipeline per URL:
  1. Feature extraction          (core/features.py         — sync, instant)
  2. ML anomaly scoring          (core/models.py           — sync, instant)
  3. Homograph / typosquat check (core/brand_protection.py — sync, instant)
  4. External threat intel       (VirusTotal, Google Safe Browsing,
                                   WHOIS, URLhaus, redirect chain, SSL,
                                   optional LLM content analysis — async, concurrent)
  5. Aggregate all signals into a single result dict

The result dict is what gets stored as result_json in scan_jobs and later
handed to the report generator.

Environment variables needed (put in .env at project root):
  VIRUSTOTAL_API_KEY
  GOOGLE_SAFE_BROWSING_API_KEY
  ANTHROPIC_API_KEY          (only required if use_llm=True)
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

import httpx

from core.features import extract_features, extract_features_dict, normalize_url, FEATURE_NAMES
from core.models import ModelStore, AnomalyResult
from core.whois_lookup import whois_lookup, whois_risk_signals
from core.urlhaus import urlhaus_scan, urlhaus_risk_signals
from core.redirect_chain import trace_redirects, redirect_chain_signals
from core.ssl_check import ssl_check, ssl_risk_signals
from core.brand_protection import (
    check_homograph, homograph_risk_signals,
    check_typosquat, typosquat_risk_signals,
)
from core.llm_content_check import analyze_content, content_risk_signals

# Anomaly thresholds — values in normalised score space.
# > 1.0 = notably outside the trained distribution.
# Tunable later from the admin panel; hardcoded here for now.
KMEANS_THRESHOLD = 1.0
SOM_THRESHOLD = 1.0

# Combined score above which we declare the URL suspicious from ML alone
# (external APIs can still override either direction).
ML_SUSPICIOUS_THRESHOLD = 2.0

# Stricter bar for the case where the two models DISAGREE (one flags, one
# doesn't). A lone spiking model isn't enough to override an otherwise
# clean record (VT/GSB/WHOIS/URLhaus all quiet) unless the spike clears
# this higher threshold, or something else corroborates it.
ML_DISAGREE_THRESHOLD = 2.2

# Known brand domains for typosquat/combosquat comparison. Ideally load this
# from your Tranco/Majestic top-N benign pool rather than hardcoding a short
# list — this is a starter set, swap for a real loaded list in production.
BRAND_DOMAINS = [
    # Tech Giants
    "google.com", "apple.com", "microsoft.com", "amazon.com", "meta.com",
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    "linkedin.com", "github.com", "netflix.com", "adobe.com", "salesforce.com",
    "oracle.com", "ibm.com", "intel.com", "nvidia.com", "qualcomm.com",
    "amd.com", "vmware.com", "citrix.com", "atlassian.com", "slack.com",
    "zoom.us", "dropbox.com", "box.com", "notion.so", "figma.com",
    
    # Financial Services
    "paypal.com", "stripe.com", "square.com", "wise.com", "revolut.com",
    "coinbase.com", "kraken.com", "binance.com", "gemini.com", "ftx.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "americanexpress.com", "discover.com", "capitalone.com", "ally.com",
    "ing.com", "ing.de", "deutsche-boerse.com", "lse.co.uk",
    "nyse.com", "nasdaq.com", "cmegroup.com", "tradingview.com",
    
    # E-commerce
    "ebay.com", "etsy.com", "shopify.com", "alibaba.com", "aliexpress.com",
    "wish.com", "newegg.com", "bestbuy.com", "target.com", "walmart.com",
    "costco.com", "ikea.com", "zara.com", "hm.com", "uniqlo.com",
    "nike.com", "adidas.com", "puma.com", "timberland.com", "columbia.com",
    
    # Travel & Hospitality
    "uber.com", "lyft.com", "airbnb.com", "booking.com", "expedia.com",
    "trivago.com", "hotels.com", "kayak.com", "skyscanner.com",
    "doordash.com", "grubhub.com", "ubereats.com", "deliveroo.com",
    "airbnb.com", "vrbo.com",
    
    # Streaming & Media
    "youtube.com", "netflix.com", "hulu.com", "disneyplus.com", "peacock.com",
    "paramountplus.com", "primevideo.com", "hbomax.com", "appletv.com",
    "twitch.tv", "tiktok.com", "snapchat.com", "reddit.com", "pinterest.com",
    "discord.com", "telegram.org", "viber.com", "signal.org",
    "spotify.com", "apple.com", "amazon-music.com",
    
    # Communication & Collaboration
    "gmail.com", "outlook.com", "yahoo.com", "mail.yahoo.com", "icloud.com",
    "protonmail.com", "tutanota.com", "zoho.com", "mailchimp.com",
    "microsoft365.com", "teams.microsoft.com", "skype.com",
    
    # Cloud Storage & Productivity
    "onedrive.com", "dropbox.com", "googledrive.com", "icloud.com",
    "sharepoint.com", "nextcloud.com", "sync.com", "tresorit.com",
    "pcloud.com", "mega.nz", "mediafire.com",
    
    # Enterprise & SaaS
    "salesforce.com", "workday.com", "successfactors.com", "netsuites.com",
    "sap.com", "tableau.com", "qlik.com", "splunk.com", "datadog.com",
    "newrelic.com", "mongodb.com", "elasticsearch.com", "apache.org",
    "hashicorp.com", "terraform.io", "ansible.com", "puppet.com",
    
    # Security & Antivirus
    "norton.com", "mcafee.com", "avast.com", "avg.com", "kaspersky.com",
    "bitdefender.com", "malwarebytes.com", "eset.com", "sophos.com",
    "trendmicro.com", "symantec.com", "crowdstrike.com",
    
    # Banking & Insurance
    "allstate.com", "statefarm.com", "geico.com", "progressive.com",
    "aig.com", "travelers.com", "chubb.com", "metlife.com", "prudential.com",
    "aetna.com", "humana.com", "cigna.com", "bluecross.com",
    
    # Utilities & Services
    "verizon.com", "att.com", "tmobile.com", "comcast.com", "spectrum.com",
    "cox.com", "centurylink.com", "frontier.com", "suddenlink.com",
    "exelon.com", "theelectric.com", "pge.com", "scedison.com",
    
    # Social Networks
    "facebook.com", "instagram.com", "tiktok.com", "snapchat.com",
    "twitter.com", "x.com", "reddit.com", "pinterest.com", "quora.com",
    "nextdoor.com", "myspace.com", "viber.com", "line.me", "kakaotalk.com",
    "wechat.com", "qq.com", "weibo.com", "douyin.com",
    
    # Dating & Social
    "match.com", "tinder.com", "bumble.com", "hinge.com", "okc.com",
    "eharmony.com", "plenty-of-fish.com", "badoo.com",
    
    # Job Platforms
    "linkedin.com", "indeed.com", "glassdoor.com", "monster.com",
    "dice.com", "careerbuilder.com", "ziprecruiter.com", "linkedin.com",
    
    # Gaming
    "steam.com", "epicgames.com", "playstation.com", "xbox.com",
    "nintendo.com", "roblox.com", "minecraft.net", "fortnite.com",
    "riot.com", "blizzard.com", "activision.com", "ea.com", "ubisoft.com",
    "2k.com", "capcom.com", "konami.com", "bandainamco.com",
    
    # Automotive
    "tesla.com", "ford.com", "gm.com", "toyota.com", "honda.com",
    "bmw.com", "mercedesbenz.com", "audi.com", "volkswagen.com",
    "porsche.com", "lamborghini.com", "ferrari.com", "bugatti.com",
    
    # Healthcare
    "pfizer.com", "moderna.com", "jnj.com", "merck.com", "abbvie.com",
    "amgen.com", "biogen.com", "regeneron.com", "mayo.edu", "mayoclinic.com",
    "cleveland-clinic.org", "ucsf.edu", "harvard.edu", "stanford.edu",
    
    # Cryptocurrency Exchanges
    "coinbase.com", "kraken.com", "binance.com", "gemini.com", "crypto.com",
    "huobi.com", "gate.io", "bitfinex.com", "bybit.com", "kucoin.com",
    
    # Real Estate
    "zillow.com", "redfin.com", "trulia.com", "realtor.com",
    "apartments.com", "rent.com", "airbnb.com", "vrbo.com",
]

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
      4. ML models disagree, combined score above ML_SUSPICIOUS_THRESHOLD:
           - flagged as SUSPICIOUS (LOW confidence) only if the spike is
             severe (>= ML_DISAGREE_THRESHOLD) or corroborated by another
             signal (WHOIS/URLhaus/redirect/partial-VT)
           - otherwise treated as ML noise: noted for transparency, but
             does not by itself override an otherwise clean record
      5. WHOIS: newly registered domain → SUSPICIOUS if no other signals
      6. A LONE weak WHOIS/SSL/URLhaus/chain signal (nothing else
         corroborating it, e.g. "newly issued cert" or "only 1 name
         server" on its own) → treated as noise, not flagged alone.
         2+ signals, or a single strong one (newly registered young
         domain), still escalates to SUSPICIOUS.
      7. Otherwise → SAFE
    """
    reasons = list(extra_signals or [])
    ml_note: Optional[str] = None

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
        # Models disagree — one model is spiking while the other reads
        # normal. Don't let a lone disagreeing model override an
        # otherwise clean record unless the spike is severe (clears
        # ML_DISAGREE_THRESHOLD) or something else corroborates it
        # (WHOIS/URLhaus/redirect signals, or a partial VT hit — all of
        # which would already be sitting in `reasons` at this point).
        has_corroboration = bool(reasons)
        if ml_combined_score >= ML_DISAGREE_THRESHOLD or has_corroboration:
            reasons.append(
                f"ML anomaly score {ml_combined_score:.3f} above threshold "
                "(models disagree — treat as low confidence)"
            )
            return {"verdict": "SUSPICIOUS", "confidence": "LOW", "reasons": reasons}
        else:
            # Not severe enough on its own, and nothing else corroborates
            # it — keep evaluating; note the score for transparency rather
            # than silently dropping it.
            ml_note = (
                f"ML anomaly score {ml_combined_score:.3f} above threshold, "
                "but models disagree and no other signal corroborates it "
                "(treated as noise, not flagged on its own)"
            )
        # falls through to the checks below only when not flagged

    if reasons and any(
        "malicious" in r.lower() or "engine" in r.lower() for r in reasons
    ):
        return {"verdict": "SUSPICIOUS", "confidence": "LOW", "reasons": reasons}

    # A LONE weak WHOIS/SSL/URLhaus/chain signal, with nothing else
    # corroborating it, isn't enough on its own to override an otherwise
    # clean record (ML normal, VT clean, GSB clean). This generalizes what
    # was previously a cert-only special case: routine automatic cert
    # renewal (Let's Encrypt/ZeroSSL, ~60-90 day cycles) produces baseline
    # "newly issued" noise on ordinary sites, and the same is true of
    # other single weak signals — e.g. "Only 1 name server" fires on some
    # perfectly legitimate minimal-DNS setups too. A single weak signal is
    # only meaningful when paired with something else that corroborates
    # it (2+ signals present), or when the signal itself is inherently
    # strong enough to stand alone (a newly REGISTERED young domain, or
    # an actively-online URLhaus hit — already handled earlier via the
    # "ACTIVELY ONLINE" short-circuit above).
    STRONG_LONE_SIGNAL_MARKERS = (
        "newly registered domain",
        "disposable phishing infrastructure",
        "punycode",
        "confusable character",
        "combosquatting",
        "credentials via a password field",
    )

    lone_note: Optional[str] = None
    if len(reasons) == 1 and not any(
        marker in reasons[0].lower() for marker in STRONG_LONE_SIGNAL_MARKERS
    ):
        # Single weak signal, uncorroborated — treat as noise rather than
        # an automatic escalation, but keep it visible for transparency.
        lone_note = reasons[0]
        reasons = []

    if reasons:  # 2+ corroborating signals, or a single strong one
        reasons_out = reasons[:]
        reasons_out.append("No direct threat detections — WHOIS/SSL signals only")
        return {"verdict": "SUSPICIOUS", "confidence": "LOW", "reasons": reasons_out}

    reasons.append(ml_note or lone_note or "No threat signals detected")
    return {"verdict": "SAFE", "confidence": "HIGH", "reasons": reasons}


# ── Main scan function ────────────────────────────────────────────────────────

async def scan_url(
    url: str,
    model_store: ModelStore,
    use_llm: bool = False,
) -> dict:
    """
    Full scan pipeline. Returns (result_dict, raw_vector).

    Pipeline:
      1. Feature extraction        (sync, instant)
      2. ML scoring                (sync, instant)
      3. Homograph / typosquat check (sync, instant)   ← NEW
      4. Concurrent async gather:
           - VirusTotal API
           - Google Safe Browsing API
           - WHOIS / RDAP lookup
           - URLhaus lookup (URL + host)
           - Redirect chain trace
           - SSL certificate inspection
           - LLM content analysis (only when use_llm=True)  ← NEW
      5. Verdict engine
      6. Assemble result dict
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    scan_target = normalize_url(url)

    # 1. Feature extraction — uses submitted URL, not final URL.
    #    Chain tracing happens concurrently; we score what the user gave us.
    raw_vector    = extract_features(scan_target)
    features_named = extract_features_dict(scan_target)

    # 2. ML scoring (sync — in-process, instant)
    try:
        ml_result    = model_store.score_dict(
            raw_vector,
            kmeans_threshold=KMEANS_THRESHOLD,
            som_threshold=SOM_THRESHOLD,
        )
        ml_available = True
    except Exception as e:
        ml_result    = {}
        ml_available = False
        ml_error     = str(e)

    # 3. Homograph / typosquat check (sync — in-process, instant, no I/O)
    homograph_result = check_homograph(url)
    typosquat_result = check_typosquat(url, known_brand_domains=BRAND_DOMAINS)

    # 4. All external lookups fire concurrently — zero serial latency.
    #    LLM content analysis is opt-in (use_llm flag) since it adds real
    #    latency and per-scan cost — only included in the gather batch
    #    when explicitly requested.
    async with httpx.AsyncClient() as client:
        tasks = [
            _query_virustotal(scan_target, client),
            _query_safe_browsing(scan_target, client),
            whois_lookup(scan_target),
            urlhaus_scan(scan_target),
            trace_redirects(scan_target),          # follows redirect chain
            ssl_check(scan_target),                # inspects TLS certificate
        ]
        if use_llm:
            tasks.append(analyze_content(scan_target, client))

        gathered = await asyncio.gather(*tasks)

    (
        vt_result,
        gsb_result,
        whois_result,
        urlhaus_result,
        chain_result,
        ssl_result,
    ) = gathered[:6]
    content_result = gathered[6] if use_llm else {"available": False, "reason": "use_llm disabled"}

    # 4. Verdict — combine all signal sources
    ml_score = ml_result.get("combined_score", 0.0) if ml_available else 0.0
    ml_agree = ml_result.get("models_agree", False) if ml_available else False

    chain_signals      = redirect_chain_signals(chain_result)
    urlhaus_signals    = urlhaus_risk_signals(urlhaus_result)
    whois_signals      = whois_risk_signals(whois_result)
    ssl_signals        = ssl_risk_signals(ssl_result)
    homograph_signals  = homograph_risk_signals(homograph_result)
    typosquat_signals  = typosquat_risk_signals(typosquat_result)
    content_signals    = content_risk_signals(content_result)

    # Priority order: chain/URLhaus first, then brand-impersonation checks
    # (homograph/typosquat), then SSL, then WHOIS, then LLM content analysis
    all_extra = (
        chain_signals + urlhaus_signals
        + homograph_signals + typosquat_signals
        + ssl_signals + whois_signals
        + content_signals
    )
    verdict = _compute_verdict(ml_score, ml_agree, vt_result, gsb_result, all_extra)

    # 5. Assemble result
    result = {
        "url":        url,
        "scanned_at": scanned_at,
        "verdict":    verdict,
        "ml": {
            "available": ml_available,
            **(ml_result if ml_available else {"error": ml_error if not ml_available else ""}),
        },
        "virustotal":       vt_result,
        "safe_browsing":    gsb_result,
        "whois":            whois_result,
        "urlhaus":          urlhaus_result,
        "redirect_chain":   chain_result,
        "ssl":              ssl_result,
        "homograph":        homograph_result,
        "typosquat":        typosquat_result,
        "content_analysis": content_result,
        "features":         features_named,
        "use_llm":          use_llm,
    }

    return result, raw_vector