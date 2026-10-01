"""
report/generator.py

Report generation system. Takes the structured result dict from scanner.py
and produces:
  1. A rich terminal output (always, during a scan)
  2. Saved files in any/all of: .md  .txt  .pdf  .docx  .json

Optionally enhances the summary section with an LLM when use_llm=True was
specified at scan time. Two providers, switchable via REPORT_LLM_PROVIDER:

  REPORT_LLM_PROVIDER=ollama   (default) - local Ollama
    Requires Ollama running with at least one model pulled.
    Default model: "llama3" — overridable via OLLAMA_MODEL env var.

  REPORT_LLM_PROVIDER=gemini   - Google Gemini API (Flash / Flash-Lite)
    Requires GEMINI_API_KEY. Default model: "gemini-3.5-flash-lite" —
    overridable via GEMINI_MODEL. NOTE: Gemini's Flash lineup deprecates
    fast (2.0 Flash/Flash-Lite already shut down June 2026; 2.5
    Flash/Flash-Lite are slated to shut down Oct 2026) — check
    https://ai.google.dev/gemini-api/docs/models for the current GA model
    if this default has gone stale by the time you're reading this.

If the configured provider is unreachable/unavailable, the report falls
back gracefully (no crash, just an unenhanced summary).

The key design principle here is a single internal `ReportData` dataclass
that all format renderers consume — add a new format later by just adding
a new `_write_<fmt>()` method without touching any other renderer.
"""

from dotenv import load_dotenv


load_dotenv()

import asyncio
import json
import os
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# reportlab
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table as RLTable,
    TableStyle, HRFlowable,
)

# python-docx
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"


# NOTE: these read os.getenv() lazily (at call time), not at module import
# time. A previous version read OLLAMA_HOST/REPORT_LLM_PROVIDER/etc as
# plain module-level constants, which froze them to their defaults if
# generator.py got imported anywhere before load_dotenv() ran - the same
# import-ordering bug already found and fixed in main.py/discord_bot.py.
# Reading them lazily inside functions makes this immune to import order
# entirely, rather than relying on getting the import order right.

def _ollama_base() -> str:
    return os.getenv("OLLAMA_HOST", "http://localhost:11434")


def _ollama_model_pref() -> str:
    return os.getenv("OLLAMA_MODEL", "")   # empty = auto-detect first available


def _report_llm_provider() -> str:
    return (
        os.getenv("REPORT_LLM_PROVIDER")
        or os.getenv("LLM_PROVIDER")
        or "ollama"
    ).strip().lower()


def _normalize_llm_provider(provider: str | None) -> str:
    """Normalize allowed provider names from env/CLI values."""
    value = (provider or _report_llm_provider() or "ollama").strip().lower()
    aliases = {
        "google": "gemini",
        "gemini": "gemini",
        "googlegemini": "gemini",
        "ollama": "ollama",
    }
    return aliases.get(value, value)


def _gemini_api_key() -> str:
    return os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")


def _gemini_model() -> str:
    # See the module docstring above re: how fast this default goes stale.
    return os.getenv("GEMINI_MODEL", "gemini-3.6-flash")


console = Console()


# ── Ollama helpers ─────────────────────────────────────────────────────────────

async def _ollama_list_models() -> list[str]:
    """Return list of locally available model names from /api/tags."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{_ollama_base()}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                return [m["name"] for m in models]
    except Exception:
        pass
    return []


async def _ollama_resolve_model() -> str | None:
    """
    Resolve which model to use:
      1. OLLAMA_MODEL env var if set and available
      2. First model returned by /api/tags
      3. None if Ollama is unreachable or no models installed
    """
    available = await _ollama_list_models()
    if not available:
        return None

    preferred = _ollama_model_pref().strip()

    # Exact match first
    if preferred and preferred in available:
        return preferred

    # Prefix match (e.g. "llama3" matches "llama3:latest" or "llama3.2:latest")
    if preferred:
        for m in available:
            if m.startswith(preferred.split(":")[0]):
                return m

    # Fall back to first available model
    return available[0]


RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 1.0


async def _ollama_generate(model: str, prompt: str) -> str | None:
    """
    Try /api/chat first (Ollama ≥ 0.1.14), fall back to /api/generate.
    Retries transient failures (429/5xx, timeouts) with exponential
    backoff (1s, 2s, 4s) before giving up. Returns the response text or
    None on failure (never raises).
    """
    async with httpx.AsyncClient(timeout=60.0) as client:
        for attempt in range(1, MAX_RETRIES + 1):
            status_code = None

            # ── Try /api/chat ──────────────────────────────────────────────
            try:
                resp = await client.post(
                    f"{_ollama_base()}/api/chat",
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "stream": False,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("message", {}).get("content", "").strip()
                status_code = resp.status_code
                # 400 / 404 → try the older endpoint
            except httpx.TimeoutException:
                console.print("[yellow]  Ollama /api/chat timed out — trying /api/generate…[/yellow]")
                status_code = "timeout"
            except Exception:
                pass

            # ── Fall back to /api/generate ─────────────────────────────────
            try:
                resp = await client.post(
                    f"{_ollama_base()}/api/generate",
                    json={"model": model, "prompt": prompt, "stream": False},
                )
                if resp.status_code == 200:
                    return resp.json().get("response", "").strip()
                status_code = resp.status_code
                body = resp.text[:300]
                console.print(f"[yellow]  Ollama /api/generate returned {resp.status_code}: {body}[/yellow]")
            except httpx.TimeoutException:
                console.print("[yellow]  Ollama /api/generate timed out.[/yellow]")
                status_code = "timeout"
            except Exception as e:
                console.print(f"[yellow]  Ollama error: {e}[/yellow]")

            is_retryable = status_code in RETRYABLE_STATUS_CODES or status_code == "timeout"
            if not is_retryable or attempt == MAX_RETRIES:
                break
            backoff = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
            console.print(f"[dim]  Retrying Ollama in {backoff:.0f}s… (attempt {attempt + 1}/{MAX_RETRIES})[/dim]")
            await asyncio.sleep(backoff)

    return None


# ── Gemini helpers ──────────────────────────────────────────────────────────

async def _gemini_generate(model: str, prompt: str) -> str | None:
    """
    Call the Gemini API's generateContent endpoint. Retries transient
    failures (429/5xx, timeouts) with exponential backoff (1s, 2s, 4s)
    before giving up — a bare 503 ("model overloaded") is common and
    usually resolves itself within a few seconds. Returns the response
    text, or None on failure (never raises).
    """
    api_key = _gemini_api_key()
    if not api_key:
        return None

    url = f"{GEMINI_API_URL}/{model}:generateContent?key={api_key}"

    for attempt in range(1, MAX_RETRIES + 1):
        status_code = None
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    url,
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                )
                if resp.status_code != 200:
                    status_code = resp.status_code
                    console.print(
                        f"[yellow]  Gemini API returned {resp.status_code}: {resp.text[:300]}[/yellow]"
                    )
                else:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if not candidates:
                        console.print(
                            "[yellow]  Gemini returned no candidates (possibly safety-filtered).[/yellow]"
                        )
                        return None  # a real response, just empty - not retryable
                    parts = candidates[0].get("content", {}).get("parts", [])
                    text = "".join(p.get("text", "") for p in parts).strip()
                    return text or None
        except httpx.TimeoutException:
            console.print("[yellow]  Gemini API timed out.[/yellow]")
            status_code = "timeout"
        except Exception as e:
            console.print(f"[yellow]  Gemini error: {e}[/yellow]")
            break  # unexpected error - not retryable

        is_retryable = status_code in RETRYABLE_STATUS_CODES or status_code == "timeout"
        if not is_retryable or attempt == MAX_RETRIES:
            break
        backoff = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
        console.print(f"[dim]  Retrying Gemini in {backoff:.0f}s… (attempt {attempt + 1}/{MAX_RETRIES})[/dim]")
        await asyncio.sleep(backoff)

    return None


# ── Provider-agnostic dispatch ───────────────────────────────────────────────

async def _resolve_llm_model(provider: str | None = None, preferred_model: str | None = None) -> tuple[str | None, str | None]:
    """
    Resolve (provider, model) for the active report. If provider is not
    supplied, read REPORT_LLM_PROVIDER / LLM_PROVIDER from the environment.
    """
    provider_name = _normalize_llm_provider(provider)
    if provider_name == "gemini":
        api_key = _gemini_api_key()
        if not api_key:
            console.print(
                "[yellow]  GEMINI_API_KEY not set — cannot use Gemini provider.[/yellow]\n"
                "  Get a key: https://aistudio.google.com/apikey\n"
                "  Or switch back: REPORT_LLM_PROVIDER=ollama"
            )
            return None, None
        model = (preferred_model or os.getenv("GEMINI_MODEL") or _gemini_model()).strip()
        return "gemini", model or "gemini-3.6-flash"

    model = (preferred_model or os.getenv("OLLAMA_MODEL") or "").strip()
    if model:
        return "ollama", model

    resolved = await _ollama_resolve_model()
    if not resolved:
        console.print(
            "[yellow]  Ollama unavailable or no models installed.[/yellow]\n"
            "  Install Ollama: https://ollama.com\n"
            "  Pull a model:   ollama pull llama3"
        )
        return None, None
    return "ollama", resolved


async def _generate_with(provider: str, model: str, prompt: str) -> tuple[str | None, str, str]:
    """
    Dispatches to the right backend once (provider, model) is resolved.
    Transient-failure retries happen inside _gemini_generate/_ollama_generate
    themselves. If the primary provider still fails after its retries,
    falls back to the OTHER provider (Gemini <-> Ollama) - controlled by
    LLM_FALLBACK_ENABLED (default true) - resolving a model for that
    fallback provider automatically.

    Returns (text, actual_provider, actual_model). The actual_provider/
    actual_model may differ from the requested provider/model if fallback
    was used - callers should use the RETURNED values for bookkeeping
    (e.g. rd.llm_model) rather than assuming the originally requested
    provider is what actually generated the text, so it's never silently
    ambiguous which provider actually served a given summary.
    """
    if provider == "gemini":
        text = await _gemini_generate(model, prompt)
    else:
        text = await _ollama_generate(model, prompt)

    if text:
        return text, provider, model

    fallback_enabled = os.getenv("LLM_FALLBACK_ENABLED", "true").strip().lower() == "true"
    if not fallback_enabled:
        return None, provider, model

    fallback_provider = "ollama" if provider == "gemini" else "gemini"
    console.print(f"[yellow]  {provider} failed after retries — trying fallback provider: {fallback_provider}[/yellow]")

    fb_provider, fb_model = await _resolve_llm_model(fallback_provider)
    if not fb_model:
        console.print(f"[yellow]  Fallback provider {fallback_provider} also unavailable.[/yellow]")
        return None, provider, model

    fb_text = (
        await _gemini_generate(fb_model, prompt)
        if fb_provider == "gemini"
        else await _ollama_generate(fb_model, prompt)
    )

    if fb_text:
        console.print(f"[dim]  Fallback succeeded via {fb_provider} ({fb_model})[/dim]")
        return fb_text, fb_provider, fb_model

    return None, provider, model


# ── Internal report structure ─────────────────────────────────────────────────

@dataclass
class ReportData:
    scan_id: str
    url: str
    scanned_at: str
    verdict: str           # SAFE | SUSPICIOUS | MALICIOUS
    confidence: str        # HIGH | MEDIUM | LOW
    reasons: list[str]

    # ML section
    ml_available: bool
    ml_combined_score: float
    ml_kmeans_score: float
    ml_som_score: float
    ml_kmeans_cluster: int
    ml_models_agree: bool
    ml_version: str

    # External APIs
    vt_available: bool
    vt_malicious: int
    vt_suspicious: int
    vt_harmless: int
    vt_status: str          # "found" | "not_found" | ""

    gsb_available: bool
    gsb_is_threat: bool
    gsb_threat_types: list[str]

    # Features (for detail section)
    features: dict[str, float]

    # Per-feature % contribution to anomaly score — sorted descending
    # list of (feature_name, pct) tuples, top-N ready
    ml_feature_importance: list = None

    # WHOIS section
    whois_available: bool = False
    whois_domain: str = ""
    whois_registrar: Optional[str] = None
    whois_country: Optional[str] = None
    whois_creation_date: Optional[str] = None
    whois_expiration_date: Optional[str] = None
    whois_updated_date: Optional[str] = None
    whois_age_days: Optional[int] = None
    whois_expiry_days: Optional[int] = None
    whois_ns_count: int = 0
    whois_is_new_domain: bool = False
    whois_expiring_soon: bool = False
    whois_is_ip_host: bool = False
    whois_error: Optional[str] = None

    # Redirect chain section
    chain_original_url: str = ""
    chain_final_url: str = ""
    chain_hops: list = None           # list of hop dicts
    chain_hop_count: int = 0
    chain_is_shortened: bool = False
    chain_shorteners: list = None
    chain_error: Optional[str] = None

    # SSL/TLS certificate section
    ssl_available: bool = False
    ssl_is_http: bool = False
    ssl_verified: bool = False
    ssl_verify_error: Optional[str] = None
    ssl_subject_cn: Optional[str] = None
    ssl_issuer_cn: Optional[str] = None
    ssl_issuer_org: Optional[str] = None
    ssl_not_before: Optional[str] = None
    ssl_not_after: Optional[str] = None
    ssl_cert_age_days: Optional[int] = None
    ssl_expiry_days: Optional[int] = None
    ssl_is_expired: bool = False
    ssl_is_self_signed: bool = False
    ssl_is_new_cert: bool = False
    ssl_expiring_soon: bool = False
    ssl_san_count: int = 0
    ssl_is_wildcard: bool = False
    ssl_is_free_ca: bool = False
    ssl_error: Optional[str] = None

    # LLM narrative (populated later if use_llm=True)
    llm_summary: Optional[str] = None
    llm_model: Optional[str] = None

    # Homograph / typosquat (brand impersonation) section
    homograph_is_punycode: bool = False
    homograph_is_mixed_script: bool = False
    homograph_decoded_hostname: Optional[str] = None
    homograph_confusable_count: int = 0
    homograph_latin_lookalike: Optional[str] = None

    typosquat_is_close: bool = False
    typosquat_edit_distance: Optional[int] = None
    typosquat_closest_brand: Optional[str] = None
    typosquat_is_combosquat: bool = False
    typosquat_combosquat_brand: Optional[str] = None
    typosquat_combosquat_suffix: Optional[str] = None

    # LLM content analysis section (populated only if use_llm=True and the
    # content_check module ran successfully — distinct from llm_summary
    # above, which narrates the scan rather than analyzing page content)
    content_analysis_available: bool = False
    content_analysis_provider: Optional[str] = None
    content_phishing_language_detected: bool = False
    content_urgency_language: bool = False
    content_credential_request: bool = False
    content_claimed_brand: Optional[str] = None
    content_brand_mismatch: bool = False
    content_confidence: Optional[str] = None
    content_explanation: Optional[str] = None
    content_unavailable_reason: Optional[str] = None


def _build_report_data(scan_id: str, result: dict) -> ReportData:
    verdict_block = result.get("verdict", {})
    ml  = result.get("ml", {})
    vt  = result.get("virustotal", {})
    gsb = result.get("safe_browsing", {})
    w   = result.get("whois", {})
    ch  = result.get("redirect_chain", {})
    ssl_r = result.get("ssl", {})
    hg  = result.get("homograph", {})
    ts  = result.get("typosquat", {})
    ca  = result.get("content_analysis", {})

    return ReportData(
        scan_id=scan_id,
        url=result.get("url", ""),
        scanned_at=result.get("scanned_at", ""),
        verdict=verdict_block.get("verdict", "UNKNOWN"),
        confidence=verdict_block.get("confidence", "UNKNOWN"),
        reasons=verdict_block.get("reasons", []),
        ml_available=ml.get("available", False),
        ml_combined_score=ml.get("combined_score", 0.0),
        ml_kmeans_score=ml.get("kmeans", {}).get("anomaly_score", 0.0),
        ml_som_score=ml.get("som", {}).get("anomaly_score", 0.0),
        ml_kmeans_cluster=ml.get("kmeans", {}).get("cluster_id", -1),
        ml_models_agree=ml.get("models_agree", False),
        ml_version=ml.get("model_version", "none"),
        ml_feature_importance=sorted(
            ml.get("feature_contributions", {}).items(),
            key=lambda x: x[1], reverse=True,
        ),
        vt_available=vt.get("available", False),
        vt_malicious=vt.get("malicious", 0),
        vt_suspicious=vt.get("suspicious", 0),
        vt_harmless=vt.get("harmless", 0),
        vt_status=vt.get("status", ""),
        gsb_available=gsb.get("available", False),
        gsb_is_threat=gsb.get("is_threat", False),
        gsb_threat_types=gsb.get("threat_types", []),
        features=result.get("features", {}),
        # WHOIS
        whois_available=w.get("available", False),
        whois_domain=w.get("domain", ""),
        whois_registrar=w.get("registrar"),
        whois_country=w.get("country"),
        whois_creation_date=w.get("creation_date"),
        whois_expiration_date=w.get("expiration_date"),
        whois_updated_date=w.get("updated_date"),
        whois_age_days=w.get("age_days"),
        whois_expiry_days=w.get("expiry_days"),
        whois_ns_count=w.get("ns_count", 0),
        whois_is_new_domain=w.get("is_new_domain", False),
        whois_expiring_soon=w.get("expiring_soon", False),
        whois_is_ip_host=w.get("is_ip_host", False),
        whois_error=w.get("reason") if not w.get("available") else None,
        # Redirect chain
        chain_original_url=ch.get("original_url", ""),
        chain_final_url=ch.get("final_url", ""),
        chain_hops=ch.get("hops") or [],
        chain_hop_count=ch.get("hop_count", 0),
        chain_is_shortened=ch.get("is_shortened", False),
        chain_shorteners=ch.get("shorteners_found") or [],
        chain_error=ch.get("error"),
        # SSL/TLS
        ssl_available=ssl_r.get("available", False),
        ssl_is_http=ssl_r.get("is_http", False),
        ssl_verified=ssl_r.get("verified", False),
        ssl_verify_error=ssl_r.get("verify_error"),
        ssl_subject_cn=ssl_r.get("subject_cn"),
        ssl_issuer_cn=ssl_r.get("issuer_cn"),
        ssl_issuer_org=ssl_r.get("issuer_org"),
        ssl_not_before=ssl_r.get("not_before"),
        ssl_not_after=ssl_r.get("not_after"),
        ssl_cert_age_days=ssl_r.get("cert_age_days"),
        ssl_expiry_days=ssl_r.get("expiry_days"),
        ssl_is_expired=ssl_r.get("is_expired", False),
        ssl_is_self_signed=ssl_r.get("is_self_signed", False),
        ssl_is_new_cert=ssl_r.get("is_new_cert", False),
        ssl_expiring_soon=ssl_r.get("expiring_soon", False),
        ssl_san_count=ssl_r.get("san_count", 0),
        ssl_is_wildcard=ssl_r.get("is_wildcard", False),
        ssl_is_free_ca=ssl_r.get("is_free_ca", False),
        ssl_error=ssl_r.get("error") if not ssl_r.get("available") else None,
        # Homograph
        homograph_is_punycode=hg.get("is_punycode", False),
        homograph_is_mixed_script=hg.get("is_mixed_script", False),
        homograph_decoded_hostname=hg.get("decoded_hostname"),
        homograph_confusable_count=hg.get("confusable_char_count", 0),
        homograph_latin_lookalike=hg.get("latin_lookalike"),
        # Typosquat / combosquat
        typosquat_is_close=ts.get("is_close_typosquat", False),
        typosquat_edit_distance=ts.get("edit_distance"),
        typosquat_closest_brand=ts.get("closest_brand_match"),
        typosquat_is_combosquat=ts.get("is_combosquat_pattern", False),
        typosquat_combosquat_brand=ts.get("combosquat_brand"),
        typosquat_combosquat_suffix=ts.get("combosquat_suffix"),
        # LLM content analysis
        content_analysis_available=ca.get("available", False),
        content_analysis_provider=ca.get("provider"),
        content_phishing_language_detected=ca.get("phishing_language_detected", False),
        content_urgency_language=ca.get("urgency_language", False),
        content_credential_request=ca.get("credential_request", False),
        content_claimed_brand=ca.get("claimed_brand"),
        content_brand_mismatch=ca.get("brand_mismatch", False),
        content_confidence=ca.get("confidence"),
        content_explanation=ca.get("explanation"),
        content_unavailable_reason=ca.get("reason") if not ca.get("available") else None,
    )


# ── LLM enhancement ───────────────────────────────────────────────────────────

def _build_llm_prompt(rd: ReportData) -> str:
    """Shared prompt builder used by both single-scan and batch LLM summaries."""
    return (
        "You are a cybersecurity analyst. Analyse this URL scan result and write a "
        "concise 3-5 sentence threat summary for a security report. Be specific about "
        "what signals were found. Do not repeat numbers verbatim — interpret them. "
        "Do not use markdown headers or bullet points. Plain prose only.\n\n"
        f"URL: {rd.url}\n"
        f"Verdict: {rd.verdict} (confidence: {rd.confidence})\n"
        f"Reasons: {'; '.join(rd.reasons)}\n"
        f"ML anomaly score: {rd.ml_combined_score:.3f} "
        f"(K-means: {rd.ml_kmeans_score:.3f}, SOM: {rd.ml_som_score:.3f})\n"
        f"Models agree: {rd.ml_models_agree}\n"
        f"VirusTotal: {rd.vt_malicious} malicious, {rd.vt_suspicious} suspicious detections\n"
        f"Google Safe Browsing: "
        f"{'THREAT — ' + ', '.join(rd.gsb_threat_types) if rd.gsb_is_threat else 'no threat'}\n"
        f"Notable URL features: "
        f"entropy={rd.features.get('shannon_entropy', 0):.2f}, "
        f"typosquat_distance={rd.features.get('typosquat_distance', 0)}, "
        f"suspicious_tld={int(rd.features.get('suspicious_tld', 0))}, "
        f"has_ip_host={int(rd.features.get('has_ip_host', 0))}"
    )


async def _fetch_llm_summary(rd: ReportData, provider: str | None = None, model: str | None = None) -> tuple[str | None, str | None]:
    """
    Generate a human-readable threat summary via the configured LLM
    provider (REPORT_LLM_PROVIDER / LLM_PROVIDER or an explicit override).
    Returns (summary_text, model_used) or (None, None) on failure.
    Never raises — all errors surface as console warnings.
    """
    provider_name, resolved_model = await _resolve_llm_model(provider, model)
    if not resolved_model:
        return None, None

    console.print(f"[dim]  Using model: {resolved_model} (provider: {provider_name})[/dim]")

    text, actual_provider, actual_model = await _generate_with(
        provider_name, resolved_model, _build_llm_prompt(rd)
    )
    if not text:
        return None, None
    if actual_provider != provider_name or actual_model != resolved_model:
        console.print(f"[dim]  (served by fallback: {actual_provider} / {actual_model})[/dim]")
    return text, actual_model


# ── Terminal renderer ──────────────────────────────────────────────────────────

def _verdict_color(verdict: str) -> str:
    return {"SAFE": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}.get(verdict, "white")



def _importance_bar(pct: float, width: int = 20) -> str:
    """Unicode block bar representing a percentage (0-100)."""
    filled = round(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)

def render_terminal(rd: ReportData):
    """Print a rich formatted report to the terminal."""
    color = _verdict_color(rd.verdict)

    console.print()
    console.rule("[bold]URL Threat Scan Report[/bold]")
    console.print()

    # Header panel
    header = Text()
    header.append(f"  URL        : {rd.url}\n")
    header.append(f"  Scan ID    : {rd.scan_id}\n")
    header.append(f"  Scanned at : {rd.scanned_at}\n")
    header.append(f"  Verdict    : ", style="bold")
    header.append(f"{rd.verdict}", style=f"bold {color}")
    header.append(f"  (confidence: {rd.confidence})\n")
    console.print(Panel(header, title="[bold]Overview[/bold]", border_style=color))

    # Reasons
    console.print("\n[bold]Signal Summary[/bold]")
    for reason in rd.reasons:
        console.print(f"  [dim]•[/dim] {reason}")

    # Redirect Chain section
    if rd.chain_hop_count > 0 or rd.chain_error:
        console.print("\n[bold]Redirect Chain[/bold]")
        if rd.chain_original_url != rd.chain_final_url:
            console.print(
                f"  [dim]Original:[/dim] {rd.chain_original_url}\n"
                f"  [dim]Final:   [/dim] [cyan]{rd.chain_final_url}[/cyan]"
            )
        chain_tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        chain_tbl.add_column("Hop", width=4, justify="right")
        chain_tbl.add_column("URL",    max_width=50, no_wrap=True)
        chain_tbl.add_column("Status", width=7)
        chain_tbl.add_column("→",      max_width=30, no_wrap=True)
        chain_tbl.add_column("Note",   width=12)
        for i, hop in enumerate(rd.chain_hops or [], 1):
            status_color = "green" if hop["status_code"] < 300 else "yellow"
            note = ""
            if hop.get("is_shortener"):
                note = "[yellow]⚑ shortener[/yellow]"
            chain_tbl.add_row(
                str(i),
                hop["url"][:50],
                f"[{status_color}]{hop['status_code']}[/{status_color}]",
                (hop.get("redirect_to") or "—")[:30],
                note,
            )
        console.print(chain_tbl)
        if rd.chain_is_shortened:
            console.print(
                f"  [yellow]⚑ Shortener(s) detected:[/yellow] "
                f"{', '.join(rd.chain_shorteners)}"
            )
        if rd.chain_error:
            console.print(f"  [dim]Chain trace note: {rd.chain_error}[/dim]")

    # ML section
    console.print("\n[bold]ML Anomaly Detection[/bold]")
    if rd.ml_available:
        ml_table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        ml_table.add_column("Model")
        ml_table.add_column("Score", justify="right")
        ml_table.add_column("Cluster/BMU", justify="right")
        ml_table.add_row(
            "K-means",
            f"{rd.ml_kmeans_score:.4f}",
            f"cluster {rd.ml_kmeans_cluster}",
        )
        ml_table.add_row(
            "SOM",
            f"{rd.ml_som_score:.4f}",
            "—",
        )
        ml_table.add_row(
            "[bold]Combined[/bold]",
            f"[bold]{rd.ml_combined_score:.4f}[/bold]",
            f"models {'[green]agree[/green]' if rd.ml_models_agree else '[yellow]disagree[/yellow]'}",
        )
        console.print(ml_table)
        console.print(f"  [dim]Model version: {rd.ml_version}[/dim]")

        # Feature importance — top 5
        top = (rd.ml_feature_importance or [])[:5]
        if top:
            console.print("\n  [bold dim]Top anomaly drivers:[/bold dim]")
            fi_tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
            fi_tbl.add_column("Feature", style="dim",     width=22)
            fi_tbl.add_column("Bar",                      width=22)
            fi_tbl.add_column("Pct",     justify="right", width=6)
            for feat, pct in top:
                bar_color = "red" if pct > 15 else "yellow" if pct > 8 else "green"
                fi_tbl.add_row(
                    feat,
                    f"[{bar_color}]{_importance_bar(pct)}[/{bar_color}]",
                    f"{pct:.1f}%",
                )
            console.print(fi_tbl)
    else:
        console.print("  [dim]ML scoring unavailable (no trained model)[/dim]")

    # External APIs
    console.print("\n[bold]External Threat Intelligence[/bold]")
    ext_table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
    ext_table.add_column("Source")
    ext_table.add_column("Result")
    ext_table.add_column("Detail")

    if rd.vt_available:
        vt_result = (
            f"[red]{rd.vt_malicious} malicious[/red]" if rd.vt_malicious > 0
            else "[green]clean[/green]"
        )
        ext_table.add_row(
            "VirusTotal",
            vt_result,
            f"{rd.vt_suspicious} suspicious, {rd.vt_harmless} harmless",
        )
    else:
        ext_table.add_row("VirusTotal", "[dim]unavailable[/dim]", "API key not set or timeout")

    if rd.gsb_available:
        gsb_result = (
            f"[red]THREAT[/red]" if rd.gsb_is_threat else "[green]clean[/green]"
        )
        ext_table.add_row(
            "Safe Browsing",
            gsb_result,
            ", ".join(rd.gsb_threat_types) if rd.gsb_threat_types else "—",
        )
    else:
        ext_table.add_row("Safe Browsing", "[dim]unavailable[/dim]", "API key not set or timeout")

    console.print(ext_table)

    # SSL/TLS Certificate
    console.print("\n[bold]SSL/TLS Certificate[/bold]")
    if not rd.ssl_available:
        ssl_tbl = Table(box=box.SIMPLE, show_header=False)
        ssl_tbl.add_column("Field", width=22)
        ssl_tbl.add_column("Value")
        ssl_tbl.add_row("Status", f"[dim]unavailable — {rd.ssl_error or 'check failed or not attempted'}[/dim]")
        console.print(ssl_tbl)
    elif rd.ssl_is_http:
        console.print("  [red bold]⚑ No HTTPS[/red bold] — connection is unencrypted")
    else:
        ssl_tbl = Table(box=box.SIMPLE, show_header=False)
        ssl_tbl.add_column("Field",  style="bold dim", width=22)
        ssl_tbl.add_column("Value")

        verified_str = "[green]verified[/green]" if rd.ssl_verified else "[yellow]unverified[/yellow]"
        ssl_tbl.add_row("Chain",            verified_str)
        ssl_tbl.add_row("Subject CN",       rd.ssl_subject_cn or "—")
        ssl_tbl.add_row("Issuer",           f"{rd.ssl_issuer_cn or '—'}" + (f" ({rd.ssl_issuer_org})" if rd.ssl_issuer_org else ""))

        if rd.ssl_is_expired:
            age_str = f"[red bold]EXPIRED {abs(rd.ssl_expiry_days or 0)} days ago[/red bold]"
        elif rd.ssl_expiring_soon:
            age_str = f"[yellow]expires in {rd.ssl_expiry_days} days ⚑[/yellow]"
        elif rd.ssl_expiry_days is not None:
            age_str = f"[green]expires in {rd.ssl_expiry_days} days[/green]"
        else:
            age_str = "—"
        ssl_tbl.add_row("Expiry",           age_str)

        if rd.ssl_cert_age_days is not None:
            issued_str = (
                f"[red]{rd.ssl_cert_age_days} days ago ⚑ newly issued[/red]"
                if rd.ssl_is_new_cert else f"{rd.ssl_cert_age_days} days ago"
            )
            ssl_tbl.add_row("Issued", issued_str)

        ssl_tbl.add_row("SAN count",        str(rd.ssl_san_count) + (" (wildcard)" if rd.ssl_is_wildcard else ""))

        flags = []
        if rd.ssl_is_self_signed: flags.append("[red]⚑ Self-signed[/red]")
        if rd.ssl_is_free_ca:     flags.append("[dim]free/low-cost CA[/dim]")
        ssl_tbl.add_row("Risk Flags", "  ".join(flags) if flags else "[green]None[/green]")

        console.print(ssl_tbl)

    # WHOIS Domain Intelligence
    console.print("\n[bold]WHOIS Domain Intelligence[/bold]")
    if rd.whois_available:
        whois_tbl = Table(box=box.SIMPLE, show_header=False)
        whois_tbl.add_column("Field",  style="bold dim", width=22)
        whois_tbl.add_column("Value")

        def _fmt_age(days):
            if days is None: return "—"
            if days < 30:   return f"[red bold]{days} days[/red bold] ⚑ NEWLY REGISTERED"
            if days < 90:   return f"[yellow]{days} days[/yellow] ⚑ < 90 days old"
            if days < 365:  return f"[yellow]{days} days ({days//30} months)[/yellow]"
            return f"[green]{days} days ({days//365}y {(days%365)//30}m)[/green]"

        def _fmt_expiry(days):
            if days is None: return "—"
            if days < 0:    return f"[red bold]EXPIRED {abs(days)} days ago[/red bold]"
            if days < 30:   return f"[red]{days} days remaining ⚑ EXPIRING SOON[/red]"
            if days < 180:  return f"[yellow]{days} days remaining[/yellow]"
            return f"[green]{days} days remaining[/green]"

        if rd.whois_is_ip_host:
            whois_tbl.add_row("Type", "[dim]IP address host — WHOIS not applicable[/dim]")
        else:
            whois_tbl.add_row("Domain",          rd.whois_domain or "—")
            whois_tbl.add_row("Registrar",        rd.whois_registrar or "[dim]not available[/dim]")
            whois_tbl.add_row("Country",          rd.whois_country   or "[dim]not available[/dim]")
            whois_tbl.add_row("Created",          rd.whois_creation_date or "[dim]not available[/dim]")
            whois_tbl.add_row("Expires",          rd.whois_expiration_date or "[dim]not available[/dim]")
            whois_tbl.add_row("Last Updated",     rd.whois_updated_date  or "[dim]not available[/dim]")
            whois_tbl.add_row("Domain Age",       _fmt_age(rd.whois_age_days))
            whois_tbl.add_row("Expiry",           _fmt_expiry(rd.whois_expiry_days))
            whois_tbl.add_row("Name Servers",     str(rd.whois_ns_count) if rd.whois_ns_count else "[dim]not available[/dim]")
            # Risk flags
            flags = []
            if rd.whois_is_new_domain:   flags.append("[red]⚑ Newly registered (< 30 days)[/red]")
            if rd.whois_expiring_soon:   flags.append("[yellow]⚑ Expiring soon (< 30 days)[/yellow]")
            if rd.whois_ns_count == 1:   flags.append("[yellow]⚑ Only 1 name server[/yellow]")
            if flags:
                whois_tbl.add_row("Risk Flags", "  ".join(flags))
            else:
                whois_tbl.add_row("Risk Flags", "[green]None[/green]")
    else:
        whois_tbl = Table(box=box.SIMPLE, show_header=False)
        whois_tbl.add_column("Field", width=22)
        whois_tbl.add_column("Value")
        reason = rd.whois_error or "lookup failed or not attempted"
        whois_tbl.add_row("Status", f"[dim]unavailable — {reason}[/dim]")
    console.print(whois_tbl)

    # URL Features
    console.print("\n[bold]URL Feature Breakdown[/bold]")
    feat_table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
    feat_table.add_column("Feature")
    feat_table.add_column("Value", justify="right")
    feat_table.add_column("Flag", justify="center")

    flag_features = {
        "has_ip_host": ("IP host", "red"),
        "suspicious_tld": ("Suspicious TLD", "red"),
        "has_at_symbol": ("@ symbol", "yellow"),
    }
    for name, value in rd.features.items():
        flag = ""
        if name in flag_features and value == 1:
            label, col = flag_features[name]
            flag = f"[{col}]⚑ {label}[/{col}]"
        feat_table.add_row(name, str(round(value, 4)), flag)
    console.print(feat_table)

    # LLM summary
    if rd.llm_summary:
        console.print()
        console.print(Panel(
            rd.llm_summary,
            title=f"[bold]AI Analysis[/bold] [dim]({rd.llm_model})[/dim]",
            border_style="blue",
        ))

    console.print()
    console.rule()
    console.print()


# ── JSON renderer ──────────────────────────────────────────────────────────

def _report_to_dict(rd: ReportData) -> dict:
    return {
        "scan_id": rd.scan_id,
        "url": rd.url,
        "scanned_at": rd.scanned_at,
        "verdict": rd.verdict,
        "confidence": rd.confidence,
        "reasons": rd.reasons,
        "ml": {
            "available": rd.ml_available,
            "combined_score": rd.ml_combined_score,
            "kmeans_score": rd.ml_kmeans_score,
            "som_score": rd.ml_som_score,
            "kmeans_cluster": rd.ml_kmeans_cluster,
            "models_agree": rd.ml_models_agree,
            "model_version": rd.ml_version,
            "feature_importance": [
                {"feature": name, "contribution_pct": pct}
                for name, pct in (rd.ml_feature_importance or [])
            ],
        },
        "virustotal": {
            "available": rd.vt_available,
            "malicious": rd.vt_malicious,
            "suspicious": rd.vt_suspicious,
            "harmless": rd.vt_harmless,
            "status": rd.vt_status,
        },
        "safe_browsing": {
            "available": rd.gsb_available,
            "is_threat": rd.gsb_is_threat,
            "threat_types": rd.gsb_threat_types,
        },
        "features": rd.features,
        "whois": {
            "available": rd.whois_available,
            "domain": rd.whois_domain,
            "registrar": rd.whois_registrar,
            "country": rd.whois_country,
            "creation_date": rd.whois_creation_date,
            "expiration_date": rd.whois_expiration_date,
            "updated_date": rd.whois_updated_date,
            "age_days": rd.whois_age_days,
            "expiry_days": rd.whois_expiry_days,
            "ns_count": rd.whois_ns_count,
            "is_new_domain": rd.whois_is_new_domain,
            "expiring_soon": rd.whois_expiring_soon,
            "is_ip_host": rd.whois_is_ip_host,
            "error": rd.whois_error,
        },
        "redirect_chain": {
            "original_url": rd.chain_original_url,
            "final_url": rd.chain_final_url,
            "hops": rd.chain_hops,
            "hop_count": rd.chain_hop_count,
            "is_shortened": rd.chain_is_shortened,
            "shorteners_found": rd.chain_shorteners,
            "error": rd.chain_error,
        },
        "ssl": {
            "available": rd.ssl_available,
            "is_http": rd.ssl_is_http,
            "verified": rd.ssl_verified,
            "verify_error": rd.ssl_verify_error,
            "subject_cn": rd.ssl_subject_cn,
            "issuer_cn": rd.ssl_issuer_cn,
            "issuer_org": rd.ssl_issuer_org,
            "not_before": rd.ssl_not_before,
            "not_after": rd.ssl_not_after,
            "cert_age_days": rd.ssl_cert_age_days,
            "expiry_days": rd.ssl_expiry_days,
            "is_expired": rd.ssl_is_expired,
            "is_self_signed": rd.ssl_is_self_signed,
            "is_new_cert": rd.ssl_is_new_cert,
            "expiring_soon": rd.ssl_expiring_soon,
            "san_count": rd.ssl_san_count,
            "is_wildcard": rd.ssl_is_wildcard,
            "is_free_ca": rd.ssl_is_free_ca,
            "error": rd.ssl_error,
        },
        "llm_summary": rd.llm_summary,
        "llm_model": rd.llm_model,
        "content_analysis": {
            "available": rd.content_analysis_available,
            "provider": rd.content_analysis_provider,
            "phishing_language_detected": rd.content_phishing_language_detected,
            "urgency_language": rd.content_urgency_language,
            "credential_request": rd.content_credential_request,
            "claimed_brand": rd.content_claimed_brand,
            "brand_mismatch": rd.content_brand_mismatch,
            "confidence": rd.content_confidence,
            "explanation": rd.content_explanation,
            "reason": rd.content_unavailable_reason,
        },
    }


def _write_json(rd: ReportData, path: Path):
    payload = _report_to_dict(rd)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


# ── Markdown renderer ─────────────────────────────────────────────────────────

def _write_md(rd: ReportData, path: Path):
    lines = [
        f"# URL Threat Scan Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **URL** | `{rd.url}` |",
        f"| **Scan ID** | `{rd.scan_id}` |",
        f"| **Scanned at** | {rd.scanned_at} |",
        f"| **Verdict** | **{rd.verdict}** |",
        f"| **Confidence** | {rd.confidence} |",
        f"",
        f"## Signal Summary",
        f"",
    ]
    for r in rd.reasons:
        lines.append(f"- {r}")

    # Redirect chain section
    if rd.chain_hop_count > 0 or rd.chain_error:
        lines += ["", "## Redirect Chain", ""]
        if rd.chain_original_url != rd.chain_final_url:
            lines += [
                f"| | |",
                f"|---|---|",
                f"| **Original URL** | `{rd.chain_original_url}` |",
                f"| **Final URL** | `{rd.chain_final_url}` |",
                f"| **Hops** | {rd.chain_hop_count} |",
                "",
            ]
        if rd.chain_hops:
            lines += ["| Hop | URL | Status | Redirects To | Note |",
                      "|-----|-----|--------|--------------|------|"]
            for i, hop in enumerate(rd.chain_hops, 1):
                note = "⚑ shortener" if hop.get("is_shortener") else ""
                lines.append(
                    f"| {i} | `{hop['url'][:55]}` | {hop['status_code']} "
                    f"| `{(hop.get('redirect_to') or '—')[:40]}` | {note} |"
                )
        if rd.chain_is_shortened:
            lines.append(
                f"\n> ⚠️ **URL shortener(s) detected:** "
                f"{', '.join(rd.chain_shorteners)} — masks true destination"
            )
        if rd.chain_error:
            lines.append(f"\n_Chain trace note: {rd.chain_error}_")

    lines += [
        f"",
        f"## ML Anomaly Detection",
        f"",
    ]
    if rd.ml_available:
        lines += [
            f"| Model | Anomaly Score |",
            f"|-------|--------------|",
            f"| K-means (cluster {rd.ml_kmeans_cluster}) | {rd.ml_kmeans_score:.4f} |",
            f"| SOM | {rd.ml_som_score:.4f} |",
            f"| **Combined** | **{rd.ml_combined_score:.4f}** |",
            f"",
            f"Models agree: {'Yes' if rd.ml_models_agree else 'No (mixed signal — lower confidence)'}  ",
            f"Model version: `{rd.ml_version}`",
        ]
        top = (rd.ml_feature_importance or [])[:5]
        if top:
            lines += [
                f"",
                f"**Top anomaly drivers:**",
                f"",
                f"| Feature | Contribution | Bar |",
                f"|---------|-------------|-----|",
            ]
            for feat, pct in top:
                bar = "█" * round(pct / 5) + "░" * (20 - round(pct / 5))
                lines.append(f"| `{feat}` | {pct:.1f}% | `{bar}` |")
    else:
        lines.append("_ML scoring unavailable (no trained model loaded)._")

    lines += [
        f"",
        f"## External Threat Intelligence",
        f"",
        f"### VirusTotal",
    ]
    if rd.vt_available:
        lines += [
            f"- Malicious detections: **{rd.vt_malicious}**",
            f"- Suspicious: {rd.vt_suspicious}",
            f"- Harmless: {rd.vt_harmless}",
            f"- Status: {rd.vt_status}",
        ]
    else:
        lines.append("_Unavailable (API key not configured or request timed out)._")

    lines += [f"", f"### Google Safe Browsing"]
    if rd.gsb_available:
        lines.append(f"- Threat detected: **{'Yes — ' + ', '.join(rd.gsb_threat_types) if rd.gsb_is_threat else 'No'}**")
    else:
        lines.append("_Unavailable (API key not configured or request timed out)._")

    # SSL/TLS section
    lines += [f"", f"## SSL/TLS Certificate", f""]
    if not rd.ssl_available:
        lines.append(f"_Unavailable — {rd.ssl_error or 'check failed or not attempted'}_")
    elif rd.ssl_is_http:
        lines.append("**⚠️ No HTTPS** — connection is unencrypted.")
    else:
        lines.append(f"- Chain: **{'verified' if rd.ssl_verified else 'unverified'}**")
        lines.append(f"- Subject CN: `{rd.ssl_subject_cn or '—'}`")
        issuer = rd.ssl_issuer_cn or "—"
        if rd.ssl_issuer_org:
            issuer += f" ({rd.ssl_issuer_org})"
        lines.append(f"- Issuer: {issuer}")
        if rd.ssl_is_expired:
            lines.append(f"- Expiry: **EXPIRED {abs(rd.ssl_expiry_days or 0)} days ago**")
        elif rd.ssl_expiry_days is not None:
            note = " ⚠️ expiring soon" if rd.ssl_expiring_soon else ""
            lines.append(f"- Expiry: {rd.ssl_expiry_days} days remaining{note}")
        if rd.ssl_cert_age_days is not None:
            note = " ⚠️ newly issued" if rd.ssl_is_new_cert else ""
            lines.append(f"- Issued: {rd.ssl_cert_age_days} days ago{note}")
        lines.append(f"- SAN count: {rd.ssl_san_count}" + (" (wildcard)" if rd.ssl_is_wildcard else ""))
        flags = []
        if rd.ssl_is_self_signed: flags.append("Self-signed")
        if rd.ssl_is_free_ca:     flags.append("Free/low-cost CA")
        lines.append(f"- Risk flags: {', '.join(flags) if flags else 'None'}")

    # WHOIS section
    lines += [f"", f"## WHOIS Domain Intelligence", f""]
    if rd.whois_available:
        if rd.whois_is_ip_host:
            lines.append("_Host is an IP address — WHOIS domain lookup not applicable._")
        else:
            def _age_note(days):
                if days is None: return ""
                if days < 30:   return " ⚠️ **NEWLY REGISTERED**"
                if days < 90:   return " ⚠️ less than 90 days old"
                return ""
            def _exp_note(days):
                if days is None: return ""
                if days < 0:    return " ⚠️ **EXPIRED**"
                if days < 30:   return " ⚠️ **EXPIRING SOON**"
                return ""
            lines += [
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Domain | `{rd.whois_domain}` |",
                f"| Registrar | {rd.whois_registrar or '—'} |",
                f"| Country | {rd.whois_country or '—'} |",
                f"| Created | {rd.whois_creation_date or '—'} |",
                f"| Expires | {rd.whois_expiration_date or '—'} |",
                f"| Last Updated | {rd.whois_updated_date or '—'} |",
                f"| Domain Age | {f'{rd.whois_age_days} days' if rd.whois_age_days is not None else '—'}"
                f"{_age_note(rd.whois_age_days)} |",
                f"| Days Until Expiry | {f'{rd.whois_expiry_days} days' if rd.whois_expiry_days is not None else '—'}"
                f"{_exp_note(rd.whois_expiry_days)} |",
                f"| Name Server Count | {rd.whois_ns_count or '—'} |",
            ]
            # Risk flags
            flags = []
            if rd.whois_is_new_domain:  flags.append("⚠️ Newly registered domain (< 30 days)")
            if rd.whois_expiring_soon:  flags.append("⚠️ Domain expiring soon (< 30 days)")
            if rd.whois_ns_count == 1:  flags.append("⚠️ Only 1 name server")
            lines += [f"", f"**WHOIS Risk Flags:**"]
            if flags:
                for flag in flags:
                    lines.append(f"- {flag}")
            else:
                lines.append("- None detected")
    else:
        reason = rd.whois_error or "lookup failed or not attempted"
        lines.append(f"_WHOIS data unavailable — {reason}_")

    lines += [f"", f"## URL Feature Breakdown", f"", f"| Feature | Value |", f"|---------|-------|"]
    for name, val in rd.features.items():
        lines.append(f"| {name} | {round(val, 4)} |")

    if rd.llm_summary:
        lines += [f"", f"## AI Analysis", f"", f"> _{rd.llm_model}_", f"", rd.llm_summary]

    path.write_text("\n".join(lines), encoding="utf-8")


# ── Plain text renderer ───────────────────────────────────────────────────────

def _write_txt(rd: ReportData, path: Path):
    sep = "=" * 60
    lines = [
        sep,
        "URL THREAT SCAN REPORT",
        sep,
        f"URL         : {rd.url}",
        f"Scan ID     : {rd.scan_id}",
        f"Scanned at  : {rd.scanned_at}",
        f"Verdict     : {rd.verdict} (confidence: {rd.confidence})",
        sep,
        "SIGNAL SUMMARY",
        sep,
    ]
    for r in rd.reasons:
        lines.append(f"  - {r}")

    if rd.chain_hop_count > 0 or rd.chain_error:
        lines += [sep, "REDIRECT CHAIN", sep]
        if rd.chain_original_url != rd.chain_final_url:
            lines += [
                f"  Original : {rd.chain_original_url}",
                f"  Final    : {rd.chain_final_url}",
                f"  Hops     : {rd.chain_hop_count}",
            ]
        for i, hop in enumerate(rd.chain_hops or [], 1):
            note = " [SHORTENER]" if hop.get("is_shortener") else ""
            lines.append(
                f"  {i:2}. [{hop['status_code']}] {hop['url'][:55]}{note}"
            )
            if hop.get("redirect_to"):
                lines.append(f"       → {hop['redirect_to'][:55]}")
        if rd.chain_is_shortened:
            lines.append(
                f"  [!] Shortener(s): {', '.join(rd.chain_shorteners)}"
            )
        if rd.chain_error:
            lines.append(f"  Note: {rd.chain_error}")

    lines += [sep, "ML ANOMALY DETECTION", sep]
    if rd.ml_available:
        lines += [
            f"  K-means score  : {rd.ml_kmeans_score:.4f}  (cluster {rd.ml_kmeans_cluster})",
            f"  SOM score      : {rd.ml_som_score:.4f}",
            f"  Combined score : {rd.ml_combined_score:.4f}",
            f"  Models agree   : {'Yes' if rd.ml_models_agree else 'No (mixed signal)'}",
            f"  Model version  : {rd.ml_version}",
        ]
        top = (rd.ml_feature_importance or [])[:5]
        if top:
            lines.append("  Top anomaly drivers:")
            for feat, pct in top:
                bar = "█" * round(pct / 5)
                lines.append(f"    {feat:<26} {bar:<20} {pct:.1f}%")
    else:
        lines.append("  ML scoring unavailable.")

    lines += [sep, "EXTERNAL THREAT INTELLIGENCE", sep]
    if rd.vt_available:
        lines += [
            f"  VirusTotal  — malicious: {rd.vt_malicious}, suspicious: {rd.vt_suspicious}, harmless: {rd.vt_harmless}",
        ]
    else:
        lines.append("  VirusTotal  — unavailable")

    if rd.gsb_available:
        threat_str = "THREAT: " + ", ".join(rd.gsb_threat_types) if rd.gsb_is_threat else "clean"
        lines.append(f"  Safe Browsing — {threat_str}")
    else:
        lines.append("  Safe Browsing — unavailable")

    lines += [sep, "SSL/TLS CERTIFICATE", sep]
    if not rd.ssl_available:
        lines.append(f"  Unavailable — {rd.ssl_error or 'check failed or not attempted'}")
    elif rd.ssl_is_http:
        lines.append("  [!] No HTTPS — connection is unencrypted")
    else:
        lines.append(f"  Chain          : {'verified' if rd.ssl_verified else 'unverified'}")
        lines.append(f"  Subject CN     : {rd.ssl_subject_cn or '—'}")
        issuer = rd.ssl_issuer_cn or "—"
        if rd.ssl_issuer_org:
            issuer += f" ({rd.ssl_issuer_org})"
        lines.append(f"  Issuer         : {issuer}")
        if rd.ssl_is_expired:
            lines.append(f"  Expiry         : EXPIRED {abs(rd.ssl_expiry_days or 0)} days ago")
        elif rd.ssl_expiry_days is not None:
            note = " [!] expiring soon" if rd.ssl_expiring_soon else ""
            lines.append(f"  Expiry         : {rd.ssl_expiry_days} days remaining{note}")
        if rd.ssl_cert_age_days is not None:
            note = " [!] newly issued" if rd.ssl_is_new_cert else ""
            lines.append(f"  Issued         : {rd.ssl_cert_age_days} days ago{note}")
        lines.append(f"  SAN count      : {rd.ssl_san_count}" + (" (wildcard)" if rd.ssl_is_wildcard else ""))
        flags = []
        if rd.ssl_is_self_signed: flags.append("Self-signed")
        if rd.ssl_is_free_ca:     flags.append("Free/low-cost CA")
        lines.append(f"  Risk flags     : {', '.join(flags) if flags else 'None'}")

    lines += [sep, "WHOIS DOMAIN INTELLIGENCE", sep]
    if rd.whois_available:
        if rd.whois_is_ip_host:
            lines.append("  IP address host — WHOIS not applicable.")
        else:
            lines += [
                f"  Domain       : {rd.whois_domain or '—'}",
                f"  Registrar    : {rd.whois_registrar or '—'}",
                f"  Country      : {rd.whois_country or '—'}",
                f"  Created      : {rd.whois_creation_date or '—'}",
                f"  Expires      : {rd.whois_expiration_date or '—'}",
                f"  Last Updated : {rd.whois_updated_date or '—'}",
                f"  Domain Age   : {f'{rd.whois_age_days} days' if rd.whois_age_days is not None else '—'}"
                + (" [!] NEWLY REGISTERED" if rd.whois_is_new_domain else ""),
                f"  Until Expiry : {f'{rd.whois_expiry_days} days' if rd.whois_expiry_days is not None else '—'}"
                + (" [!] EXPIRING SOON" if rd.whois_expiring_soon else ""),
                f"  Name Servers : {rd.whois_ns_count or '—'}",
            ]
            flags = []
            if rd.whois_is_new_domain:  flags.append("[!] Newly registered domain (< 30 days)")
            if rd.whois_expiring_soon:  flags.append("[!] Domain expiring soon (< 30 days)")
            if rd.whois_ns_count == 1:  flags.append("[!] Only 1 name server")
            lines.append(f"  Risk Flags   : {', '.join(flags) if flags else 'None'}")
    else:
        lines.append(f"  Status       : unavailable — {rd.whois_error or 'lookup failed'}")

    lines += [sep, "URL FEATURES", sep]
    for name, val in rd.features.items():
        lines.append(f"  {name:<26}: {round(val, 4)}")

    if rd.llm_summary:
        lines += [sep, f"AI ANALYSIS ({rd.llm_model})", sep]
        wrapped = textwrap.fill(rd.llm_summary, width=60)
        lines.append(wrapped)

    lines.append(sep)
    path.write_text("\n".join(lines), encoding="utf-8")


# ── PDF renderer ──────────────────────────────────────────────────────────────

def _write_pdf(rd: ReportData, path: Path):
    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
    )
    styles = getSampleStyleSheet()
    VERDICT_COLOR = {
        "SAFE": colors.HexColor("#1a7f37"),
        "SUSPICIOUS": colors.HexColor("#bf8700"),
        "MALICIOUS": colors.HexColor("#cf222e"),
    }
    v_color = VERDICT_COLOR.get(rd.verdict, colors.black)

    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=6)
    h1_style    = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=13, spaceBefore=14, spaceAfter=4)
    normal      = styles["Normal"]
    small       = ParagraphStyle("Small", parent=normal, fontSize=8, textColor=colors.grey)
    verdict_style = ParagraphStyle(
        "Verdict", parent=styles["Normal"], fontSize=20, textColor=v_color,
        fontName="Helvetica-Bold", spaceAfter=4,
    )

    story = []

    story.append(Paragraph("URL Threat Scan Report", title_style))
    story.append(Paragraph(f"Scan ID: {rd.scan_id}", small))
    story.append(Paragraph(f"Scanned: {rd.scanned_at}", small))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(f"{rd.verdict}", verdict_style))
    story.append(Paragraph(f"Confidence: {rd.confidence}", normal))
    story.append(Paragraph(f"URL: <font name='Courier'>{rd.url}</font>", normal))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=4))

    story.append(Paragraph("Signal Summary", h1_style))
    for r in rd.reasons:
        story.append(Paragraph(f"• {r}", normal))
    story.append(Spacer(1, 4*mm))

    # Redirect chain
    if rd.chain_hop_count > 0 or rd.chain_error:
        story.append(Paragraph("Redirect Chain", h1_style))
        if rd.chain_original_url != rd.chain_final_url:
            story.append(Paragraph(
                f"Original URL: <font name='Courier' size='8'>{rd.chain_original_url}</font>",
                normal
            ))
            story.append(Paragraph(
                f"Final URL: <font name='Courier' size='8'>{rd.chain_final_url}</font>",
                normal
            ))
        if rd.chain_hops:
            hop_data = [["Hop", "URL", "Status", "Redirects To", "Note"]]
            for i, hop in enumerate(rd.chain_hops, 1):
                note = "⚑ shortener" if hop.get("is_shortener") else ""
                hop_data.append([
                    str(i),
                    Paragraph(f'<font name="Courier" size="7">{hop["url"][:55]}</font>', normal),
                    str(hop["status_code"]),
                    Paragraph(f'<font name="Courier" size="7">{(hop.get("redirect_to") or "—")[:40]}</font>', normal),
                    note,
                ])
            ht = RLTable(hop_data, colWidths=[10*mm, 65*mm, 14*mm, 50*mm, 21*mm])
            ht.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,0),  colors.HexColor("#f0f0f0")),
                ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
                ("FONTSIZE",     (0,0),(-1,-1), 8),
                ("GRID",         (0,0),(-1,-1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#fafafa")]),
                ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
            ]))
            story.append(ht)
        if rd.chain_is_shortened:
            story.append(Paragraph(
                f"⚠ Shortener(s) detected: {', '.join(rd.chain_shorteners)}",
                ParagraphStyle("warn", parent=normal, fontSize=8,
                               textColor=colors.HexColor("#bf8700"))
            ))
        if rd.chain_error:
            story.append(Paragraph(f"Note: {rd.chain_error}",
                ParagraphStyle("note", parent=normal, fontSize=8,
                               textColor=colors.grey)))
        story.append(Spacer(1, 4*mm))

    story.append(Paragraph("ML Anomaly Detection", h1_style))
    if rd.ml_available:
        ml_data = [
            ["Model", "Score", "Detail"],
            ["K-means", f"{rd.ml_kmeans_score:.4f}", f"cluster {rd.ml_kmeans_cluster}"],
            ["SOM", f"{rd.ml_som_score:.4f}", "—"],
            ["Combined", f"{rd.ml_combined_score:.4f}", "agree" if rd.ml_models_agree else "disagree"],
        ]
        t = RLTable(ml_data, colWidths=[60*mm, 40*mm, 60*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ]))
        story.append(t)
        story.append(Paragraph(f"Model version: {rd.ml_version}", small))

        # Feature importance table
        top = (rd.ml_feature_importance or [])[:5]
        if top:
            story.append(Spacer(1, 3*mm))
            story.append(Paragraph("Top anomaly drivers:", h1_style))
            fi_data = [["Feature", "Contribution", "Visual"]]
            for feat, pct in top:
                bar_filled  = round(pct / 5)
                bar_empty   = 20 - bar_filled
                bar_str     = "█" * bar_filled + "░" * bar_empty
                fi_data.append([feat, f"{pct:.1f}%", bar_str])
            fi_t = RLTable(fi_data, colWidths=[55*mm, 28*mm, 77*mm])
            fi_t.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0),  colors.HexColor("#f0f0f0")),
                ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
                ("FONTNAME",      (2,1),(2,-1),  "Courier"),
                ("FONTSIZE",      (0,0),(-1,-1), 8),
                ("GRID",          (0,0),(-1,-1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#fafafa")]),
                # Colour the bar column: red for top contributor, yellow for 2nd, green rest
                ("TEXTCOLOR",     (2,1),(2,1),   colors.HexColor("#cf222e")),
                ("TEXTCOLOR",     (2,2),(2,2),   colors.HexColor("#bf8700")),
                ("TEXTCOLOR",     (2,3),(2,-1),  colors.HexColor("#1a7f37")),
            ]))
            story.append(fi_t)
    else:
        story.append(Paragraph("ML scoring unavailable (no trained model).", normal))
    story.append(Spacer(1, 4*mm))

    story.append(Paragraph("External Threat Intelligence", h1_style))
    ext_data = [["Source", "Result", "Detail"]]
    if rd.vt_available:
        ext_data.append(["VirusTotal", f"{rd.vt_malicious} malicious", f"{rd.vt_suspicious} susp / {rd.vt_harmless} harmless"])
    else:
        ext_data.append(["VirusTotal", "unavailable", ""])
    if rd.gsb_available:
        ext_data.append(["Safe Browsing", "THREAT" if rd.gsb_is_threat else "clean", ", ".join(rd.gsb_threat_types)])
    else:
        ext_data.append(["Safe Browsing", "unavailable", ""])
    t2 = RLTable(ext_data, colWidths=[50*mm, 50*mm, 60*mm])
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
    ]))
    story.append(t2)
    story.append(Spacer(1, 4*mm))

    RISK_COLOR = colors.HexColor("#cf222e")
    WARN_COLOR = colors.HexColor("#bf8700")
    OK_COLOR   = colors.HexColor("#1a7f37")

    # SSL/TLS Certificate
    story.append(Paragraph("SSL/TLS Certificate", h1_style))
    if not rd.ssl_available:
        story.append(Paragraph(f"Unavailable — {rd.ssl_error or 'check failed or not attempted'}", normal))
    elif rd.ssl_is_http:
        story.append(Paragraph(
            "⚠ No HTTPS — connection is unencrypted",
            ParagraphStyle("ssl_warn", parent=normal, textColor=RISK_COLOR),
        ))
    else:
        ssl_data = [["Field", "Value", "Risk"]]
        ssl_data.append(["Chain", "verified" if rd.ssl_verified else "unverified",
                          "" if rd.ssl_verified else "⚠"])
        ssl_data.append(["Subject CN", rd.ssl_subject_cn or "—", ""])
        issuer = rd.ssl_issuer_cn or "—"
        if rd.ssl_issuer_org:
            issuer += f" ({rd.ssl_issuer_org})"
        ssl_data.append(["Issuer", issuer, ""])
        if rd.ssl_is_expired:
            ssl_data.append(["Expiry", f"EXPIRED {abs(rd.ssl_expiry_days or 0)} days ago", "⚠"])
        elif rd.ssl_expiry_days is not None:
            ssl_data.append(["Expiry", f"{rd.ssl_expiry_days} days remaining",
                              "⚠" if rd.ssl_expiring_soon else ""])
        if rd.ssl_cert_age_days is not None:
            ssl_data.append(["Issued", f"{rd.ssl_cert_age_days} days ago",
                              "⚠" if rd.ssl_is_new_cert else ""])
        ssl_data.append(["SAN count", str(rd.ssl_san_count) + (" (wildcard)" if rd.ssl_is_wildcard else ""), ""])
        ssl_data.append(["Self-signed", "Yes" if rd.ssl_is_self_signed else "No",
                          "⚠" if rd.ssl_is_self_signed else ""])
        ssl_data.append(["Free/low-cost CA", "Yes" if rd.ssl_is_free_ca else "No", ""])

        ssl_t = RLTable(ssl_data, colWidths=[40*mm, 90*mm, 15*mm])
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ]
        for ri, row in enumerate(ssl_data[1:], start=1):
            if row[2] == "⚠":
                style_cmds.append(("TEXTCOLOR", (2, ri), (2, ri), WARN_COLOR))
        ssl_t.setStyle(TableStyle(style_cmds))
        story.append(ssl_t)
    story.append(Spacer(1, 4*mm))

    # WHOIS section
    story.append(Paragraph("WHOIS Domain Intelligence", h1_style))

    if rd.whois_available:
        if rd.whois_is_ip_host:
            story.append(Paragraph("Host is an IP address — WHOIS domain lookup not applicable.", normal))
        else:
            def _age_str(days):
                if days is None: return "—"
                return f"{days} days"
            def _exp_str(days):
                if days is None: return "—"
                if days < 0:    return f"EXPIRED ({abs(days)} days ago)"
                return f"{days} days"

            whois_data = [
                ["Field", "Value", "Risk"],
                ["Domain",          rd.whois_domain or "—",               ""],
                ["Registrar",       rd.whois_registrar or "—",            ""],
                ["Country",         rd.whois_country or "—",              ""],
                ["Created",         rd.whois_creation_date or "—",        "⚠ NEW" if rd.whois_is_new_domain else ""],
                ["Expires",         rd.whois_expiration_date or "—",      "⚠ SOON" if rd.whois_expiring_soon else ""],
                ["Last Updated",    rd.whois_updated_date or "—",         ""],
                ["Domain Age",      _age_str(rd.whois_age_days),          "⚠ < 30 days" if rd.whois_is_new_domain else ("⚠ < 90 days" if rd.whois_age_days and rd.whois_age_days < 90 else "")],
                ["Until Expiry",    _exp_str(rd.whois_expiry_days),       "⚠ EXPIRING" if rd.whois_expiring_soon else ""],
                ["Name Servers",    str(rd.whois_ns_count) if rd.whois_ns_count else "—",
                                    "⚠ Only 1 NS" if rd.whois_ns_count == 1 else ""],
            ]
            tw = RLTable(whois_data, colWidths=[38*mm, 90*mm, 32*mm])
            tw.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0),  colors.HexColor("#f0f0f0")),
                ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
                ("FONTNAME",      (0,1),(0,-1),  "Helvetica-Bold"),
                ("FONTSIZE",      (0,0),(-1,-1), 8),
                ("GRID",          (0,0),(-1,-1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#fafafa")]),
                ("TEXTCOLOR",     (2,1),(-1,-1), WARN_COLOR),
                ("FONTNAME",      (2,1),(-1,-1), "Helvetica-Bold"),
                ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ]))
            story.append(tw)

            # Risk flags summary
            flags = []
            if rd.whois_is_new_domain:  flags.append("Newly registered domain (< 30 days)")
            if rd.whois_expiring_soon:  flags.append("Domain expiring soon (< 30 days)")
            if rd.whois_ns_count == 1:  flags.append("Only 1 name server")
            if flags:
                story.append(Spacer(1, 2*mm))
                story.append(Paragraph(
                    "<b>WHOIS Risk Flags:</b> " + " | ".join(f"⚠ {f}" for f in flags),
                    ParagraphStyle("wf", parent=normal, fontSize=8, textColor=WARN_COLOR)
                ))
            else:
                story.append(Spacer(1, 2*mm))
                story.append(Paragraph(
                    "WHOIS Risk Flags: None detected",
                    ParagraphStyle("wf_ok", parent=normal, fontSize=8, textColor=OK_COLOR)
                ))
    else:
        story.append(Paragraph(
            f"WHOIS data unavailable — {rd.whois_error or 'lookup failed or not attempted'}",
            ParagraphStyle("wna", parent=normal, fontSize=9, textColor=colors.grey)
        ))
    story.append(Spacer(1, 4*mm))

    story.append(Paragraph("URL Feature Breakdown", h1_style))
    feat_data = [["Feature", "Value"]] + [[k, str(round(v, 4))] for k, v in rd.features.items()]
    t3 = RLTable(feat_data, colWidths=[90*mm, 70*mm])
    t3.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
    ]))
    story.append(t3)

    if rd.llm_summary:
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph(f"AI Analysis ({rd.llm_model})", h1_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#0969da"), spaceAfter=4))
        story.append(Paragraph(rd.llm_summary, normal))

    doc.build(story)


# ── DOCX renderer ─────────────────────────────────────────────────────────────

def _write_docx(rd: ReportData, path: Path):
    doc = Document()

    # Title
    title = doc.add_heading("URL Threat Scan Report", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT

    meta = doc.add_paragraph()
    meta.add_run(f"Scan ID: ").bold = False
    meta.add_run(rd.scan_id).font.size = Pt(9)
    p2 = doc.add_paragraph()
    p2.add_run(f"Scanned: {rd.scanned_at}").font.size = Pt(9)

    # Verdict
    doc.add_heading("Verdict", level=1)
    VERDICT_RGB = {
        "SAFE": RGBColor(0x1a, 0x7f, 0x37),
        "SUSPICIOUS": RGBColor(0xbf, 0x87, 0x00),
        "MALICIOUS": RGBColor(0xcf, 0x22, 0x2e),
    }
    vp = doc.add_paragraph()
    run = vp.add_run(rd.verdict)
    run.bold = True
    run.font.size = Pt(18)
    run.font.color.rgb = VERDICT_RGB.get(rd.verdict, RGBColor(0, 0, 0))
    doc.add_paragraph(f"Confidence: {rd.confidence}")
    url_p = doc.add_paragraph()
    url_run = url_p.add_run(f"URL: {rd.url}")
    url_run.font.name = "Courier New"
    url_run.font.size = Pt(9)

    # Reasons
    doc.add_heading("Signal Summary", level=1)
    for r in rd.reasons:
        doc.add_paragraph(r, style="List Bullet")

    # Redirect chain
    if rd.chain_hop_count > 0 or rd.chain_error:
        doc.add_heading("Redirect Chain", level=1)
        if rd.chain_original_url != rd.chain_final_url:
            p = doc.add_paragraph()
            p.add_run("Original URL: ").bold = True
            r = p.add_run(rd.chain_original_url)
            r.font.name = "Courier New"; r.font.size = Pt(8)
            p2 = doc.add_paragraph()
            p2.add_run("Final URL: ").bold = True
            r2 = p2.add_run(rd.chain_final_url)
            r2.font.name = "Courier New"; r2.font.size = Pt(8)

        if rd.chain_hops:
            ch_tbl = doc.add_table(rows=len(rd.chain_hops)+1, cols=4)
            ch_tbl.style = "Table Grid"
            for ci, h in enumerate(["Hop", "URL", "Status", "Redirects To"]):
                ch_tbl.rows[0].cells[ci].text = h
                ch_tbl.rows[0].cells[ci].paragraphs[0].runs[0].bold = True
            for ri, hop in enumerate(rd.chain_hops, 1):
                ch_tbl.rows[ri].cells[0].text = str(ri)
                ch_tbl.rows[ri].cells[1].text = hop["url"][:60]
                ch_tbl.rows[ri].cells[2].text = str(hop["status_code"])
                ch_tbl.rows[ri].cells[3].text = (hop.get("redirect_to") or "—")[:50]

        if rd.chain_is_shortened:
            p = doc.add_paragraph()
            run = p.add_run(f"⚠ Shortener(s) detected: {', '.join(rd.chain_shorteners)}")
            run.font.color.rgb = RGBColor(0xbf, 0x87, 0x00)
            run.bold = True
        if rd.chain_error:
            doc.add_paragraph(f"Note: {rd.chain_error}")

    # ML
    doc.add_heading("ML Anomaly Detection", level=1)
    if rd.ml_available:
        ml_tbl = doc.add_table(rows=4, cols=3)
        ml_tbl.style = "Table Grid"
        headers = ["Model", "Score", "Detail"]
        for i, h in enumerate(headers):
            cell = ml_tbl.rows[0].cells[i]
            cell.text = h
            cell.paragraphs[0].runs[0].bold = True
        rows = [
            ["K-means", f"{rd.ml_kmeans_score:.4f}", f"cluster {rd.ml_kmeans_cluster}"],
            ["SOM",     f"{rd.ml_som_score:.4f}",    "—"],
            ["Combined",f"{rd.ml_combined_score:.4f}", "agree" if rd.ml_models_agree else "disagree (mixed signal)"],
        ]
        for ri, row_data in enumerate(rows, start=1):
            for ci, val in enumerate(row_data):
                ml_tbl.rows[ri].cells[ci].text = val
        p_mv = doc.add_paragraph(f"Model version: {rd.ml_version}")
        p_mv.runs[0].font.size = Pt(8)

        # Feature importance table
        top = (rd.ml_feature_importance or [])[:5]
        if top:
            doc.add_heading("Top anomaly drivers", level=2)
            fi_tbl = doc.add_table(rows=len(top) + 1, cols=3)
            fi_tbl.style = "Table Grid"
            for ci, h in enumerate(["Feature", "Contribution", "Visual"]):
                fi_tbl.rows[0].cells[ci].text = h
                fi_tbl.rows[0].cells[ci].paragraphs[0].runs[0].bold = True
            COLORS = [RGBColor(0xcf, 0x22, 0x2e), RGBColor(0xbf, 0x87, 0x00),
                      RGBColor(0x1a, 0x7f, 0x37), RGBColor(0x1a, 0x7f, 0x37),
                      RGBColor(0x1a, 0x7f, 0x37)]
            for ri, (feat, pct) in enumerate(top, 1):
                bar = "█" * round(pct / 5) + "░" * (20 - round(pct / 5))
                fi_tbl.rows[ri].cells[0].text = feat
                fi_tbl.rows[ri].cells[1].text = f"{pct:.1f}%"
                c = fi_tbl.rows[ri].cells[2]
                c.text = bar
                if c.paragraphs[0].runs:
                    c.paragraphs[0].runs[0].font.color.rgb = COLORS[ri - 1]
                    c.paragraphs[0].runs[0].font.name = "Courier New"
                    c.paragraphs[0].runs[0].font.size = Pt(8)
    else:
        doc.add_paragraph("ML scoring unavailable (no trained model loaded).")

    # External APIs
    doc.add_heading("External Threat Intelligence", level=1)
    ext_tbl = doc.add_table(rows=3, cols=3)
    ext_tbl.style = "Table Grid"
    for i, h in enumerate(["Source", "Result", "Detail"]):
        ext_tbl.rows[0].cells[i].text = h
        ext_tbl.rows[0].cells[i].paragraphs[0].runs[0].bold = True

    if rd.vt_available:
        ext_tbl.rows[1].cells[0].text = "VirusTotal"
        ext_tbl.rows[1].cells[1].text = f"{rd.vt_malicious} malicious"
        ext_tbl.rows[1].cells[2].text = f"{rd.vt_suspicious} suspicious, {rd.vt_harmless} harmless"
    else:
        ext_tbl.rows[1].cells[0].text = "VirusTotal"
        ext_tbl.rows[1].cells[1].text = "unavailable"

    if rd.gsb_available:
        ext_tbl.rows[2].cells[0].text = "Google Safe Browsing"
        ext_tbl.rows[2].cells[1].text = "THREAT" if rd.gsb_is_threat else "clean"
        ext_tbl.rows[2].cells[2].text = ", ".join(rd.gsb_threat_types) if rd.gsb_threat_types else "—"
    else:
        ext_tbl.rows[2].cells[0].text = "Google Safe Browsing"
        ext_tbl.rows[2].cells[1].text = "unavailable"

    # SSL/TLS Certificate
    doc.add_heading("SSL/TLS Certificate", level=1)
    SSL_WARN = RGBColor(0xbf, 0x87, 0x00)
    SSL_RISK = RGBColor(0xcf, 0x22, 0x2e)
    if not rd.ssl_available:
        doc.add_paragraph(f"Unavailable — {rd.ssl_error or 'check failed or not attempted'}")
    elif rd.ssl_is_http:
        p = doc.add_paragraph()
        r = p.add_run("⚠ No HTTPS — connection is unencrypted")
        r.font.color.rgb = SSL_RISK
        r.bold = True
    else:
        ssl_rows = [
            ("Chain", "verified" if rd.ssl_verified else "unverified", not rd.ssl_verified),
            ("Subject CN", rd.ssl_subject_cn or "—", False),
            ("Issuer", (rd.ssl_issuer_cn or "—") + (f" ({rd.ssl_issuer_org})" if rd.ssl_issuer_org else ""), False),
        ]
        if rd.ssl_is_expired:
            ssl_rows.append(("Expiry", f"EXPIRED {abs(rd.ssl_expiry_days or 0)} days ago", True))
        elif rd.ssl_expiry_days is not None:
            ssl_rows.append(("Expiry", f"{rd.ssl_expiry_days} days remaining", rd.ssl_expiring_soon))
        if rd.ssl_cert_age_days is not None:
            ssl_rows.append(("Issued", f"{rd.ssl_cert_age_days} days ago", rd.ssl_is_new_cert))
        ssl_rows.append(("SAN count", str(rd.ssl_san_count) + (" (wildcard)" if rd.ssl_is_wildcard else ""), False))
        ssl_rows.append(("Self-signed", "Yes" if rd.ssl_is_self_signed else "No", rd.ssl_is_self_signed))
        ssl_rows.append(("Free/low-cost CA", "Yes" if rd.ssl_is_free_ca else "No", False))

        ssl_tbl = doc.add_table(rows=len(ssl_rows) + 1, cols=2)
        ssl_tbl.style = "Table Grid"
        ssl_tbl.rows[0].cells[0].text = "Field"
        ssl_tbl.rows[0].cells[1].text = "Value"
        ssl_tbl.rows[0].cells[0].paragraphs[0].runs[0].bold = True
        ssl_tbl.rows[0].cells[1].paragraphs[0].runs[0].bold = True
        for ri, (field, value, is_warn) in enumerate(ssl_rows, start=1):
            ssl_tbl.rows[ri].cells[0].text = field
            ssl_tbl.rows[ri].cells[1].text = value
            if is_warn and ssl_tbl.rows[ri].cells[1].paragraphs[0].runs:
                ssl_tbl.rows[ri].cells[1].paragraphs[0].runs[0].font.color.rgb = SSL_WARN
                ssl_tbl.rows[ri].cells[1].paragraphs[0].runs[0].bold = True

    # WHOIS section
    doc.add_heading("WHOIS Domain Intelligence", level=1)
    if rd.whois_available:
        if rd.whois_is_ip_host:
            doc.add_paragraph("Host is an IP address — WHOIS domain lookup not applicable.")
        else:
            whois_rows = [
                ("Domain",         rd.whois_domain or "—",                False),
                ("Registrar",      rd.whois_registrar or "—",             False),
                ("Country",        rd.whois_country or "—",               False),
                ("Created",        rd.whois_creation_date or "—",         False),
                ("Expires",        rd.whois_expiration_date or "—",       rd.whois_expiring_soon),
                ("Last Updated",   rd.whois_updated_date or "—",          False),
                ("Domain Age",     f"{rd.whois_age_days} days" if rd.whois_age_days is not None else "—",
                                   rd.whois_is_new_domain),
                ("Until Expiry",   f"{rd.whois_expiry_days} days" if rd.whois_expiry_days is not None else "—",
                                   rd.whois_expiring_soon),
                ("Name Servers",   str(rd.whois_ns_count) if rd.whois_ns_count else "—",
                                   rd.whois_ns_count == 1),
            ]
            wtbl = doc.add_table(rows=len(whois_rows) + 1, cols=3)
            wtbl.style = "Table Grid"
            for ci, h in enumerate(["Field", "Value", "Risk Flag"]):
                wtbl.rows[0].cells[ci].text = h
                wtbl.rows[0].cells[ci].paragraphs[0].runs[0].bold = True
            WARN = RGBColor(0xbf, 0x87, 0x00)
            for ri, (field, value, is_risk) in enumerate(whois_rows, 1):
                wtbl.rows[ri].cells[0].text = field
                wtbl.rows[ri].cells[1].text = value
                flag_text = "⚠ Risk detected" if is_risk else ""
                wtbl.rows[ri].cells[2].text = flag_text
                if is_risk and wtbl.rows[ri].cells[2].paragraphs[0].runs:
                    wtbl.rows[ri].cells[2].paragraphs[0].runs[0].font.color.rgb = WARN
                    wtbl.rows[ri].cells[2].paragraphs[0].runs[0].bold = True

            # Risk summary paragraph
            flags = []
            if rd.whois_is_new_domain:  flags.append("Newly registered (< 30 days)")
            if rd.whois_expiring_soon:  flags.append("Expiring soon (< 30 days)")
            if rd.whois_ns_count == 1:  flags.append("Only 1 name server")
            p = doc.add_paragraph()
            r = p.add_run("WHOIS Risk Flags: " + (", ".join(flags) if flags else "None detected"))
            r.font.size = Pt(9)
            if flags:
                r.font.color.rgb = WARN
                r.bold = True
    else:
        doc.add_paragraph(
            f"WHOIS data unavailable — {rd.whois_error or 'lookup failed or not attempted'}"
        )

    # Features table
    doc.add_heading("URL Feature Breakdown", level=1)
    feat_tbl = doc.add_table(rows=len(rd.features) + 1, cols=2)
    feat_tbl.style = "Table Grid"
    feat_tbl.rows[0].cells[0].text = "Feature"
    feat_tbl.rows[0].cells[1].text = "Value"
    feat_tbl.rows[0].cells[0].paragraphs[0].runs[0].bold = True
    feat_tbl.rows[0].cells[1].paragraphs[0].runs[0].bold = True
    for ri, (k, v) in enumerate(rd.features.items(), start=1):
        feat_tbl.rows[ri].cells[0].text = k
        feat_tbl.rows[ri].cells[1].text = str(round(v, 4))

    # LLM section
    if rd.llm_summary:
        doc.add_heading(f"AI Analysis ({rd.llm_model})", level=1)
        doc.add_paragraph(rd.llm_summary)

    doc.save(str(path))


# ── Public API ────────────────────────────────────────────────────────────────

async def generate_report(
    scan_id: str,
    result: dict,
    formats: list[str] = None,    # ["md", "txt", "pdf", "docx", "json"] or subset
    show_terminal: bool = True,
    llm_provider: str | None = None,
    llm_model: str | None = None,
) -> dict[str, Path]:
    """
    Main entry point called by the CLI after a scan completes.

    Args:
        scan_id:       UUID of the completed scan.
        result:        The result dict from scan_jobs.result_json.
        formats:       List of file formats to save. None = all supported formats.
        show_terminal: Whether to print the rich terminal report.

    Returns:
        dict mapping format -> saved Path (only for formats that were saved).
    """
    if formats is None:
        formats = ["md", "txt", "pdf", "docx", "json"]

    rd = _build_report_data(scan_id, result)

    # LLM enhancement
    if result.get("use_llm"):
        provider = _normalize_llm_provider(llm_provider or result.get("llm_provider") or os.getenv("LLM_PROVIDER") or os.getenv("REPORT_LLM_PROVIDER"))
        chosen_model = llm_model or result.get("llm_model") or (os.getenv("GEMINI_MODEL") if provider == "gemini" else os.getenv("OLLAMA_MODEL"))
        console.print(f"[dim]Generating AI summary via {provider}…[/dim]")
        rd.llm_summary, rd.llm_model = await _fetch_llm_summary(rd, provider=provider, model=chosen_model)
        if not rd.llm_summary:
            console.print("[yellow]  Skipping AI summary — see warnings above.[/yellow]")

    # Terminal
    if show_terminal:
        render_terminal(rd)

    # File outputs
    saved: dict[str, Path] = {}
    writers = {
        "md":   _write_md,
        "txt":  _write_txt,
        "pdf":  _write_pdf,
        "docx": _write_docx,
        "json": _write_json,
    }

    for fmt in formats:
        if fmt not in writers:
            console.print(f"[yellow]Unknown format '{fmt}' — skipping.[/yellow]")
            continue
        out_path = REPORTS_DIR / f"{scan_id}.{fmt}"
        try:
            writers[fmt](rd, out_path)
            saved[fmt] = out_path
            console.print(f"[dim]  Saved {fmt.upper()} report → {out_path}[/dim]")
        except Exception as e:
            console.print(f"[red]  Failed to write {fmt} report: {e}[/red]")

    return saved


# ── Batch report ───────────────────────────────────────────────────────────────

async def generate_batch_report(
    batch_id: str,
    results: list[dict],
    formats: list[str] = None,
    show_terminal: bool = True,
    llm_provider: str | None = None,
    llm_model: str | None = None,
) -> dict[str, Path]:
    """
    Generate a single consolidated report for a batch scan.
    One file per format, named batch_<batch_id>.<fmt>.
    Terminal output shows a summary table + per-URL verdict breakdown.
    LLM summary is generated per-URL if use_llm=True is present in any result.
    """
    if formats is None:
        formats = ["md", "txt", "pdf", "docx", "json"]

    if not results:
        console.print("[yellow]Batch report: no results to report.[/yellow]")
        return {}

    scanned_at = results[0].get("scanned_at", "")
    total      = len(results)
    counts     = {"SAFE": 0, "SUSPICIOUS": 0, "MALICIOUS": 0, "UNKNOWN": 0}
    use_llm    = any(r.get("use_llm") for r in results)
    rows       = []

    # ── LLM summaries (one per URL if enabled) ────────────────────────────────
    llm_summaries: dict[str, str] = {}
    llm_model_name: str | None = None

    if use_llm:
        provider = _normalize_llm_provider(llm_provider or os.getenv("LLM_PROVIDER") or os.getenv("REPORT_LLM_PROVIDER"))
        console.print(f"[dim]Generating LLM summaries for {total} URLs via {provider}…[/dim]")
        resolved_provider, model = await _resolve_llm_model(provider, llm_model)
        if not model:
            console.print(f"[yellow]  {provider} unavailable — skipping LLM summaries.[/yellow]")
        else:
            llm_model_name = model
            for i, r in enumerate(results, 1):
                rd = _build_report_data(f"batch-{i}", r)
                console.print(f"  [dim]({i}/{total}) {r.get('url','')[:60]}[/dim]")
                text, _, _ = await _generate_with(resolved_provider or provider, model, _build_llm_prompt(rd))
                if text:
                    llm_summaries[r.get("url", "")] = text

    for r in results:
        v_block    = r.get("verdict", {})
        verdict    = v_block.get("verdict", "UNKNOWN")
        confidence = v_block.get("confidence", "—")
        reasons    = v_block.get("reasons", [])
        url        = r.get("url", "")
        counts[verdict] = counts.get(verdict, 0) + 1
        rows.append({
            "url": url, "verdict": verdict,
            "confidence": confidence, "reasons": reasons,
            "ml_score": r.get("ml", {}).get("combined_score", 0.0),
            "vt_malicious": r.get("virustotal", {}).get("malicious", 0),
            "gsb_threat": r.get("safe_browsing", {}).get("is_threat", False),
            "llm_summary": llm_summaries.get(url),
        })

    # ── Terminal ──────────────────────────────────────────────────────────────
    if show_terminal:
        from rich.table import Table as RichTable
        from rich import box as rbox

        console.print()
        console.rule(f"[bold]Batch Scan Report — {batch_id[:8]}…[/bold]")
        console.print(f"\n  Total URLs   : {total}")
        console.print(f"  [green]Safe         : {counts.get('SAFE',0)}[/green]")
        console.print(f"  [yellow]Suspicious   : {counts.get('SUSPICIOUS',0)}[/yellow]")
        console.print(f"  [red]Malicious    : {counts.get('MALICIOUS',0)}[/red]")
        console.print()

        tbl = RichTable(box=rbox.ROUNDED, show_lines=True, title="Per-URL Results")
        tbl.add_column("#",          width=4,  justify="right")
        tbl.add_column("URL",        max_width=50, no_wrap=True)
        tbl.add_column("Verdict",    width=12)
        tbl.add_column("Confidence", width=10)
        tbl.add_column("ML Score",   width=9,  justify="right")
        tbl.add_column("VT Mal",     width=7,  justify="right")
        tbl.add_column("GSB",        width=6,  justify="center")

        COLOR = {"SAFE": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "red"}
        for i, row in enumerate(rows, 1):
            col = COLOR.get(row["verdict"], "white")
            tbl.add_row(
                str(i), row["url"],
                f"[{col}]{row['verdict']}[/{col}]",
                row["confidence"],
                f"{row['ml_score']:.3f}",
                str(row["vt_malicious"]),
                "[red]✗[/red]" if row["gsb_threat"] else "[green]✓[/green]",
            )
        console.print(tbl)
        console.print()

    # ── File outputs ──────────────────────────────────────────────────────────
    saved: dict[str, Path] = {}
    prefix = f"batch_{batch_id}"

    # Markdown
    if "md" in formats:
        md_lines = [
            f"# Batch Scan Report",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Batch ID** | `{batch_id}` |",
            f"| **Scanned at** | {scanned_at} |",
            f"| **Total URLs** | {total} |",
            f"| **Safe** | {counts.get('SAFE',0)} |",
            f"| **Suspicious** | {counts.get('SUSPICIOUS',0)} |",
            f"| **Malicious** | {counts.get('MALICIOUS',0)} |",
            f"",
            f"## Per-URL Results",
            f"",
            f"| # | URL | Verdict | Confidence | ML Score | VT Malicious | GSB Threat |",
            f"|---|-----|---------|------------|----------|-------------|-----------|",
        ]
        for i, row in enumerate(rows, 1):
            gsb = "Yes" if row["gsb_threat"] else "No"
            md_lines.append(
                f"| {i} | `{row['url']}` | **{row['verdict']}** | "
                f"{row['confidence']} | {row['ml_score']:.3f} | "
                f"{row['vt_malicious']} | {gsb} |"
            )
        md_lines += ["", "## Detail per URL", ""]
        for i, (row, result) in enumerate(zip(rows, results), 1):
            md_lines += [
                f"### {i}. `{row['url']}`",
                f"- **Verdict**: {row['verdict']} ({row['confidence']})",
            ]
            for reason in row["reasons"]:
                md_lines.append(f"- {reason}")
            if row.get("llm_summary"):
                md_lines += [
                    "",
                    f"> **AI Analysis** _{llm_model_name}_",
                    f"> {row['llm_summary']}",
                ]
            md_lines.append("")

        p = REPORTS_DIR / f"{prefix}.md"
        p.write_text("\n".join(md_lines), encoding="utf-8")
        saved["md"] = p
        console.print(f"[dim]  Saved MD  → {p}[/dim]")

    # Plain text
    if "txt" in formats:
        sep = "=" * 60
        txt_lines = [
            sep, "BATCH SCAN REPORT", sep,
            f"Batch ID    : {batch_id}",
            f"Scanned at  : {scanned_at}",
            f"Total URLs  : {total}",
            f"Safe        : {counts.get('SAFE',0)}",
            f"Suspicious  : {counts.get('SUSPICIOUS',0)}",
            f"Malicious   : {counts.get('MALICIOUS',0)}",
            sep, "PER-URL RESULTS", sep,
        ]
        for i, row in enumerate(rows, 1):
            txt_lines += [
                f"  {i:3}. {row['url']}",
                f"       Verdict    : {row['verdict']} ({row['confidence']})",
                f"       ML Score   : {row['ml_score']:.4f}",
                f"       VT Mal     : {row['vt_malicious']}",
                f"       GSB Threat : {'Yes' if row['gsb_threat'] else 'No'}",
                "",
            ]
        p = REPORTS_DIR / f"{prefix}.txt"
        p.write_text("\n".join(txt_lines), encoding="utf-8")
        saved["txt"] = p
        console.print(f"[dim]  Saved TXT → {p}[/dim]")

    # PDF
    if "pdf" in formats:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table as RLTable,
                TableStyle, HRFlowable,
            )
            pdf_path = REPORTS_DIR / f"{prefix}.pdf"
            doc = SimpleDocTemplate(str(pdf_path), pagesize=A4,
                                    leftMargin=18*mm, rightMargin=18*mm,
                                    topMargin=18*mm, bottomMargin=18*mm)
            styles  = getSampleStyleSheet()
            normal  = styles["Normal"]
            title_s = ParagraphStyle("T", parent=styles["Title"], fontSize=16, spaceAfter=6)
            h1_s    = ParagraphStyle("H", parent=styles["Heading1"], fontSize=12, spaceBefore=10, spaceAfter=4)
            small   = ParagraphStyle("S", parent=normal, fontSize=8, textColor=colors.grey)
            C = {"SAFE": colors.HexColor("#1a7f37"),
                 "SUSPICIOUS": colors.HexColor("#bf8700"),
                 "MALICIOUS": colors.HexColor("#cf222e")}

            story = [
                Paragraph("Batch Scan Report", title_s),
                Paragraph(f"Batch ID: {batch_id}", small),
                Paragraph(f"Scanned: {scanned_at}  |  Total: {total}  |  "
                          f"Safe: {counts.get('SAFE',0)}  Suspicious: {counts.get('SUSPICIOUS',0)}  "
                          f"Malicious: {counts.get('MALICIOUS',0)}", normal),
                Spacer(1, 6*mm),
                Paragraph("Per-URL Results", h1_s),
            ]
            tbl_data = [["#", "URL", "Verdict", "Conf.", "ML", "VT", "GSB"]]
            for i, row in enumerate(rows, 1):
                tbl_data.append([
                    str(i),
                    Paragraph(f'<font size="7" name="Courier">{row["url"][:60]}</font>', normal),
                    Paragraph(f'<font color="{C.get(row["verdict"], colors.black).hexval()}">'
                              f'<b>{row["verdict"]}</b></font>', normal),
                    row["confidence"],
                    f'{row["ml_score"]:.3f}',
                    str(row["vt_malicious"]),
                    "Y" if row["gsb_threat"] else "N",
                ])
            t = RLTable(tbl_data, colWidths=[10*mm, 75*mm, 28*mm, 18*mm, 16*mm, 10*mm, 10*mm])
            t.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,0),  colors.HexColor("#f0f0f0")),
                ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
                ("FONTSIZE",     (0,0),(-1,-1), 8),
                ("GRID",         (0,0),(-1,-1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#fafafa")]),
                ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
            ]))
            story.append(t)
            doc.build(story)
            saved["pdf"] = pdf_path
            console.print(f"[dim]  Saved PDF → {pdf_path}[/dim]")
        except Exception as e:
            console.print(f"[red]  PDF batch report failed: {e}[/red]")

    # DOCX
    if "docx" in formats:
        try:
            from docx import Document
            from docx.shared import Pt, RGBColor
            doc = Document()
            doc.add_heading("Batch Scan Report", 0)
            doc.add_paragraph(f"Batch ID: {batch_id}")
            doc.add_paragraph(f"Scanned: {scanned_at}")
            doc.add_paragraph(f"Total: {total}  |  Safe: {counts.get('SAFE',0)}  "
                               f"Suspicious: {counts.get('SUSPICIOUS',0)}  "
                               f"Malicious: {counts.get('MALICIOUS',0)}")
            doc.add_heading("Per-URL Results", 1)
            tbl = doc.add_table(rows=len(rows)+1, cols=6)
            tbl.style = "Table Grid"
            for i, h in enumerate(["URL","Verdict","Confidence","ML Score","VT Mal","GSB"]):
                tbl.rows[0].cells[i].text = h
                tbl.rows[0].cells[i].paragraphs[0].runs[0].bold = True
            VRGB = {"SAFE": RGBColor(0x1a,0x7f,0x37),
                    "SUSPICIOUS": RGBColor(0xbf,0x87,0x00),
                    "MALICIOUS": RGBColor(0xcf,0x22,0x2e)}
            for ri, row in enumerate(rows, 1):
                tbl.rows[ri].cells[0].text = row["url"]
                c = tbl.rows[ri].cells[1]
                c.text = row["verdict"]
                if c.paragraphs[0].runs:
                    c.paragraphs[0].runs[0].font.color.rgb = VRGB.get(row["verdict"], RGBColor(0,0,0))
                tbl.rows[ri].cells[2].text = row["confidence"]
                tbl.rows[ri].cells[3].text = f"{row['ml_score']:.4f}"
                tbl.rows[ri].cells[4].text = str(row["vt_malicious"])
                tbl.rows[ri].cells[5].text = "Yes" if row["gsb_threat"] else "No"
            docx_path = REPORTS_DIR / f"{prefix}.docx"
            doc.save(str(docx_path))
            saved["docx"] = docx_path
            console.print(f"[dim]  Saved DOCX → {docx_path}[/dim]")
        except Exception as e:
            console.print(f"[red]  DOCX batch report failed: {e}[/red]")

    # JSON
    if "json" in formats:
        payload = {
            "batch_id": batch_id,
            "scanned_at": scanned_at,
            "total_urls": total,
            "counts": counts,
            "results": [
                {
                    "url": row["url"],
                    "verdict": row["verdict"],
                    "confidence": row["confidence"],
                    "reasons": row["reasons"],
                    "ml_score": row["ml_score"],
                    "vt_malicious": row["vt_malicious"],
                    "gsb_threat": row["gsb_threat"],
                    "llm_summary": row["llm_summary"],
                }
                for row in rows
            ],
        }
        json_path = REPORTS_DIR / f"{prefix}.json"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        saved["json"] = json_path
        console.print(f"[dim]  Saved JSON → {json_path}[/dim]")

    return saved