"""
core/llm_content_check.py

LLM-based page content analysis - a fourth detection layer alongside
lexical/ML, WHOIS, and external threat intel. Fetches the page's rendered
text and asks Claude to assess it for phishing-style content patterns:
credential-harvesting forms, urgency/fear language, and brand mismatch
between the page's claimed identity and its actual domain.

This targets a specific documented trend: 82.6% of phishing emails now
contain AI-generated content (Keepnet/VIPRE 2025), and ENISA's 2025 Threat
Landscape reports AI-supported phishing campaigns account for 80%+ of
observed social engineering activity. AI-generated phishing pages are
increasingly well-written and typo-free, so lexical URL features alone can
miss them - but the underlying *intent* patterns (urgency, credential
requests, brand impersonation) are still detectable by reading the actual
page content.

Deliberately opt-in via the existing `use_llm` flag in scanner.py, since
this adds real latency (a page fetch + an LLM call) and per-scan cost
(if using a hosted API) or compute (if using a local model), unlike the
other checks which are either instant (ML/lexical) or already-parallelized
fast API calls.

Supports two providers, switchable via the LLM_PROVIDER env var:

  LLM_PROVIDER=gemini      (default) - calls the Gemini API (Flash / Flash-Lite)
    Requires: GEMINI_API_KEY
    Default model: "gemini-3.5-flash-lite" - overridable via GEMINI_MODEL.
    NOTE: Gemini's Flash lineup deprecates fast (2.0 Flash/Flash-Lite
    already shut down June 2026; 2.5 Flash/Flash-Lite slated to shut down
    Oct 2026) - check https://ai.google.dev/gemini-api/docs/models for
    the current GA model if this default has gone stale.

  LLM_PROVIDER=ollama      - calls a local Ollama instance
    Requires: Ollama running locally (default http://localhost:11434)
    with a model pulled, e.g.:  ollama pull llama3.1
    Optional env vars: OLLAMA_BASE_URL (default http://localhost:11434)
                        OLLAMA_MODEL    (default llama3.1)

Add to .env:
  LLM_PROVIDER=ollama          # or "gemini"
  GEMINI_API_KEY=...           # only needed if LLM_PROVIDER=gemini
  GEMINI_MODEL=gemini-3.5-flash-lite       # only needed if overriding the default
  OLLAMA_BASE_URL=http://localhost:11434   # only needed if LLM_PROVIDER=ollama, and only if not using the default
  OLLAMA_MODEL=llama3.1                    # only needed if LLM_PROVIDER=ollama, and only if not using the default
"""

import asyncio
import json
import os
import re
from html.parser import HTMLParser

import httpx

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_MODEL = "gemini-3.5-flash-lite"  # see docstring above re: how fast this goes stale

OLLAMA_BASE_URL_DEFAULT = "http://localhost:11434"
OLLAMA_MODEL_DEFAULT = "llama3.1"

REQUEST_TIMEOUT = 20.0
MAX_CONTENT_CHARS = 6000  # caps page text sent, bounds cost/latency per scan


# ── Minimal HTML text extraction (no BeautifulSoup dependency) ──────────────

class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.chunks: list[str] = []
        self.has_password_field = False
        self.form_count = 0
        self._skip_tags = {"script", "style", "noscript"}
        self._current_skip = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag in self._skip_tags:
            self._current_skip = True
        if tag == "form":
            self.form_count += 1
        if tag == "input" and attrs_dict.get("type", "").lower() == "password":
            self.has_password_field = True

    def handle_endtag(self, tag):
        if tag in self._skip_tags:
            self._current_skip = False

    def handle_data(self, data):
        if not self._current_skip:
            text = data.strip()
            if text:
                self.chunks.append(text)

    def get_text(self) -> str:
        return " ".join(self.chunks)


async def _fetch_page_content(url: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
        if resp.status_code != 200:
            return {"available": False, "reason": f"HTTP {resp.status_code}"}
        parser = _TextExtractor()
        parser.feed(resp.text)
        text = parser.get_text()[:MAX_CONTENT_CHARS]
        return {
            "available": True,
            "text": text,
            "has_password_field": parser.has_password_field,
            "form_count": parser.form_count,
            "final_url": str(resp.url),
        }
    except httpx.TimeoutException:
        return {"available": False, "reason": "timeout"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


# ── LLM analysis ─────────────────────────────────────────────────────────────

LLM_SYSTEM_PROMPT = """You are a phishing content analyst. You will be given \
the extracted visible text of a webpage, the domain it was found on, and \
whether the page contains a password input field. Assess whether the \
content shows phishing-style patterns:

- Urgency or fear language ("account suspended", "verify immediately", "unusual activity")
- Requests for credentials, payment info, or personal data
- Claims to represent a brand/company that does NOT match the actual domain
- Generic or inconsistent branding inconsistent with a real company site

Respond with ONLY a JSON object, no other text, in this exact shape:
{"phishing_language_detected": true/false, "urgency_language": true/false, \
"credential_request": true/false, "claimed_brand": "string or null", \
"brand_mismatch": true/false, "confidence": "low"/"medium"/"high", \
"explanation": "one sentence"}
"""


RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 1.0


async def _call_with_retries(call_fn, user_content: str, client: httpx.AsyncClient) -> dict:
    """
    Retries a provider call on transient failures (429/5xx HTTP status,
    timeouts) with exponential backoff (1s, 2s, 4s). Does NOT retry on
    permanent-looking failures (missing API key, malformed response) -
    no point burning retries on something a delay won't fix.
    """
    last_result = None
    for attempt in range(1, MAX_RETRIES + 1):
        result = await call_fn(user_content, client)
        if result.get("available"):
            return result

        last_result = result
        is_retryable = (
            result.get("status_code") in RETRYABLE_STATUS_CODES
            or "timeout" in str(result.get("reason", "")).lower()
        )
        if not is_retryable or attempt == MAX_RETRIES:
            break

        backoff = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
        await asyncio.sleep(backoff)

    return last_result


async def analyze_content(url: str, client: httpx.AsyncClient) -> dict:
    """
    Fetches page content and asks an LLM (Gemini API or local Ollama,
    depending on LLM_PROVIDER) to assess it for phishing-style language and
    brand-impersonation patterns. Never raises - failures degrade to
    {"available": False, ...} so a slow/broken fetch or LLM call doesn't
    take down the whole scan.

    Resilience: retries the primary provider up to MAX_RETRIES times on
    transient errors (429/5xx, timeouts) with exponential backoff. If the
    primary provider still fails after retries, falls back to the OTHER
    configured provider (Gemini <-> Ollama) rather than giving up outright
    - set LLM_FALLBACK_ENABLED=false to disable this and fail fast instead.
    When fallback is used, the result includes "fallback_used": true and
    "primary_provider_failed" so it's visible which provider actually
    served the analysis, rather than silently masking the switch.
    """
    page = await _fetch_page_content(url, client)
    if not page.get("available"):
        return {"available": False, "reason": f"page fetch failed: {page.get('reason')}"}
    if not page["text"]:
        return {"available": False, "reason": "no extractable text content"}

    domain = url.split("://", 1)[-1].split("/", 1)[0]
    user_content = (
        f"Domain: {domain}\n"
        f"Has password field: {page['has_password_field']}\n"
        f"Form count: {page['form_count']}\n\n"
        f"Page text:\n{page['text']}"
    )

    primary = os.getenv("LLM_PROVIDER", "gemini").strip().lower()
    call_fns = {"gemini": _call_gemini, "ollama": _call_ollama}
    fallback = "ollama" if primary == "gemini" else "gemini"

    raw_result = await _call_with_retries(call_fns[primary], user_content, client)
    used_provider = primary

    if not raw_result.get("available"):
        fallback_enabled = os.getenv("LLM_FALLBACK_ENABLED", "true").strip().lower() == "true"
        if fallback_enabled:
            primary_failure_reason = raw_result.get("reason")
            fallback_result = await _call_with_retries(call_fns[fallback], user_content, client)
            if fallback_result.get("available"):
                raw_result = fallback_result
                used_provider = fallback
                raw_result["fallback_used"] = True
                raw_result["primary_provider_failed"] = primary
                raw_result["primary_failure_reason"] = primary_failure_reason
            else:
                # Both providers failed - surface the primary's failure
                # reason since that's the one actually configured/intended.
                return {
                    "available": False,
                    "reason": f"primary ({primary}) failed: {primary_failure_reason}; "
                              f"fallback ({fallback}) also failed: {fallback_result.get('reason')}",
                }
        else:
            return raw_result  # already in {"available": False, "reason": ...} shape

    try:
        raw_text = raw_result["raw_text"]
        # Strip markdown code fences in case the model wraps the JSON anyway
        raw_text = re.sub(r"^```(?:json)?|```$", "", raw_text, flags=re.MULTILINE).strip()
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return {
            "available": False,
            "reason": f"could not parse LLM response as JSON: {raw_result['raw_text'][:200]!r}",
        }

    parsed["available"] = True
    parsed["provider"] = used_provider
    if raw_result.get("fallback_used"):
        parsed["fallback_used"] = True
        parsed["primary_provider_failed"] = raw_result.get("primary_provider_failed")
        parsed["primary_failure_reason"] = raw_result.get("primary_failure_reason")
    parsed["has_password_field"] = page["has_password_field"]
    parsed["form_count"] = page["form_count"]
    parsed["final_url"] = page["final_url"]
    return parsed


async def _call_gemini(user_content: str, client: httpx.AsyncClient) -> dict:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "GEMINI_API_KEY not set"}

    model = os.getenv("GEMINI_MODEL", GEMINI_MODEL)
    url = f"{GEMINI_API_URL}/{model}:generateContent?key={api_key}"

    try:
        resp = await client.post(
            url,
            json={
                # Gemini has no separate "system" field in this endpoint
                # shape - prepend the system prompt to the first user turn.
                "contents": [
                    {"role": "user", "parts": [{"text": f"{LLM_SYSTEM_PROMPT}\n\n{user_content}"}]}
                ],
                "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": 300,
                    "responseMimeType": "application/json",  # nudges Gemini to emit clean JSON
                },
            },
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return {
                "available": False,
                "reason": f"HTTP {resp.status_code} from Gemini API: {resp.text[:200]}",
                "status_code": resp.status_code,
            }

        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return {"available": False, "reason": "Gemini returned no candidates (possibly safety-filtered)"}

        parts = candidates[0].get("content", {}).get("parts", [])
        raw_text = "".join(p.get("text", "") for p in parts).strip()
        if not raw_text:
            return {"available": False, "reason": "empty response from Gemini"}
        return {"available": True, "raw_text": raw_text}

    except httpx.TimeoutException:
        return {"available": False, "reason": "timeout"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


async def _call_ollama(user_content: str, client: httpx.AsyncClient) -> dict:
    base_url = os.getenv("OLLAMA_BASE_URL", OLLAMA_BASE_URL_DEFAULT).rstrip("/")
    model = os.getenv("OLLAMA_MODEL", OLLAMA_MODEL_DEFAULT)

    try:
        resp = await client.post(
            f"{base_url}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": LLM_SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                "stream": False,
                # Nudges most local models toward emitting clean JSON.
                # Ollama's "format": "json" constrains output to valid JSON
                # on models that support it - harmless no-op otherwise.
                "format": "json",
                "options": {"temperature": 0.1},
            },
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return {
                "available": False,
                "reason": f"HTTP {resp.status_code} from Ollama at {base_url} "
                          f"(is `ollama serve` running and is '{model}' pulled?)",
                "status_code": resp.status_code,
            }

        data = resp.json()
        raw_text = data.get("message", {}).get("content", "").strip()
        if not raw_text:
            return {"available": False, "reason": "empty response from Ollama"}
        return {"available": True, "raw_text": raw_text}

    except httpx.ConnectError:
        return {
            "available": False,
            "reason": f"could not connect to Ollama at {base_url} - is it running? (`ollama serve`)",
        }
    except httpx.TimeoutException:
        return {"available": False, "reason": "timeout"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def content_risk_signals(result: dict) -> list[str]:
    if not result.get("available"):
        return []
    signals = []
    if result.get("credential_request") and result.get("has_password_field"):
        signals.append(
            "Page requests credentials via a password field alongside "
            "credential-request language"
        )
    elif result.get("credential_request"):
        signals.append("Page content requests credentials or personal/payment data")
    if result.get("urgency_language"):
        signals.append(
            "Page uses urgency/fear language (e.g. account suspension, verify immediately)"
        )
    if result.get("brand_mismatch") and result.get("claimed_brand"):
        signals.append(
            f"Page claims to represent '{result['claimed_brand']}' but domain does not match that brand"
        )
    return signals