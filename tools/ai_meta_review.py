#!/usr/bin/env python3
"""
tools/ai_meta_review.py

Standalone "second opinion" tool. Takes a SAVED JSON scan report (produced
by report/generator.py's JSON output format) and asks an LLM to read the
full report - every signal at once - and provide FREEFORM commentary
flagging anything worth a second look.

WHY THIS EXISTS: several false positives during development (frameley.com,
google.com) were only caught by manually reading the ENTIRE scan report at
once and noticing signals that contradicted each other or a verdict whose
stated reasons didn't actually hold up. This tool automates that "read
everything together and sanity-check it" step - it's what a human analyst
does when reviewing a flagged scan, not another detection layer.

DELIBERATE DESIGN CHOICES (test-phase, may change later):
  - FREEFORM output, not structured JSON - easier to read, and this tool
    isn't trying to be machine-parsed or compared field-by-field yet.
  - COMMENTARY ONLY, no independent verdict/label - this is meant to
    prompt a human to look closer, not to produce a competing SAFE /
    SUSPICIOUS / MALICIOUS call that would need its own accuracy tracking.
  - SINGLE REPORT at a time - no batch mode yet.
  - NOT wired into scanner.py, _compute_verdict(), or any live pipeline.
    Fully standalone: you run it manually against a report you already
    saved. Nothing here can affect a live scan's outcome.
  - Self-contained provider calls (does NOT import from
    core/llm_content_check.py) - that module's Gemini/Ollama callers are
    tailored to its own structured-JSON, 300-token phishing-content-check
    use case (hardcoded system prompt, forced JSON mime type). Reusing
    them here would mean this tool's behavior silently shifts if that
    module's prompt/limits change later. Kept deliberately separate.

Usage:
    python tools/ai_meta_review.py path/to/scan_report.json

Config (shared naming with the rest of the project, separate values):
    LLM_PROVIDER=gemini          # or "ollama" - default: gemini
    GEMINI_API_KEY=...
    GEMINI_MODEL=gemini-3.5-flash-lite        # default
    OLLAMA_BASE_URL=http://localhost:11434
    OLLAMA_MODEL=llama3.1
    LLM_FALLBACK_ENABLED=true    # fall back to the other provider on failure
"""


from dotenv import load_dotenv


load_dotenv()

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx

LLM_PROVIDER = os.getenv("LLM_PROVIDER") or "gemini"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL") or "gemini-3.5-flash-lite"
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL") or "llama3.1"
LLM_FALLBACK_ENABLED = os.getenv("LLM_FALLBACK_ENABLED", "false").lower() == "true"

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_MODEL_DEFAULT = "gemini-3.5-flash-lite"

OLLAMA_BASE_URL_DEFAULT = "http://localhost:11434"
OLLAMA_MODEL_DEFAULT = "llama3.1"

REQUEST_TIMEOUT = 45.0          # freeform commentary takes longer to generate than a 300-token JSON reply
MAX_OUTPUT_TOKENS = 1024
MAX_REPORT_JSON_CHARS = 12000   # safety cap - truncate an unusually large report rather than blow the context

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 1.0


REVIEW_PROMPT_TEMPLATE = """You are a senior security analyst doing a second-opinion \
review of an automated phishing-detection scan. Below is the FULL JSON result from \
the scan - every signal the system collected: ML anomaly scores, WHOIS, SSL, \
homograph/typosquat checks, VirusTotal, Google Safe Browsing, LLM content analysis \
(if present), sandbox detonation (if present), and the automated verdict with its \
stated reasons.

Read everything together and flag anything worth a human double-checking:
- Signals that contradict each other
- A verdict whose stated reasons don't actually seem to hold up given the full context
- Anything that looks like it could be a false positive OR a false negative
- Anything unusual you notice that the automated reasons didn't mention

Do NOT assign your own verdict or label (SAFE / SUSPICIOUS / MALICIOUS). This is \
commentary only, meant to prompt a human to look closer - not to replace or \
re-derive the automated decision. If nothing looks off, say so plainly and briefly \
rather than manufacturing concerns to fill space.

SCAN REPORT:
{report_json}
"""


def _load_report(report_path: str) -> dict | None:
    path = Path(report_path)
    if not path.exists():
        print(f"File not found: {report_path}")
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Could not parse {report_path} as JSON: {e}")
        return None


def _build_prompt(report: dict) -> str:
    report_json = json.dumps(report, indent=2, default=str)
    if len(report_json) > MAX_REPORT_JSON_CHARS:
        report_json = report_json[:MAX_REPORT_JSON_CHARS] + "\n... (truncated, report was unusually large)"
    return REVIEW_PROMPT_TEMPLATE.format(report_json=report_json)


# ── Provider calls (self-contained - see module docstring for why) ──────────

async def _call_gemini(prompt: str, client: httpx.AsyncClient) -> dict:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "GEMINI_API_KEY not set"}

    model = os.getenv("GEMINI_MODEL", GEMINI_MODEL_DEFAULT)
    url = f"{GEMINI_API_URL}/{model}:generateContent?key={api_key}"

    try:
        resp = await client.post(
            url,
            json={
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.3,          # a little room for judgment, still fairly grounded
                    "maxOutputTokens": MAX_OUTPUT_TOKENS,
                    # NOTE: no responseMimeType here - freeform text, on purpose
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
        text = "".join(p.get("text", "") for p in parts).strip()
        if not text:
            return {"available": False, "reason": "empty response from Gemini"}
        return {"available": True, "raw_text": text}
    except httpx.TimeoutException:
        return {"available": False, "reason": "timeout"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


async def _call_ollama(prompt: str, client: httpx.AsyncClient) -> dict:
    base_url = os.getenv("OLLAMA_BASE_URL", OLLAMA_BASE_URL_DEFAULT).rstrip("/")
    model = os.getenv("OLLAMA_MODEL", OLLAMA_MODEL_DEFAULT)

    try:
        resp = await client.post(
            f"{base_url}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": MAX_OUTPUT_TOKENS},
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
        text = data.get("message", {}).get("content", "").strip()
        if not text:
            return {"available": False, "reason": "empty response from Ollama"}
        return {"available": True, "raw_text": text}
    except httpx.ConnectError:
        return {
            "available": False,
            "reason": f"could not connect to Ollama at {base_url} - is it running? (`ollama serve`)",
        }
    except httpx.TimeoutException:
        return {"available": False, "reason": "timeout"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


async def _call_with_retries(call_fn, prompt: str, client: httpx.AsyncClient) -> dict:
    """Retries a provider call on transient failures (429/5xx, timeouts) with
    exponential backoff (1s, 2s, 4s). Skips retries on permanent-looking
    failures (missing key, malformed response) - no delay fixes those."""
    last_result = None
    for attempt in range(1, MAX_RETRIES + 1):
        result = await call_fn(prompt, client)
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
        print(f"  transient failure ({result.get('reason')}) - retrying in {backoff:.0f}s… "
              f"(attempt {attempt + 1}/{MAX_RETRIES})")
        await asyncio.sleep(backoff)
    return last_result


# ── Main entry point ─────────────────────────────────────────────────────────

async def review_report(report_path: str) -> str | None:
    report = _load_report(report_path)
    if report is None:
        return None

    prompt = _build_prompt(report)

    primary = os.getenv("LLM_PROVIDER", "gemini").strip().lower()
    call_fns = {"gemini": _call_gemini, "ollama": _call_ollama}
    fallback = "ollama" if primary == "gemini" else "gemini"

    async with httpx.AsyncClient() as client:
        result = await _call_with_retries(call_fns[primary], prompt, client)
        used_provider = primary

        if not result.get("available"):
            fallback_enabled = os.getenv("LLM_FALLBACK_ENABLED", "true").strip().lower() == "true"
            if fallback_enabled:
                print(f"  {primary} unavailable ({result.get('reason')}) - trying {fallback}…")
                result = await _call_with_retries(call_fns[fallback], prompt, client)
                used_provider = fallback

    if not result.get("available"):
        print(f"Both providers failed. Last error: {result.get('reason')}")
        return None

    print(f"(reviewed via {used_provider})\n{'=' * 70}\n")
    return result["raw_text"]


async def main():
    if len(sys.argv) != 2:
        print("Usage: python tools/ai_meta_review.py path/to/scan_report.json")
        sys.exit(1)

    commentary = await review_report(sys.argv[1])
    if commentary:
        print(commentary)
    else:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
