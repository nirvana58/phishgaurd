import asyncio
import json

from report.generator import (
    _extract_ollama_response,
    _normalize_llm_provider,
    _resolve_llm_model,
    generate_report,
)


def test_extracts_message_content_from_chat_response():
    payload = {"message": {"content": "safe summary"}}
    assert _extract_ollama_response(payload) == "safe summary"


def test_falls_back_to_legacy_response_field():
    payload = {"response": "legacy summary"}
    assert _extract_ollama_response(payload) == "legacy summary"


def test_returns_none_for_missing_content():
    payload = {"done": True}
    assert _extract_ollama_response(payload) is None


def test_normalizes_supported_llm_provider_names():
    assert _normalize_llm_provider("ollama") == "ollama"
    assert _normalize_llm_provider("Ollama") == "ollama"
    assert _normalize_llm_provider("gemini") == "gemini"
    assert _normalize_llm_provider("google") == "gemini"


def test_resolves_gemini_default_model_from_env(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash-lite")
    assert _resolve_llm_model("gemini", None) == "gemini-2.5-flash-lite"


def test_resolves_flash_default_when_env_not_set(monkeypatch):
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    assert _resolve_llm_model("gemini", None) == "gemini-2.5-flash"


def test_generate_report_supports_json_format():
    result = {
        "url": "https://example.com",
        "scanned_at": "2024-01-01T00:00:00Z",
        "verdict": {"verdict": "SAFE", "confidence": "HIGH", "reasons": ["No issues found"]},
        "features": {"shannon_entropy": 3.5, "suspicious_tld": 0, "has_ip_host": 0},
    }

    async def _run():
        return await generate_report(
            scan_id="json-report-test",
            result=result,
            formats=["json"],
            show_terminal=False,
        )

    saved = asyncio.run(_run())
    assert "json" in saved
    assert saved["json"].suffix == ".json"
    payload = json.loads(saved["json"].read_text(encoding="utf-8"))
    assert payload["scan_id"] == "json-report-test"
    assert payload["url"] == "https://example.com"
