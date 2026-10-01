#!/usr/bin/env python
"""
Test script to demonstrate LLM provider selection in report generation.
Shows how Gemini vs Ollama selection works.
"""

import os
import asyncio
from report.generator import (
    _normalize_llm_provider,
    _resolve_llm_model,
    generate_report,
)


async def test_provider_normalization():
    """Test provider alias handling."""
    print("\n=== Provider Normalization ===")
    test_cases = [
        ("ollama", "ollama"),
        ("Ollama", "ollama"),
        ("gemini", "gemini"),
        ("google", "gemini"),
        ("Gemini", "gemini"),
        ("GoogleGemini", "gemini"),
        (None, "ollama"),  # defaults to ollama
    ]
    for input_val, expected in test_cases:
        result = _normalize_llm_provider(input_val)
        status = "✓" if result == expected else "✗"
        print(f"  {status} _normalize_llm_provider({input_val!r}) → {result!r}")


async def test_provider_resolution():
    """Test how provider + model gets resolved."""
    print("\n=== Provider Resolution ===")
    
    # Test 1: Gemini without API key (falls back gracefully)
    print("\n  Test 1: Gemini (no GEMINI_API_KEY set)")
    os.environ.pop("GEMINI_API_KEY", None)
    provider, model = await _resolve_llm_model("gemini", "gemini-2.5-flash")
    print(f"    Result: provider={provider}, model={model}")
    
    # Test 2: Gemini with API key
    print("\n  Test 2: Gemini (with GEMINI_API_KEY)")
    os.environ["GEMINI_API_KEY"] = "test-key"
    provider, model = await _resolve_llm_model("gemini", "gemini-2.5-flash")
    print(f"    Result: provider={provider}, model={model}")
    
    # Test 3: Ollama
    print("\n  Test 3: Ollama (no server running, will fail gracefully)")
    os.environ.pop("GEMINI_API_KEY", None)
    provider, model = await _resolve_llm_model("ollama", None)
    print(f"    Result: provider={provider}, model={model}")


async def test_report_generation():
    """Test report generation with explicit provider selection."""
    print("\n=== Report Generation with Provider Selection ===")
    
    # Minimal result dict
    result = {
        "url": "https://example.com",
        "scanned_at": "2026-08-30",
        "verdict": {"verdict": "SAFE", "confidence": "HIGH", "reasons": []},
        "ml": {
            "available": False,
            "combined_score": 0.0,
            "kmeans": {"anomaly_score": 0.0},
            "som": {"anomaly_score": 0.0},
            "models_agree": False,
            "model_version": "none",
        },
        "virustotal": {"available": False, "malicious": 0, "suspicious": 0, "harmless": 0},
        "safe_browsing": {"available": False, "is_threat": False, "threat_types": []},
        "features": {},
        "use_llm": False,  # Not calling LLM in this test
    }
    
    print("\n  Test 1: Report with Gemini provider (no LLM call)")
    saved = await generate_report(
        scan_id="test-gemini",
        result=result,
        formats=["txt"],
        show_terminal=False,
        llm_provider="gemini",
        llm_model="gemini-2.5-flash",
    )
    print(f"    ✓ Report saved: {list(saved.keys())}")
    
    print("\n  Test 2: Report with Ollama provider (no LLM call)")
    saved = await generate_report(
        scan_id="test-ollama",
        result=result,
        formats=["txt"],
        show_terminal=False,
        llm_provider="ollama",
        llm_model="llama3",
    )
    print(f"    ✓ Report saved: {list(saved.keys())}")


async def main():
    print("\n" + "=" * 60)
    print("LLM PROVIDER SELECTION TEST")
    print("=" * 60)
    
    await test_provider_normalization()
    await test_provider_resolution()
    await test_report_generation()
    
    print("\n" + "=" * 60)
    print("USAGE EXAMPLES")
    print("=" * 60)
    print("""
# Use Gemini provider:
  export GEMINI_API_KEY=your-actual-api-key
  python -m cli.client scan https://example.com --llm --llm-provider gemini --llm-model gemini-2.5-flash

# Use Ollama provider:
  python -m cli.client scan https://example.com --llm --llm-provider ollama --llm-model llama3

# Use default (reads REPORT_LLM_PROVIDER/LLM_PROVIDER env, defaults to ollama):
  python -m cli.client scan https://example.com --llm

# Regenerate report with different provider:
  python -m cli.client report <scan_id> --llm --llm-provider gemini --llm-model gemini-2.5-flash-lite
""")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
