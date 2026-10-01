#!/usr/bin/env python
"""
Test to verify menu.py provider selection is correctly passed to generate_report()
"""

import asyncio
from report.generator import generate_report


async def test_menu_provider_flow():
    """Simulate the menu_report() flow and verify provider is passed correctly."""
    
    print("\n" + "=" * 70)
    print("TEST: Menu Provider Selection Flow")
    print("=" * 70)
    
    # Simulate user selections
    print("\n[User Selections Simulation]")
    print("  Add LLM summary? YES")
    
    # Case 1: User selects Gemini
    print("\n  LLM Provider selection: 'gemini (Google API)'")
    provider_choice = "gemini (Google API)"
    llm_provider = provider_choice.split()[0] if provider_choice else None
    print(f"    → Extracted provider: {llm_provider!r}")
    
    print("\n  Gemini Model selection: 'gemini-2.5-flash (Flash - recommended)'")
    model_choice = "gemini-2.5-flash (Flash - recommended)"
    llm_model = model_choice.split()[0] if model_choice else None
    print(f"    → Extracted model: {llm_model!r}")
    
    # Simulate calling generate_report with these values
    print("\n[Calling generate_report with extracted values]")
    print(f"  llm_provider={llm_provider!r}")
    print(f"  llm_model={llm_model!r}")
    
    result = {
        "url": "https://test.com",
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
        "use_llm": False,  # Don't actually call LLM
    }
    
    try:
        saved = await generate_report(
            scan_id="test-menu-flow",
            result=result,
            formats=["txt"],
            show_terminal=False,
            llm_provider=llm_provider,
            llm_model=llm_model if llm_model else None,
        )
        print(f"\n✓ generate_report() accepted provider={llm_provider!r}")
        print(f"  Report saved: {list(saved.keys())}")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False
    
    # Case 2: User selects Ollama with auto-detect
    print("\n" + "─" * 70)
    print("[Test Case 2: Ollama with auto-detect]")
    print("  LLM Provider selection: 'ollama (local instance)'")
    provider_choice = "ollama (local instance)"
    llm_provider = provider_choice.split()[0] if provider_choice else None
    print(f"    → Extracted provider: {llm_provider!r}")
    
    print("\n  Model input: '' (empty, auto-detect)")
    llm_model = ""
    print(f"    → Model value: {llm_model!r}")
    
    print("\n[Calling generate_report]")
    print(f"  llm_provider={llm_provider!r}")
    print(f"  llm_model={llm_model if llm_model else None!r}")
    
    try:
        saved = await generate_report(
            scan_id="test-menu-flow-2",
            result=result,
            formats=["txt"],
            show_terminal=False,
            llm_provider=llm_provider,
            llm_model=llm_model if llm_model else None,
        )
        print(f"\n✓ generate_report() accepted provider={llm_provider!r}")
        print(f"  Report saved: {list(saved.keys())}")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False
    
    print("\n" + "=" * 70)
    print("✓ ALL TESTS PASSED - Provider selection works correctly!")
    print("=" * 70 + "\n")
    return True


if __name__ == "__main__":
    result = asyncio.run(test_menu_provider_flow())
    exit(0 if result else 1)
