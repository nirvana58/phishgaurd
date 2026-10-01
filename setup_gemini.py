#!/usr/bin/env python
"""
Setup and test script for GEMINI_API_KEY configuration.
Shows users how to properly set up Gemini provider.
"""

import os
import sys
import asyncio


def check_gemini_setup():
    """Check if Gemini is properly configured."""
    print("\n" + "=" * 70)
    print("GEMINI SETUP CHECK")
    print("=" * 70)
    
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    
    print("\n1. Check environment variable:")
    key_display = api_key if api_key else "NOT SET"
    print(f"   GEMINI_API_KEY: {key_display!r}")
    google_key = os.getenv('GOOGLE_API_KEY')
    google_display = google_key if google_key else "NOT SET"
    print(f"   GOOGLE_API_KEY: {google_display!r}")
    
    if api_key:
        print(f"\n   ✓ API key is set: {api_key[:10]}...{api_key[-5:]}")
        return True
    else:
        print("\n   ✗ API key NOT set")
        print("\n   HOW TO SET IT:")
        print("   " + "─" * 66)
        print("   PowerShell (for this session only):")
        print("     $env:GEMINI_API_KEY = 'your-actual-api-key-here'")
        print("     # Then run the menu in the SAME terminal")
        print("\n   PowerShell (permanent - requires admin):")
        print("     [Environment]::SetEnvironmentVariable('GEMINI_API_KEY', 'your-key', 'User')")
        print("   " + "─" * 66)
        print("\n   GET YOUR API KEY:")
        print("   1. Go to: https://aistudio.google.com/apikey")
        print("   2. Create a new API key")
        print("   3. Copy the key value")
        print("   4. Set the environment variable (see above)")
        print("   5. RESTART the menu or terminal window")
        return False


async def test_gemini_provider():
    """Test if Gemini provider works with current settings."""
    print("\n" + "=" * 70)
    print("GEMINI PROVIDER TEST")
    print("=" * 70)
    
    from report.generator import (
        _gemini_api_key,
        _normalize_llm_provider,
        _resolve_llm_model,
    )
    
    api_key = _gemini_api_key()
    api_key_display = api_key if api_key else "EMPTY"
    print(f"\n1. _gemini_api_key() = {api_key_display!r}")
    
    if not api_key:
        print("   ✗ No API key available to the Python process")
        print("   → Check that you set the env var BEFORE starting Python")
        return False
    
    provider = _normalize_llm_provider("gemini")
    print(f"\n2. _normalize_llm_provider('gemini') = {provider!r}")
    
    p, m = await _resolve_llm_model("gemini", "gemini-2.5-flash")
    print(f"\n3. _resolve_llm_model('gemini', 'gemini-2.5-flash'):")
    print(f"   provider = {p!r}")
    print(f"   model = {m!r}")
    
    if p == "gemini" and m:
        print("\n   ✓ Gemini provider is ready!")
        return True
    else:
        print("\n   ✗ Gemini provider resolution failed")
        return False


async def main():
    setup_ok = check_gemini_setup()
    
    if setup_ok:
        provider_ok = await test_gemini_provider()
        
        if provider_ok:
            print("\n" + "=" * 70)
            print("✓ GEMINI SETUP COMPLETE AND WORKING")
            print("=" * 70)
            print("\nYou can now:")
            print("  1. Run the interactive menu: python -m cli.menu")
            print("  2. Select 'Generate Report'")
            print("  3. Answer 'Yes' to 'Add LLM summary?'")
            print("  4. Select 'gemini (Google API)' as the provider")
            print("  5. Choose your preferred Gemini model")
            print("\n" + "=" * 70 + "\n")
        else:
            print("\n" + "=" * 70)
            print("✗ GEMINI PROVIDER NOT WORKING")
            print("=" * 70)
            print("\nTroubleshooting:")
            print("  • Make sure GEMINI_API_KEY is set in the SAME terminal")
            print("  • The env var must be set BEFORE running Python")
            print("  • Try: $env:GEMINI_API_KEY = 'your-key'")
            print("  • Then: python -m cli.menu")
            print("\n" + "=" * 70 + "\n")
    else:
        print("\n" + "=" * 70)
        print("SETUP REQUIRED")
        print("=" * 70)
        print("\nNext steps:")
        print("  1. Get an API key from https://aistudio.google.com/apikey")
        print("  2. Set the environment variable in PowerShell:")
        print("     $env:GEMINI_API_KEY = 'your-api-key'")
        print("  3. Run this script again to verify:")
        print("     python setup_gemini.py")
        print("  4. Then run the menu:")
        print("     python -m cli.menu")
        print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
