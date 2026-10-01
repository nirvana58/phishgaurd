#!/usr/bin/env python
"""
Demo script showing the interactive menu flow for LLM provider selection.
This shows what users will see when they select "Generate Report" from the menu.
"""

import asyncio


async def demo_menu_flow():
    """Simulate the interactive menu_report() flow."""
    
    print("\n" + "=" * 70)
    print("INTERACTIVE MENU: Generate Report")
    print("=" * 70)
    
    print("\n[User prompt 1]")
    print("? Scan ID:")
    print("  > abc-123-def-456")
    
    print("\n[User prompt 2]")
    print("? Report formats:")
    print("  ◉ md")
    print("  ◉ txt")
    print("  ◎ pdf")
    print("  ◎ docx")
    print("  (md, txt selected)")
    
    print("\n[User prompt 3]")
    print("? Add LLM summary? (y/N)")
    print("  > y")
    
    print("\n" + "─" * 70)
    print("NEW: Interactive provider selection (after user says yes to LLM):")
    print("─" * 70)
    
    print("\n[User prompt 4 - NEW FEATURE]")
    print("? LLM Provider:")
    print("  ◉ ollama (local Ollama instance)")
    print("  ◎ gemini (Google Gemini API)")
    print("  > ollama")
    
    print("\n[User prompt 5 - NEW FEATURE]")
    print("? Model name (or press Enter for auto-detect):")
    print("  > llama3")
    
    print("\n[Generating report...]")
    print("  Generating AI summary via ollama…")
    print("  Using model: llama3 (provider: ollama)")
    print("  Saved MD report → C:\\Users\\ASUS\\Documents\\pguardai\\reports\\abc-123-def-456.md")
    print("  Saved TXT report → C:\\Users\\ASUS\\Documents\\pguardai\\reports\\abc-123-def-456.txt")
    
    print("\n✓ Report saved:")
    print("  MD → C:\\Users\\ASUS\\Documents\\pguardai\\reports\\abc-123-def-456.md")
    print("  TXT → C:\\Users\\ASUS\\Documents\\pguardai\\reports\\abc-123-def-456.txt")
    
    print("\n" + "=" * 70)
    print("ALTERNATIVE FLOW: Gemini Provider")
    print("=" * 70)
    
    print("\n[User selects Gemini in prompt 4]")
    print("? LLM Provider:")
    print("  ◎ ollama (local Ollama instance)")
    print("  ◉ gemini (Google Gemini API)")
    print("  > gemini")
    
    print("\n[User prompt 5 - DIFFERENT OPTIONS for Gemini]")
    print("? Gemini Model:")
    print("  ◉ gemini-2.5-flash (Flash - recommended)")
    print("  ◎ gemini-2.5-flash-lite (Flash Lite - faster)")
    print("  > gemini-2.5-flash")
    
    print("\n[Generating report...]")
    print("  Generating AI summary via gemini…")
    print("  Using model: gemini-2.5-flash (provider: gemini)")
    print("  Saved MD report → C:\\Users\\ASUS\\Documents\\pguardai\\reports\\abc-123-def-456.md")
    print("  Saved TXT report → C:\\Users\\ASUS\\Documents\\pguardai\\reports\\abc-123-def-456.txt")
    
    print("\n✓ Report saved:")
    print("  MD → C:\\Users\\ASUS\\Documents\\pguardai\\reports\\abc-123-def-456.md")
    print("  TXT → C:\\Users\\ASUS\\Documents\\pguardai\\reports\\abc-123-def-456.txt")
    
    print("\n" + "=" * 70)
    print("CODE CHANGES IN cli/menu.py")
    print("=" * 70)
    print("""
The menu_report() function now includes:

1. After user answers "Add LLM summary?", if YES:
   - Prompt: "LLM Provider:" with choices
     • ollama (local Ollama instance)
     • gemini (Google Gemini API)
   
2. Based on provider selection:
   
   If OLLAMA:
   - Prompt: "Model name (or press Enter for auto-detect):"
   - User can type any model name or leave blank for auto-detect
   
   If GEMINI:
   - Prompt: "Gemini Model:" with preset choices
     • gemini-2.5-flash (recommended)
     • gemini-2.5-flash-lite (faster)

3. Pass selected values to generate_report():
   - llm_provider="ollama"|"gemini"
   - llm_model="llama3"|"gemini-2.5-flash"|etc

The provider and model selections are then used to:
- Resolve the correct LLM backend
- Validate API keys (e.g., GEMINI_API_KEY for Gemini)
- Generate the summary with the selected provider
- Gracefully fall back if provider unavailable
""")
    
    print("\n" + "=" * 70)
    print("CONFIGURATION")
    print("=" * 70)
    print("""
For Gemini to work:
  export GEMINI_API_KEY=your-actual-api-key  (Windows: $env:GEMINI_API_KEY=...)
  Get key from: https://aistudio.google.com/apikey

For Ollama:
  Make sure Ollama is running
  Pull a model: ollama pull llama3
  Set model (optional): export OLLAMA_MODEL=llama3
  Or leave blank to auto-detect first available
""")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(demo_menu_flow())
