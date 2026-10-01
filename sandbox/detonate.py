"""
sandbox/detonate.py

Runs INSIDE the isolated Docker container — never on the host directly.
Visits a single URL in headless Chromium, captures a screenshot and a set
of behavioral signals, and writes the result as JSON.

This is the "detonation" step of URL sandboxing: rendering the page for
real (so JS-based redirects, cloaking, and dynamically-injected phishing
forms all execute) while everything the page could possibly do — write
files, spawn processes, read host data — is contained by the Docker
isolation the host sets up around this process (see core/url_sandbox.py
for the container flags).

Reads the target URL from the TARGET_URL environment variable.
Writes /output/result.json and /output/screenshot.png.

Never raises on a bad/malicious/unreachable page — always writes SOME
result.json (with "available": False and an error message on failure) so
the host side has something to read.
"""

import asyncio
import json
import os
import re
import time
from urllib.parse import urlparse

from playwright.async_api import async_playwright

NAV_TIMEOUT_MS = 15_000
OUTPUT_DIR = "/output"

# Known brand names to look for in page text/title — a page that visually
# claims to be one of these while living on a structurally unrelated
# domain (checked back on the host side via typosquat_distance) is a
# classic phishing pattern this sandbox is specifically built to catch.
BRAND_KEYWORDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "bank of america", "chase", "wells fargo",
    "linkedin", "github", "office 365", "outlook", "icloud",
]


def _registrable_domain(host: str) -> str:
    if not host:
        return ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def detonate(url: str) -> dict:
    t0 = time.time()
    result = {
        "available": False,
        "url": url,
        "final_url": None,
        "title": None,
        "error": None,
        "load_time_ms": None,
        "num_forms": 0,
        "num_password_fields": 0,
        "has_cross_origin_password_form": False,
        "num_iframes": 0,
        "num_external_scripts": 0,
        "download_attempted": False,
        "download_filename": None,
        "console_errors": [],
        "brand_keywords_found": [],
        "screenshot_available": False,
    }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",  # container itself is the sandbox boundary
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                ],
            )
            context = await browser.new_context(
                ignore_https_errors=True,  # still want to see cert-invalid pages
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()

            console_errors = []
            page.on(
                "console",
                lambda msg: console_errors.append(msg.text)
                if msg.type == "error"
                else None,
            )

            # Intercept downloads: record metadata, never save/execute the
            # file. An unsolicited download attempt on page load is itself
            # a strong phishing/malware signal.
            download_info = {"attempted": False, "filename": None}

            async def _on_download(download):
                download_info["attempted"] = True
                download_info["filename"] = download.suggested_filename
                try:
                    await download.cancel()
                except Exception:
                    pass

            page.on("download", lambda d: asyncio.create_task(_on_download(d)))

            try:
                await page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="load")
            except Exception as e:
                result["error"] = f"navigation failed: {e}"
                await browser.close()
                _write_result(result)
                return result

            # Let any JS-based redirect / dynamically injected content settle
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass  # fine if the page never goes idle (trackers, polling, etc.)

            result["final_url"] = page.url
            result["title"] = await page.title()
            result["load_time_ms"] = int((time.time() - t0) * 1000)
            result["console_errors"] = console_errors[:10]
            result["download_attempted"] = download_info["attempted"]
            result["download_filename"] = download_info["filename"]

            # Forms + password fields, and whether any password form posts
            # cross-origin relative to the page it's on.
            final_domain = _registrable_domain(urlparse(page.url).hostname or "")
            forms = await page.query_selector_all("form")
            result["num_forms"] = len(forms)
            cross_origin_pw_form = False
            pw_field_count = 0
            for form in forms:
                pw_inputs = await form.query_selector_all("input[type=password]")
                if pw_inputs:
                    pw_field_count += len(pw_inputs)
                    action = await form.get_attribute("action") or ""
                    if action.startswith("http"):
                        action_domain = _registrable_domain(urlparse(action).hostname or "")
                        if action_domain and action_domain != final_domain:
                            cross_origin_pw_form = True
            result["num_password_fields"] = pw_field_count
            result["has_cross_origin_password_form"] = cross_origin_pw_form

            iframes = await page.query_selector_all("iframe")
            result["num_iframes"] = len(iframes)

            scripts = await page.query_selector_all("script[src]")
            ext_scripts = 0
            for s in scripts:
                src = await s.get_attribute("src") or ""
                if src.startswith("http"):
                    src_domain = _registrable_domain(urlparse(src).hostname or "")
                    if src_domain and src_domain != final_domain:
                        ext_scripts += 1
            result["num_external_scripts"] = ext_scripts

            # Brand-keyword scan of title + visible body text
            try:
                body_text = (await page.inner_text("body"))[:4000].lower()
            except Exception:
                body_text = ""
            haystack = f"{(result['title'] or '').lower()} {body_text}"
            result["brand_keywords_found"] = [
                b for b in BRAND_KEYWORDS if b in haystack
            ]

            # Screenshot
            try:
                await page.screenshot(
                    path=os.path.join(OUTPUT_DIR, "screenshot.png"),
                    full_page=False,  # viewport only -- full_page can be huge/slow on long pages
                    timeout=8000,
                )
                result["screenshot_available"] = True
            except Exception as e:
                result["screenshot_available"] = False
                result["error"] = (result["error"] or "") + f" | screenshot failed: {e}"

            result["available"] = True
            await browser.close()

    except Exception as e:
        result["error"] = f"sandbox error: {e}"

    _write_result(result)
    return result


def _write_result(result: dict) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "result.json"), "w") as f:
        json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    target = os.environ.get("TARGET_URL", "").strip()
    if not target:
        _write_result({"available": False, "error": "TARGET_URL not set"})
        raise SystemExit(1)
    asyncio.run(detonate(target))
