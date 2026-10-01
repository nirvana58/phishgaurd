#!/usr/bin/env python3
"""
test_sandbox.py

Standalone smoke test for core/url_sandbox.py — run this on your own
machine (needs Docker installed and the sandbox image built), NOT in a
restricted sandbox/CI environment without Docker access.

Setup before running:
    docker build -t phishguard-sandbox sandbox/
    python test_sandbox.py

What this checks, in order of increasing complexity:
  1. Plumbing sanity  - does the container run at all and write result.json?
  2. Clean site        - a real, boring page (example.com) - should detonate
                          cleanly with no risk signals.
  3. Same-origin login  - a real login form (github.com/login) - HAS a
                          password field, but same-origin, so it should
                          NOT trigger has_cross_origin_password_form.
  4. Timeout handling   - an intentionally slow/unreachable URL, to confirm
                          the timeout kill path works and doesn't hang.

This does not test true cross-origin credential exfiltration (that needs
a purpose-built two-domain test page) - it's a plumbing/sanity test, not
a full red-team validation of the detection logic itself.
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import url_sandbox as sandbox


def _print_result(label: str, result: dict):
    print(f"\n{'=' * 70}")
    print(f"TEST: {label}")
    print("=" * 70)
    print(json.dumps({k: v for k, v in result.items() if k != "screenshot_path"}, indent=2, default=str))
    if result.get("screenshot_path"):
        print(f"\nScreenshot: {result['screenshot_path']}")
    signals = sandbox.sandbox_risk_signals(result)
    print(f"\nRisk signals: {signals if signals else '(none)'}")


async def test_plumbing():
    """Most basic check: does the container run and produce output at all?"""
    result = await sandbox.detonate_url("https://example.com")
    _print_result("Plumbing sanity (example.com)", result)

    assert result.get("available") is True, (
        "Container did not report available=True — check `docker build` succeeded "
        "and DOCKER_IMAGE env var / SANDBOX_DOCKER_IMAGE matches your built tag"
    )
    assert result.get("screenshot_path") is not None, "Screenshot was not captured"
    print("\n✅ PASS: plumbing works, container ran and wrote output")


async def test_clean_site():
    result = await sandbox.detonate_url("https://example.com")
    signals = sandbox.sandbox_risk_signals(result)
    _print_result("Clean site (example.com)", result)

    assert not result.get("has_cross_origin_password_form"), "False positive: example.com has no forms"
    assert not result.get("download_attempted"), "False positive: example.com shouldn't trigger a download"
    assert len(signals) == 0, f"Expected zero risk signals for a clean site, got: {signals}"
    print("\n✅ PASS: clean site produced zero risk signals")


async def test_same_origin_login_form():
    """A real login form that IS same-origin — should NOT be flagged as
    cross-origin credential exfiltration, since it isn't."""
    result = await sandbox.detonate_url("https://github.com/login")
    _print_result("Same-origin login form (github.com/login)", result)

    if not result.get("available"):
        print(f"\n⚠️  SKIP: could not reach github.com/login ({result.get('reason')}) — "
              "not a sandbox failure, just a network/site issue")
        return

    assert result.get("num_password_fields", 0) >= 1, "Expected to find a password field on the login page"
    assert not result.get("has_cross_origin_password_form"), (
        "FALSE POSITIVE: github.com's own login form should not be flagged as "
        "cross-origin — check the _registrable_domain() comparison logic"
    )
    print("\n✅ PASS: same-origin password field correctly NOT flagged")


async def test_timeout_handling():
    """Confirm a hung/unreachable target doesn't block indefinitely."""
    # 10.255.255.1 is a non-routable address that will hang rather than
    # fail fast, good for testing the timeout-kill path specifically.
    original_timeout = sandbox.CONTAINER_TIMEOUT_SECONDS
    sandbox.CONTAINER_TIMEOUT_SECONDS = 8  # shrink for a faster test run
    try:
        result = await sandbox.detonate_url("http://10.255.255.1/")
        _print_result("Timeout handling (unreachable host)", result)
        assert result.get("available") is False, "Expected unavailable result for an unreachable host"
        print("\n✅ PASS: unreachable/hung target handled without blocking forever")
    finally:
        sandbox.CONTAINER_TIMEOUT_SECONDS = original_timeout


async def main():
    print("PhishGuard URL Sandbox — smoke test")
    print(f"Docker image: {sandbox.DOCKER_IMAGE}")
    print(f"Container timeout: {sandbox.CONTAINER_TIMEOUT_SECONDS}s")

    tests = [
        ("Plumbing sanity", test_plumbing),
        ("Clean site", test_clean_site),
        ("Same-origin login form", test_same_origin_login_form),
        ("Timeout handling", test_timeout_handling),
    ]

    failures = []
    for name, test_fn in tests:
        try:
            await test_fn()
        except AssertionError as e:
            print(f"\n❌ FAIL: {name} — {e}")
            failures.append(name)
        except Exception as e:
            print(f"\n💥 ERROR: {name} — unexpected exception: {e}")
            failures.append(name)

    print(f"\n{'=' * 70}")
    if failures:
        print(f"RESULT: {len(failures)}/{len(tests)} test(s) failed: {', '.join(failures)}")
        sys.exit(1)
    else:
        print(f"RESULT: all {len(tests)} tests passed")


if __name__ == "__main__":
    asyncio.run(main())
