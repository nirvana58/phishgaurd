"""
core/url_sandbox.py

Host-side orchestrator for sandbox/detonate.py. Runs a suspicious URL
inside the isolated Docker container defined by sandbox/Dockerfile,
enforces the actual security boundary via `docker run` flags (the image
alone is not the sandbox - see Dockerfile's top comment), and reads back
the result JSON + screenshot the container writes to its output volume.

Isolation model:
  - --read-only          container filesystem is read-only except the
                          explicit output volume mount
  - --cap-drop=ALL        strips all Linux capabilities
  - --security-opt no-new-privileges   blocks privilege escalation
                          (setuid binaries etc.) even if something inside
                          the container tries
  - --network=none        the detonated page's OWN requests still work
                          (Chromium inside the container can reach the
                          internet via Docker's default bridge for THAT
                          container) - wait, see note below
  - --memory / --cpus     hard resource caps, so a malicious page can't
                          exhaust host resources (crypto miners, zip
                          bombs via a triggered download, fork bombs)
  - --user 1000:1000       matches the non-root `sandboxuser` baked into
                          the image; belt-and-suspenders even though the
                          Dockerfile already drops to that user
  - --rm                  container is always removed after exit, never
                          left running or lingering on disk

NOTE on networking: the container DOES need outbound network access for
Chromium to actually load the target page - that's the whole point of
detonation. The isolation boundary here is NOT "no network," it's
"no access to the host filesystem, no elevated privileges, no persistent
state, and a hard resource ceiling." Don't confuse this with a fully
air-gapped sandbox; it protects the HOST, not the wider network the page
itself might try to reach out to (that's a separate concern - e.g. run
this on infrastructure with its own egress monitoring/limits if you need
that layer too).

This is a genuinely expensive check relative to the rest of the pipeline
(container startup + real browser render, typically 3-10+ seconds vs.
milliseconds for lexical/WHOIS/SSL checks), so it's opt-in - only run it
when the cheaper signals already suggest something worth a closer look,
not on every scan. See SANDBOX_TRIGGER_VERDICTS below.
"""

import asyncio
import json
import os
import shutil
import tempfile
import time
from urllib.parse import urlparse

DOCKER_IMAGE = os.getenv("SANDBOX_DOCKER_IMAGE", "phishguard-sandbox:latest")
CONTAINER_TIMEOUT_SECONDS = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "30"))
MEMORY_LIMIT = os.getenv("SANDBOX_MEMORY_LIMIT", "512m")
CPU_LIMIT = os.getenv("SANDBOX_CPU_LIMIT", "1.0")

# Only worth paying the detonation cost when cheaper signals already made
# the URL look interesting. Call should_detonate() with the verdict that
# the rest of the pipeline produced BEFORE this check, and only run this
# when it returns True. Wire this into scanner.py's flow, not as an
# always-on step.
SANDBOX_TRIGGER_VERDICTS = {"SUSPICIOUS", "MALICIOUS"}


def should_detonate(preliminary_verdict: str, sandbox_enabled: bool) -> bool:
    """
    Gate function - decide whether this URL is worth the cost of actually
    detonating it. Call with the verdict computed from the cheap signals
    (ML, WHOIS, SSL, homograph, typosquat, VT, GSB) BEFORE running the
    LLM content check and this sandbox, since both are the two most
    expensive checks in the pipeline and gating on cheaper signals first
    avoids paying for either on the large majority of SAFE scans.
    """
    return sandbox_enabled and preliminary_verdict in SANDBOX_TRIGGER_VERDICTS


def _registrable_domain(host: str) -> str:
    if not host:
        return ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def detonate_url(url: str) -> dict:
    """
    Runs the target URL through the isolated Docker sandbox and returns
    the parsed result. Never raises - all failure modes (Docker not
    installed, image not built, container timeout, crash) degrade to
    {"available": False, "reason": ...} so a sandboxing failure can't
    take down the rest of the scan.
    """
    if shutil.which("docker") is None:
        return {"available": False, "reason": "docker binary not found on host"}

    with tempfile.TemporaryDirectory(prefix="phishguard_sandbox_") as tmpdir:
        output_dir = os.path.join(tmpdir, "output")
        os.makedirs(output_dir, exist_ok=True)

        cmd = [
            "docker", "run",
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges",
            "--user", "1000:1000",
            "--memory", MEMORY_LIMIT,
            "--cpus", CPU_LIMIT,
            "--tmpfs", "/tmp:rw,size=256m",  # Chromium needs a writable /tmp despite --read-only
            "-e", f"TARGET_URL={url}",
            "-v", f"{output_dir}:/output",
            DOCKER_IMAGE,
        ]

        t0 = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=CONTAINER_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                # Container ran past its budget - kill it. This is itself
                # informative (a page that hangs the browser for 30s+ is
                # unusual, though not conclusive on its own - note it and
                # move on rather than blocking the whole scan indefinitely).
                proc.kill()
                await proc.wait()
                return {
                    "available": False,
                    "reason": f"container exceeded {CONTAINER_TIMEOUT_SECONDS}s timeout - "
                              f"killed (page may have hung or been unusually slow)",
                    "timed_out": True,
                }
        except FileNotFoundError:
            return {"available": False, "reason": "docker command not found"}
        except Exception as e:
            return {"available": False, "reason": f"failed to launch container: {e}"}

        elapsed_ms = int((time.time() - t0) * 1000)

        result_path = os.path.join(output_dir, "result.json")
        if not os.path.exists(result_path):
            stderr_tail = (stderr or b"").decode(errors="replace")[-500:]
            return {
                "available": False,
                "reason": "container exited without writing result.json "
                          f"(exit code {proc.returncode}): {stderr_tail}",
            }

        try:
            with open(result_path) as f:
                detonation = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return {"available": False, "reason": f"could not read result.json: {e}"}

        screenshot_path = os.path.join(output_dir, "screenshot.png")
        detonation["screenshot_path"] = screenshot_path if os.path.exists(screenshot_path) else None
        detonation["orchestration_time_ms"] = elapsed_ms

        # Cross-check the final (post-redirect) domain against detected
        # brand keywords - a page whose visible content claims to be
        # "PayPal" while sitting on a domain unrelated to paypal.com is
        # exactly the visual-impersonation pattern this sandbox exists
        # to catch, distinct from what homograph/typosquat already cover
        # (those look at the URL string itself, not rendered page content).
        final_domain = _registrable_domain(
            urlparse(detonation.get("final_url") or url).hostname or ""
        )
        brand_hits = detonation.get("brand_keywords_found", [])
        detonation["brand_domain_mismatch"] = bool(
            brand_hits and not any(brand.replace(" ", "") in final_domain for brand in brand_hits)
        )

        return detonation


def sandbox_risk_signals(result: dict) -> list[str]:
    """
    Formats detonation findings into the same list[str] shape used by
    whois_risk_signals() / ssl_risk_signals() / etc., ready to drop into
    scanner.py's all_extra aggregation.
    """
    if not result.get("available"):
        return []

    signals = []

    if result.get("has_cross_origin_password_form"):
        signals.append(
            "Password form submits to a different domain than the page itself "
            "- classic credential-exfiltration pattern"
        )

    if result.get("download_attempted"):
        fname = result.get("download_filename") or "unknown file"
        signals.append(f"Page attempted an unsolicited file download ('{fname}') on load")

    if result.get("brand_domain_mismatch"):
        brands = ", ".join(result.get("brand_keywords_found", []))
        signals.append(
            f"Page content claims brand identity ({brands}) not reflected in its "
            f"actual domain ({result.get('final_url', '?')})"
        )

    if result.get("timed_out"):
        signals.append(
            "Page failed to finish loading within the sandbox time budget - "
            "unusually slow or hung, worth manual review"
        )

    num_iframes = result.get("num_iframes", 0)
    num_ext_scripts = result.get("num_external_scripts", 0)
    if num_iframes >= 3 or num_ext_scripts >= 5:
        signals.append(
            f"Page loads {num_iframes} iframe(s) and {num_ext_scripts} external "
            f"script(s) - unusually complex third-party surface"
        )

    return signals
