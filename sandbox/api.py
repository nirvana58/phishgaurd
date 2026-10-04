"""Authenticated HTTP API for the Render-hosted URL detonation service."""

import asyncio
import base64
import hmac
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from detonate import detonate, is_public_http_url

MAX_CONCURRENT_DETONATIONS = 1
DETONATION_TIMEOUT_SECONDS = 45
_detonation_slots = asyncio.Semaphore(MAX_CONCURRENT_DETONATIONS)

app = FastAPI(title="PhishGuard URL Sandbox", docs_url=None, redoc_url=None)


class DetonationRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/detonate")
async def detonate_endpoint(
    request: DetonationRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    expected_token = os.environ.get("SANDBOX_API_TOKEN", "")
    if not expected_token:
        raise HTTPException(status_code=503, detail="Sandbox API token is not configured")

    scheme, separator, supplied_token = (authorization or "").partition(" ")
    if (
        scheme.lower() != "bearer"
        or not separator
        or not hmac.compare_digest(supplied_token, expected_token)
    ):
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token")

    if not await asyncio.to_thread(is_public_http_url, request.url):
        raise HTTPException(status_code=400, detail="URL must resolve only to public HTTP(S) addresses")

    async with _detonation_slots:
        with tempfile.TemporaryDirectory(prefix="phishguard_detonation_") as output_dir:
            try:
                result = await asyncio.wait_for(
                    detonate(request.url, output_dir=output_dir),
                    timeout=DETONATION_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                return {
                    "available": False,
                    "url": request.url,
                    "reason": f"detonation exceeded {DETONATION_TIMEOUT_SECONDS}s timeout",
                    "timed_out": True,
                }

            screenshot_path = Path(output_dir) / "screenshot.png"
            if screenshot_path.is_file():
                result["screenshot_base64"] = base64.b64encode(
                    screenshot_path.read_bytes()
                ).decode("ascii")
            return result
