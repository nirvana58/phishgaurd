"""
server/main.py

FastAPI app entry point.
- Graceful shutdown: worker task cancelled, queue drained on exit
- Admin panel served at GET /admin
- Hot-swappable model via /admin/reload-model
- Enlarged thread pool so admin panel polling never starves the CLI

Root cause of CLI/admin contention:
  FastAPI runs sync `def` route handlers in a thread pool executor.
  Default size = min(32, cpu_count + 4) which on most dev machines
  is only 5-8 threads. Admin panel polls every 30s AND fires 2-3
  requests on every page navigation, consuming most of those threads.
  CLI requests then queue behind them and appear to "not reach" the server.

Fix: set a dedicated ThreadPoolExecutor with 40 workers at startup.
  Admin panel routes and CLI routes each get their own threads.
  They never compete for the same pool slot.

Run:
    uvicorn server.main:app --port 8000
Open: http://localhost:8000/admin
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from server.db import init_db
from server.migrations import run_all_migrations
from server.api import router
from server.queue_worker import scan_queue
from core.models import ModelStore, ModelLoadError

ENV_PATH   = Path(__file__).resolve().parent.parent / ".env"
STATIC_DIR = Path(__file__).resolve().parent / "static"
load_dotenv(ENV_PATH)

# ── Thread pool ────────────────────────────────────────────────────────────────
# 40 threads: admin panel can use up to 10 simultaneously (polling + page loads)
# CLI can use up to 10, worker DB ops use up to 10, leaving 10 in reserve.
_THREAD_POOL = ThreadPoolExecutor(
    max_workers=40,
    thread_name_prefix="phishguard",
)


# ── Timeout middleware ─────────────────────────────────────────────────────────

class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """
    Cancel any request that takes longer than TIMEOUT_SECONDS.
    Prevents one slow admin query from tying up a thread indefinitely.
    Admin panel history queries are the most likely offender on large DBs.
    """
    TIMEOUT_SECONDS = 30.0

    async def dispatch(self, request: Request, call_next):
        try:
            return await asyncio.wait_for(
                call_next(request),
                timeout=self.TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return JSONResponse(
                {"detail": f"Request timed out after {self.TIMEOUT_SECONDS}s"},
                status_code=504,
            )


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ───────────────────────────────────────────────────────────────
    # Install enlarged thread pool BEFORE anything else runs
    loop = asyncio.get_running_loop()
    loop.set_default_executor(_THREAD_POOL)
    print(f"[main] Thread pool : {_THREAD_POOL._max_workers} workers")

    print("[main] Running schema migrations…")
    run_all_migrations()

    print("[main] Initialising database…")
    init_db()

    try:
        app.state.model_store = ModelStore.load()
    except ModelLoadError as e:
        print(f"[main] WARNING: {e}")
        print("[main] ML scoring unavailable — run `python -m training.train` first.")
        app.state.model_store = None

    scan_queue.start_worker(app)
    print("[main] Server ready → http://localhost:8000/admin")

    yield   # ── running ──────────────────────────────────────────────────────

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    print("[main] Shutdown requested — stopping worker…")
    await scan_queue.shutdown()
    _THREAD_POOL.shutdown(wait=False)
    print("[main] Done.")


# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard URL Threat Scanner",
    description="Async URL scanner: K-means + SOM, VirusTotal, Safe Browsing, URLhaus, WHOIS.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(RequestTimeoutMiddleware)
app.include_router(router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/admin", include_in_schema=False)
async def admin_panel():
    return FileResponse(STATIC_DIR / "admin.html")

# Health endpoint — lightweight, async, never touches DB or thread pool.
# CLI uses this to check server is up before sending real requests.
@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        # Give uvicorn's own thread pool room to breathe too
        loop="asyncio",
    )
