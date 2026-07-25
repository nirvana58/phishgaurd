"""
server/queue_worker.py

Async job queue with:
  - Per-job cancellation (checks cancel set before + during processing)
  - Graceful shutdown (worker task stored and cancelled in lifespan teardown)
  - Batch job tracking (increments batch progress after each URL)
  - Exception isolation (one bad URL never crashes the worker loop)
"""

import asyncio
import traceback
import uuid
from typing import TYPE_CHECKING, Optional

from sqlmodel import Session

from server.db import (
    engine,
    create_scan_job,
    update_job_status,
    complete_job,
    fail_job,
    cancel_job,
    save_feature_vector,
    increment_batch_progress,
    get_batch_job,
    get_batch_scan_jobs,
    complete_batch_job,
)
from server.scanner import scan_url

if TYPE_CHECKING:
    from fastapi import FastAPI


class ScanQueue:
    def __init__(self):
        self._q: asyncio.Queue          = asyncio.Queue()
        self._cancel_set: set[str]      = set()
        self._worker_task: Optional[asyncio.Task] = None
        # Stored in start_worker so enqueue() can use call_soon_threadsafe
        # when called from thread-pool route handlers (sync def routes).
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def enqueue(self, job_id: str, url: str, use_llm: bool,
                batch_id: Optional[str] = None):
        """
        Thread-safe enqueue. Safe to call from BOTH:
          - async def routes (on event loop)
          - sync def routes  (running in FastAPI thread pool)

        asyncio.Queue is NOT thread-safe for cross-thread access.
        call_soon_threadsafe() schedules put_nowait() to run on the
        event loop thread, which is the only safe way to add to an
        asyncio.Queue from a different thread.
        """
        item = (job_id, url, use_llm, batch_id)
        if self._loop and self._loop.is_running():
            # Called from a thread pool thread — schedule on event loop
            self._loop.call_soon_threadsafe(self._q.put_nowait, item)
        else:
            # Called directly from event loop (e.g. during startup)
            self._q.put_nowait(item)

    def request_cancel(self, scan_id: str):
        """Thread-safe — just adds to a plain Python set (GIL-protected)."""
        self._cancel_set.add(scan_id)

    def is_cancelled(self, scan_id: str) -> bool:
        return scan_id in self._cancel_set

    def start_worker(self, app: "FastAPI"):
        """
        Schedule the worker coroutine. Capture the running event loop
        so enqueue() can use call_soon_threadsafe from thread pool threads.
        """
        self._loop = asyncio.get_event_loop()
        self._worker_task = asyncio.create_task(
            self._worker(app), name="scan-worker"
        )

    async def shutdown(self):
        """
        Cancel the worker task and drain any remaining queued jobs,
        marking them cancelled in the DB. Called from lifespan teardown.
        """
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

        # Drain queue — mark leftover jobs as cancelled
        while not self._q.empty():
            try:
                job_id, url, _, batch_id = self._q.get_nowait()
                with Session(engine) as session:
                    cancel_job(session, job_id)
                print(f"[worker] Drained queued job {job_id} → cancelled")
            except asyncio.QueueEmpty:
                break

        print("[worker] Shutdown complete.")

    # ── Worker loop ────────────────────────────────────────────────────────────

    async def _worker(self, app: "FastAPI"):
        print("[worker] Scanner worker started.")
        while True:
            job_id, url, use_llm, batch_id = await self._q.get()

            try:
                await self._process(app, job_id, url, use_llm, batch_id)
            except asyncio.CancelledError:
                # Worker itself is being shut down — re-raise to exit loop
                with Session(engine) as session:
                    cancel_job(session, job_id)
                raise
            except Exception:
                # Isolate: log and continue — never crash the worker loop
                err = traceback.format_exc()
                print(f"[worker] Unhandled error on job {job_id}:\n{err}")
                with Session(engine) as session:
                    fail_job(session, job_id, err)
                    if batch_id:
                        increment_batch_progress(session, batch_id, success=False)
            finally:
                self._q.task_done()

    async def _process(self, app, job_id: str, url: str,
                       use_llm: bool, batch_id: Optional[str]):
        """
        Process a single scan job with cancellation checkpoints.

        All synchronous SQLite calls are wrapped in asyncio.to_thread() so
        they run in a thread-pool worker rather than blocking the event loop.
        This keeps the server responsive to admin-panel and CLI requests
        even while the worker is writing results to the DB.
        """

        def _db_cancel(jid, bid):
            with Session(engine) as s:
                cancel_job(s, jid)
                if bid:
                    increment_batch_progress(s, bid, success=False)

        def _db_set_scanning(jid):
            with Session(engine) as s:
                update_job_status(s, jid, "scanning")

        def _db_persist(jid, result, raw_vector, bid):
            with Session(engine) as s:
                save_feature_vector(s, jid, raw_vector)
                complete_job(s, jid, result)
                if bid:
                    increment_batch_progress(s, bid, success=True)

        # ── Checkpoint 1: cancelled before start? ─────────────────────────────
        if self.is_cancelled(job_id):
            self._cancel_set.discard(job_id)
            print(f"[worker] Job {job_id} cancelled before start.")
            await asyncio.to_thread(_db_cancel, job_id, batch_id)
            return

        print(f"[worker] Processing {job_id} — {url}")
        # DB write in thread — event loop stays free for HTTP requests
        await asyncio.to_thread(_db_set_scanning, job_id)

        # ── Checkpoint 2: cancelled while setting status? ─────────────────────
        if self.is_cancelled(job_id):
            self._cancel_set.discard(job_id)
            await asyncio.to_thread(_db_cancel, job_id, batch_id)
            return

        # ── Run scan (async — VT + GSB fire concurrently via asyncio.gather) ──
        model_store = getattr(app.state, "model_store", None)
        result, raw_vector = await scan_url(
            url=url,
            model_store=model_store,
            use_llm=use_llm,
        )

        # ── Checkpoint 3: cancelled during scan? ──────────────────────────────
        if self.is_cancelled(job_id):
            self._cancel_set.discard(job_id)
            print(f"[worker] Job {job_id} cancelled after scan — discarding result.")
            await asyncio.to_thread(_db_cancel, job_id, batch_id)
            return

        # ── Persist result (in thread) ────────────────────────────────────────
        await asyncio.to_thread(_db_persist, job_id, result, raw_vector, batch_id)

        verdict = result.get("verdict", {}).get("verdict", "?")
        print(f"[worker] Job {job_id} completed — {verdict}")

        # Yield briefly so pending HTTP requests get a turn before we
        # immediately pick up the next queued job
        await asyncio.sleep(0)

        # ── Trigger batch report when all URLs are done ───────────────────────
        if batch_id:
            await self._maybe_finalize_batch(app, batch_id)

    async def _maybe_finalize_batch(self, app, batch_id: str):
        """
        Called after every URL in a batch completes.
        When ALL URLs are accounted for, generate the single batch report.
        """
        with Session(engine) as session:
            batch = get_batch_job(session, batch_id)
            if not batch:
                return
            all_done = (batch.completed + batch.failed) >= batch.total_urls
            if not all_done:
                return   # more URLs still in flight
            scan_jobs = get_batch_scan_jobs(session, batch_id)

        print(f"[worker] Batch {batch_id} complete — generating report…")
        try:
            from report.generator import generate_batch_report
            results = []
            for sj in scan_jobs:
                import json as _json
                if sj.result_json:
                    results.append(_json.loads(sj.result_json))

            report_path = await generate_batch_report(
                batch_id=batch_id,
                results=results,
                formats=["md", "txt", "pdf", "docx"],
                show_terminal=True,
            )
            with Session(engine) as session:
                complete_batch_job(session, batch_id, str(report_path.get("md", "")))
            print(f"[worker] Batch {batch_id} report saved.")
        except Exception:
            print(f"[worker] Batch {batch_id} report generation failed:\n{traceback.format_exc()}")


# Module-level singleton
scan_queue = ScanQueue()
