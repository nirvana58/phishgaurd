"""
server/api.py

Routes:
  POST /scan                    Submit single URL → scan_id
  GET  /scan/{id}               Poll status + result
  POST /scan/{id}/cancel        Cancel a running/queued scan
  GET  /scan/{id}/report        Download saved report

  POST /batch                   Submit batch of URLs → single batch_id
  GET  /batch/{id}              Poll batch progress + per-URL results
  GET  /batch/{id}/report       Download consolidated batch report

  POST /admin/reload-model      Hot-swap model artifacts
  POST /admin/label/{id}        Label a scan result
  GET  /admin/stats             Overview stats
  GET  /admin/scans             List all scans
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlmodel import Session, select

import os

from server.db import (
    engine,
    get_session,
    create_scan_job,
    create_batch_job,
    bulk_create_scan_jobs,
    get_scan_job,
    get_batch_job,
    get_batch_scan_jobs,
    cancel_job,
    ScanJob, BatchJob, Feedback,
)

# Maximum URLs per batch — override with BATCH_MAX_URLS env var.
# No hard cap: large batches are chunked automatically so SQLite stays responsive.
BATCH_MAX_URLS = int(os.getenv("BATCH_MAX_URLS", "0")) or None  # None = unlimited
from server.queue_worker import scan_queue
from core.models import ModelStore

router = APIRouter()

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


# ── Schemas ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    use_llm: bool = False

class BatchRequest(BaseModel):
    urls: list[str]
    use_llm: bool = False

class LabelRequest(BaseModel):
    label: str   # "malicious" | "benign"


# ── Single scan ────────────────────────────────────────────────────────────────

@router.post("/scan", tags=["scan"])
async def submit_scan(body: ScanRequest, session: Session = Depends(get_session)):
    url = body.url.strip()
    if not url:
        raise HTTPException(400, "url must not be empty")
    job_id = str(uuid.uuid4())
    create_scan_job(session, job_id=job_id, url=url, use_llm=body.use_llm)
    scan_queue.enqueue(job_id, url, body.use_llm)
    return {"scan_id": job_id, "status": "queued"}


@router.get("/scan/{scan_id}", tags=["scan"])
def get_scan_status(scan_id: str, session: Session = Depends(get_session)):
    """Sync handler — thread pool, never blocks event loop during DB read."""
    job = get_scan_job(session, scan_id)
    if not job:
        raise HTTPException(404, f"No scan found: {scan_id}")
    result = json.loads(job.result_json) if job.result_json else None
    return {
        "scan_id": job.id, "url": job.url, "status": job.status,
        "created_at": job.created_at, "completed_at": job.completed_at,
        "result": result, "error": job.error,
    }


@router.post("/scan/{scan_id}/cancel", tags=["scan"])
async def cancel_scan(scan_id: str, session: Session = Depends(get_session)):
    """
    Request cancellation of a queued or running scan.
    The worker honours this at its next checkpoint (near-instant for queued
    jobs, within one async yield for running ones).
    """
    job = get_scan_job(session, scan_id)
    if not job:
        raise HTTPException(404, f"No scan found: {scan_id}")
    if job.status in ("completed", "failed", "cancelled"):
        return {"scan_id": scan_id, "status": job.status,
                "message": "Already finished — nothing to cancel."}
    scan_queue.request_cancel(scan_id)
    cancel_job(session, scan_id)
    return {"scan_id": scan_id, "status": "cancelled",
            "message": "Cancellation requested. Worker will stop at next checkpoint."}


@router.get("/scan/{scan_id}/report", tags=["scan"])
async def download_report(scan_id: str, fmt: str = "md"):
    allowed = {"md", "pdf", "docx", "txt"}
    if fmt not in allowed:
        raise HTTPException(400, f"fmt must be one of {allowed}")
    path = REPORTS_DIR / f"{scan_id}.{fmt}"
    if not path.exists():
        raise HTTPException(404, "Report not found. Has the scan completed?")
    return FileResponse(path, filename=path.name)


# ── Batch scan ─────────────────────────────────────────────────────────────────

@router.post("/batch", tags=["batch"])
async def submit_batch(body: BatchRequest, session: Session = Depends(get_session)):
    """
    Submit multiple URLs as one batch — no hard URL cap.
    Returns a single batch_id immediately. All URLs are scanned
    individually but tracked under one ID. A single consolidated
    report is generated when every URL finishes.

    Large batches are inserted in chunks of 100 rows per commit so
    SQLite never holds a long exclusive lock during submission.

    Override the default unlimited cap by setting BATCH_MAX_URLS env var.
    """
    # Deduplicate preserving order
    seen, urls = set(), []
    for u in body.urls:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    if not urls:
        raise HTTPException(400, "urls list must not be empty")

    if BATCH_MAX_URLS and len(urls) > BATCH_MAX_URLS:
        raise HTTPException(
            400,
            f"Batch contains {len(urls)} URLs but BATCH_MAX_URLS={BATCH_MAX_URLS}. "
            "Increase or unset BATCH_MAX_URLS to allow larger batches."
        )

    batch_id = str(uuid.uuid4())

    # Create batch header row
    create_batch_job(session, batch_id=batch_id,
                     total_urls=len(urls), use_llm=body.use_llm)

    # Build job records and bulk-insert in 100-row chunks (keeps write-locks short)
    job_records = [
        {"job_id": str(uuid.uuid4()), "url": url,
         "use_llm": body.use_llm, "batch_id": batch_id}
        for url in urls
    ]
    await asyncio.to_thread(
        bulk_create_scan_jobs, session, job_records, 100
    )

    # Enqueue all jobs for the worker (non-blocking — just fills asyncio.Queue)
    for j in job_records:
        scan_queue.enqueue(j["job_id"], j["url"], j["use_llm"], batch_id=batch_id)

    return {
        "batch_id": batch_id,
        "status": "running",
        "total_urls": len(urls),
        "message": f"Batch queued. Poll GET /batch/{batch_id} for progress.",
    }


@router.get("/batch/{batch_id}", tags=["batch"])
def get_batch_status(
    batch_id: str,
    session: Session = Depends(get_session),
    page: int = 1,
    page_size: int = 200,
):
    """
    Poll batch progress. `scans` is paginated (default 200/page) so large
    batches with thousands of URLs don't produce a huge single response.
    The CLI only needs the progress counters while polling — it fetches
    pages only when displaying the final summary table.

    Query params:
      page      — 1-based page number (default: 1)
      page_size — rows per page, max 500 (default: 200)
    """
    batch = get_batch_job(session, batch_id)
    if not batch:
        raise HTTPException(404, f"No batch found: {batch_id}")

    page_size = min(max(page_size, 1), 500)
    offset    = (page - 1) * page_size

    # Count total scan_jobs for this batch
    all_jobs  = get_batch_scan_jobs(session, batch_id)
    total_jobs = len(all_jobs)
    page_jobs  = all_jobs[offset : offset + page_size]

    scans = []
    for sj in page_jobs:
        verdict = None
        if sj.result_json:
            try:
                verdict = json.loads(sj.result_json).get("verdict", {}).get("verdict")
            except Exception:
                pass
        scans.append({
            "scan_id": sj.id, "url": sj.url,
            "status": sj.status, "verdict": verdict,
        })

    total_pages = max(1, (total_jobs + page_size - 1) // page_size)

    return {
        "batch_id":    batch.id,
        "status":      batch.status,
        "total_urls":  batch.total_urls,
        "completed":   batch.completed,
        "failed":      batch.failed,
        "progress_pct": round(
            (batch.completed + batch.failed) / max(batch.total_urls, 1) * 100, 1
        ),
        "report_path":  batch.report_path,
        "created_at":   batch.created_at,
        "completed_at": batch.completed_at,
        # Pagination metadata
        "page":         page,
        "page_size":    page_size,
        "total_pages":  total_pages,
        "scans":        scans,
    }


@router.post("/batch/{batch_id}/cancel", tags=["batch"])
async def cancel_batch(batch_id: str, session: Session = Depends(get_session)):
    """Cancel all queued/running scans in a batch."""
    batch = get_batch_job(session, batch_id)
    if not batch:
        raise HTTPException(404, f"No batch found: {batch_id}")

    scan_jobs = get_batch_scan_jobs(session, batch_id)
    cancelled = 0
    for sj in scan_jobs:
        if sj.status in ("queued", "scanning"):
            scan_queue.request_cancel(sj.id)
            cancel_job(session, sj.id)
            cancelled += 1

    batch.status = "cancelled"
    session.add(batch); session.commit()

    return {"batch_id": batch_id, "cancelled_scans": cancelled,
            "message": "Batch cancellation requested."}


@router.get("/batch/{batch_id}/report", tags=["batch"])
async def download_batch_report(batch_id: str, fmt: str = "md"):
    allowed = {"md", "pdf", "docx", "txt"}
    if fmt not in allowed:
        raise HTTPException(400, f"fmt must be one of {allowed}")
    path = REPORTS_DIR / f"batch_{batch_id}.{fmt}"
    if not path.exists():
        raise HTTPException(404, "Batch report not found. Has the batch completed?")
    return FileResponse(path, filename=path.name)


# ── Admin ──────────────────────────────────────────────────────────────────────

@router.post("/admin/reload-model", tags=["admin"])
async def reload_model(request: Request):
    try:
        new_store = ModelStore.load()
        request.app.state.model_store = new_store
        meta = new_store.meta
        return {"reloaded": True, "version": meta["version"],
                "trained_at": meta.get("trained_at"), "n_samples": meta.get("n_samples")}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/admin/label/{scan_id}", tags=["admin"])
async def label_scan(scan_id: str, body: LabelRequest,
                     session: Session = Depends(get_session)):
    if body.label not in {"malicious", "benign"}:
        raise HTTPException(400, "label must be 'malicious' or 'benign'")
    job = get_scan_job(session, scan_id)
    if not job:
        raise HTTPException(404, f"No scan: {scan_id}")
    existing = session.exec(
        select(Feedback).where(Feedback.scan_id == scan_id)
    ).first()
    if existing:
        existing.label = body.label
        existing.labeled_at = datetime.now(timezone.utc)
        session.add(existing)
    else:
        session.add(Feedback(scan_id=scan_id, label=body.label,
                             labeled_at=datetime.now(timezone.utc)))
    session.commit()
    return {"scan_id": scan_id, "label": body.label, "status": "saved"}


@router.get("/admin/scans", tags=["admin"])
def list_scans(session: Session = Depends(get_session),
               limit: int = 100, status: Optional[str] = None):
    """
    Sync handler — FastAPI runs this in a thread pool so it never
    blocks the event loop while reading potentially large scan history.
    """
    jobs = session.exec(
        select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
    ).all()
    rows = []
    for job in jobs:
        if status and job.status != status:
            continue
        verdict = confidence = None
        if job.result_json:
            try:
                r = json.loads(job.result_json)
                verdict    = r.get("verdict", {}).get("verdict")
                confidence = r.get("verdict", {}).get("confidence")
            except Exception:
                pass
        rows.append({
            "scan_id": job.id, "url": job.url, "status": job.status,
            "verdict": verdict, "confidence": confidence,
            "batch_id": job.batch_id,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        })
    return {"scans": rows, "total": len(rows)}


@router.get("/admin/stats", tags=["admin"])
def get_stats(request: Request, session: Session = Depends(get_session)):
    """Sync handler — runs in thread pool, never blocks the event loop."""
    all_jobs = session.exec(select(ScanJob)).all()
    verdicts: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for job in all_jobs:
        statuses[job.status] = statuses.get(job.status, 0) + 1
        if job.result_json:
            try:
                v = json.loads(job.result_json).get("verdict", {}).get("verdict", "UNKNOWN")
                verdicts[v] = verdicts.get(v, 0) + 1
            except Exception:
                pass
    model_version = "none"
    try:
        model_version = request.app.state.model_store.version
    except AttributeError:
        pass
    return {"total_scans": len(all_jobs), "statuses": statuses,
            "verdicts": verdicts, "active_model_version": model_version}