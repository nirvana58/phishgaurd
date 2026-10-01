"""
server/db.py

SQLModel schema + session handling.
Tables:
  - scan_jobs        : one row per individual URL scan
  - batch_jobs       : one row per batch submission (single ID, single report)
  - batch_scan_items : links batch_jobs → scan_jobs (many URLs under one batch)
  - feature_vectors  : raw feature vectors saved for offline training
  - feedback         : admin labeling of scan results for future training
"""

import json
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

import sqlite3
from sqlalchemy import event
from sqlalchemy.engine import Engine as _SAEngine
from sqlmodel import Field, Session, SQLModel, create_engine, select

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH      = PROJECT_ROOT / "data.db"
DB_URL       = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DB_URL,
    echo=False,
    connect_args={
        "check_same_thread": False,
        "timeout": 30,
    },
    # QueuePool lets multiple threads hold their own connections simultaneously.
    # This is what makes sync route handlers (running in FastAPI's thread pool)
    # truly concurrent — each handler thread gets its own SQLite connection
    # rather than queuing on a single shared one.
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600,    # recycle connections after 1h to avoid stale handles
)


@event.listens_for(_SAEngine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _record):
    """
    Applied to every new SQLite connection.

    WAL mode  — Write-Ahead Logging allows concurrent readers + one writer.
                Without this, a worker write holds an EXCLUSIVE lock that
                blocks ALL admin-panel reads until the write finishes.

    busy_timeout — redundant with connect_args timeout but set at PRAGMA
                   level too so it applies to all lock contention paths.

    synchronous=NORMAL — safe WAL-mode default; faster than FULL, still
                         crash-safe at the WAL checkpoint boundary.

    cache_size — larger page cache reduces I/O during bulk batch inserts.
    """
    if isinstance(dbapi_conn, sqlite3.Connection):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=10000")   # ms
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA cache_size=-8000")      # 8 MB page cache
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


# ── Table models ───────────────────────────────────────────────────────────────

class ScanJob(SQLModel, table=True):
    __tablename__ = "scan_jobs"

    id           : str            = Field(primary_key=True)
    url          : str
    # queued | scanning | completed | failed | cancelled
    status       : str            = Field(default="queued")
    use_llm      : bool           = Field(default=False)
    batch_id     : Optional[str]  = Field(default=None)   # FK → batch_jobs.id if part of a batch
    created_at   : datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at : Optional[datetime] = Field(default=None)
    result_json  : Optional[str]  = Field(default=None)
    error        : Optional[str]  = Field(default=None)


class BatchJob(SQLModel, table=True):
    __tablename__ = "batch_jobs"

    id           : str            = Field(primary_key=True)   # single batch UUID
    # running | completed | failed | cancelled
    status       : str            = Field(default="running")
    total_urls   : int            = Field(default=0)
    completed    : int            = Field(default=0)          # incremented as each URL finishes
    failed       : int            = Field(default=0)
    use_llm      : bool           = Field(default=False)
    created_at   : datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at : Optional[datetime] = Field(default=None)
    report_path  : Optional[str]  = Field(default=None)       # path to the single generated report


class FeatureVector(SQLModel, table=True):
    __tablename__ = "feature_vectors"

    id         : Optional[int] = Field(default=None, primary_key=True)
    scan_id    : str           = Field(foreign_key="scan_jobs.id")
    vector_json: str
    created_at : datetime      = Field(default_factory=lambda: datetime.now(timezone.utc))


class Feedback(SQLModel, table=True):
    __tablename__ = "feedback"

    id         : Optional[int]      = Field(default=None, primary_key=True)
    scan_id    : str                 = Field(foreign_key="scan_jobs.id")
    label      : Optional[str]       = Field(default=None)   # "malicious" | "benign"
    labeled_at : Optional[datetime]  = Field(default=None)


# ── DB init ────────────────────────────────────────────────────────────────────

def init_db():
    SQLModel.metadata.create_all(engine)


# ── Session helper ─────────────────────────────────────────────────────────────

def get_session():
    with Session(engine) as session:
        yield session


# ── ScanJob CRUD ───────────────────────────────────────────────────────────────

def create_scan_job(
    session: Session, job_id: str, url: str,
    use_llm: bool, batch_id: Optional[str] = None,
) -> ScanJob:
    job = ScanJob(id=job_id, url=url, use_llm=use_llm, batch_id=batch_id)
    session.add(job); session.commit(); session.refresh(job)
    return job


def get_scan_job(session: Session, job_id: str) -> Optional[ScanJob]:
    return session.get(ScanJob, job_id)


def update_job_status(session: Session, job_id: str, status: str):
    job = session.get(ScanJob, job_id)
    if job:
        job.status = status
        session.add(job); session.commit()


def complete_job(session: Session, job_id: str, result: dict):
    job = session.get(ScanJob, job_id)
    if job:
        job.status       = "completed"
        job.result_json  = json.dumps(result)
        job.completed_at = datetime.now(timezone.utc)
        session.add(job); session.commit()


def fail_job(session: Session, job_id: str, error: str):
    job = session.get(ScanJob, job_id)
    if job:
        job.status       = "failed"
        job.error        = error
        job.completed_at = datetime.now(timezone.utc)
        session.add(job); session.commit()


def cancel_job(session: Session, job_id: str):
    job = session.get(ScanJob, job_id)
    if job and job.status in ("queued", "scanning"):
        job.status       = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        session.add(job); session.commit()
        return True
    return False


def save_feature_vector(session: Session, scan_id: str, vector: list[float]):
    fv = FeatureVector(scan_id=scan_id, vector_json=json.dumps(vector))
    session.add(fv); session.commit()


def bulk_create_scan_jobs(
    session: Session,
    jobs: list[dict],   # list of {job_id, url, use_llm, batch_id}
    chunk_size: int = 100,
) -> None:
    """
    Insert scan jobs in chunks of `chunk_size` rows per transaction.
    Avoids holding a single long write-lock when submitting thousands
    of URLs at once. Each chunk commits independently so the lock is
    released between chunks, keeping the DB responsive to other readers.
    """
    now = datetime.now(timezone.utc)
    for i in range(0, len(jobs), chunk_size):
        chunk = jobs[i : i + chunk_size]
        for j in chunk:
            session.add(ScanJob(
                id=j["job_id"], url=j["url"],
                use_llm=j["use_llm"], batch_id=j["batch_id"],
                status="queued", created_at=now,
            ))
        session.commit()   # release write-lock between chunks


# ── BatchJob CRUD ──────────────────────────────────────────────────────────────

def create_batch_job(
    session: Session, batch_id: str, total_urls: int, use_llm: bool
) -> BatchJob:
    job = BatchJob(id=batch_id, total_urls=total_urls, use_llm=use_llm)
    session.add(job); session.commit(); session.refresh(job)
    return job


def get_batch_job(session: Session, batch_id: str) -> Optional[BatchJob]:
    return session.get(BatchJob, batch_id)


def increment_batch_progress(session: Session, batch_id: str, success: bool):
    """Called after each URL in a batch finishes. Increments completed/failed."""
    job = session.get(BatchJob, batch_id)
    if not job:
        return
    if success:
        job.completed += 1
    else:
        job.failed += 1
    # Mark batch complete when all URLs are accounted for
    if (job.completed + job.failed) >= job.total_urls:
        job.status       = "completed"
        job.completed_at = datetime.now(timezone.utc)
    session.add(job); session.commit()


def complete_batch_job(session: Session, batch_id: str, report_path: str):
    job = session.get(BatchJob, batch_id)
    if job:
        job.status       = "completed"
        job.report_path  = report_path
        job.completed_at = datetime.now(timezone.utc)
        session.add(job); session.commit()


def get_batch_scan_jobs(session: Session, batch_id: str) -> list[ScanJob]:
    """Return all individual scan_jobs belonging to a batch."""
    return session.exec(
        select(ScanJob).where(ScanJob.batch_id == batch_id)
    ).all()