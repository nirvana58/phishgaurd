"""
server/migrations.py

Lightweight migration system for SQLite schema changes.
Called once at server startup (before SQLModel create_all).

Each migration is a function named migrate_NNN_<description>.
Migrations are idempotent — they check if the change is needed
before applying it, so safe to run on every startup.

Add new migrations at the bottom. Never edit or remove old ones.
"""

import sqlite3
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH      = PROJECT_ROOT / "data.db"


def _col_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    return column in cols


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    r = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return r is not None


def run_all_migrations():
    """Run every migrate_NNN function in definition order. Safe on every startup."""
    if not DB_PATH.exists():
        return   # fresh DB — SQLModel create_all will build everything correctly

    migrations = [
        migrate_001_scan_jobs_add_batch_id,
        migrate_002_ensure_batch_jobs_columns,
    ]

    conn = sqlite3.connect(DB_PATH)
    try:
        applied = 0
        for fn in migrations:
            try:
                changed = fn(conn)
                if changed:
                    print(f"[migrate] Applied: {fn.__name__}")
                    applied += 1
            except Exception:
                print(f"[migrate] ERROR in {fn.__name__}:\n{traceback.format_exc()}")
        conn.commit()
        if applied:
            print(f"[migrate] {applied} migration(s) applied.")
        else:
            print("[migrate] Schema up to date.")
    finally:
        conn.close()


# ── Migrations ─────────────────────────────────────────────────────────────────

def migrate_001_scan_jobs_add_batch_id(conn: sqlite3.Connection) -> bool:
    """Add batch_id column to scan_jobs (nullable FK to batch_jobs.id)."""
    if not _table_exists(conn, "scan_jobs"):
        return False   # table doesn't exist yet — create_all will handle it
    if _col_exists(conn, "scan_jobs", "batch_id"):
        return False   # already there
    conn.execute("ALTER TABLE scan_jobs ADD COLUMN batch_id TEXT DEFAULT NULL")
    return True


def migrate_002_ensure_batch_jobs_columns(conn: sqlite3.Connection) -> bool:
    """
    Ensure batch_jobs has all required columns.
    If the table was created by an old schema (e.g. only had id/status),
    add any missing columns with safe defaults.
    """
    if not _table_exists(conn, "batch_jobs"):
        return False   # create_all will build it fresh

    needed = {
        "total_urls":   "INTEGER NOT NULL DEFAULT 0",
        "completed":    "INTEGER NOT NULL DEFAULT 0",
        "failed":       "INTEGER NOT NULL DEFAULT 0",
        "use_llm":      "INTEGER NOT NULL DEFAULT 0",
        "completed_at": "TEXT DEFAULT NULL",
        "report_path":  "TEXT DEFAULT NULL",
    }
    changed = False
    for col, definition in needed.items():
        if not _col_exists(conn, "batch_jobs", col):
            conn.execute(f"ALTER TABLE batch_jobs ADD COLUMN {col} {definition}")
            changed = True
    return changed
