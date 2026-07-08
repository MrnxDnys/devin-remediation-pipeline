"""SQLite state store. One connection per call (WAL) - fine at this scale."""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

from .config import settings
from .models import Job, JobStatus


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(settings.db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(settings.db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db() -> None:
    with _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_number INTEGER NOT NULL,
                issue_title TEXT NOT NULL,
                dedup_key TEXT UNIQUE,
                finding_type TEXT, source TEXT, severity TEXT,
                ecosystem TEXT, package TEXT, vulnerability_id TEXT, fix_versions TEXT,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                devin_session_id TEXT, devin_session_url TEXT,
                pr_url TEXT, summary TEXT,
                fix_strategy TEXT, tests_run TEXT, residual_risk_or_blocker TEXT,
                review_verdict TEXT, review_summary TEXT, review_session_url TEXT,
                error TEXT, acu_used REAL,
                created_at TEXT NOT NULL,
                started_at TEXT, finished_at TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                job_id INTEGER,
                kind TEXT NOT NULL,
                message TEXT
            );
            """
        )
        _migrate(c)


def _migrate(c: sqlite3.Connection) -> None:
    """Additively add newer nullable columns to an existing `jobs` table.
    Keeps pre-existing SQLite dev DBs working without a rebuild."""
    have = {r["name"] for r in c.execute("PRAGMA table_info(jobs)").fetchall()}
    for col in ("finding_type", "source", "severity",
                "fix_strategy", "tests_run", "residual_risk_or_blocker",
                "review_verdict", "review_summary", "review_session_url"):
        if col not in have:
            c.execute(f"ALTER TABLE jobs ADD COLUMN {col} TEXT")


def add_event(kind: str, message: str, job_id: int | None = None) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO events (ts, job_id, kind, message) VALUES (?,?,?,?)",
            (_now(), job_id, kind, message),
        )


def create_job(job: Job) -> Job:
    with _conn() as c:
        cur = c.execute(
            """INSERT INTO jobs
               (issue_number, issue_title, dedup_key, finding_type, source, severity,
                ecosystem, package, vulnerability_id, fix_versions, status, attempts, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                job.issue_number, job.issue_title, job.dedup_key, job.finding_type,
                job.source, job.severity, job.ecosystem, job.package,
                job.vulnerability_id, job.fix_versions,
                job.status.value, job.attempts, _now(),
            ),
        )
        job.id = cur.lastrowid
    add_event("job_created", f"Queued #{job.issue_number}: {job.issue_title}", job.id)
    return job


def get_job(job_id: int) -> Job | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    return _row_to_job(row) if row else None


def get_job_by_dedup(dedup_key: str) -> Job | None:
    if not dedup_key:
        return None
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM jobs WHERE dedup_key=? ORDER BY id DESC LIMIT 1", (dedup_key,)
        ).fetchone()
    return _row_to_job(row) if row else None


def get_job_by_issue(issue_number: int) -> Job | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM jobs WHERE issue_number=? ORDER BY id DESC LIMIT 1",
            (issue_number,),
        ).fetchone()
    return _row_to_job(row) if row else None


def update_job(job: Job) -> None:
    with _conn() as c:
        c.execute(
            """UPDATE jobs SET
               status=?, attempts=?, devin_session_id=?, devin_session_url=?,
               pr_url=?, summary=?, fix_strategy=?, tests_run=?,
               residual_risk_or_blocker=?, review_verdict=?, review_summary=?,
               review_session_url=?, error=?, acu_used=?,
               started_at=?, finished_at=?
               WHERE id=?""",
            (
                job.status.value, job.attempts, job.devin_session_id,
                job.devin_session_url, job.pr_url, job.summary,
                job.fix_strategy, job.tests_run, job.residual_risk_or_blocker,
                job.review_verdict, job.review_summary, job.review_session_url,
                job.error, job.acu_used, job.started_at, job.finished_at, job.id,
            ),
        )


def list_jobs() -> list[Job]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM jobs ORDER BY id DESC").fetchall()
    return [_row_to_job(r) for r in rows]


def list_events(limit: int = 100) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def _row_to_job(row: sqlite3.Row) -> Job:
    d = dict(row)
    d["status"] = JobStatus(d["status"])
    return Job(**d)
