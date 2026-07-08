"""Light, deterministic, offline test for the observability metrics contract."""
from datetime import datetime, timedelta

import pytest

from app import db
from app.config import settings
from app.dashboard import metrics_summary, serialize_job
from app.models import Job, JobStatus


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "db_path", str(tmp_path / "test.db"))
    db.init_db()
    yield


def _mk(issue_number, severity, dedup_key):
    return db.create_job(
        Job(
            issue_number=issue_number,
            issue_title=f"Finding #{issue_number}",
            dedup_key=dedup_key,
            severity=severity,
            vulnerability_id=f"GHSA-{issue_number}",
        )
    )


def _terminal(job, status, *, pr_url=None, duration_sec=None):
    # created_at is fixed at creation time; re-read it and set finished_at relative to it so
    # the elapsed remediation time is deterministic.
    fresh = db.get_job(job.id)
    fresh.status = status
    if pr_url is not None:
        fresh.pr_url = pr_url
    if duration_sec is not None:
        finished = datetime.fromisoformat(fresh.created_at) + timedelta(seconds=duration_sec)
        fresh.finished_at = finished.isoformat()
    db.update_job(fresh)


def test_metrics_summary():
    a = _mk(1, "critical", "k1")
    b = _mk(2, "high", "k2")
    c = _mk(3, "medium", "k3")
    d = _mk(4, "low", "k4")

    # Two succeeded (one with a PR, one without), one escalated, one still queued.
    _terminal(a, JobStatus.SUCCEEDED, pr_url="https://github.com/o/r/pull/1", duration_sec=600)
    _terminal(b, JobStatus.SUCCEEDED, pr_url="", duration_sec=1200)
    _terminal(c, JobStatus.ESCALATED)
    # d stays queued

    m = metrics_summary()

    assert m["total"] == 4
    assert m["by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 1}
    assert m["auto_fixed"] == 2
    assert m["escalated"] == 1
    assert m["active"] == 1  # the queued job
    assert m["prs_awaiting_review"] == 1  # only the succeeded job with a non-empty pr_url

    # terminal = 2 succeeded + 1 escalated = 3 ; 2/3 -> 66.7
    assert m["success_rate_pct"] == pytest.approx(66.7)
    assert 0.0 <= m["success_rate_pct"] <= 100.0

    # mean of 600s and 1200s
    assert m["mean_time_to_remediation_sec"] == pytest.approx(900.0)
    assert m["throughput_per_hour"] >= 0.0


def test_metrics_summary_empty_is_safe():
    m = metrics_summary()
    assert m["total"] == 0
    assert m["success_rate_pct"] == 0.0
    assert m["mean_time_to_remediation_sec"] == 0.0
    assert m["throughput_per_hour"] == 0.0


def test_serialize_job_shape():
    job = _mk(7, "high", "k7")
    job.pr_url = "https://example/pr/7"
    job.devin_session_url = "https://app.devin.ai/sessions/x"
    job.summary = "did the thing"
    d = serialize_job(job)
    assert d["issue_number"] == 7
    assert d["advisory"] == "GHSA-7"
    assert d["status"] == JobStatus.QUEUED.value
    assert d["pr_url"] == "https://example/pr/7"
