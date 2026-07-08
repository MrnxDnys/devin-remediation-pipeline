"""Light, deterministic, offline test for the observability metrics contract."""
from datetime import datetime, timedelta, timezone

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


def _set_finished(job, *, minutes_ago):
    # Force a succeeded job's finished_at to a precise point relative to now, so throughput's
    # rolling-window behaviour is deterministic regardless of wall-clock at creation.
    fresh = db.get_job(job.id)
    fresh.status = JobStatus.SUCCEEDED
    fresh.finished_at = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    db.update_job(fresh)


def test_success_rate_ignores_transient_failed():
    # 1 succeeded + 1 escalated + 1 (transient) failed. Denominator is the resting set
    # succeeded+escalated only, so the failed attempt must not deflate the rate.
    a = _mk(1, "high", "k1")
    b = _mk(2, "high", "k2")
    c = _mk(3, "high", "k3")
    _terminal(a, JobStatus.SUCCEEDED, pr_url="https://github.com/o/r/pull/1", duration_sec=300)
    _terminal(b, JobStatus.ESCALATED)
    _terminal(c, JobStatus.FAILED)

    m = metrics_summary()

    # 1 succeeded / (1 succeeded + 1 escalated) = 50.0, FAILED excluded from the denominator.
    assert m["success_rate_pct"] == pytest.approx(50.0)
    assert m["failed"] == 1  # still surfaced as an "in retry" signal
    assert m["by_status"]["failed"] == 1  # by_status keeps reporting FAILED as-is


def test_open_by_severity_excludes_terminal():
    # Succeeded/failed drop out of open risk; queued/running/escalated stay.
    a = _mk(1, "critical", "k1")   # -> succeeded (fixed, closed)
    _mk(2, "high", "k2")           # queued (open)
    c = _mk(3, "medium", "k3")     # -> running (open)
    d = _mk(4, "low", "k4")        # -> escalated (needs human, open)
    e = _mk(5, "critical", "k5")   # -> failed (transient, not open)

    _terminal(a, JobStatus.SUCCEEDED, pr_url="https://github.com/o/r/pull/1", duration_sec=60)
    c_fresh = db.get_job(c.id)
    c_fresh.status = JobStatus.RUNNING
    db.update_job(c_fresh)
    _terminal(d, JobStatus.ESCALATED)
    _terminal(e, JobStatus.FAILED)

    m = metrics_summary()

    # All-time severity still counts every finding.
    assert m["by_severity"] == {"critical": 2, "high": 1, "medium": 1, "low": 1}
    # Open severity excludes the succeeded critical and the failed critical.
    assert m["open_by_severity"] == {"critical": 0, "high": 1, "medium": 1, "low": 1}


def test_throughput_counts_only_recent_succeeded():
    # Two succeeded finished within the last hour, one succeeded finished long ago.
    a = _mk(1, "high", "k1")
    b = _mk(2, "high", "k2")
    c = _mk(3, "high", "k3")
    _set_finished(a, minutes_ago=5)
    _set_finished(b, minutes_ago=30)
    _set_finished(c, minutes_ago=180)  # outside the rolling 60-minute window

    m = metrics_summary()

    # Only the two recent succeeded jobs count toward the rolling-window throughput.
    assert m["throughput_per_hour"] == pytest.approx(2.0)


def test_throughput_zero_without_recent_succeeded():
    a = _mk(1, "high", "k1")
    _set_finished(a, minutes_ago=240)  # older than the window
    assert metrics_summary()["throughput_per_hour"] == 0.0


def test_serialize_job_shape():
    job = _mk(7, "high", "k7")
    job.pr_url = "https://example/pr/7"
    job.devin_session_url = "https://app.devin.ai/sessions/x"
    job.summary = "did the thing"
    job.fix_strategy = "upgrade"
    d = serialize_job(job)
    assert d["issue_number"] == 7
    assert d["advisory"] == "GHSA-7"
    assert d["status"] == JobStatus.QUEUED.value
    assert d["pr_url"] == "https://example/pr/7"
    assert d["fix_strategy"] == "upgrade"


def test_report_shows_strategy_and_specific_blocker():
    from app.dashboard import render_report
    a = _mk(1, "high", "k1")
    fresh = db.get_job(a.id)
    fresh.status = JobStatus.SUCCEEDED
    fresh.pr_url = "https://github.com/o/r/pull/1"
    fresh.fix_strategy = "upgrade"
    db.update_job(fresh)

    b = _mk(2, "high", "k2")
    esc = db.get_job(b.id)
    esc.status = JobStatus.ESCALATED
    esc.fix_strategy = "escalate"
    esc.residual_risk_or_blocker = "Transitive pin conflicts with an incompatible parent."
    esc.error = "session ended without a successful PR"
    db.update_job(esc)

    html = render_report()
    assert "<th>Strategy</th>" in html
    assert "upgrade" in html
    # Escalations section prefers residual_risk_or_blocker over the generic error.
    assert "Transitive pin conflicts with an incompatible parent." in html
    assert "session ended without a successful PR" not in html
