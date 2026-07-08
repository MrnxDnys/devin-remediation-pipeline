"""End-to-end loop tests against the mock Devin client (no network, deterministic)."""
import time

import pytest

from app import db
from app.config import settings
from app.models import JobStatus


@pytest.fixture(autouse=True)
def fast_mock(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "db_path", str(tmp_path / "test.db"))
    monkeypatch.setattr(settings, "devin_mode", "mock")
    monkeypatch.setattr(settings, "poll_interval_seconds", 0)
    monkeypatch.setattr(settings, "session_timeout_seconds", 10)
    monkeypatch.setattr(settings, "max_retries", 1)
    monkeypatch.setattr(settings, "github_token", "")  # skip real GitHub writes
    db.init_db()
    yield
    from app import orchestrator
    orchestrator.join_workers()  # let background threads finish before db_path is reverted


def _wait(job_id, timeout=5):
    # A job is settled only once finished_at is set; an intermediate FAILED status during
    # the retry loop leaves finished_at empty, so waiting on it avoids a race.
    end = time.time() + timeout
    while time.time() < end:
        j = db.get_job(job_id)
        if j and j.finished_at:
            return j
        time.sleep(0.02)
    return db.get_job(job_id)


def _issue(number, vuln_id="GHSA-xxxx"):
    meta = (f'{{"dedup_key":"pip:Flask:{vuln_id}","package":"Flask","ecosystem":"pip",'
            f'"vulnerability_id":"{vuln_id}","fix_versions":"2.2.5"}}')
    return {"number": number, "title": f"Upgrade Flask ({vuln_id})",
            "body": f"body\n<!--devin-meta {meta} -->"}


def test_happy_path_opens_pr():
    from app import orchestrator
    job = orchestrator.enqueue(_issue(101))
    done = _wait(job.id)
    assert done.status == JobStatus.SUCCEEDED
    assert done.pr_url and "pull/" in done.pr_url
    assert done.attempts == 1


def test_failure_retries_then_escalates():
    from app import orchestrator
    # vulnerability_id "force-fail" makes the mock session fail deterministically.
    job = orchestrator.enqueue(_issue(102, vuln_id="force-fail"))
    done = _wait(job.id)
    assert done.status == JobStatus.ESCALATED
    assert done.attempts == 2  # initial + one retry


def test_duplicate_issue_ignored():
    from app import orchestrator
    orchestrator.enqueue(_issue(103))
    dup = orchestrator.enqueue(_issue(103))
    assert dup is None


def test_duplicate_advisory_across_issues_ignored():
    # Same advisory (dedup_key) filed under two different issue numbers must not 500.
    from app import orchestrator
    orchestrator.enqueue(_issue(110, vuln_id="GHSA-dup"))
    dup = orchestrator.enqueue(_issue(111, vuln_id="GHSA-dup"))
    assert dup is None


def test_blocked_session_escalates_without_retry():
    from app import orchestrator
    job = orchestrator.enqueue(_issue(112, vuln_id="force-block"))
    done = _wait(job.id)
    assert done.status == JobStatus.ESCALATED
    assert done.attempts == 1  # blocked -> no wasted retry


def test_structured_output_fields_persisted_on_success():
    from app import orchestrator
    job = orchestrator.enqueue(_issue(120))
    done = _wait(job.id)
    assert done.status == JobStatus.SUCCEEDED
    assert done.fix_strategy == "upgrade"
    assert done.tests_run
    assert done.residual_risk_or_blocker
    # And they survive a reload from SQLite (round-trip through create_job/update_job).
    reloaded = db.get_job(job.id)
    assert reloaded.fix_strategy == "upgrade"
    assert reloaded.residual_risk_or_blocker == done.residual_risk_or_blocker


def test_specific_blocker_persisted_on_escalation():
    from app import orchestrator
    job = orchestrator.enqueue(_issue(121, vuln_id="force-fail"))
    orchestrator.join_workers(timeout=10)  # settle past the retry before asserting
    done = db.get_job(job.id)
    assert done.status == JobStatus.ESCALATED
    # /report needs the SPECIFIC evidenced blocker, not a generic message.
    assert done.residual_risk_or_blocker
    assert "incompatible parent" in done.residual_risk_or_blocker
    assert done.fix_strategy == "escalate"


def test_new_fields_roundtrip_through_db():
    from app.models import Job
    job = db.create_job(Job(issue_number=130, issue_title="t", dedup_key="k:130"))
    job.fix_strategy = "dismiss-false-positive"
    job.tests_run = "pytest tests/security"
    job.residual_risk_or_blocker = "None: proven false positive (name collision)."
    db.update_job(job)
    reloaded = db.get_job(job.id)
    assert reloaded.fix_strategy == "dismiss-false-positive"
    assert reloaded.tests_run == "pytest tests/security"
    assert reloaded.residual_risk_or_blocker.startswith("None: proven")


def test_concurrency_cap_limits_running_sessions(monkeypatch):
    from app import orchestrator
    # Cap at 2; slow each mock session slightly so overlap is forced.
    monkeypatch.setattr(settings, "max_concurrent_sessions", 2)
    monkeypatch.setattr(settings, "poll_interval_seconds", 0.05)
    orchestrator.reset_concurrency_stats()

    jobs = [orchestrator.enqueue(_issue(140 + i, vuln_id=f"C{i}")) for i in range(6)]
    assert all(j is not None for j in jobs)
    orchestrator.join_workers(timeout=10)

    # The hard guarantee: never more than N sessions live at once...
    assert orchestrator.max_concurrent_observed <= 2
    # ...and the cap actually bound (with 6 jobs it must have saturated 2 slots).
    assert orchestrator.max_concurrent_observed == 2
    # All findings were eventually serviced (queued ones picked up as slots freed).
    assert all(db.get_job(j.id).status == JobStatus.SUCCEEDED for j in jobs)
