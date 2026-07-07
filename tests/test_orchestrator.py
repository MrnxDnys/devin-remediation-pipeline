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
    from app.orchestrator import JobStatus as JS
    end = time.time() + timeout
    while time.time() < end:
        j = db.get_job(job_id)
        if j and j.status in (JS.SUCCEEDED, JS.FAILED, JS.ESCALATED):
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
