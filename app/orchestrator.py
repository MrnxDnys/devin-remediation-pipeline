"""The core: turn a labelled issue into a managed Devin session and a decided outcome.

Flow per issue:
    queue -> create Devin session (with structured-output contract + ACU cap)
          -> poll until terminal
          -> parse structured_output -> success? comment PR + close loop
                                        failure? retry once, else escalate to a human
"""
from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime, timezone

from . import db, github_client
from .config import settings
from .devin_client import get_client
from .models import (
    DEVIN_BLOCKED_STATES,
    DEVIN_TERMINAL_STATES,
    REVIEW_VERDICT_SCHEMA,
    REVIEW_VERDICTS,
    STRUCTURED_OUTPUT_SCHEMA,
    Job,
    JobStatus,
)

# Map a review verdict to the event kind recorded on the timeline.
_REVIEW_EVENTS = {
    "approve": "review_approved",
    "request_changes": "review_changes_requested",
    "reject": "review_rejected",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_prompt(job: Job) -> str:
    """The task handed to Devin. The security-remediation Playbook (invoked by
    `playbook_id`) carries the procedure and fix-strategy branching; this prompt just
    scopes the single finding and the write-back contract."""
    if job.finding_type == "code":
        target = f"""Finding type: code-level security vulnerability
Advisory / id: {job.vulnerability_id or 'n/a'}
Severity: {job.severity}
Where: see the issue body for the location and reproduction detail."""
    else:
        fixes = job.fix_versions or "the latest patched version"
        target = f"""Finding type: dependency vulnerability
Advisory: {job.vulnerability_id}
Package: {job.package} ({job.ecosystem})
Severity: {job.severity}
Fixed in: {fixes}"""

    return f"""You are remediating a SINGLE security finding in the repository
`{settings.github_repo}` (a fork of apache/superset), tracked by GitHub issue
#{job.issue_number}: "{job.issue_title}".

{target}

Follow the security-remediation Playbook: triage first (a finding may be a false
positive - if so, dismiss it with evidence rather than deleting good code), then choose
the correct strategy (dependency upgrade / transitive fix / removal / code fix), implement
it so the codebase still works, and verify with the narrowest relevant tests.

Open a pull request against the default branch referencing this issue ("Fixes
#{job.issue_number}"), with a body that states the strategy, the changes, and the test
evidence. Keep the diff minimal and reviewable. Do NOT merge - a human approves.

If it cannot be done safely, STOP and return success=false with a specific, evidenced
blocker. Return structured output per the Playbook's schema (at minimum: success, pr_url,
summary)."""


def enqueue(issue: dict) -> Job | None:
    """Accept a GitHub issue payload and start remediation in the background.
    Returns the Job (or None if it was a duplicate already in flight)."""
    number = issue["number"]
    meta = _parse_issue_meta(issue)
    dedup_key = meta.get("dedup_key", f"issue:{number}")

    active = (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.SUCCEEDED)
    for existing in (db.get_job_by_issue(number), db.get_job_by_dedup(dedup_key)):
        if existing and existing.status in active:
            db.add_event("duplicate_ignored", f"Issue #{number} already tracked", existing.id)
            return None

    job = Job(
        issue_number=number,
        issue_title=issue.get("title", f"Issue #{number}"),
        dedup_key=dedup_key,
        finding_type=meta.get("finding_type", "dependency"),
        source=meta.get("source", "manual"),
        severity=meta.get("severity", "medium"),
        ecosystem=meta.get("ecosystem", ""),
        package=meta.get("package", ""),
        vulnerability_id=meta.get("vulnerability_id", ""),
        fix_versions=meta.get("fix_versions", ""),
        status=JobStatus.QUEUED,
    )
    try:
        job = db.create_job(job)
    except sqlite3.IntegrityError:
        db.add_event("duplicate_ignored", f"#{number} duplicate advisory {dedup_key}")
        return None
    t = threading.Thread(target=_run, args=(job,), daemon=True)
    _workers.append(t)
    t.start()
    return job


# Track worker threads so tests can wait for them deterministically.
_workers: list[threading.Thread] = []

# Concurrency governance: cap how many sessions run against Devin at once. Findings whose
# worker thread is blocked here stay QUEUED (no session created yet) until a slot frees.
_slots_lock = threading.Lock()
_slots: threading.BoundedSemaphore | None = None
_slots_size: int = 0

# Observability for tests: peak number of jobs holding a session slot simultaneously.
_concurrency_lock = threading.Lock()
_concurrent_now = 0
max_concurrent_observed = 0


def _session_slots() -> threading.BoundedSemaphore:
    """Return the shared concurrency gate, (re)sized to the current setting."""
    global _slots, _slots_size
    desired = max(1, settings.max_concurrent_sessions)
    with _slots_lock:
        if _slots is None or _slots_size != desired:
            _slots = threading.BoundedSemaphore(desired)
            _slots_size = desired
        return _slots


def reset_concurrency_stats() -> None:
    global _concurrent_now, max_concurrent_observed
    with _concurrency_lock:
        _concurrent_now = 0
        max_concurrent_observed = 0


def join_workers(timeout: float = 5.0) -> None:
    for t in list(_workers):
        t.join(timeout)
    _workers[:] = [t for t in _workers if t.is_alive()]


def _run(job: Job) -> None:
    """Full lifecycle for one job (background thread). Blocks on a concurrency slot first
    (staying QUEUED until one frees), then retries transient failures and escalates a
    blocked session or exhausted retries to a human."""
    slots = _session_slots()
    slots.acquire()
    global _concurrent_now, max_concurrent_observed
    with _concurrency_lock:
        _concurrent_now += 1
        max_concurrent_observed = max(max_concurrent_observed, _concurrent_now)
    try:
        while True:
            outcome = _attempt(job)
            if outcome == "success":
                # The independent review gate runs INSIDE this same slot - a job holds one
                # slot across fix + review, so we never acquire a second (which could
                # deadlock when the pool is full). A job may thus use 2 sessions serially.
                _maybe_review(job)
                return
            if outcome == "retry" and job.attempts <= settings.max_retries:
                db.add_event("retry", f"Retrying #{job.issue_number} (attempt {job.attempts + 1})", job.id)
                continue
            break
        _escalate(job)
    except Exception as e:  # never let a worker thread die silently
        job.status = JobStatus.FAILED
        job.error = f"{type(e).__name__}: {e}"
        job.finished_at = _now()
        db.update_job(job)
        db.add_event("error", job.error, job.id)
    finally:
        with _concurrency_lock:
            _concurrent_now -= 1
        slots.release()


def _attempt(job: Job) -> str:
    """Run one Devin session. Returns 'success' | 'retry' | 'give_up'."""
    client = get_client()
    job.attempts += 1
    job.status = JobStatus.RUNNING
    job.started_at = job.started_at or _now()
    db.update_job(job)

    tags = [f"issue-{job.issue_number}", "superset-security", job.severity,
            job.finding_type, job.vulnerability_id or "finding"]
    subject = job.package or job.vulnerability_id or f"issue #{job.issue_number}"
    created = client.create_session(
        prompt=build_prompt(job),
        title=f"Remediate {subject} ({job.severity}) #{job.issue_number}",
        tags=tags,
        schema=STRUCTURED_OUTPUT_SCHEMA,
        playbook_id=settings.devin_playbook_id or None,
    )
    job.devin_session_id = created["session_id"]
    job.devin_session_url = created.get("url")
    db.update_job(job)
    db.add_event("session_created", f"Devin session {job.devin_session_id}", job.id)

    detail = _poll_until_terminal(client, job.devin_session_id, job)
    if detail is None:  # timed out - transient, worth a retry
        job.status = JobStatus.FAILED
        job.error = "session exceeded timeout"
        db.update_job(job)
        db.add_event("failed", job.error, job.id)
        return "retry"

    out = detail.get("structured_output") or {}
    job.acu_used = detail.get("acu_used")
    status = (detail.get("status_enum") or "").lower()
    pr_url = out.get("pr_url") or (detail.get("pull_request") or {}).get("url")

    # Persist the rich triage fields (present on both success and failure) so the
    # leader-facing trace/report can tell the "triage, not just patch" story.
    job.fix_strategy = out.get("fix_strategy")
    job.tests_run = out.get("tests_run")
    job.residual_risk_or_blocker = out.get("residual_risk_or_blocker")

    if out.get("success") and pr_url:
        job.status = JobStatus.SUCCEEDED
        job.pr_url = pr_url
        job.summary = out.get("summary")
        job.finished_at = _now()
        db.update_job(job)
        _comment_success(job)
        db.add_event("succeeded", f"PR opened: {pr_url}", job.id)
        return "success"

    job.status = JobStatus.FAILED
    job.summary = out.get("summary")
    if status in DEVIN_BLOCKED_STATES:  # awaiting human input - retry won't help
        job.error = "session suspended awaiting human input"
        db.update_job(job)
        db.add_event("blocked", job.error, job.id)
        return "give_up"
    job.error = "session ended without a successful PR"
    db.update_job(job)
    db.add_event("failed", job.error, job.id)
    return "retry"


def _poll_until_terminal(client, session_id: str, job: Job) -> dict | None:
    """Poll the given session until it is terminal or blocked; None on timeout."""
    deadline = time.time() + settings.session_timeout_seconds
    stop = DEVIN_TERMINAL_STATES | DEVIN_BLOCKED_STATES
    while time.time() < deadline:
        detail = client.get_session(session_id)
        if (detail.get("status_enum") or "").lower() in stop:
            return detail
        time.sleep(settings.poll_interval_seconds)
    db.add_event("timeout", f"#{job.issue_number} exceeded session timeout", job.id)
    return None


def build_review_prompt(job: Job) -> str:
    """Prompt for the SECOND, independent reviewer session. Makes clear the reviewer did not
    write the PR and must be adversarial."""
    finding = (f"the {job.finding_type} finding {job.vulnerability_id or ''}".strip()
               + (f" in {job.package}" if job.package else ""))
    return f"""Independently review PR {job.pr_url} that remediates {finding} in the
repository `{settings.github_repo}` (a fork of apache/superset), tracked by GitHub issue
#{job.issue_number}: "{job.issue_title}".

You did NOT write this PR. Be adversarial. Independently verify that:
- it actually fixes the vulnerability (not just silences a scanner);
- the diff is correct, minimal, and safe;
- it introduces no regressions or new issues (including leaked secrets);
- the tests are adequate for the change.

Do NOT push commits or merge. Return the review verdict per the provided schema: a
`verdict` of approve | request_changes | reject, your `confidence`, concrete
`blocking_issues` that block merge, what you `checked`, and a one-sentence `summary`."""


def _maybe_review(job: Job) -> None:
    """Run the independent review gate on a freshly-opened PR, if enabled. Only SUCCEEDED
    jobs that actually opened a PR are reviewed (failed/escalated/no-PR are skipped)."""
    if not settings.enable_review_gate:
        return
    if job.status != JobStatus.SUCCEEDED or not (job.pr_url or "").strip():
        return
    _review(job)


def _review(job: Job) -> None:
    """Second, independent Devin session that audits the fixer's PR and records a verdict.
    Comment-only: never merges. Runs inside the job's existing concurrency slot."""
    client = get_client()
    tags = ["review", f"issue-{job.issue_number}", job.finding_type, job.severity,
            job.vulnerability_id or "finding"]
    created = client.create_session(
        prompt=build_review_prompt(job),
        title=f"Review remediation PR for #{job.issue_number} ({job.severity})",
        tags=tags,
        schema=REVIEW_VERDICT_SCHEMA,
        playbook_id=None,  # review is an independent audit, not the remediation Playbook
    )
    job.review_session_url = created.get("url")
    db.update_job(job)
    db.add_event("review_started",
                 f"Independent review session {created['session_id']}", job.id)

    detail = _poll_until_terminal(client, created["session_id"], job)
    if detail is None:
        db.add_event("review_timeout", f"#{job.issue_number} review session timed out", job.id)
        return

    out = detail.get("structured_output") or {}
    verdict = (out.get("verdict") or "").strip().lower()
    if verdict not in REVIEW_VERDICTS:
        db.add_event("review_error",
                     f"#{job.issue_number} review returned no valid verdict", job.id)
        return

    blocking = [str(b).strip() for b in (out.get("blocking_issues") or []) if str(b).strip()]
    summary = (out.get("summary") or "").strip()
    review_summary = summary
    if blocking:
        review_summary = (summary + " Blocking: " + "; ".join(blocking)).strip()

    job.review_verdict = verdict
    job.review_summary = review_summary or None
    db.update_job(job)
    detail_msg = f"#{job.issue_number} review: {verdict}"
    if blocking:
        detail_msg += f" ({len(blocking)} blocking issue(s))"
    db.add_event(_REVIEW_EVENTS[verdict], detail_msg, job.id)
    _comment_review(job, verdict, blocking)

    # Comment-only default: even when opted in, only RECORD a would-merge decision here.
    if settings.auto_merge_on_approve and verdict == "approve" and not blocking:
        db.add_event("would_auto_merge",
                     f"#{job.issue_number} gate passed - would auto-merge (not merging)", job.id)


def _comment_review(job: Job, verdict: str, blocking: list[str]) -> None:
    lines = [
        f"**Independent Devin review gate**: `{verdict}`",
        "",
        f"> {job.review_summary or ''}",
    ]
    if blocking:
        lines += ["", "Blocking issues:"] + [f"- {b}" for b in blocking]
    lines += [
        "",
        f"Reviewer session: {job.review_session_url}",
        "_A second, independent Devin session audited this PR. Comment-only - a human still "
        "approves and merges._",
    ]
    body = "\n".join(lines)
    _safe_github(lambda: github_client.comment_issue(job.issue_number, body))


def _comment_success(job: Job) -> None:
    body = (
        f"Devin opened a pull request to remediate this issue: {job.pr_url}\n\n"
        f"> {job.summary or ''}\n\n"
        f"Session: {job.devin_session_url}\n"
        f"_Automated by the Devin remediation pipeline. A human review is required before merge._"
    )
    _safe_github(lambda: github_client.comment_issue(job.issue_number, body))


def _escalate(job: Job) -> None:
    job.status = JobStatus.ESCALATED
    job.finished_at = _now()
    db.update_job(job)
    db.add_event("escalated", f"#{job.issue_number} escalated to a human", job.id)
    body = (
        f"Devin could not automatically remediate this issue after {job.attempts} attempt(s).\n"
        f"Last session: {job.devin_session_url}\n\n"
        f"Labelling `{settings.devin_failed_label}` for human attention."
    )
    _safe_github(lambda: github_client.comment_issue(job.issue_number, body))
    _safe_github(lambda: github_client.add_label(job.issue_number, settings.devin_failed_label))


def _safe_github(fn) -> None:
    """GitHub writes are best-effort in mock/no-token mode; never crash the worker."""
    if not settings.github_token or settings.github_token.startswith("ghp_replace"):
        return
    try:
        fn()
    except Exception as e:
        db.add_event("github_error", f"{type(e).__name__}: {e}")


def _parse_issue_meta(issue: dict) -> dict:
    """Findings are embedded as an HTML comment in the issue body by the scanner.
    Fall back to empty metadata for manually-labelled issues."""
    import json
    import re

    body = issue.get("body") or ""
    m = re.search(r"<!--devin-meta\s+(\{.*?\})\s*-->", body, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    return {}
