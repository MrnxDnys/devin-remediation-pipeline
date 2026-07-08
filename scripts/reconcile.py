"""Reconcile in-flight jobs against their Devin sessions.

Devin sessions often keep running ("awaiting instructions") after opening a PR, and a job's
poller lives in a background thread - so if the app restarts (e.g. a rebuild), a job can be left
stuck RUNNING in the DB with no thread to resolve it, even though its PR is already open/merged.

This re-polls every RUNNING job's session and, if the session opened a PR, marks the job
succeeded with that PR (same rule the orchestrator now uses). It never wipes jobs.

Run:  docker compose exec pipeline python -m scripts.reconcile      # shares the app's DB
  or: python -m scripts.reconcile                                   # native, reads .env.local
"""
from datetime import datetime, timezone

from app import db
from app.devin_client import get_client
from app.models import JobStatus


def main() -> None:
    db.init_db()
    client = get_client()
    running = [j for j in db.list_jobs() if j.status == JobStatus.RUNNING]
    print(f"{len(running)} RUNNING job(s) to reconcile")
    for job in running:
        if not job.devin_session_id:
            print(f"  #{job.issue_number}: no session id, skipping")
            continue
        detail = client.get_session(job.devin_session_id)
        out = detail.get("structured_output") or {}
        pr_url = out.get("pr_url") or (detail.get("pull_request") or {}).get("url")
        if pr_url and out.get("success") is not False:
            job.status = JobStatus.SUCCEEDED
            job.pr_url = pr_url
            job.summary = out.get("summary") or job.summary
            job.fix_strategy = out.get("fix_strategy") or job.fix_strategy
            job.tests_run = out.get("tests_run") or job.tests_run
            job.residual_risk_or_blocker = (
                out.get("residual_risk_or_blocker") or job.residual_risk_or_blocker
            )
            if detail.get("acu_used") is not None:
                job.acu_used = detail.get("acu_used")
            job.finished_at = datetime.now(timezone.utc).isoformat()
            db.update_job(job)
            db.add_event("reconciled", f"#{job.issue_number} resolved from session: {pr_url}", job.id)
            print(f"  #{job.issue_number}: -> succeeded  {pr_url}")
        else:
            print(f"  #{job.issue_number}: no PR yet (session status {detail.get('status_enum')})")


if __name__ == "__main__":
    main()
