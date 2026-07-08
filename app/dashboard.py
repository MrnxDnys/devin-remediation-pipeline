"""Observability layer: metrics API + the Devin-dark-mode leader dashboard + /report.

Everything here is derived purely from job state (``app.db``); this module owns no state
and never touches the orchestrator, so it can be included or dropped as a self-contained unit.
"""
from __future__ import annotations

import html
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse

from . import db
from .models import REVIEW_VERDICTS, Job, JobStatus

router = APIRouter()

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
_DASHBOARD_HTML = os.path.join(_STATIC_DIR, "dashboard.html")

_SEVERITIES = ("critical", "high", "medium", "low")
_TERMINAL = (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.ESCALATED)

# Resting states: the true terminal outcomes a job comes to rest in, used as the success-rate
# denominator. FAILED is deliberately excluded - in this orchestrator a failed attempt either
# retries back to RUNNING or is escalated; only the unhandled-exception path in _run() leaves a
# job permanently FAILED. Counting transient FAILED would deflate the rate while a retry pends.
_RESTING = (JobStatus.SUCCEEDED, JobStatus.ESCALATED)

# "Open" findings = current open risk, not all-time. QUEUED/RUNNING are in-flight; ESCALATED is
# included because it still needs human action (not resolved). SUCCEEDED (fixed) and transient
# FAILED (a retry pending) are excluded.
_OPEN_STATUSES = (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.ESCALATED)


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def metrics_summary() -> dict:
    """Compute the leader-facing metrics purely from job state. Pure function; a test targets
    this exact name."""
    jobs = db.list_jobs()
    total = len(jobs)

    by_status = {s.value: 0 for s in JobStatus}
    for job in jobs:
        by_status[job.status.value] = by_status.get(job.status.value, 0) + 1

    by_severity = {sev: 0 for sev in _SEVERITIES}
    for job in jobs:
        sev = (job.severity or "").strip().lower()
        if sev in by_severity:
            by_severity[sev] += 1

    # Open findings by severity: computed over open (non-terminal) jobs only, so the dashboard's
    # "Open findings by severity" heading reflects open risk rather than every finding ever seen.
    open_by_severity = {sev: 0 for sev in _SEVERITIES}
    for job in jobs:
        if job.status not in _OPEN_STATUSES:
            continue
        sev = (job.severity or "").strip().lower()
        if sev in open_by_severity:
            open_by_severity[sev] += 1

    active = by_status[JobStatus.QUEUED.value] + by_status[JobStatus.RUNNING.value]
    auto_fixed = by_status[JobStatus.SUCCEEDED.value]
    escalated = by_status[JobStatus.ESCALATED.value]
    failed = by_status[JobStatus.FAILED.value]  # transient "in retry" signal; not a resting state

    # Named for API stability; semantically this is "PRs opened", not "awaiting review": nothing
    # updates a job after SUCCEEDED, so it never decreases when a human merges/closes the PR.
    prs_awaiting_review = sum(
        1 for j in jobs if j.status == JobStatus.SUCCEEDED and (j.pr_url or "").strip()
    )

    resting = sum(by_status[s.value] for s in _RESTING)
    success_rate_pct = round(auto_fixed / resting * 100, 1) if resting else 0.0

    # Mean time-to-remediation over succeeded jobs that carry both timestamps.
    durations: list[float] = []
    for j in jobs:
        if j.status != JobStatus.SUCCEEDED:
            continue
        created = _parse_ts(j.created_at)
        finished = _parse_ts(j.finished_at)
        if created and finished and finished >= created:
            durations.append((finished - created).total_seconds())
    mean_ttr = round(sum(durations) / len(durations), 1) if durations else 0.0

    # Throughput: a rolling 60-minute window ending now - the count of succeeded jobs whose
    # finished_at falls within the last hour, over a 1-hour window (i.e. just the in-window
    # count). This replaces the old all-time average anchored at the earliest created_at, which
    # decayed forever after a burst-then-idle run.
    #
    # We intentionally divide by the full hour (count / 1h) even for a young run, rather than
    # extrapolating over the elapsed sub-hour window (count / elapsed_hours): extrapolation
    # explodes for freshly-seeded data (a demo seeded seconds ago would report thousands/hour)
    # and, worse, *decays* as the window fills toward an hour - the opposite of what we want. The
    # plain in-window count is already sensible and non-decaying for an early demo: N fixes in the
    # last hour reads as N. Guarded for missing timestamps (-> 0.0).
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=1)
    recent_succeeded = [
        t
        for t in (_parse_ts(j.finished_at) for j in jobs if j.status == JobStatus.SUCCEEDED)
        if t and t >= window_start
    ]
    throughput_per_hour = round(float(len(recent_succeeded)), 2)

    return {
        "total": total,
        "active": active,
        "by_status": by_status,
        "by_severity": by_severity,
        "open_by_severity": open_by_severity,
        "auto_fixed": auto_fixed,
        "escalated": escalated,
        "failed": failed,
        "prs_awaiting_review": prs_awaiting_review,
        "success_rate_pct": success_rate_pct,
        "mean_time_to_remediation_sec": mean_ttr,
        "throughput_per_hour": throughput_per_hour,
    }


def serialize_job(job: Job) -> dict:
    """Serialise a Job to a JSON-friendly dict for the per-finding trace table."""
    return {
        "id": job.id,
        "issue_number": job.issue_number,
        "issue_title": job.issue_title,
        "severity": job.severity,
        "finding_type": job.finding_type,
        "advisory": job.vulnerability_id,
        "status": job.status.value,
        "fix_strategy": job.fix_strategy,
        "review_verdict": job.review_verdict,
        "pr_url": job.pr_url,
        "devin_session_url": job.devin_session_url,
        "summary": job.summary,
        "source": job.source,
        "package": job.package,
    }


@router.get("/api/metrics")
def api_metrics() -> JSONResponse:
    return JSONResponse(metrics_summary())


@router.get("/api/jobs")
def api_jobs() -> JSONResponse:
    return JSONResponse([serialize_job(j) for j in db.list_jobs()])


@router.get("/api/events")
def api_events(limit: int = Query(default=50, ge=1, le=500)) -> JSONResponse:
    return JSONResponse(db.list_events(limit=limit))


@router.get("/", response_class=HTMLResponse)
def dashboard_page() -> HTMLResponse:
    with open(_DASHBOARD_HTML, encoding="utf-8") as fh:
        return HTMLResponse(fh.read())


# --- /report: a standalone, shareable post-run summary rendered server-side ------------------

_TOKENS = {
    "bg": "#0b0b0d", "panel": "#141417", "border": "#242428", "text": "#ededf0",
    "muted": "#86868c", "accent": "#8b5cf6", "success": "#3fb950", "amber": "#e0912f",
    "danger": "#f0563f",
}

_REPORT_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:%(bg)s;color:%(text)s;font-family:Inter,system-ui,sans-serif;
  line-height:1.5;padding:32px;max-width:1100px;margin:0 auto}
h1{font-size:22px;font-weight:600;margin-bottom:4px}
h2{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;
  color:%(muted)s;margin:32px 0 12px}
.sub{color:%(muted)s;font-size:13px;margin-bottom:24px}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
@media(max-width:1000px){.tiles{grid-template-columns:repeat(2,1fr)}}
@media(max-width:560px){.tiles{grid-template-columns:1fr}}
.tile{background:%(panel)s;border:1px solid %(border)s;border-radius:10px;padding:16px}
.tile .cap{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:%(muted)s}
.tile .val{font-size:26px;font-weight:600;margin-top:6px}
.sev{display:flex;gap:10px;flex-wrap:wrap;margin-top:4px}
.sev .chip{background:%(panel)s;border:1px solid %(border)s;border-radius:10px;
  padding:10px 14px;font-size:13px}
.sev .n{font-weight:600;font-size:16px}
table{width:100%%;border-collapse:collapse;background:%(panel)s;border:1px solid %(border)s;
  border-radius:10px;overflow:hidden;font-size:13px}
th{text-align:left;text-transform:uppercase;letter-spacing:.06em;font-size:11px;
  color:%(muted)s;font-weight:600;padding:10px 12px;border-bottom:1px solid %(border)s}
td{padding:10px 12px;border-bottom:1px solid %(border)s;vertical-align:top}
tr:last-child td{border-bottom:none}
a{color:%(accent)s;text-decoration:none}
a:hover{text-decoration:underline}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;
  text-transform:uppercase;letter-spacing:.04em}
.b-succeeded{background:rgba(63,185,80,.15);color:%(success)s}
.b-failed,.b-escalated{background:rgba(240,86,63,.15);color:%(danger)s}
.b-running{background:rgba(139,92,246,.15);color:%(accent)s}
.b-queued{background:rgba(134,134,140,.15);color:%(muted)s}
.b-approve{background:rgba(63,185,80,.15);color:%(success)s}
.b-request_changes{background:rgba(224,145,47,.15);color:%(amber)s}
.b-reject{background:rgba(240,86,63,.15);color:%(danger)s}
.s-critical{color:%(danger)s;font-weight:600}
.s-high{color:%(amber)s;font-weight:600}
.s-medium,.s-low{color:%(muted)s}
.esc{background:%(panel)s;border:1px solid %(border)s;border-left:3px solid %(danger)s;
  border-radius:10px;padding:14px 16px;margin-bottom:10px}
.esc .t{font-weight:600;margin-bottom:6px}
.esc .blk{color:%(muted)s;font-size:13px}
.muted{color:%(muted)s}
""" % _TOKENS


def _e(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _fmt_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


def _status_badge(status: str) -> str:
    return f'<span class="badge b-{_e(status)}">{_e(status)}</span>'


def _severity_cell(severity: str) -> str:
    sev = (severity or "").strip().lower()
    cls = f"s-{sev}" if sev in _SEVERITIES else "muted"
    return f'<span class="{cls}">{_e(severity)}</span>'


def _strategy_cell(strategy: str | None) -> str:
    if not (strategy or "").strip():
        return '<span class="muted">-</span>'
    return _e(strategy)


def _review_cell(verdict: str | None) -> str:
    v = (verdict or "").strip().lower()
    if v not in REVIEW_VERDICTS:
        return '<span class="muted">-</span>'
    return f'<span class="badge b-{_e(v)}">{_e(v.replace("_", " "))}</span>'


def render_report() -> str:
    m = metrics_summary()
    jobs = db.list_jobs()
    escalated = [j for j in jobs if j.status == JobStatus.ESCALATED]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    tiles = [
        ("Findings", m["total"]),
        ("Active", m["active"]),
        ("Auto-fixed", m["auto_fixed"]),
        ("Escalated", m["escalated"]),
        # Display label "PRs opened": the JSON key stays prs_awaiting_review for API stability,
        # but the metric only ever counts PRs opened (it never decreases on human merge/close).
        ("PRs opened", m["prs_awaiting_review"]),
        ("Success rate", f'{m["success_rate_pct"]}%'),
        ("Mean time-to-remediation", _fmt_duration(m["mean_time_to_remediation_sec"])),
        ("Throughput / hour", m["throughput_per_hour"]),
    ]
    tiles_html = "".join(
        f'<div class="tile"><div class="cap">{_e(cap)}</div>'
        f'<div class="val">{_e(val)}</div></div>'
        for cap, val in tiles
    )

    sev = m["open_by_severity"]
    sev_html = "".join(
        f'<div class="chip"><span class="{("s-"+s) if s in _SEVERITIES else "muted"}">'
        f'{_e(s)}</span> <span class="n">{sev.get(s, 0)}</span></div>'
        for s in _SEVERITIES
    )

    rows = []
    for j in jobs:
        pr = (f'<a href="{_e(j.pr_url)}">PR</a>' if (j.pr_url or "").strip() else
              '<span class="muted">-</span>')
        session = (f'<a href="{_e(j.devin_session_url)}">session</a>'
                   if (j.devin_session_url or "").strip() else '<span class="muted">-</span>')
        rows.append(
            "<tr>"
            f'<td>#{_e(j.issue_number)} {_e(j.issue_title)}</td>'
            f"<td>{_severity_cell(j.severity)}</td>"
            f"<td>{_e(j.finding_type)}</td>"
            f'<td class="muted">{_e(j.vulnerability_id)}</td>'
            f"<td>{_strategy_cell(j.fix_strategy)}</td>"
            f"<td>{_review_cell(j.review_verdict)}</td>"
            f"<td>{_status_badge(j.status.value)}</td>"
            f"<td>{pr}</td>"
            f"<td>{session}</td>"
            "</tr>"
        )
    table_html = "".join(rows) or (
        '<tr><td colspan="9" class="muted">No findings yet.</td></tr>'
    )

    # Review gate: independent Devin verdicts that block merge (request_changes / reject).
    flagged = [j for j in jobs
               if (j.review_verdict or "").strip().lower() in ("request_changes", "reject")]
    if flagged:
        gate_items = []
        for j in flagged:
            gate_items.append(
                f'<div class="esc"><div class="t">#{_e(j.issue_number)} '
                f'{_e(j.issue_title)} &middot; {_review_cell(j.review_verdict)}</div>'
                f'<div class="blk">{_e(j.review_summary or "No detail recorded.")}</div></div>'
            )
        gate_html = "".join(gate_items)
    else:
        gate_html = ('<div class="muted">No blocking review verdicts - '
                     'every reviewed PR was approved by the independent gate.</div>')

    if escalated:
        esc_items = []
        for j in escalated:
            blocker = (j.residual_risk_or_blocker or j.error or j.summary
                       or "No blocker recorded.").strip()
            esc_items.append(
                f'<div class="esc"><div class="t">#{_e(j.issue_number)} '
                f'{_e(j.issue_title)}</div>'
                f'<div class="blk">{_e(blocker)}</div></div>'
            )
        esc_html = "".join(esc_items)
    else:
        esc_html = '<div class="muted">No escalations - every terminal finding was resolved.</div>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Remediation Report</title>
<style>{_REPORT_CSS}</style></head>
<body>
<h1>Security-Remediation Report</h1>
<div class="sub">Generated {generated} &middot; derived from pipeline job state</div>

<div class="tiles">{tiles_html}</div>

<h2>Open findings by severity</h2>
<div class="sev">{sev_html}</div>

<h2>Per-finding trace</h2>
<table>
<thead><tr><th>Issue</th><th>Severity</th><th>Type</th><th>Advisory</th>
<th>Strategy</th><th>Review</th><th>Status</th><th>PR</th><th>Session</th></tr></thead>
<tbody>{table_html}</tbody>
</table>

<h2>Review gate</h2>
{gate_html}

<h2>Escalations</h2>
{esc_html}
</body></html>"""


@router.get("/report", response_class=HTMLResponse)
def report_page() -> HTMLResponse:
    return HTMLResponse(render_report())
