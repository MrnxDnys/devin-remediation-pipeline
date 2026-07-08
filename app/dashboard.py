"""Observability layer: metrics API + the Devin-dark-mode leader dashboard + /report.

Everything here is derived purely from job state (``app.db``); this module owns no state
and never touches the orchestrator, so it can be included or dropped as a self-contained unit.
"""
from __future__ import annotations

import html
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse

from . import db
from .models import Job, JobStatus

router = APIRouter()

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
_DASHBOARD_HTML = os.path.join(_STATIC_DIR, "dashboard.html")

_SEVERITIES = ("critical", "high", "medium", "low")
_TERMINAL = (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.ESCALATED)


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

    active = by_status[JobStatus.QUEUED.value] + by_status[JobStatus.RUNNING.value]
    auto_fixed = by_status[JobStatus.SUCCEEDED.value]
    escalated = by_status[JobStatus.ESCALATED.value]

    prs_awaiting_review = sum(
        1 for j in jobs if j.status == JobStatus.SUCCEEDED and (j.pr_url or "").strip()
    )

    terminal = sum(by_status[s.value] for s in _TERMINAL)
    success_rate_pct = round(auto_fixed / terminal * 100, 1) if terminal else 0.0

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

    # Throughput: succeeded jobs per hour over the observed window (earliest created_at -> now).
    throughput_per_hour = 0.0
    created_times = [t for t in (_parse_ts(j.created_at) for j in jobs) if t]
    if auto_fixed and created_times:
        earliest = min(created_times)
        finished_times = [
            t for t in (_parse_ts(j.finished_at) for j in jobs) if t
        ]
        latest = max([datetime.now(timezone.utc)] + finished_times)
        window_hours = (latest - earliest).total_seconds() / 3600.0
        if window_hours > 1e-6:
            throughput_per_hour = round(auto_fixed / window_hours, 2)

    return {
        "total": total,
        "active": active,
        "by_status": by_status,
        "by_severity": by_severity,
        "auto_fixed": auto_fixed,
        "escalated": escalated,
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
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
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
        ("PRs awaiting review", m["prs_awaiting_review"]),
        ("Success rate", f'{m["success_rate_pct"]}%'),
        ("Mean time-to-remediation", _fmt_duration(m["mean_time_to_remediation_sec"])),
        ("Throughput / hour", m["throughput_per_hour"]),
    ]
    tiles_html = "".join(
        f'<div class="tile"><div class="cap">{_e(cap)}</div>'
        f'<div class="val">{_e(val)}</div></div>'
        for cap, val in tiles
    )

    sev = m["by_severity"]
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
            f"<td>{_status_badge(j.status.value)}</td>"
            f"<td>{pr}</td>"
            f"<td>{session}</td>"
            "</tr>"
        )
    table_html = "".join(rows) or (
        '<tr><td colspan="7" class="muted">No findings yet.</td></tr>'
    )

    if escalated:
        esc_items = []
        for j in escalated:
            blocker = (j.error or j.summary or "No blocker recorded.").strip()
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
<th>Status</th><th>PR</th><th>Session</th></tr></thead>
<tbody>{table_html}</tbody>
</table>

<h2>Escalations</h2>
{esc_html}
</body></html>"""


@router.get("/report", response_class=HTMLResponse)
def report_page() -> HTMLResponse:
    return HTMLResponse(render_report())
