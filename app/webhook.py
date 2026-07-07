"""Trigger layer: GitHub webhook (inner) + a scan trigger (outer) + a simulate endpoint
so the whole loop is demonstrable without a public tunnel."""
from __future__ import annotations

import hashlib
import hmac

from fastapi import APIRouter, Header, HTTPException, Request

from . import db, orchestrator, scanner
from .config import settings

router = APIRouter()


def _verify_signature(body: bytes, signature: str | None) -> bool:
    secret = settings.github_webhook_secret.encode()
    if not signature or not secret:
        return False
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
):
    body = await request.body()
    # Signature is enforced only when a real secret is configured.
    if settings.github_webhook_secret not in ("", "change_me"):
        if not _verify_signature(body, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="invalid signature")

    payload = await request.json()
    if x_github_event != "issues":
        return {"ignored": f"event {x_github_event}"}
    return _handle_issue_event(payload)


@router.post("/trigger/simulate")
async def simulate(payload: dict):
    """Simulate a GitHub `issues.labeled` webhook. Body: {number, title, body?, label?}."""
    event = {
        "action": "labeled",
        "label": {"name": payload.get("label", settings.devin_trigger_label)},
        "issue": {
            "number": payload["number"],
            "title": payload.get("title", f"Issue #{payload['number']}"),
            "body": payload.get("body", ""),
            "labels": [{"name": payload.get("label", settings.devin_trigger_label)}],
        },
    }
    return _handle_issue_event(event)


@router.post("/scan")
async def trigger_scan():
    """Run the scanner now: audit the fork and file labelled issues (outer trigger)."""
    findings = scanner.run_scan()
    numbers = scanner.create_issues(findings)
    db.add_event("scan_complete", f"{len(findings)} findings, {len(numbers)} issues filed")
    return {"findings": len(findings), "issues_created": numbers}


def _handle_issue_event(payload: dict) -> dict:
    action = payload.get("action")
    label = (payload.get("label") or {}).get("name")
    issue = payload.get("issue") or {}
    if action != "labeled" or label != settings.devin_trigger_label:
        return {"ignored": f"action={action} label={label}"}
    job = orchestrator.enqueue(issue)
    if job is None:
        return {"status": "duplicate", "issue": issue.get("number")}
    return {"status": "queued", "issue": issue.get("number"), "job_id": job.id}
