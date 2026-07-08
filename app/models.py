"""Domain models shared across scanner, orchestrator, dashboard."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class JobStatus(str, Enum):
    QUEUED = "queued"        # finding accepted, no session yet
    RUNNING = "running"      # Devin session live
    SUCCEEDED = "succeeded"  # session finished with a PR (fix or evidenced dismissal)
    FAILED = "failed"        # session finished without success (may retry)
    ESCALATED = "escalated"  # retries exhausted / blocked -> handed to a human


# Devin v3 session states. Terminal = the session is done; blocked = suspended awaiting
# human input (we escalate rather than hang until timeout).
DEVIN_TERMINAL_STATES = {"exit", "error"}
DEVIN_BLOCKED_STATES = {"suspended"}

# Where a finding came from - so the pipeline can show provenance (scanners and Cognition's
# Security Swarm FIND; this system FIXES).
FINDING_SOURCES = {"pip-audit", "npm-audit", "security-swarm", "manual"}


class Finding(BaseModel):
    """One remediable security finding, normalised across scanners and Swarm.

    `finding_type` routes intent inside the one security-remediation Playbook:
      dependency - a vulnerable package (upgrade / transitive / removal)
      code       - a code-level vulnerability (business-logic fix, e.g. a privesc chain)
    """
    finding_type: str = "dependency"       # "dependency" | "code"
    source: str = "pip-audit"              # see FINDING_SOURCES
    severity: str = "medium"               # critical | high | medium | low
    title: str = ""
    ecosystem: str = ""                    # pip | npm (dependency findings)
    package: str = ""
    installed_version: str | None = None
    vulnerability_id: str = ""             # GHSA / CVE / Swarm id
    fix_versions: list[str] = []
    location: str = ""                     # file/path for a code finding
    description: str = ""

    def dedup_key(self) -> str:
        if self.package:
            return f"{self.ecosystem}:{self.package}:{self.vulnerability_id}"
        return f"code:{self.vulnerability_id or self.location}"


class Job(BaseModel):
    """A single remediation unit: one finding -> one Devin session -> one outcome."""
    id: int | None = None
    issue_number: int
    issue_title: str
    dedup_key: str = ""
    finding_type: str = "dependency"
    source: str = ""
    severity: str = "medium"
    ecosystem: str = ""
    package: str = ""
    vulnerability_id: str = ""
    fix_versions: str = ""            # comma-joined for storage

    status: JobStatus = JobStatus.QUEUED
    attempts: int = 0
    devin_session_id: str | None = None
    devin_session_url: str | None = None
    pr_url: str | None = None
    summary: str | None = None
    fix_strategy: str | None = None            # upgrade | transitive | removal | code-fix | dismiss-false-positive | escalate
    tests_run: str | None = None               # what Devin ran to verify
    residual_risk_or_blocker: str | None = None  # residual risk, or the specific blocker if unsuccessful
    # Independent review-gate verdict on the opened PR (a second, independent Devin session).
    review_verdict: str | None = None          # approve | request_changes | reject
    review_summary: str | None = None          # reviewer's one-line rationale + blocking issues
    review_session_url: str | None = None       # the independent reviewer session
    error: str | None = None
    acu_used: float | None = None

    created_at: str = ""
    started_at: str | None = None
    finished_at: str | None = None


# JSON Schema handed to Devin so its structured_output is machine-parseable. Mirrors the
# fields the security-remediation Playbook promises to return.
STRUCTURED_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "success": {
            "type": "boolean",
            "description": "true only if a PR was opened (a fix, or an evidenced dismissal)",
        },
        "pr_url": {"type": "string", "description": "URL of the opened PR, or empty string"},
        "summary": {"type": "string", "description": "one-sentence description of the change"},
        "fix_strategy": {
            "type": "string",
            "description": "upgrade | transitive | removal | code-fix | dismiss-false-positive | escalate",
        },
        "tests_run": {"type": "string", "description": "what was run to verify"},
        "residual_risk_or_blocker": {
            "type": "string",
            "description": "residual risk, or the specific blocker if success=false",
        },
    },
    "required": ["success", "summary"],
}


# JSON Schema for the independent review-gate session. A SECOND Devin session audits the
# fixer's PR and returns this adversarial verdict; the orchestrator records + comments it.
REVIEW_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["approve", "request_changes", "reject"],
            "description": "approve | request_changes | reject",
        },
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "reviewer's confidence in the verdict",
        },
        "blocking_issues": {
            "type": "array",
            "items": {"type": "string"},
            "description": "concrete problems that block merge",
        },
        "checked": {
            "type": "array",
            "items": {"type": "string"},
            "description": "what the reviewer independently verified",
        },
        "summary": {"type": "string", "description": "one-sentence review rationale"},
    },
    "required": ["verdict", "summary"],
}

# Review verdicts. approve = mergeable; request_changes = fixable problems; reject = do not merge.
REVIEW_VERDICTS = {"approve", "request_changes", "reject"}
