"""Devin API client. Live (v3 org-scoped Sessions API) + Mock, behind one interface.

The orchestrator depends only on:
    create_session(prompt, title, tags, schema) -> {session_id, url}
    get_session(session_id) -> {status_enum, structured_output, pull_request, acu_used}

get_session returns a NORMALISED shape, so the orchestrator is API-version agnostic -
swapping the API surface (as we did from v1 to v3) is contained entirely to this file.
"""
from __future__ import annotations

import hashlib
from typing import Protocol

import httpx

from .config import settings


class DevinClient(Protocol):
    def create_session(
        self, prompt: str, title: str, tags: list[str], schema: dict,
        playbook_id: str | None = None,
    ) -> dict: ...
    def get_session(self, session_id: str) -> dict: ...


class LiveDevinClient:
    """Devin v3 org-scoped Sessions API, authenticated with a service-user `cog_` key.

    POST/GET https://api.devin.ai/v3/organizations/{org_id}/sessions[/{id}]
    """

    def __init__(self) -> None:
        self._http = httpx.Client(
            base_url=f"{settings.devin_api_base}/organizations/{settings.devin_org_id}",
            headers={"Authorization": f"Bearer {settings.devin_api_key}"},
            timeout=30.0,
        )

    def create_session(
        self, prompt: str, title: str, tags: list[str], schema: dict,
        playbook_id: str | None = None,
    ) -> dict:
        body: dict = {
            "prompt": prompt,
            "title": title,
            "tags": tags,
            "structured_output_schema": schema,
            "repos": [f"github.com/{settings.github_repo}"],  # target repo for Devin
        }
        if playbook_id:
            body["playbook_id"] = playbook_id  # the security-remediation procedure
        if settings.devin_max_acu:
            body["max_acu_limit"] = settings.devin_max_acu  # budget guardrail
        r = self._http.post("/sessions", json=body)
        r.raise_for_status()
        d = r.json()
        return {"session_id": d["session_id"], "url": d.get("url")}

    def get_session(self, session_id: str) -> dict:
        r = self._http.get(f"/sessions/{session_id}")
        r.raise_for_status()
        return _normalise(r.json())


def _normalise(d: dict) -> dict:
    """Map a v3 SessionResponse to the orchestrator's canonical shape."""
    prs = d.get("pull_requests") or []
    pr_url = (prs[0] or {}).get("url") if prs else None
    return {
        "status_enum": d.get("status"),
        "structured_output": d.get("structured_output"),
        "pull_request": {"url": pr_url} if pr_url else None,
        "acu_used": d.get("acus_consumed"),
    }


class MockDevinClient:
    """In-process fake mirroring the v3 status vocabulary. Deterministic; runs the whole
    loop with no key for tests and keyless review. NOT the source of the live demo."""

    POLLS_TO_FINISH = 2

    def __init__(self) -> None:
        # Instance state so it does not bleed across get_client() calls / tests.
        self._polls: dict[str, int] = {}
        self._meta: dict[str, dict] = {}

    def create_session(
        self, prompt: str, title: str, tags: list[str], schema: dict,
        playbook_id: str | None = None,
    ) -> dict:
        seed = hashlib.sha1((title + "".join(tags)).encode()).hexdigest()
        session_id = f"devin-mock-{seed[:12]}"
        self._polls[session_id] = 0
        # Tags inject deterministic outcomes: "force-fail" -> ends without a PR (retry path),
        # "force-block" -> suspends awaiting input (escalate-without-retry path).
        self._meta[session_id] = {
            "fail": "force-fail" in tags, "block": "force-block" in tags,
            "code": "code" in tags, "review": "review" in tags,
            "seed": seed, "title": title,
        }
        return {"session_id": session_id, "url": f"https://app.devin.ai/sessions/{session_id}"}

    def get_session(self, session_id: str) -> dict:
        self._polls[session_id] = self._polls.get(session_id, 0) + 1
        meta = self._meta.get(
            session_id,
            {"fail": False, "block": False, "code": False, "review": False, "seed": "0" * 12},
        )
        if self._polls[session_id] < self.POLLS_TO_FINISH:
            return {"status_enum": "running", "structured_output": None,
                    "pull_request": None, "acu_used": 0.0}
        if meta.get("review"):
            return self._review_result(meta)
        if meta.get("block"):
            return {
                "status_enum": "suspended",
                "structured_output": {
                    "success": False,
                    "summary": "Suspended awaiting a maintainer decision",
                    "fix_strategy": "escalate",
                    "tests_run": "none (blocked before changes)",
                    "residual_risk_or_blocker": (
                        "Fix requires dropping Python 3.9 support; needs a maintainer "
                        "decision before proceeding."
                    ),
                },
                "pull_request": None, "acu_used": 1.5,
            }
        if meta["fail"]:
            return {
                "status_enum": "exit",
                "structured_output": {
                    "success": False,
                    "summary": "Could not resolve conflict",
                    "fix_strategy": "escalate",
                    "tests_run": "pip install (failed to resolve)",
                    "residual_risk_or_blocker": (
                        "Transitive pin conflicts with an incompatible parent dependency; "
                        "no compatible version set exists without a breaking major upgrade."
                    ),
                },
                "pull_request": None, "acu_used": 1.0,
            }
        pr_number = int(meta["seed"][:4], 16) % 9000 + 1000
        pr_url = f"https://github.com/{settings.github_repo}/pull/{pr_number}"
        if meta.get("code"):
            fix_strategy, summary, residual = (
                "code-fix",
                f"Fixed authorization logic and added a regression test (mock) for {meta.get('title')}",
                "None: regression test added covering the privilege-escalation path.",
            )
        else:
            fix_strategy, summary, residual = (
                "upgrade",
                f"Bumped dependency and opened PR (mock) for {meta.get('title')}",
                "None: pinned to the patched version; full test suite green.",
            )
        return {
            "status_enum": "exit",
            "structured_output": {
                "success": True,
                "pr_url": pr_url,
                "summary": summary,
                "fix_strategy": fix_strategy,
                "tests_run": "pytest (targeted suite)",
                "residual_risk_or_blocker": residual,
            },
            "pull_request": {"url": pr_url},
            "acu_used": 2.0,
        }

    def _review_result(self, meta: dict) -> dict:
        """Independent review-gate verdict. Deterministic: dependency upgrades pass; the
        code-fix case requests changes with a concrete blocking issue, so replay shows the
        gate CATCHING something on the highest-stakes item."""
        if meta.get("code"):
            output = {
                "verdict": "request_changes",
                "confidence": "high",
                "blocking_issues": [
                    "Regression test doesn't cover the embedded-guest read path; add "
                    "coverage before merge."
                ],
                "checked": ["reproduced the privesc chain", "read the authorization diff"],
                "summary": "Fix is on the right track but test coverage is incomplete.",
            }
        else:
            output = {
                "verdict": "approve",
                "confidence": "high",
                "blocking_issues": [],
                "checked": ["confirmed the patched version resolves the advisory",
                            "ran the targeted suite"],
                "summary": "Minimal, correct dependency upgrade; no regressions found.",
            }
        return {"status_enum": "exit", "structured_output": output,
                "pull_request": None, "acu_used": 1.0}


def get_client() -> DevinClient:
    return LiveDevinClient() if settings.is_live else MockDevinClient()
