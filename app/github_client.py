"""Thin GitHub REST client (httpx, no gh binary needed in the container)."""
from __future__ import annotations

import base64

import httpx

from .config import settings

_API = "https://api.github.com"


def _http() -> httpx.Client:
    return httpx.Client(
        base_url=_API,
        headers={
            "Authorization": f"Bearer {settings.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=30.0,
    )


def create_issue(title: str, body: str, labels: list[str]) -> dict:
    with _http() as h:
        r = h.post(
            f"/repos/{settings.github_repo}/issues",
            json={"title": title, "body": body, "labels": labels},
        )
        r.raise_for_status()
        return r.json()


def get_issue(issue_number: int) -> dict:
    with _http() as h:
        r = h.get(f"/repos/{settings.github_repo}/issues/{issue_number}")
        r.raise_for_status()
        return r.json()


def comment_issue(issue_number: int, body: str) -> None:
    with _http() as h:
        r = h.post(
            f"/repos/{settings.github_repo}/issues/{issue_number}/comments",
            json={"body": body},
        )
        r.raise_for_status()


def add_label(issue_number: int, label: str) -> None:
    with _http() as h:
        r = h.post(
            f"/repos/{settings.github_repo}/issues/{issue_number}/labels",
            json={"labels": [label]},
        )
        r.raise_for_status()


def get_raw(path: str, ref: str = "master") -> str | None:
    """Fetch a file via the raw host - handles large files (>1MB) the contents API caps.
    Works unauthenticated for public repos."""
    url = f"https://raw.githubusercontent.com/{settings.github_repo}/{ref}/{path}"
    with httpx.Client(timeout=60.0, follow_redirects=True) as h:
        r = h.get(url)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.text


def get_file(path: str, ref: str = "master") -> str | None:
    """Return decoded text of a file in the repo, or None if missing."""
    with _http() as h:
        r = h.get(
            f"/repos/{settings.github_repo}/contents/{path}", params={"ref": ref}
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", "replace")
        return data.get("content")
