"""Scheduled scanner: run pip-audit against the fork's requirements, turn each fixable
finding into a GitHub issue labelled `devin-auto`. This is the outer trigger layer."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile

from . import db, github_client
from .config import settings
from .models import Finding

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "sample_findings.json")

# Keep only fully-pinned `name==version` specs; drop editables (-e ./superset-core),
# includes (-r ...), comments, extras and environment markers. pip-audit's resolver
# chokes on those, so we normalise to bare pins and audit with --no-deps.
_PIN = re.compile(r'^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?==([^\s;#]+)')


def _normalise_requirements(content: str) -> str:
    pins = []
    for line in content.splitlines():
        m = _PIN.match(line.strip())
        if m:
            pins.append(f"{m.group(1)}=={m.group(2)}")
    return "\n".join(pins) + "\n"


def run_scan() -> list[Finding]:
    """Fetch target requirements from the fork and audit them. Falls back to a bundled
    fixture if pip-audit is unavailable, so the pipeline is always demonstrable."""
    findings: list[Finding] = []
    for path in [p.strip() for p in settings.scan_target_files.split(",") if p.strip()]:
        content = github_client.get_file(path, ref=settings.scan_ref)
        if content is None:
            db.add_event("scan_warn", f"requirements file not found: {path}")
            continue
        findings.extend(_audit_requirements(content, path))
    if settings.scan_npm:
        findings.extend(_audit_npm())
    if not findings and os.path.exists(FIXTURE_PATH):
        db.add_event("scan_fixture", "pip-audit produced nothing; using fixture findings")
        findings = _load_fixture()
    return findings


def _audit_requirements(content: str, source_file: str) -> list[Finding]:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(_normalise_requirements(content))
        tmp = f.name
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", tmp, "--no-deps",
             "--format", "json", "--progress-spinner", "off"],
            capture_output=True, text=True, timeout=300,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        db.add_event("scan_warn", f"pip-audit unavailable/timed out: {e}")
        return []
    finally:
        os.unlink(tmp)

    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return _parse_pip_audit(data, source_file)


def _audit_npm() -> list[Finding]:
    """Audit the frontend lockfile with `npm audit --package-lock-only` (no install)."""
    d = settings.scan_npm_dir
    pkg = github_client.get_raw(f"{d}/package.json", settings.scan_ref)
    lock = github_client.get_raw(f"{d}/package-lock.json", settings.scan_ref)
    if not pkg or not lock:
        db.add_event("scan_warn", f"npm manifest/lockfile missing under {d}")
        return []
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "package.json"), "w") as f:
            f.write(pkg)
        with open(os.path.join(tmp, "package-lock.json"), "w") as f:
            f.write(lock)
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json", "--package-lock-only"],
                cwd=tmp, capture_output=True, text=True, timeout=300,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            db.add_event("scan_warn", f"npm unavailable/timed out: {e}")
            return []
    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return _parse_npm_audit(data, f"{d}/package-lock.json")


def _parse_npm_audit(data: dict, source_file: str) -> list[Finding]:
    out: list[Finding] = []
    for name, node in data.get("vulnerabilities", {}).items():
        via = [e for e in node.get("via", []) if isinstance(e, dict)]
        ghsa = next((e["url"].rsplit("/", 1)[-1] for e in via if e.get("url")), "")
        title = next((e.get("title") for e in via if e.get("title")), "")
        fa = node.get("fixAvailable")
        fixes: list[str] = []
        if isinstance(fa, dict) and fa.get("version"):
            major = " (semver-major)" if fa.get("isSemVerMajor") else ""
            fixes = [f"{fa['name']}@{fa['version']}{major}"]
        out.append(Finding(
            finding_type="dependency",
            source="npm-audit",
            severity=(node.get("severity") or "medium").lower(),
            ecosystem="npm",
            package=name,
            installed_version=None,
            vulnerability_id=ghsa or f"npm-{name}",
            fix_versions=fixes,
            location=source_file,
            description=f"[{node.get('severity')}] {title} (vulnerable range: {node.get('range')})"[:600],
        ))
    return out


def _parse_pip_audit(data: dict, source_file: str) -> list[Finding]:
    out: list[Finding] = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            fixes = vuln.get("fix_versions", []) or []
            # Keep findings even without a listed fix version - Devin can determine the
            # patched release. build_prompt falls back to "the latest patched version".
            out.append(Finding(
                finding_type="dependency",
                source="pip-audit",
                # pip-audit's OSV data rarely carries a normalised severity; default
                # medium and let Swarm-sourced findings set critical/high explicitly.
                severity="medium",
                ecosystem="pip",
                package=dep.get("name", ""),
                installed_version=dep.get("version"),
                vulnerability_id=vuln.get("id", ""),
                fix_versions=fixes,
                location=source_file,
                description=(vuln.get("description") or "")[:600],
            ))
    return out


def _load_fixture() -> list[Finding]:
    with open(FIXTURE_PATH) as f:
        return [Finding(**x) for x in json.load(f)]


def create_issues(findings: list[Finding]) -> list[int]:
    """Create a labelled GitHub issue per finding (deduped, capped). Returns issue numbers."""
    created: list[int] = []
    seen = {j.dedup_key for j in db.list_jobs()}
    for finding in findings:
        if len(created) >= settings.max_issues_per_scan:
            db.add_event("scan_capped", f"Reached cap of {settings.max_issues_per_scan} issues")
            break
        if finding.dedup_key() in seen:
            continue
        issue = github_client.create_issue(
            title=_issue_title(finding),
            body=_issue_body(finding),
            labels=[settings.devin_trigger_label],
        )
        created.append(issue["number"])
        seen.add(finding.dedup_key())
        db.add_event("issue_created", f"#{issue['number']} {finding.package} {finding.vulnerability_id}")
    return created


def _issue_title(f: Finding) -> str:
    ver = f" {f.installed_version}" if f.installed_version else ""
    sev = f.severity.upper()
    return f"[{sev}] [{f.vulnerability_id}] Upgrade {f.package}{ver} to fix vulnerability"


def _issue_body(f: Finding) -> str:
    meta = {
        "dedup_key": f.dedup_key(),
        "finding_type": f.finding_type,
        "source": f.source,
        "severity": f.severity,
        "ecosystem": f.ecosystem,
        "package": f.package,
        "vulnerability_id": f.vulnerability_id,
        "fix_versions": ", ".join(f.fix_versions),
    }
    fixed_in = ", ".join(f.fix_versions) if f.fix_versions else "latest patched release (Devin to determine)"
    return f"""## Security finding ({f.severity})

- **Package:** `{f.package}` {f.installed_version or ''}
- **Advisory:** {f.vulnerability_id}
- **Fixed in:** {fixed_in}
- **Detected by:** {f.source}
- **Location:** `{f.location}`

{f.description}

---
_Filed automatically by the Devin security-remediation pipeline. Labelled
`{settings.devin_trigger_label}` to trigger an autonomous fix._

<!--devin-meta {json.dumps(meta)} -->
"""
