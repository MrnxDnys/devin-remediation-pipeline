"""Seed the pipeline with simulated security findings so the dashboard has data to show
without GitHub or live Devin. This is the `simulate`/replay path. Usage:

    python -m scripts.seed_demo

The findings mirror the real ones remediated on the fork (see the fork's PRs #8/#9) plus a
Swarm-style code finding and one deliberately-hard finding to exercise escalation."""
import time

from app import db
from app.config import settings


def _meta(**kw) -> str:
    import json
    return f"<!--devin-meta {json.dumps(kw)} -->"


# (issue_number, title, meta-fields)
DEMO = [
    (301, "[HIGH] SemanticLayer view menus omitted from role-restriction sets (Gamma privilege escalation)",
     dict(finding_type="code", source="security-swarm", severity="high",
          vulnerability_id="SWARM-SUP-PRIVESC-01",
          dedup_key="code:SWARM-SUP-PRIVESC-01")),
    (302, "[HIGH] eslint-plugin-i18n-strings flagged as malicious (name collision)",
     dict(finding_type="dependency", source="npm-audit", severity="high",
          ecosystem="npm", package="eslint-plugin-i18n-strings",
          vulnerability_id="GHSA-55h3-fm53-wq99", fix_versions="n/a (false positive)",
          dedup_key="npm:eslint-plugin-i18n-strings:GHSA-55h3-fm53-wq99")),
    (303, "[HIGH] Upgrade Flask 2.3.3 to fix GHSA-68rp-wp8r-4726",
     dict(finding_type="dependency", source="pip-audit", severity="high",
          ecosystem="pip", package="Flask", vulnerability_id="GHSA-68rp-wp8r-4726",
          fix_versions="3.1.3", dedup_key="pip:Flask:GHSA-68rp-wp8r-4726")),
    (304, "[MEDIUM] Upgrade paramiko 3.5.1 to fix GHSA-r374-rxx8-8654",
     dict(finding_type="dependency", source="pip-audit", severity="medium",
          ecosystem="pip", package="paramiko", vulnerability_id="GHSA-r374-rxx8-8654",
          fix_versions="3.6.0", dedup_key="pip:paramiko:GHSA-r374-rxx8-8654")),
    # Code-level findings from the Security Swarm - Devin fixes these; the independent review
    # gate approves them (only the privesc above is flagged for extra test coverage).
    (306, "[HIGH] Hive file-upload: SQL injection via unescaped table/schema name",
     dict(finding_type="code", source="security-swarm", severity="high",
          vulnerability_id="SWARM-SUP-SQLI-HIVE", dedup_key="code:SWARM-SUP-SQLI-HIVE")),
    (307, "[HIGH] RLS bypass: get_column_values cache key omits the RLS context",
     dict(finding_type="code", source="security-swarm", severity="high",
          vulnerability_id="SWARM-SUP-RLS-BYPASS", dedup_key="code:SWARM-SUP-RLS-BYPASS")),
    (308, "[MEDIUM] Open redirect in /redirect via backslash-prefixed path",
     dict(finding_type="code", source="security-swarm", severity="medium",
          vulnerability_id="SWARM-SUP-OPENREDIRECT", dedup_key="code:SWARM-SUP-OPENREDIRECT")),
    # Engineered to fail -> demonstrates retry + escalation to a human.
    (309, "[HIGH] Upgrade transitive dep pinned by an incompatible parent",
     dict(finding_type="dependency", source="pip-audit", severity="high",
          ecosystem="pip", package="pyarrow", vulnerability_id="force-fail",
          fix_versions="14.0.1", dedup_key="pip:pyarrow:force-fail")),
]


def main():
    db.init_db()
    from app import orchestrator
    for number, title, meta in DEMO:
        issue = {"number": number, "title": title, "body": _meta(**meta)}
        orchestrator.enqueue(issue)
        time.sleep(0.3)
    print(f"Seeded {len(DEMO)} security findings in {settings.devin_mode.upper()} mode. "
          f"Open the dashboard at http://localhost:8000/")
    # Give background threads time to complete against the mock.
    time.sleep(max(3, settings.poll_interval_seconds * 3))
    for j in db.list_jobs():
        print(f"  #{j.issue_number:>3} {j.severity:<8} {j.status.value:<10} {j.pr_url or ''}")


if __name__ == "__main__":
    main()
