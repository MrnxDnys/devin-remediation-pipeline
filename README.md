# Devin Remediation Pipeline

Autonomous dependency and security remediation for a fork of Apache Superset, built on Devin's
native primitives. GitHub's own **Dependabot alerts** trigger a **GitHub Action** that launches
**Devin sessions** bound to a remediation **Playbook**; Devin diagnoses each finding, applies
the correct fix, runs tests, and opens a reviewable pull request - or escalates with a specific
blocker. An executive **cockpit** reads Devin's and GitHub's own APIs so an engineering leader
can see whether it is working.

Target repository (what Devin remediates): [`MrnxDnys/superset`](https://github.com/MrnxDnys/superset).

## Design principle
Devin and GitHub do the heavy lifting; this repo is only the connective tissue neither ships
out of the box. If a capability exists in the product, we configure it - we do not re-implement
it. The remediation intelligence lives in a Devin Playbook, not in our code.

## How it maps to Devin
- **Playbook** (`playbooks/`) - the remediation procedure Devin follows. Source of truth here;
  loaded into Devin and invoked by `playbook_id`.
- **Knowledge** (`knowledge/`) - repo conventions applied to every session.
- **Sessions API (v3)** - the trigger creates and monitors sessions programmatically using a
  service-user (`cog_`) credential scoped to `ManageOrgSessions`.
- **Native trigger** - GitHub Dependabot alerts + GitHub Actions. Real enterprise infrastructure:
  no mock feed, no webhook tunnel.

## Architecture
```
  Dependabot alert ──▶ GitHub Action ──▶ Devin Sessions API (+ Playbook, Knowledge)
   (native, real)      (native host)          │
                                              ▼
                                       Devin diagnoses, fixes, tests
                                              │
                                    ┌─────────┴──────────┐
                                    ▼                    ▼
                            reviewable PR         escalate (blocker)
                                    │
        cockpit ◀── reads Devin v3 metrics + GitHub alert/PR/issue state
      (leader view)
```

## Components
- `playbooks/` - remediation Playbook, as code
- `knowledge/` - Devin Knowledge, as code
- `.github/workflows/` - the trigger Action *(authored by Devin from the build spec)*
- `cockpit/` - executive dashboard *(authored by Devin)*, Dockerised

## Governance
Service-user RBAC scoped to `ManageOrgSessions`; per-session `max_acu_limit` budget cap;
a human approves every merge. Secrets come from env / GitHub Actions secrets - nothing sensitive
is committed (see `.env.example`).

## Status
- Playbook + Knowledge live in the Devin org; Dependabot alerts enabled on the fork.
- Live remediation proven end-to-end (see the fork's pull requests).
- The Action + cockpit are built by Devin itself - the connective tissue is the last mile.
