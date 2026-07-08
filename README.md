# Devin Security-Remediation Pipeline

An event-driven automation, built on the **Devin v3 Sessions API**, that autonomously
**remediates security findings** in a fork of Apache Superset into reviewable pull requests -
and gives an engineering leader a live view of whether it is working.

Target repository (what Devin remediates):
[`MrnxDnys/superset`](https://github.com/MrnxDnys/superset).

## What each Devin session does

Each finding is handed to a Devin session that performs the remediation a version-bump bot can't -
it triages the finding and applies the correct fix. Examples from the fork:

- **Triage, not just patch.** On a flagged "malicious" npm package, Devin proved it was a
  **false positive** (a name collision) and fixed the root cause - instead of deleting working
  code to silence the scanner. (Fork PR #8.)
- **Breaking fixes, done properly.** On a Flask CVE it didn't just bump the pin - it drove the
  **Flask 2 → 3 migration**, upgraded the extensions that broke, and ran the test suite. (PR #9.)
- **Code-level security bugs.** For a business-logic vulnerability - a privilege-escalation chain
  in the SemanticLayer that a dependency scanner structurally cannot see - Devin fixes the flawed
  authorization logic and adds a regression test.

Every result is a reviewable PR that references its issue; nothing is merged automatically.

## Architecture

```
  security finding                 issues.labeled = devin-auto        Devin v3 Sessions API
  ├─ pip-audit / npm audit  ──▶  GitHub issue (devin-auto)  ──▶  orchestrator  ──▶  one session
  │   (scheduled scanner)                    ▲                    (fan out,          per finding
  └─ Security Swarm finding                  │                     poll, decide)     + Playbook
      (filed as an issue)          /trigger/simulate POST                                │
                                   (no-tunnel fallback)                                  ▼
                                                                        Devin: triage → fix → test
                                                                                         │
                                                              ┌──────────────────────────┤
                                                              ▼                          ▼
                                                     reviewable PR (Fixes #n)     escalate w/ blocker
                                                     comment back on issue        (label devin-failed)
                                                              │
                    live dashboard  ◀── metrics from job state (severity, MTTR, success, throughput)
                  (Devin dark-mode UI)
```

## How it maps to Devin

- **Sessions API (v3)** - the orchestrator creates and manages one session per finding
  programmatically, using a **service-user (`cog_`) credential scoped to `ManageOrgSessions`**.
- **Playbook** (`playbooks/security-remediation.md`) - the remediation procedure Devin follows,
  one branching Playbook (dependency upgrade / transitive / removal / **code fix** /
  **dismiss-with-evidence** / escalate). Source of truth here; loaded into Devin, invoked by
  `playbook_id`.
- **Knowledge** (`knowledge/`) - repo conventions (dependency layout, test entrypoints, "never
  merge") applied to every session.
- **Structured output** - each session returns a machine-parseable verdict
  (`success`, `pr_url`, `fix_strategy`, `tests_run`, `residual_risk_or_blocker`) the orchestrator
  uses to decide: comment the PR, retry once, or escalate.

## Observability - "how would a leader know it's working?"

A live dashboard (styled to Devin's dark-mode aesthetic) at `http://localhost:8000/`:

- Open findings **by severity** (critical / high / medium / low).
- **Auto-fixed**, **escalated**, **PRs opened**, **success rate**.
- **Mean time-to-remediation** (issue → PR) and **throughput/hour**.
- A per-finding trace: issue → severity → status → PR link → Devin session link.

No cost/$ panel: ACUs read `0.0` on this (self-serve) org, and a fabricated ROI number would
subtract credibility with an engineering audience. The dashboard reports what actually happened.

## Run it

Two modes. **Replay** needs no keys or credits - a reviewer can run the whole loop at their desk.

### Replay / simulate (no Devin key, no GitHub)

```bash
cp .env.example .env.local        # defaults are already DEVIN_MODE=replay
docker compose up --build         # dashboard at http://localhost:8000/
# in another shell, seed simulated security findings through the real orchestrator loop:
docker compose exec pipeline python -m scripts.seed_demo
```

Or natively, without Docker:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
DEVIN_MODE=replay uvicorn app.main:app --port 8000 &     # dashboard
DEVIN_MODE=replay python -m scripts.seed_demo            # drive findings through the loop
```

The replay uses an in-process fake Devin (`app/devin_client.py`) that mirrors the v3 session
lifecycle and structured-output contract deterministically, so the dashboard populates with a
high-severity code fix, dependency fixes, and one escalated finding - no network, no credits.

### Live (real Devin sessions on the fork)

Fill `.env.local` with a real service-user key and playbook id, then:

```bash
DEVIN_API_KEY=cog_...            # service user, ManageOrgSessions
DEVIN_ORG_ID=org-...
DEVIN_PLAYBOOK_ID=playbook-...   # the security-remediation Playbook, loaded into Devin
DEVIN_MODE=live
GITHUB_TOKEN=ghp_...             # repo scope on the fork (issues, PR read)
```

```bash
docker compose up --build
# trigger a real scan (files devin-auto issues from real pip-audit / npm audit output):
curl -X POST http://localhost:8000/scan
# or replay a single labelled-issue event without a public webhook tunnel:
curl -X POST http://localhost:8000/trigger/simulate \
     -H 'content-type: application/json' \
     -d '{"number": 1, "title": "GHSA-...", "body": "<!--devin-meta {...} -->"}'
```

For a real GitHub webhook, point `issues` deliveries at `/webhook/github` (HMAC-verified with
`GITHUB_WEBHOOK_SECRET`); labelling an issue `devin-auto` then fires the pipeline.

## Governance

- **Least privilege:** a service-user `cog_` credential scoped to `ManageOrgSessions`.
- **Budget guardrail:** every session sets `max_acu_limit` so one runaway session can't drain the
  account.
- **Bounded fan-out:** a concurrency cap (`MAX_CONCURRENT_SESSIONS`) limits how many Devin sessions
  run at once; further findings stay queued until a slot frees - so a large backlog can't spike
  cost or blast radius.
- **Blast radius = a PR.** The system **never auto-merges** and never touches upstream
  `apache/superset` - a human reviews every change. Failures escalate (label `devin-failed`) with
  the specific blocker rather than shipping a broken PR.
- **No secrets in git** - everything is read from env / `.env.example` placeholders.

## Layout

| Path | What |
|------|------|
| `app/orchestrator.py` | session lifecycle: create → poll → parse structured output → decide |
| `app/devin_client.py` | Devin v3 client (live) + deterministic replay fake, one interface |
| `app/scanner.py` | scheduled `pip-audit` + `npm audit` → files `devin-auto` issues |
| `app/webhook.py` | `issues.labeled` webhook + `/trigger/simulate` + `/scan` |
| `app/dashboard.py`, `app/static/` | metrics API + the Devin-dark-mode leader dashboard |
| `playbooks/security-remediation.md` | the remediation procedure Devin follows (as code) |
| `knowledge/` | repo conventions applied to every session (as code) |
| `scripts/seed_demo.py` | replay: drive simulated findings through the real loop |

## The fork

[`MrnxDnys/superset`](https://github.com/MrnxDnys/superset) holds the selected findings (issues),
Devin's remediation PRs (#8 malware false-positive, #9 Flask 2→3), and the `devin-auto` /
`devin-failed` labels. Upstream `apache/superset` is never touched.
