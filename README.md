# Devin Remediation Pipeline

An event-driven automation that turns dependency-vulnerability findings into reviewed pull
requests, autonomously, using [Devin](https://devin.ai) as the worker. A scan files GitHub
issues; labelling an issue fires a Devin session; the orchestrator manages that session to a
decided outcome (PR opened, or escalated to a human); a live dashboard shows whether the
whole thing is working.

Built as a take-home for Cognition. Target repo: a fork of
[`apache/superset`](https://github.com/apache/superset) at `mrnxdnys/superset`.

---

## Why this matters

Every engineering org carries a backlog of low-judgement, high-toil fixes: CVEs in
dependencies, deprecations, lint. They're individually trivial and collectively never
prioritised. This pipeline makes that backlog self-clearing while keeping a human on the
merge button. Devin is the primitive that makes it possible: it doesn't just *flag* the
issue, it opens the branch, edits the right dependency file, and raises a reviewable PR.

## Architecture

```
                    scheduled                       label: devin-auto
  ┌───────────┐    (outer trigger)   ┌──────────┐   (inner trigger)   ┌──────────────┐
  │  scanner  │ ───pip-audit──────▶  │  GitHub  │ ───webhook───────▶  │ orchestrator │
  │ (cron)    │   files issues       │  issues  │                     │              │
  └───────────┘                      └──────────┘                     └──────┬───────┘
                                          ▲                                   │ create + poll
                                          │ comment PR / escalate             ▼  (v1 sessions API,
                                          └───────────────────────────  ┌──────────┐  structured_output,
                                                                         │  Devin   │  max_acu_limit)
        ┌───────────┐   polls /api/*                                     └──────────┘
        │ dashboard │ ◀──────────────  SQLite state  ◀────────────────────────┘
        └───────────┘                  (jobs + events)
```

- **Layered trigger.** The scheduled scanner (`scripts/scheduler.py`) files labelled issues;
  the `devin-auto` label is the actual event that fires Devin via webhook. Two independent
  triggers, one chain.
- **Devin as a core primitive.** The orchestrator creates one session per issue, hands Devin a
  scoped remediation playbook plus a **`structured_output_schema`** so the result comes back as
  machine-parseable JSON (`{success, pr_url, summary}`) — not prose to scrape. It polls
  `status_enum` to a terminal state, then *decides*: comment the PR back on the issue, or retry
  once and escalate (label `devin-failed`).
- **Budget guard.** Every session sets `max_acu_limit`, so one runaway session can't drain the
  account.
- **Observability.** All state lives in SQLite; the dashboard polls a JSON API for job status,
  success rate, throughput, time-to-fix, and estimated ACU cost.

## Quickstart (simulated — no keys needed)

The full loop runs against an in-process **mock Devin**, so you can see it work with zero
credentials. This is for reviewers and tests; the real demo uses live Devin (below).

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env.local          # defaults are already DEVIN_MODE=mock

# Option A: seed a batch of jobs and print outcomes
DB_PATH=data/state.db POLL_INTERVAL_SECONDS=0 .venv/bin/python -m scripts.seed_demo

# Option B: run the web service and drive it
.venv/bin/python -m uvicorn app.main:app --port 8000
#   then open http://localhost:8000  and trigger a job:
#   POST http://localhost:8000/trigger/simulate
#        {"number": 301, "title": "Upgrade Flask", "body": "<!--devin-meta {...} -->"}
```

### With Docker

```bash
cp .env.example .env.local          # fill in real values for live mode
docker compose up --build           # web service + dashboard on :8000
docker compose --profile scanner up # also run the periodic scanner
```

## Going live

1. In your Devin org, create an API key (`apk_...`) and connect the GitHub integration so
   Devin can push branches / open PRs on the fork.
2. Create a GitHub PAT with `repo` scope on the fork.
3. Edit `.env.local`:
   ```
   DEVIN_MODE=live
   DEVIN_API_KEY=apk_...
   GITHUB_TOKEN=ghp_...
   GITHUB_REPO=mrnxdnys/superset
   GITHUB_WEBHOOK_SECRET=<random>
   ```
4. Point a GitHub webhook (repo → Settings → Webhooks) at `/webhook/github` (use
   [smee.io](https://smee.io) or ngrok to expose localhost), event: **Issues**, with the same
   secret. Signature is HMAC-verified.
5. Trigger the scanner (`POST /scan` or the scheduler) to file real issues, then label one
   `devin-auto`.

## Endpoints

| Method | Path                 | Purpose                                             |
|--------|----------------------|-----------------------------------------------------|
| GET    | `/`                  | Observability dashboard                             |
| GET    | `/health`            | Mode + repo                                         |
| POST   | `/scan`              | Run the scanner now (files labelled issues)         |
| POST   | `/webhook/github`    | GitHub `issues.labeled` receiver (HMAC-verified)    |
| POST   | `/trigger/simulate`  | Simulate a labelled-issue event (no tunnel needed)  |
| GET    | `/api/metrics`       | Aggregate metrics (JSON)                            |
| GET    | `/api/jobs`          | All remediation jobs (JSON)                         |
| GET    | `/api/events`        | Recent activity feed (JSON)                         |

## Tests

```bash
.venv/bin/python -m pytest -q      # loop happy-path, retry→escalate, dedup
```

## Layout

```
app/
  config.py          settings (env / .env.local)
  models.py          domain models + the structured-output JSON Schema
  db.py              SQLite state store (jobs + events)
  devin_client.py    Live (v1 API) + Mock Devin, same interface
  orchestrator.py    core: issue -> session -> poll -> decide -> retry/escalate
  scanner.py         pip-audit -> ScanFindings -> labelled issues
  webhook.py         GitHub webhook + /scan + /trigger/simulate
  dashboard.py       metrics + JSON API + dashboard page
  static/dashboard.html
scripts/
  scheduler.py       periodic scan loop (outer trigger)
  seed_demo.py       seed simulated jobs for a keyless demo
tests/
```

> Secrets are read from env / `.env.local` (git-ignored). Nothing sensitive is committed.
> `max_acu_limit` caps per-session spend.
