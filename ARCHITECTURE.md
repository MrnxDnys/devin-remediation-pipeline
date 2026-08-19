# Architecture

What this system is: a governed orchestration layer around Devin. Devin does the
remediation. Our code decides *which* findings Devin gets, *under what limits*, and
*how a leader knows it worked*.

Blue = code in this repo. Grey, dashed = Devin / GitHub native capability we configure
rather than rebuild.

## System flow

```mermaid
flowchart TD
    subgraph SRC["Finding sources"]
        SCAN["pip-audit / npm audit<br/><i>scheduled</i>"]
        SWARM["Devin Security Swarm<br/><i>filed as issues</i>"]
    end

    ISSUE["GitHub issue<br/>labelled <b>devin-auto</b>"]

    subgraph ENTRY["Entrypoints: app/webhook.py"]
        WH["POST /webhook/github<br/>HMAC-verified issues.labeled"]
        SIM["POST /trigger/simulate<br/>no-tunnel fallback"]
        SCANEP["POST /scan"]
    end

    SCANNER["app/scanner.py<br/>normalise to Finding, embed devin-meta, file issues"]
    ENQ["orchestrator.enqueue<br/>dedup on issue + advisory key"]
    RUN["orchestrator._run<br/><b>concurrency cap</b>, retry-once, escalate"]
    ATT["orchestrator._attempt<br/>create session, poll, parse verdict"]
    REV["orchestrator._review<br/>2nd independent session, comment-only"]
    CLIENT["app/devin_client.py<br/>Live | Mock behind one interface"]
    DB["app/db.py, SQLite<br/>jobs + append-only event log"]
    DASH["app/dashboard.py<br/>dashboard, /report, /api/*"]

    subgraph DEVIN["Devin platform"]
        SESS["v3 Sessions API<br/>service user, ManageOrgSessions"]
        VM["Devin session<br/>triage, fix, test"]
        PB["Playbook + Knowledge<br/>fix-strategy branching"]
        SO["structured_output<br/>against our JSON Schema"]
    end

    PR["Reviewable PR<br/><i>Fixes #n, never auto-merged</i>"]
    HUMAN["Human reviews and merges"]

    SCAN --> SCANEP --> SCANNER --> ISSUE
    SWARM --> ISSUE
    ISSUE --> WH
    ISSUE -.-> SIM
    WH --> ENQ
    SIM --> ENQ
    ENQ --> RUN --> ATT --> CLIENT --> SESS --> VM
    PB -.-> VM
    VM --> SO --> ATT
    VM --> PR
    ATT -->|"PR opened"| REV --> CLIENT
    ATT -->|"no PR, retries spent"| ESC["escalate<br/>label devin-failed + blocker"]
    RUN --> DB
    ATT --> DB
    REV --> DB
    ESC --> DB
    DB --> DASH
    PR --> HUMAN
    REV -.->|"verdict comment"| PR

    classDef custom fill:#1f4e79,stroke:#0d2b45,color:#fff
    classDef native fill:#e8e8e8,stroke:#888,stroke-dasharray:4 3,color:#222
    class WH,SIM,SCANEP,SCANNER,ENQ,RUN,ATT,REV,CLIENT,DB,DASH,ESC custom
    class SESS,VM,PB,SO,ISSUE,PR,SCAN,SWARM native
```

## Job lifecycle

```mermaid
stateDiagram-v2
    [*] --> QUEUED: issue accepted, deduped
    QUEUED --> RUNNING: concurrency slot acquired, session created
    RUNNING --> SUCCEEDED: PR opened
    RUNNING --> FAILED: no PR / timeout / suspended
    FAILED --> RUNNING: retry, up to max_retries
    FAILED --> ESCALATED: retries spent or awaiting human input
    SUCCEEDED --> [*]: independent review verdict recorded
    ESCALATED --> [*]: labelled devin-failed with the blocker
```

A finding sits in `QUEUED` with **no session created** while the semaphore is full, so a
large backlog cannot spike cost or blast radius.

## The two-session governance loop

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant F as Devin (fixer)
    participant R as Devin (reviewer)
    participant G as GitHub

    O->>F: create_session(prompt, playbook_id, STRUCTURED_OUTPUT_SCHEMA)
    F->>G: open PR "Fixes #n"
    F-->>O: success, pr_url, fix_strategy, tests_run
    Note over O: same concurrency slot held across fix + review
    O->>R: create_session(adversarial prompt, REVIEW_VERDICT_SCHEMA, no playbook)
    R-->>O: approve | request_changes | reject + blocking_issues
    O->>G: comment verdict on the issue
    Note over G: comment-only. A human always merges.
```

The reviewer did not write the PR, gets no Playbook, and is prompted to be adversarial.
`AUTO_MERGE_ON_APPROVE` defaults to false and even when enabled only *records* a
would-merge decision.

## Custom vs native

| Concern | Whose |
|---|---|
| Remediation itself: triage, fix, test | Devin |
| Procedure and conventions | Devin Playbook + Knowledge, authored by us |
| Machine-readable verdict | Devin structured output, **our** JSON Schema |
| Which findings get a session, and when | Custom |
| Concurrency cap, retry-once, escalation | Custom |
| Independent review gate wiring | Custom |
| Job state, event timeline, leader metrics | Custom |
| Live/replay parity behind one interface | Custom |

## File map

| Path | Lines | Role |
|---|---|---|
| `app/orchestrator.py` | 422 | Session lifecycle, governance, review gate |
| `app/dashboard.py` | 385 | Metrics API, dashboard, `/report` |
| `app/scanner.py` | 215 | pip-audit / npm audit to `devin-auto` issues |
| `app/devin_client.py` | 209 | v3 client + deterministic replay fake |
| `app/db.py` | 157 | SQLite jobs + event log, self-healing migration |
| `app/models.py` | 144 | `Job` / `Finding`, state machine, both JSON Schemas |
| `app/github_client.py` | 84 | Issue create / comment / label |
| `app/webhook.py` | 76 | Three triggers |
| `app/config.py` | 69 | Caps and feature flags |
| `playbooks/security-remediation.md` | 63 | The procedure, as code |
| `scripts/seed_demo.py` | 73 | Replay driver, no keys needed |
| `scripts/reconcile.py` | 52 | Resolve orphaned RUNNING jobs |

~2,040 lines total, plus 23 tests.
