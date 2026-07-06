# Playbook: Remediate a security vulnerability (senior-engineer mode)

> Source of truth. Loaded into Devin as a Playbook and invoked via the v3 Sessions API with
> `playbook_id`. The goal is the *correct* remediation a senior engineer would ship - not a
> blind version bump.

## When to use
One run remediates a single dependency/security finding on `MrnxDnys/superset`. The caller
supplies, in the prompt: package, ecosystem (pip | npm), current version, advisory (GHSA/CVE),
the fixed version if known, and the tracking issue number.

## Objective
Diagnose the finding, choose the right fix strategy, implement it so the codebase still works,
verify with tests, and open a reviewable PR — or escalate with a specific, evidenced blocker.
Never merge; a human approves.

## Procedure
1. **Triage.** Determine how this repo actually uses the package: direct or transitive, runtime
   or dev-only, and whether the vulnerable code path is reachable. If the finding does not
   apply, say so with evidence and recommend dismissing the alert (document why).
2. **Choose a fix strategy:**
   - **Upgrade:** move to the lowest safe version. If it is a major/breaking upgrade, also bump
     the compatible companion packages (e.g. Flask extensions) and adapt the codebase to the
     new APIs so it still runs.
   - **Transitive:** upgrade the parent that pulls it in, or add a constraint/override — do not
     force an incompatible direct pin.
   - **Malicious / abandoned / no safe version:** if unused, remove it; if used, replace it with
     a maintained equivalent and adjust the call sites. Justify the choice.
3. **Implement** on branch `devin/fix-<package>-<advisory>`. Make it actually work: update the
   affected lockfiles, adapt calling code for breaking changes, leave unrelated code untouched.
4. **Verify.** Run the relevant test subset (see Knowledge). Iterate until the tests you can run
   pass. Record exactly what you ran and the result — do not claim more verification than you did.
5. **Decide:**
   - **Works →** open a PR (`Fixes #<n>`) whose body explains the strategy, the changes, and the
     test evidence.
   - **Cannot be done safely →** STOP and return `success=false` with a *specific* blocker: name
     the incompatibility, the versions involved, and what would unblock it. This escalates to a
     human (do not ship a broken PR).

## Constraints
- Scope the diff to the fix plus the changes required to make it work — no unrelated refactors
  or formatting sweeps.
- Never merge. Respect the ACU budget; if spend outpaces the change, stop and report progress.

## Structured output (required)
```
{ "success": bool,
  "pr_url": string,
  "fix_strategy": "upgrade" | "transitive" | "removal" | "not-applicable",
  "summary": string,
  "tests_run": string,
  "residual_risk_or_blocker": string }
```
