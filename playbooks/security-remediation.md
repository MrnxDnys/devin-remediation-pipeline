# Playbook: Remediate a security finding (senior-engineer mode)

> Source of truth. Loaded into Devin as a Playbook and invoked via the v3 Sessions API with
> `playbook_id`. One run remediates a SINGLE security finding on `MrnxDnys/superset` - a
> dependency vulnerability, or a code-level vulnerability (e.g. an access-control flaw). The
> goal is the *correct* remediation a senior engineer would ship, and the judgement to know
> when a finding is a false positive - not a blind version bump.

## When to use
The caller supplies, in the prompt: the finding type (dependency | code), severity, the
advisory/id, and - for dependencies - the package, ecosystem, current version, and fixed
version if known. The tracking GitHub issue number is always supplied.

## Objective
Diagnose the finding, decide whether it is real, choose the right fix strategy, implement it
so the codebase still works, verify with tests, and open a reviewable PR - or escalate with a
specific, evidenced blocker. Never merge; a human approves.

## Procedure
1. **Triage - is it real?** Determine whether the vulnerable code path is actually reachable
   in this repo, and whether the finding is genuine. A finding can be a **false positive** (a
   name collision, an unreachable path, a mis-scoped advisory). If it is, do NOT delete working
   code to silence a scanner - return `fix_strategy = "dismiss-false-positive"` with the
   evidence, and (if safe and low-risk) make the minimal change that removes the false signal
   at its root (e.g. rename to avoid a malicious-package name collision).
2. **Choose a fix strategy:**
   - **Dependency - upgrade:** move to the lowest safe version. If it is a major/breaking
     upgrade, also bump the compatible companion packages (e.g. Flask extensions) and adapt the
     codebase to the new APIs so it still runs.
   - **Dependency - transitive:** upgrade the parent that pulls it in, or add a
     constraint/override - do not force an incompatible direct pin.
   - **Dependency - malicious / abandoned / no safe version:** if unused, remove it; if used,
     replace it with a maintained equivalent and adjust the call sites.
   - **Code fix:** for a code-level vulnerability (e.g. a privilege-escalation / broken
     access-control chain), fix the flawed logic itself - add the missing authorization check,
     tighten the scope, close the escalation path - with a regression test that fails before and
     passes after.
3. **Implement** on branch `devin/fix-<slug>`. Make it actually work: update affected lockfiles,
   adapt calling code for breaking changes, leave unrelated code untouched.
4. **Verify.** Run the narrowest relevant test subset (see Knowledge); for a code fix, add a
   test that demonstrates the vulnerability is closed. Iterate until the tests you can run pass.
   Record exactly what you ran - do not claim more verification than you did.
5. **Decide:**
   - **Fixed / dismissed with evidence →** open a PR (`Fixes #<n>`) whose body explains the
     strategy, the changes, and the test evidence.
   - **Cannot be done safely →** STOP and return `success=false` with a *specific* blocker: name
     the incompatibility or the missing context and what would unblock it. This escalates to a
     human (do not ship a broken PR).

## Constraints
- Scope the diff to the fix plus the changes required to make it work - no unrelated refactors
  or formatting sweeps.
- Never merge. Respect the ACU budget; if spend outpaces the change, stop and report progress.

## Structured output (required)
```
{ "success": bool,
  "pr_url": string,
  "fix_strategy": "upgrade" | "transitive" | "removal" | "code-fix" | "dismiss-false-positive" | "escalate",
  "summary": string,
  "tests_run": string,
  "residual_risk_or_blocker": string }
```
