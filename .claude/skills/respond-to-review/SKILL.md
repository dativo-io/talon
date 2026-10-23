---
name: respond-to-review
description: Work through a code-review round on a Talon pull request — classify each finding, reproduce it with a failing test before fixing, prove the fix, and refresh the PR body — on the PR branch only, without merging.
---

Address the review of $ARGUMENTS on its own branch. Do not merge, do not touch other repositories named in the review (for example `talon-full-demo`), do not modify the issue or PR unless the user asks.

## Per finding

1. **Classify** before editing: confirmed defect, not a defect (document and pin), already fixed on the branch (name the commit), or out of scope (say why and propose a follow-up).
2. **Reproduce first.** Write the smallest failing test that states the reviewer's claim. When the reviewer gives a shape (cap, estimates, request count, shared or separate sessions, a primary that fails transiently), use exactly that shape. Concurrency tests are deterministic: a fixed burst started behind a `sync.WaitGroup` or channel barrier, a counting upstream, fixed estimates, no sleeps.
3. **Fix the mechanism**, not the symptom. Never restore CI by faking an input (`PricingKnown=true` in a test that validates pricing, a silent fallback price, a widened allowlist). When an external runtime wraps every Talon denial in its own code (OpenShell renders any deny as `middleware_denied`), find the underlying Talon code in Talon's evidence or logs and fix that.
4. **Prove it.** The new test fails with the fix disabled (temporarily, locally) and passes with it. Keep the atomic semantics the review asked to preserve (for example the session-store reservation) and say how.
5. **Run the ladder** (`/verify-change`) for the packages touched, then the tiers the change crosses. Race detector on for anything concurrent.
6. **Document**: `LIMITATIONS.md` and the reference docs when the guarantee changed; CHANGELOG when behaviour changed.

## Findings that are not defects

Pin the behaviour with a named test, state the mechanism (for example one settle per request across streaming and retries), and mark the row "not a defect, pinned by …" in the PR body. Do not change code to satisfy a misreading.

## Refresh the PR body

Update, never append-only: the summary table (verdict per finding), changes by commit, regression tests, verification matrix, CI history (commit → failing step → root cause → fixing commit), limitations, migration implications. Write it to a file outside the tree and hand the user `gh pr edit <n> --body-file <path>`; verify afterwards that the body on GitHub changed.

## Handoff

A table with one row per finding: classification, test that proves it, commit, residual risk. State exact commands run and their results, what needs the PR's CI (Docker lanes), and that the PR remains a draft until checks are green. The user decides when to mark it ready and merge.
