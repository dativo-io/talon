---
name: prepare-pr
description: Take a verified Talon change from working tree to a reviewable pull request handoff — diff hygiene, docs set, conventional commits, PR body, CI watch — without pushing or mutating GitHub unless the user asks.
---

Prepare a pull request for $ARGUMENTS.

## Before committing

1. Be on a feature branch (`feat/…`, `fix/…`, `docs/…`, `chore/…`), never `main`.
2. `git status` and the complete diff against `main`. Remove anything that is not this change: debug output, scratch files, personal or device files (`.bashrc`, `.idea`, `.vscode`, `.claude/settings*`, PR body drafts). Stage with explicit paths: `git add -- <files>`.
3. `git diff --check`; confirm no credentials, tokens or local paths were added.
4. Mirrored artifacts move together: `pricing/models.yaml` and `internal/pricing/default_models.yaml`; a doc table pinned by a test (error contract, governance registry) and its test list; a smoke section and its registration lines (see `.claude/rules/contract-surfaces.md`).
5. Docs set for a behaviour change:
   - `CHANGELOG.md` under `## [Unreleased]`, meeting the quality bar: problem solved, who should care, how to verify (command or test), upgrade or migration impact, one share artifact when applicable;
   - `LIMITATIONS.md` when the guarantee boundary moved, with a "Backed by" list naming real tests;
   - `docs/reference/*` for every contract surface touched; `examples/*/README.md` when a demo path changed;
   - never claim compliance outcomes; say tamper-evident, not immutable; attribution, not authentication.
6. Run `/verify-change` and keep the results for the body.

## Commits

- Conventional commits: `type(scope): subject` with types `feat fix docs test chore refactor perf`; one coherent commit per concern.
- The body states why, what was proven, and anything a reviewer must know (migration, follow-up).
- No AI `Co-Authored-By` trailers (repository policy in `.claude/rules/github-workflow.md`).
- Identity comes from the user's git config; do not invent one.

## PR body

Write the body to a file outside the tree (`$TMPDIR/pr-<n>.md`) or an untracked root file that is never staged. Sections, in order:

1. **Summary** — what is wrong today, proven how (probe test, log, CI run), and the verdict per suspected gap when there are several.
2. **Decision** — the contract chosen and the alternatives rejected, with the product boundary it follows.
3. **Changes by commit** — one line per commit; note compatibility-sensitive surfaces explicitly (schema, evidence, YAML, HTTP/JSON, machine codes, CLI output, exported Go API).
4. **Regression tests** — names, and the statement that each fails without its fix when that was checked.
5. **Verification matrix** — layer, exact command, result; Docker-only rows say "PR checks".
6. **CI history on this PR** — once there is any: commit, failing step, root cause, fixing commit. Never describe a failure as flaky without a mechanism.
7. **Limitations** — what still is not guaranteed, in the same words as `LIMITATIONS.md`.
8. **Migration implications** — new codes, changed defaults, config to add, re-verification impact.
9. **Not changed** — adjacent things deliberately left alone.

Apply with `gh pr create --draft --body-file <path>` or `gh pr edit <n> --body-file <path>`, then confirm it landed: `gh pr view <n> --json body -q .body | head`. A skipped edit leaves the first draft on the PR indefinitely.

## Push yourself, gate the rest

Commit and push the feature branch yourself (`git push -u origin <branch>`), per `.claude/rules/github-workflow.md`. Creating or editing the PR, commenting, and merging happen only when the user asks for that action; otherwise end the handoff with the exact command, for example:

```
gh pr create --draft --title "<type(scope): subject>" --body-file <path>
```

If the environment has no git credentials, report that and hand over the push command too.

## After the push

- Watch `gh pr checks <n>` (or the checks API). The jobs that gate merge are CI (test, proof-gates, product-demo-smoke, lint, shellcheck, build, docker), Docs, Security, CodeQL, Shortlist Demo and OpenShell Live (live v0.1.3 and the showcase job).
- Reproduce every red check with `/verify-change` against the commit CI actually ran before touching code.
- The PR stays a draft until all checks are green; the user marks it ready and merges.
- Merges on this repository are rebase merges: commit hashes change on `main`, and a tag placed on a branch commit will not be an ancestor of `main`. Tag releases on `main` after the merge (`/cut-release`).
