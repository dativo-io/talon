# Claude Code workflow

Claude Code 2.1.277+ reads the repository's root and nested `AGENTS.md` files directly.
Treat those files as the engineering contract.

For non-trivial architecture, policy, persistence, evidence, protocol, or multi-package changes, investigate first and present a plan before editing.

Use repository skills for repeatable multi-step workflows instead of improvising them:

- `/investigate-bug` — reproduce and root-cause before deciding on a fix;
- `/architecture-review` — review a change against product boundaries without implementing it;
- `/implement-issue` — issue → plan → implementation → verified handoff;
- `/verify-change` — the local verification ladder, the CI-job-to-command map, and how to reproduce a CI failure from a log;
- `/prepare-pr` — diff hygiene, docs set, commits, PR body, CI watch (no push or GitHub mutation without instruction);
- `/respond-to-review` — classify, reproduce, fix, prove and document each review finding on the PR branch;
- `/cut-release` — changelog section, release PR, annotated tag on merged main, release verification.

Knowledge is layered: `AGENTS.md` files (root and per package) hold durable invariants; `.claude/rules/*.md` hold always-on, path-scoped checklists (testing, GitHub workflow, contract-surface registration); skills hold invoked workflows; `docs/**`, `CONTRIBUTING.md` and `LIMITATIONS.md` hold the public truth. Put new knowledge in the layer that matches its lifetime; do not duplicate it across layers.
Use subagents only for genuinely independent exploration or work; keep simple read/edit tasks in the main context.
Use isolated git worktrees for concurrent implementation sessions.

Claude memory is non-authoritative. Re-check current code, tests, and GitHub issues before relying on remembered roadmap, issue status, or architecture.

Work on a feature branch from the first edit and commit and push it yourself at verified checkpoints (`.claude/rules/github-workflow.md`). Do not perform other irreversible Git, GitHub, release, host, credential, or infrastructure mutations (PR creation or edits, merges, tags, releases, force-pushes) without explicit human instruction.
