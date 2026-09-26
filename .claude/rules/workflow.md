# Claude Code workflow

Claude Code 2.1.277+ reads the repository's root and nested `AGENTS.md` files directly.
Treat those files as the engineering contract.

For non-trivial architecture, policy, persistence, evidence, protocol, or multi-package changes, investigate first and present a plan before editing.

Use repository skills for repeatable multi-step workflows instead of improvising them.
Use subagents only for genuinely independent exploration or work; keep simple read/edit tasks in the main context.
Use isolated git worktrees for concurrent implementation sessions.

Claude memory is non-authoritative. Re-check current code, tests, and GitHub issues before relying on remembered roadmap, issue status, or architecture.

Do not perform irreversible Git, GitHub, release, host, credential, or infrastructure mutations without explicit human instruction.
