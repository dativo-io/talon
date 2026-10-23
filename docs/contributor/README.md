# Contributor documentation

This directory holds documentation intended for **contributors and maintainers**, not end users.

- **[adding-a-provider.md](adding-a-provider.md)** — Step-by-step guide to add a new LLM provider (scaffold → implement → test → PR).
- **`adr/`** — Architecture Decision Records (ADRs). These capture design decisions, rationale, and consequences. For user-facing feature docs (e.g. how agent planning works), see the main [docs](../) folder (e.g. [Agent Planning](../AGENT_PLANNING.md)).

## Agentic development

AI coding agents (Claude Code and compatible tools) read the repository's engineering contract directly:

- **`AGENTS.md`** at the root and in `internal/<pkg>/` — durable invariants per subsystem (agent catalog, evidence, gateway, MCP, policy, pricing, session).
- **`.claude/rules/`** — always-on, path-scoped checklists: `testing.md`, `github-workflow.md`, `contract-surfaces.md` (where a machine code, evidence annotation, pricing entry, config field or smoke section must be registered).
- **`.claude/skills/`** — invoked workflows: `investigate-bug`, `architecture-review`, `implement-issue`, `verify-change` (local ladder and CI-job-to-command map), `prepare-pr`, `respond-to-review`, `cut-release`.

Human contributors can read the same files; they describe how the repository is actually verified and released. Machine-specific constraints (host resources, credentials, sandboxing) belong in an untracked `CLAUDE.local.md`, never in these files.
