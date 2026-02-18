# Changelog

All notable changes to Talon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

#### Agent Pipeline (`internal/agent/`)
- Full orchestration runner: load policy → classify input → scan attachments → evaluate OPA → resolve secrets → route LLM → call provider → classify output → generate evidence
- Execution plan generation for EU AI Act Art. 11/13 compliance (plan review gate, SHA-256 hashed prompts, configurable timeout)
- Plan review store (SQLite-backed, approve/reject/modify workflow with annotations)
- Pipeline hook system: pre/post hooks at every stage (policy, LLM, tools, memory, evidence) with webhook delivery
- MCP-compatible tool registry (thread-safe, `Register`/`Get`/`List`)
- Dry-run mode (`--dry-run` shows policy decision without calling LLM)

#### CLI Commands (`internal/cmd/`)
- `talon run [prompt]` — fully functional with `--agent`, `--tenant`, `--dry-run`, `--attach`, `--policy` flags
- `talon audit list` — query evidence records with `--tenant`, `--agent`, `--limit` filters
- `talon audit verify [id]` — verify HMAC-SHA256 signature integrity of an evidence record
- `talon secrets set [name] [value]` — store AES-256-GCM encrypted secret
- `talon secrets list` — show metadata (names + access counts, values never shown)
- `talon secrets audit` — view secret access log (allowed/denied, per tenant/agent)
- `talon secrets rotate [name]` — re-encrypt with fresh nonce

#### Evidence Store (`internal/evidence/`)
- SQLite-backed evidence persistence with HMAC-SHA256 signatures
- Progressive disclosure: index (list view) → timeline (NIS2 Art. 23) → full detail
- Evidence generator that creates, signs, and persists records in one call
- Tamper detection via signature verification
- Filtering by tenant, agent, time range

#### Secrets Vault (`internal/secrets/`)
- AES-256-GCM encrypted secret storage in SQLite
- Per-secret ACL with glob pattern matching for agents, tenants, and forbidden lists
- Every access (allowed and denied) logged to audit table
- Secret rotation (re-encrypt with fresh nonce, same plaintext)
- Access counting per secret

#### Configuration (`internal/config/`)
- Operator-level config via env vars (`TALON_*`) or `talon.config.yaml`
- Deterministic per-machine key derivation for zero-config quickstart
- Validation (key length, attachment limits)
- Warning on default crypto keys

#### LLM Key Resolution (`internal/llm/`)
- Vault-first API key resolver: tenant-scoped keys from secrets vault, env-var fallback for dev/quickstart
- Provider factory (`NewProviderWithKey`) for runtime credential injection

### Changed
- `go.mod`: `github.com/google/uuid` promoted from indirect to direct dependency
- `talon run`, `talon audit`, `talon secrets` — rewritten from stubs to full implementations

### Infrastructure
- Project bootstrap with CLI framework (cobra)
- OpenTelemetry integration (traces + structured logging)
- Policy engine (OPA embedded) with YAML loader
- PII detection (regex-based EU patterns)
- Attachment scanner (prompt injection detection + sandboxing)
- Multi-provider LLM router (OpenAI, Anthropic, Bedrock, Ollama)
