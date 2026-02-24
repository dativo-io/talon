# Changelog

All notable changes to Dativo Talon are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- (none)

## [0.8.0] - 2026-02-24

### Added

- **Memory Phase 1:** Input-hash deduplication; `memory.governance.dedup_window_minutes`; per-run `--no-memory`; `talon audit show` without ID shows latest; retention/max_entries enforcement. See [docs/MEMORY_GOVERNANCE.md](docs/MEMORY_GOVERNANCE.md).
- **Memory Phase 2:** Consolidation pipeline (ADD/UPDATE/INVALIDATE/NOOP); temporal invalidation (preserved for audit); point-in-time `AsOf` (CLI `talon memory as-of <RFC3339>` and API `GET /v1/memory/as-of`). See [docs/MEMORY_GOVERNANCE.md](docs/MEMORY_GOVERNANCE.md).
- **Memory Phase 3:** Three-type memory (semantic, episodic, procedural) and relevance-scored retrieval (relevance × recency × type weight × trust); enhanced input fingerprint (prompt + attachment hashes). See [docs/MEMORY_GOVERNANCE.md](docs/MEMORY_GOVERNANCE.md).

## [0.7.6] - 2026-02-23

### Changed

- **CLI:** When `talon run` is invoked without `--agent`, the runtime agent ID (evidence, memory, secrets) is now taken from the loaded policy file (`agent.name` in the YAML) instead of the CLI default `"default"`. Explicit `--agent <name>` continues to override. This aligns config file and runtime identity when using the default policy.

### Added

- **CLI:** `resolveRunAgentName` and unit tests for default vs explicit agent name resolution; `--agent` flag description updated; QUICKSTART and PERSONA_GUIDES note the behavior when `--agent` is omitted.

## [0.7.5] - 2026-02-23

### Added

- **Policy:** `policies.data_classification.block_on_pii` — when true, runs are denied (no LLM call) when the user prompt or any attachment content contains PII; prompt and attachment text are scanned and evidence is recorded on deny. Documented in policy cookbook.

### Fixed

- **Agent:** Deterministic ordering of `PIIDetected` / `pii_detected` in evidence and logs (merged PII entity names are now sorted to avoid flaky tests and unstable serialized evidence).

## [0.7.2] - 2026-02-23

### Fixed

- **CI:** Dockerfile Go 1.24 to match go.mod; goreleaser skip linux/arm64 (CGO assembler incompatibility in goreleaser-cross); gitleaks allowlist for test/doc placeholders.

## [0.7.1] - 2026-02-23

### Fixed

- **Release:** Use goreleaser-cross for CGO cross-compilation (fix darwin/arm64 build from Linux). GoReleaser archive deprecations (format → formats).
- **Security:** Run gitleaks CLI instead of gitleaks-action@v2 to avoid org license requirement. Dependency upgrades for govulncheck: OpenTelemetry v1.28 → v1.40 (GO-2026-4394), OPA v0.62 → v0.68 (GO-2024-3141), golang.org/x/net → v0.38 (GO-2025-3595). Go 1.22 → 1.23 for stdlib fixes.

## [0.7.0] - 2026-02-23

### Added

- **Bootstrap & CLI:** Cobra CLI with OpenTelemetry integration; zerolog structured logging with OTel bridge; Makefile, Dockerfile, docker-compose, CI workflows.
- **Policy engine:** Embedded OPA with v2.0 schema; Rego policies for cost limits, rate limits, time restrictions, resource limits, tool access, secret access, memory governance, data classification; `talon init` and `talon validate` (strict mode); template-based init.
- **MCP proxy:** Architecture and onboarding docs; proxy Rego policies (tool allowlists, rate limits, PII redaction, high-risk blocking).
- **PII, attachments, LLM:** Regex-based PII classifier (EU patterns); attachment scanner with extraction, instruction detection, sandboxing; multi-provider LLM router (OpenAI, Anthropic, Bedrock EU, Ollama); cost estimation and tier-based routing.
- **Agent pipeline:** Full runner (policy → classify → scan attachments → OPA → secrets → route LLM → evidence); execution plan generation and plan review gate (EU AI Act Art. 11/13); pipeline hooks (webhook delivery); MCP tool registry; `talon run` with `--dry-run`, `--agent`, `--tenant`, `--attach`, `--policy`.
- **Secrets & evidence:** AES-256-GCM secrets vault with per-secret ACL; secret rotation and audit log; SQLite evidence store with HMAC-SHA256; progressive disclosure (list → timeline → detail); `talon audit list/verify`, `talon secrets set/list/audit/rotate`.
- **Cost & PII:** Graceful cost degradation (fallback model when budget threshold reached); expanded EU PII patterns.
- **Testing:** Test pyramid (unit, integration, e2e); shared `internal/testutil` (mock provider, policy helpers, constants); e2e CLI flows (init, run, validate, audit, costs, secrets, memory); fuzz and benchmarks; CI coverage threshold 70%.
- **Memory, context, triggers:** Governed agent memory (Constitutional AI, allowed/forbidden categories, PII scan); shared enterprise context mounts with privacy tags; cron scheduler and webhook handler; memory CLI and search.
- **SMB governance:** Onboarding and governance improvements for SMB use cases.
- **Agent planning:** Bounded agentic loop; step-level evidence; loop containment policy; tests and docs.
- **Observability & CLI:** Config show, doctor, costs/report commands; examples and docs.
- **HTTP API & MCP:** REST API with 15+ endpoints; MCP JSON-RPC 2.0 server; MCP proxy for vendor integration; embedded dashboard (evidence, plan review, memory); per-tenant rate limits.
- **CI/CD & release:** Golden tests for policy engine; integration full-flow and gateway stub tests; gofmt, vet, OPA policy tests, Codecov in CI; security workflow (govulncheck, gitleaks, SBOM); docs workflow (markdown link check); install script with checksum verification; GoReleaser with SBOM and Docker (GHCR); SECURITY.md; issue and PR templates.

### Fixed

- Policy engine post-review fixes (PR #4).
- Memory: prevent data race on shared Governance OPA evaluator.

### Security

- AES-256-GCM encryption for secrets at rest.
- HMAC-SHA256 signatures for evidence integrity.
- Timing-safe API key comparison; per-agent/tenant ACL; fail-closed policy evaluation.

### Compliance

- ISO 27001: policy, classification, audit, secrets controls.
- GDPR: controller obligations, privacy by design, processing records, security.
- NIS2: risk management, incident reporting via evidence timeline.
- EU AI Act: risk management, transparency, human oversight (Art. 9, 13, 14).
- Data residency: tier-based EU model routing.

[Unreleased]: https://github.com/dativo-io/talon/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/dativo-io/talon/compare/v0.7.6...v0.8.0
[0.7.6]: https://github.com/dativo-io/talon/compare/v0.7.5...v0.7.6
[0.7.5]: https://github.com/dativo-io/talon/compare/v0.7.4...v0.7.5
[0.7.2]: https://github.com/dativo-io/talon/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/dativo-io/talon/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/dativo-io/talon/releases/tag/v0.7.0
