# Changelog

All notable changes to Dativo Talon are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.8.7] - 2026-02-26

### Fixed

- **fix(gateway):** Force `store: true` on OpenAI Responses API requests instead of only adding it when missing. OpenClaw (and other clients) may send `store: false` explicitly; the gateway now overwrites it so multi-turn conversations work through the proxy.

## [0.8.6] - 2026-02-26

### Fixed

- **fix(gateway):** Automatically inject `store: true` into OpenAI Responses API requests (`/v1/responses`) when not explicitly set. Without this, OpenAI does not persist response items, causing 404 errors on multi-turn conversations when the client (e.g. OpenClaw) references previous response IDs. Explicit `store: false` from the client is preserved.

### Test

- **test(gateway):** Added `TestIsResponsesAPIPath` and `TestEnsureResponsesStore` — path detection for Responses API, store injection with field preservation, explicit store override, and invalid JSON safety.

## [0.8.5] - 2026-02-26

### Fixed

- **fix(gateway):** Strip `Accept-Encoding` from headers forwarded to upstream providers. Go's `http.Transport` only auto-decompresses gzip responses when it manages the header itself; forwarding the client's `Accept-Encoding` caused raw gzip bytes to be written back to the client, producing "404 + binary garbage" in OpenClaw and other clients. Also strip stale `Content-Length` (invalid after PII redaction). Defensive strip added in both the gateway handler and the `Forward()` function.
- **fix(version):** `talon version` and OTel `service.version` resource now use `runtime/debug.ReadBuildInfo()` as fallback when ldflags are not injected (e.g. `go install ...@v0.8.5`), so the correct module version is displayed instead of "dev" in both CLI output and trace spans.

### Docs

- **docs(openclaw):** Added troubleshooting entry for "Talon dev" version string after `go install`.

### Test

- **test(gateway):** Added `TestForward_GzipErrorDecompressed` and `TestForward_GzipSuccessDecompressed` — verify that gzip-compressed upstream responses (both 404 and 200) are transparently decompressed for the client, PII scanner, and token usage parser.

## [0.8.4] - 2026-02-25

### Fixed

- **fix(gateway):** Response PII scanner now scans only LLM-generated content fields (`choices[].message.content` for OpenAI, `content[].text` for Anthropic) instead of the entire JSON body. Prevents false positives on API envelope fields (`created` timestamp, token counts, `id`, `system_fingerprint`). The `[NATIONAL_ID]` false positive on `created` timestamps is eliminated.
- **fix(init):** `talon init --pack openclaw` now shows `TALON_SECRETS_KEY` as step 1 before `talon secrets set`, preventing vault key mismatch errors.

### Docs

- **docs:** macOS `go install` linker error (`unsupported tapi file type`) workaround added to README, OpenClaw integration guide, and first-governed-agent tutorial.

### Test

- **test(gateway):** Comprehensive response PII false-positive prevention suite — 12 envelope-only subtests (timestamps, large tokens, fingerprints, Anthropic format, multi-choice, multimodal, empty/null content), 4 content-PII-with-envelope-preserved subtests, 9 `extractResponseContentText` unit tests, 5 `scanResponseForPII` mode tests.

## [0.8.2] - 2026-02-25

### Added

- **feat(init):** `talon init --pack openclaw` generates OpenClaw gateway starter (`agent.talon.yaml` + `talon.config.yaml`) with post-init instructions.
- **docs(openclaw):** Integration guide — baseUrl with trailing `/v1` for correct upstream paths; two-keys clarification (TALON_SECRETS_KEY vs caller api_key); troubleshooting (404, binary garbage, vault key); diagnostics script; recommended sequence (secrets then serve). Standardized caller api_key to `talon-gw-openclaw-001` across examples and guides; install instructions (go install, install.gettalon.dev).

### Fixed

- **fix(gateway):** Error responses (4xx/5xx) from upstream are no longer streamed; body is read and forwarded so clients receive readable JSON instead of raw binary/gzip (fixes OpenClaw "404 + garbage" when upstream returned error with SSE content-type).

### Test

- **test(gateway):** Forward-level tests for error responses (404/500/429/400/401 with SSE or JSON) not streamed; success stream unchanged. Gateway pipeline tests: upstream 404/500 readable, 404 with SSE content-type, evidence recorded on upstream error, PII redact then upstream 404, 429 rate-limit forwarded with headers.

## [0.8.1] - 2026-02-25

### Added

- **feat(governance):** Tool-aware PII redaction with per-tool, per-argument policies — allow/redact/audit/block categories (Gap T1).
- **feat(gateway):** Response-path PII scanning with redact/block/warn modes for both MCP proxy and LLM gateway (Gap F).
- **feat(agent):** Kill switch via `ActiveRunTracker.Kill()` Go API (Gap D). CLI and HTTP wrappers planned for next release.
- **feat(agent):** Circuit breaker with half-open recovery for repeated policy denials, configurable via `circuit_breaker_threshold` and `circuit_breaker_window` in `.talon.yaml` (Gap C).
- **feat(policy):** Destructive operation detection in `tool_access.rego` — blocks `delete`, `drop`, `remove` patterns (Gap A).
- **feat(policy):** Per-agent rate limit isolation in `rate_limits.rego` with `requests_last_minute_agent` policy input (Gap B).
- **feat(agent):** Contextual volume detection in plan review — flags high-volume operations (Gap E).
- **feat(evidence):** `SanitizeForEvidence` defense-in-depth — scrubs PII from evidence payloads before storage (Gap G).
- **feat(memory):** Optional HMAC signing for memory entries (Gap H).
- **feat(evidence):** Pre-execution pending evidence for tool calls — writes "pending" step record before `tool.Execute()`, updates to "completed"/"failed" after. A kill or crash never creates an unaudited action (Gap T2).
- **feat(mcp):** `tools/list` filtering in MCP proxy — agents only see tools in their `allowed_tools` list (Gap T3).
- **feat(agent):** Separate tool failure tracking — tool execution errors feed `ToolFailureTracker` with operator alerting, not the circuit breaker. Configurable via `tool_failure_threshold` and `tool_failure_window` (Gap T4).
- **feat(agent):** Per-tool execution timeouts — reads `ToolPIIPolicy.Timeout` and wraps `tool.Execute()` with `context.WithTimeout` (Gap T5).
- **feat(agent):** Tool argument validation interface — tools implementing `ArgumentValidator` get pre-execution validation. Full JSON Schema validation planned for Phase 2 (Gap T6).
- **feat(gateway):** Per-caller and global rate limiting enforced via token bucket (`golang.org/x/time/rate`). Configured via `global_requests_per_min` and `per_caller_requests_per_min`.
- **fix(agent):** Wire circuit breaker into Runner execution — checks before policy evaluation, records denials/successes.
- **fix(agent):** Pass `requests_last_minute_agent` to OPA policy input — per-agent rate limiting now functional.
- **test:** Comprehensive E2E governance test suite covering OpenClaw incident failure modes.

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

[Unreleased]: https://github.com/dativo-io/talon/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/dativo-io/talon/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/dativo-io/talon/compare/v0.7.6...v0.8.0
[0.7.6]: https://github.com/dativo-io/talon/compare/v0.7.5...v0.7.6
[0.7.5]: https://github.com/dativo-io/talon/compare/v0.7.4...v0.7.5
[0.7.2]: https://github.com/dativo-io/talon/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/dativo-io/talon/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/dativo-io/talon/releases/tag/v0.7.0
