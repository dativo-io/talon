# Changelog

All notable changes to Dativo Talon are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Release Note Quality Bar

For user-facing entries, include:

- why this change matters (problem solved),
- who should care (operator/developer persona),
- how to verify quickly (command or path),
- any upgrade/migration impact,
- at least one share artifact reference (screenshot, GIF, or snippet) when applicable.

### Fixed

- **Mid-stream upstream death now emits a family-correct terminal SSE event (#195).** Previously a provider dying mid-stream (or the gateway's own request timeout firing) simply truncated the SSE stream with a 200 already on the wire — Codex retry-loops waiting for a `response.completed` that never comes; Anthropic SDKs hang until their own timeout. Anthropic-wire streams now end with the documented `event: error` (`api_error`), Responses streams with `event: response.failed` (`upstream_error`); healthy streams are byte-identical to before. Chat Completions has no standard mid-stream error event — Talon does not fabricate `[DONE]`, and the remaining truncation is documented in LIMITATIONS. Terminal-event messages are gateway-authored constants; upstream error text is never forwarded. Who cares: anyone running Codex or long Claude generations through the gateway — a dead upstream is now an explicit, machine-readable stream ending. Verify: `go test ./internal/gateway/ -run TestStreamCopy_ -v`.
- **Gateway error envelopes are now provider-native on three more paths (#195).** (1) Anthropic-family denials without a machine code carried `"type": "error"` — not a member of Anthropic's error enum, so typed SDK error handling fell through; the fallback now maps the HTTP status to the correct enum member (`400→invalid_request_error`, `401→authentication_error`, `403→permission_error`, `404→not_found_error`, `413→request_too_large`, `429→rate_limit_error`, `529→overloaded_error`, other `5xx→api_error`). Machine codes from the documented prefix convention (e.g. `session_budget_exceeded`) still travel in `error.type`; the final enum contract table is #142's. (2) Response-PII blocks (HTTP 451) and scanner-unavailable blocks (502) — streaming and non-streaming — previously returned a bare `{"error":{…}}` on both wire families; they now render through the shared per-family envelopes (Anthropic `{"type":"error","error":{…}}`; OpenAI envelope gains its `code` field). (3) Semantic-cache hits on anthropic routes returned an OpenAI chat completion; they now return an Anthropic Messages object. Also documented: pre-route errors (unknown provider prefix) intentionally use the OpenAI shape since no wire family is resolved yet. Who cares: anyone whose Claude-family client parses gateway denials — typed error handling and retry logic now see valid shapes. Verify: `go test ./internal/gateway/ -run 'TestWriteAnthropicError_StatusMappedTypes|TestScanResponseForPII_BlockBodyPerFamily|TestWriteCachedCompletion_AnthropicShape' -v`.

## [1.7.0] - 2026-07-06

### Added

- **`talon secrets set --tenant`/`--agent`: scope CLI-set secrets per tenant (#237).** `talon secrets set` wrote an empty ACL, which means **allow-all** — any authenticated tenant's gateway traffic could cause retrieval of any CLI-set secret, so multi-tenant secret isolation silently did not exist unless secrets were seeded programmatically. New repeatable `--tenant` and `--agent` flags (glob patterns allowed) scope a secret to specific tenants/agents. The default stays allow-all for backward compatibility but now prints a stderr notice pointing at the flags, and scoped sets echo the stored ACL; `talon secrets audit` shows the per-tenant allow/deny decisions. Single-tenant deployments are unaffected. Who cares: MSP/multi-tenant operators — provider-key isolation between customers is now a one-flag change. Verify: `talon secrets set k v --tenant acme`, then confirm an unscoped `talon secrets set` prints the allow-all notice; `go test ./internal/cmd/ -run TestSecretsSet -v`. Docs: [multi-tenant/MSP guide](docs/guides/multi-tenant-msp.md) → "Scope vault secrets per tenant".
- **Coding-agents adoption surface: policy pack, integration guides, reproducible demo (#200 docs, #201, #202, #203 — epic #192 PR-I).** Three pieces turn the epic's machinery into a 10-minute rollout. **(1) `talon init --pack coding-agents`** scaffolds a governed two-caller gateway (Claude Code on the Anthropic wire, Codex CLI on the Responses wire) with honest defaults: `response_pii_action: allow` (anything else buffers whole SSE streams today), soft `max_session_cost`, raised coding timeouts, and four high-precision credential recognizers (PEM private-key block, AWS `AKIA…`, GitHub `ghp_`/`github_pat_`, Anthropic/OpenAI `sk-…` keys) that fire in the real scan path (fixture-tested) — Talon is not a secret scanner; the pack says so and points at gitleaks/trufflehog. The OpenClaw pack's "credential scanning" claim is now backed by the same recognizers. **(2) Guides:** `claude-code-integration.md`, `codex-cli-integration.md` (the docs half of #200), and `governing-coding-agents.md` — the canonical neutral-metadata-contract reference (generic `X-Talon-*` headers, vendor adapters as data, precedence, hygiene, provenance) — plus a new `LIMITATIONS.md` §7 stating every coding-agent sharp edge with its backing test (attribution≠authentication, local tools invisible, subscription billing ungovernable, stream buffering, cache-price fallback, soft caps, `store` semantics, tool-content evidence-only). README gains a coding-agents integration row; the policy cookbook gains the session-budget/recognizer recipe. **(3) `make coding-agents-demo`** (#203): one command, fully offline — the mock provider now speaks **both wire families incl. SSE** (Anthropic `message_start`/`content_block_delta`/`message_delta` with cache-token usage; Responses `response.completed` with `cached_tokens`), and `demo.sh` walks a cross-provider session with subagent attribution, a PII event, a provider-native `session_budget_exceeded` denial, and a signed export that verifies. The same sequence is CI-smoke-tested without Docker (`TestCodingAgentsDemo_EndToEnd` builds and drives the real mock binary). Who cares: platform teams who want the epic's governance running against their coding fleet this afternoon, and skeptics who want the receipts first. Verify: `go test -tags=integration ./tests/integration -run TestCodingAgentsDemo_EndToEnd` and `go test ./internal/cmd/ -run TestInitPack_CodingAgents -v`.
- **Dashboard: orchestration session drill-down (#199, epic #192 PR-H).** Operators now see coding sessions and subagents, not just callers. The gateway dashboard gains a **Coding Sessions** panel: the most recently active client/vendor-asserted sessions with request/allow/deny counts, providers, models, token totals, cost, and a click-to-expand per-subagent breakdown (`generator`, `judge ← generator`, …). A **mixed-provider session renders as one session** — the point of the neutral session contract (#194). The numbers are produced by the *same pure function* behind `talon audit list --session` (`evidence.BuildSessionSummary`), re-derived from signed evidence on every snapshot — the dashboard and the CLI are structurally incapable of disagreeing and the destructive 30s `ReconcileFromStore` rebuild can't change them (tested). Denials are now bucketed by machine-code reason (`denials_by_reason`: `session_budget_exceeded`, `budget_exceeded`, `egress_*`, …) instead of lumping under `policy_deny`; the evidence→metrics projection carries `session_id` + orchestration attribution (previously dropped). Panel is hidden without orchestration data; every client-asserted string is HTML-escaped (hostile input — enforced by tests); the old metrics feed card is renamed "Gateway Activity Feed" to end the naming collision. No new endpoints — `sessions` and `denials_by_reason` ride the existing `/api/v1/metrics` JSON + SSE (schema documented in `gateway-dashboard.md`). Who cares: platform operators running Claude Code/Codex fleets — "which session is burning money, on which subagent, across which providers" is now one glance. Verify: `go test ./internal/metrics/ -run 'TestFillSessions|TestDenialsByReason' -v`.
- **Session budget enforcement at the gateway (#198, epic #192 PR-G; fixes #214, #215).** A runaway coding session is now denied as a unit, synchronously, in the policy hot path. Set `policy_overrides.max_session_cost` on a caller and the gateway denies a new request once accumulated session spend + the pre-request estimate exceeds the cap — **cross-provider** (€6 on `anthropic` + €5 on `openai` against a €10 cap → the next request is denied on either route), with reason `session_budget_exceeded: …` rendered provider-native and a structured `session_budget: {limit, spent, estimate}` block in signed evidence (**evidence spec 1.8**, additive). This is a **soft cap**: one in-flight request can overshoot (estimate < real cost); the overshoot is caught on the next request; atomic reservation stays #144. Shadow mode records would-have-denied; a session-store failure **fails open** with a `session_budget_unavailable` evidence annotation; hot-path cost is one caller-scoped SQLite read (~0.03 ms measured, `BenchmarkSessionBudgetLookup`). Underneath, the session lifecycle is fixed (#214): asserted session ids **create-if-absent** under the caller-scoped tuple `(tenant_id, caller_id, external_session_id)` (unique index; additive `sessions` columns `external_session_id`/`caller_id`/`source`), synthetic ids **never** create session rows (the orphan-row-per-request growth is gone), usage actually accumulates, and rows follow `audit.retention_days` via a daily sweep. Isolation is structural (#215): two callers asserting the same session id get separate sessions and budgets, session reads in policy input go through the tuple (never the raw client-supplied id), and `GET/POST /v1/sessions/{id}[/complete]` + session listing now enforce tenant ownership — another tenant's session is indistinguishable from a missing one (404). Who cares: platform teams putting Claude Code/Codex fleets behind Talon — a runaway orchestrator burning budget in one session is stopped at the gateway with signed proof. Verify: `go test ./internal/gateway/ -run TestSessionBudget -v` and `go test ./internal/session/ -v`.
- **Session-scoped audit and cost rollups (#197, epic #192 PR-F).** A multi-model coding session — an orchestrator on one provider delegating to executors/judges on another, all sharing one `session_id` (#194) — is now auditable as a unit. `talon audit list --session <id>` prints a caller-scoped session summary (window, request/allow/deny/error counts, providers, models, token totals incl. cache read/write, total cost) plus a per-subagent breakdown keyed on the client-asserted `orchestration.agent_id` (falling back to the caller), then lists the session's records. `talon audit export --session <id>` scopes any export format to one session; `talon audit verify --session <id>` HMAC-verifies every record in a session and exits non-zero on any failure; `talon costs --session <id>` (with `--json`) gives the cost rollup. The aggregation is a single pure function, `evidence.BuildSessionSummary`, reused verbatim by the dashboard sessions panel (#199) so CLI and UI can never drift. **Caller-scoped by construction:** `--tenant`/`--caller` filters drop records that are not the caller's, and the summary surfaces every distinct caller that touched a `session_id` so a cross-caller collision is visible rather than silently merged. No new tables — it reads existing signed evidence via `Store.ListBySessionID`. Who cares: platform/FinOps/DPO teams governing coding-agent rollouts — "what did this whole coding session cost, across which models, and did every record verify" is now one command. Verify: `go test ./internal/evidence/ -run TestBuildSessionSummary -v` and `go test ./internal/cmd/ -run 'TestAuditListCmd_SessionScoped|TestAuditVerifyCmd_Session' -v`.
- **Provider-aware usage-detail extraction and cache-aware pricing (#196, epic #192 PR-E).** Signed cost evidence is now correct for prompt-cached and streamed traffic — the traffic class coding agents generate on nearly every call. The gateway parses prompt-cache tokens per provider family (Anthropic `cache_creation_input_tokens`/`cache_read_input_tokens`, which are separate counts; OpenAI `prompt_tokens_details.cached_tokens` / Responses `input_tokens_details.cached_tokens`, which are a *subset* of input and are normalized to `input = prompt − cached`), and reads OpenAI Responses streaming usage from the terminal `response.completed` event (Codex always streams — previously its cost was estimate-only). The cost estimator contract is now cache-aware and provider-keyed (`CostEstimator func(provider, model string, Usage) CostResult`), so the routed provider's real pricing is used instead of a max-across-providers guess, and evidence records **how** the number was derived (`pricing_basis`: `table` | `cache_fallback_input_rate` | `default_estimate`; `pricing_known`) so a signed cost is never silently a fallback. Pricing schema gains optional `cache_read_per_1m`/`cache_write_per_1m` (absent → cache tokens priced at the input rate, fail-conservative — never below pre-change); current Anthropic (write 1.25×, read 0.1×) and OpenAI (cached 0.1×, no write premium) models refreshed. Evidence `execution.tokens` gains `cache_read`/`cache_write`, `execution` gains `pricing_basis`/`pricing_known` (evidence spec **1.7**, additive); `talon audit export` gains `cache_read_tokens`/`cache_write_tokens`/`pricing_basis` columns. Chat-completions streaming requests get `stream_options.include_usage` injected (per-provider `inject_stream_usage`, default true) so their usage is captured. Who cares: anyone reading `talon costs`/signed FinOps evidence for Claude Code or Codex traffic — cached-prompt spend was materially misstated before. Verify: `go test ./internal/gateway/ -run TestGatewayCacheCost_EndToEnd -v` and `go test ./internal/pricing/ -run TestEstimateCached -v`.
- **Provider-neutral orchestration metadata contract (#194, epic #192 PR-D).** Coding agents (Claude Code, Codex, any client) now get per-subagent attribution in signed evidence. The gateway ingests session/subagent/parent identity from generic `X-Talon-Session-ID` / `-Agent-ID` / `-Parent-Agent-ID` / `-Client` headers, or a vendor adapter (Claude Code's `x-claude-code-*`, Codex's `session-id`/`x-openai-subagent`) — adapters are a data table, not code branches, so a new client needs no core change. Precedence is generic > vendor > absent; one `session_id` groups a coding session across provider routes (an `anthropic` orchestrator delegating to an `openai` executor). Recorded as an `orchestration` block (evidence spec **1.6**), flattened into `talon audit export` (`orch_agent_id`, `orch_client`, `orch_session_source`), and shown by `talon audit show`. **Evidence-only and caller-scoped by construction:** identity is `provenance: client_asserted`, never a policy input (attestation is #149), and one caller can never join another caller's session by asserting its id. Per-caller `accept_client_metadata` (default true) gates recording; hostile header values (oversized, non-token charset, HTML injection) are rejected with a 400 before reaching evidence. Also closes the #219 spec drift by backfilling the `failover` field into the integrity-spec field table. Who cares: security/DPO teams and platform leads governing coding-agent rollouts — "which subagent, in which session, sent what" is now answerable from signed evidence. Verify: send a request with `X-Claude-Code-Agent-Id: reviewer`, then `talon audit export --format json | jq '.records[-1] | {orch_agent_id, orch_client}'`.

### Fixed

- **`connect_timeout` doubled as the response-header budget — long non-streaming requests were killed at 10s (#230).** The gateway set `http.Transport.ResponseHeaderTimeout` from `connect_timeout` (default 10s), so any upstream whose time-to-first-byte exceeded 10s was aborted (`http2: timeout awaiting response headers`) regardless of `request_timeout=120s` — long-prompt non-streaming Responses/Messages calls hit this routinely. Dialing, meanwhile, was not bounded at all (no `DialContext`). Now `connect_timeout` bounds connection establishment (TCP dial + TLS handshake) via a real `net.Dialer`, and a new `gateway.timeouts.response_header_timeout` bounds the header wait, **defaulting to `request_timeout`** so slow-TTFB calls get the full request budget. The coding-agents pack and both integration guides drop their `connect_timeout: 60s` workaround. No config change is required to benefit; set `response_header_timeout` explicitly only to tighten it. Who cares: any operator running non-streaming traffic with large inputs or high reasoning effort. Verify: `go test ./internal/gateway/ -run TestHTTPClientForGateway -v`. Docs: per-phase timeout table in [configuration reference](docs/reference/configuration.md).
- **Test and CI hardening (#234, #246, #236 guard, #242).** Two order-dependent test flakes fixed: `TestToolApprovalStore_Cleanup` (a 50 ms approval timeout could expire before the poll loop observed the pending request under parallel load — #234) and `TestBudgetAlertClaimFire` (a package-global 1 h-cooldown dedupe table was never reset, so any `-count>1` run failed deterministically — #246, found while validating #234). A new integration guard (`TestExampleComposeHostPathsAreTracked`) asserts every host path bind-mounted by an example compose file is git-tracked, closing the #236 loop so a `.gitignore` rule can never again silently drop a demo's config. And CI now runs `shellcheck` over every tracked `*.sh` (#242) — the demo/ops scripts were previously invisible to CI, which is how three shell-only bugs (#239, #240, #241) shipped in sequence; 65 findings were fixed or triaged to a clean tree, including a real unquoted-expansion hazard in `run-benchmarks.sh`. Contributor-facing; no runtime behavior change.
- **`.gitignore` swallowed every `talon.config.yaml` — five example stacks referenced configs that were never in git (#236).** The repo-wide ignore (meant for user-local root configs) silently kept intentional example/template configs out of commits and out of `//go:embed`: the README's 60-second demo compose, the copaw/gateway-minimal/scanner examples — and it nearly shipped the new coding-agents pack with its config template missing (caught by PR-I's pre-merge adversarial review; a fresh clone would have failed `talon init --pack coding-agents` at runtime). `.gitignore` now carves out `internal/pack/templates/**` and `examples/**`, and all six previously-swallowed configs (verified secret-free — they carry vault secret *names* only) are committed. Also fixed en route: pack wizard post-init base URLs gain the required trailing `/v1` for OpenAI-SDK/Codex clients (#235), and the OpenClaw template's recognizer set now matches the coding-agents pack exactly.
- **`talon init` scaffold wrote a stale pricing table and schema-invalid numeric agent names (#231, #232).** The scaffold embedded a third, drifting copy of the pricing table — missing every model added since (incl. `gpt-5.3-codex`, `claude-sonnet-5`) and all prompt-cache rates — which silently *shadowed* the binary's current embedded table (`LoadOrDefault` prefers a loadable file), so freshly scaffolded projects priced current models as `default_estimate`. `talon init` now writes the embedded default's exact bytes (`pricing.DefaultModelsYAML()`; the drifting template is deleted; an equality test prevents recurrence). Separately, all init/pack templates rendered `name: {{ .Name }}` unquoted, so `--name 192` produced a YAML integer and the generated `agent.talon.yaml` failed schema validation immediately after init printed success — names are now rendered with `%q` quoting across all ten templates. Found during end-user verification of epic #192. Verify: `go test ./internal/cmd/ -run TestInitScaffold -v`.

- **Gateway force-overwrote the client's Responses API `store` field (#213).** `ensureResponsesStore` unconditionally set `store: true`, silently reversing an explicit client `store: false` — 30-day provider retention against the client's stated intent. This matters for Codex CLI, which sends `store: false` and resends the full transcript each turn. Now governed by `gateway.providers.<id>.responses_store_mode`: **`preserve`** (new default) honors client intent for every client; `force_if_absent` sets `store: true` only when the field is absent (opt-in for `previous_response_id` continuity — OpenClaw/quickstart use it); `force_true` still forces but records the override of explicit client intent in signed evidence (annotation `responses_store_overridden`). Migration: OpenClaw-style deployments relying on the old forcing must set `responses_store_mode: force_if_absent`. Verify: `go test ./internal/gateway/ -run TestConformanceResponses_StoreModes -v`.

- **Anthropic streaming cost evidence was silently input-only (#211).** Real `message_delta` SSE events carry top-level `usage`, which matched the OpenAI parsing branch first — streaming output tokens were never captured, so signed cost undercounted every streamed Anthropic response and TPOT was never computed. Typed Anthropic events are now parsed before the generic branch. Who cares: anyone reading `talon costs` or signed FinOps evidence for streamed Anthropic traffic. Verify: `go test ./internal/gateway/ -run TestConformanceAnthropic_Fixtures/streaming_sse -v`.
- **`count_tokens` recorded fabricated spend (#218).** The free `/v1/messages/count_tokens` endpoint returns no `usage` wrapper, so evidence fell back to the fixed pre-request estimate and the invented cost counted against caller budgets. Now classified as `invocation_type: "gateway_count_tokens"` with cost 0 and zero budget estimate — still fully governed (PII scan + policy run; the token count is recorded in evidence). Verify: `go test ./internal/gateway/ -run TestConformanceAnthropic_Fixtures/count_tokens -v`.
- **Block-array `system` prompts could not be redacted.** The form Claude Code sends on every request (with `cache_control`) was extracted for detection but only string-form `system` was rewritten, so PII + `pii_action: redact` failed closed with HTTP 400 on every such request. Block arrays are now redacted; `cache_control` and untouched blocks survive byte-identically.
- **Client backoff headers were dropped.** `Retry-After`, `request-id`/`anthropic-request-id`, and the Anthropic token-remaining/reset rate-limit headers are now forwarded to callers — coding-agent 429 backoff depends on them.

### Added

- **Anthropic protocol conformance suite (#193, epic #192 PR-A).** Recorded Claude-Code-shaped fixtures (streaming SSE, block-array system + `cache_control`, tool_use/tool_result round-trips, `count_tokens`, image blocks, `tool_choice`, ~50KB system prompts) replayed through the full gateway pipeline against a canned upstream, plus a transform-determinism guarantee: identical input yields byte-identical rewritten bodies (non-determinism would silently break provider-side prompt caching for clients). Fixtures are sanitized (synthetic keys, corpus emails) with a scripted recapture procedure (`scripts/record-conformance-fixtures.sh`) and a pinned last-verified client version (`internal/gateway/testdata/conformance/README.md`).
- **Pricing table refreshed to the current Anthropic and OpenAI lineups** (verified against vendor pricing pages, 2026-07): Claude Fable 5 / Opus 4.8-4.5 / Sonnet 5 / Sonnet 4.6-4.5 / Haiku 4.5, and GPT-5.5/5.4 families + gpt-5.3-codex. Fixes `unknown model for cost estimation` warnings (and the resulting flat-fallback cost evidence) for current-model traffic. Legacy entries retained; operators can still override in `pricing/models.yaml`. Cache read/write rates land with the cache-aware pricing schema (#196).
- **Large-prompt pipeline benchmark.** `BenchmarkGatewayPipelineOverheadLargePrompt` runs a ~50KB PII-bearing system prompt through the full pipeline (informational row in `docs/reference/benchmarks.md`; not regression-gated yet).
- **Observation-only PII scan of tool-related request content (#212, epic #192 PR-B).** Agentic loops feed tool output (file contents, query results) back through the gateway on every turn — previously invisible to PII detection, redaction, AND the residual-PII verifier on both wire families. Talon now scans tool_use inputs, tool_result outputs, function-call arguments (Chat Completions `tool_calls[].function.arguments`, Responses `function_call`/`function_call_output`) and records findings in signed evidence (`classification.tool_content`, evidence spec **1.5**) without changing enforcement: tool content cannot be redacted yet, so acting on the signal would fail-close every redact-mode deployment on agentic traffic. Config: `gateway.default_policy.scan_tool_content: evidence_only` (default) | `off`. Who cares: security/DPO teams governing coding agents and any agentic caller — "which sessions moved PII through tool results" is now answerable from evidence. Verify: send a request with PII only inside a `tool_result` block, then `talon audit export --format json | jq '[.records[] | select(.invocation_type=="gateway")] | sort_by(.timestamp) | last | {tool_content_scanned, tool_content_has_pii, tool_content_entity_types}'` (the flat export carries trailing `tool_content_*` fields; the full nested block is in `--format signed-json` records and `talon audit show`). Limitation stated in LIMITATIONS.md §3; enforcement is future work gated on per-block-type tool redaction.
- **Responses API `instructions` is now governed as prompt text.** The system-prompt equivalent of the Responses API was previously never extracted — PII in `instructions` was forwarded verbatim, unscanned. It now joins the main scanned text and is redactable like any other prompt content.

## [1.6.8] - 2026-07-04

### Added

- **feat(scanner): external EntityScanner adapters and local scanner engines (#181, #204).** Operators can now replace Talon's built-in regex PII scanner with an out-of-process engine — a Microsoft Presidio sidecar, any custom detector speaking the Presidio wire format (HTTP or Unix domain socket), or a local LLM (`scanner.type: llm`, flagship: Ollama) — without changing gateway, MCP, agent, evidence, or redaction paths. Who cares: operators who need detection quality beyond regexes (names, addresses, fuzzy identifiers) or who must keep scanning on their own hardware (air-gap/sovereignty). The core stays deterministic and fail-closed: adapter output is untrusted (size-capped, one invalid entity rejects the scan, rune→byte offset normalization verified against the text), engine timeouts/errors block egress in enforce mode with truthful evidence (`classification.scanner` with engine identity, version, scan duration, and typed failure kind — spec v1.4; flattened as `scanner_engine`/`scanner_type`/`scanner_version`/`scanner_failure` in `talon audit export`), and a residual-PII block is never conflated with an unverifiable scan. Startup health probes refuse to serve against a dead or unrunnable engine (the `llm` probe warm-loads the model). The `llm` engine never trusts model offsets: it prompts for verbatim values (fixed versioned prompt `llm-ner/v1`), relocates every occurrence to byte offsets itself, drops hallucinated and placeholder-shaped values, token-bounds generation, and tolerates field-observed small-model reply shapes (bare arrays, string-array values, unterminated envelopes) while staying fail-closed on anything murkier. `scanner.entities` narrows the NER prompt for CPU-constrained hosts. Built-in regex remains the zero-config default. Verify quickly: `cd examples/scanners/presidio && docker compose up`, send a PII prompt through the gateway, then `talon audit export --format json | jq '.records[-1].scanner_engine'`; or the Ollama variant in `examples/scanners/ollama/`. Docs: [external scanners reference](docs/reference/external-scanners.md), [local scanner engines cookbook](docs/guides/local-scanner-engines.md). Smoke: `tests/smoke_sections/36_external_scanner.sh` (hermetic llama stand-in; `TALON_SMOKE_OLLAMA_URL` opts into real Ollama); nightly `scanner-ollama-smoke` workflow.

## [1.6.7] - 2026-07-03

### Added

- **feat(reliability): error-driven, sovereignty-respecting provider fallback chains (#138, #191).** Operators can now keep agent traffic flowing through provider outages without giving up governance guarantees. On a **transient** upstream failure (timeout, connection error, HTTP 429/5xx) Talon walks an ordered fallback chain — on both the gateway proxy (`gateway.providers.<name>.fallback`, optional per-target model rewrite) and the `talon run` path (`policies.model_routing.tier_N.fallback_chain`). Chains are same-wire-format (OpenAI-compatible ↔ OpenAI-compatible, Anthropic ↔ Anthropic; validated at load). Permanent errors (401/4xx) pass through unchanged; once a chain is engaged only success ends it; exhaustion **fails closed** and the refusal is recorded as a successful governance outcome. Every candidate re-runs the caller's full policy surface (provider allowlist, model lists, target tool policy, budgets, session context) so failover can never become a policy bypass, and under `eu_strict` a non-EU/LOCAL candidate is never dispatched — shadow mode included, where would-be denials are recorded as shadow violations without changing runtime behavior. Each engagement produces signed evidence: one `gateway_failover_attempt`/`llm_failover_attempt` record per failed provider plus exactly one terminal record (fallback decision or fail-closed), linked by `correlation_id` and a per-engagement `failover_group_id`. The new `api_family` provider field lets aliased Anthropic-compatible endpoints get correct parsing, PII redaction, tool filtering, auth conventions (x-api-key + anthropic-version), and error shape. OTel spans expose `talon.provider.original` / `talon.provider.selected` / `talon.provider.fallback_reason`. Verify quickly: point a provider's `base_url` at a dead port, add `fallback: [{provider: backup}]`, POST through the gateway → 200 served by the backup, then `talon audit verify --failover`. Docs: [configuration reference](docs/reference/configuration.md).

### Fixed

- **fix(config): project-local `talon.config.yaml` takes precedence over `~/.talon` (#191).** Viper searched the home directory first, contradicting the documented `--config` default (`./talon.config.yaml or ~/.talon/talon.config.yaml`) — a machine-wide config silently overrode per-project sovereignty mode, cache settings, and compliance controller declarations. **Upgrade impact:** operators who (perhaps unknowingly) relied on `~/.talon/talon.config.yaml` overriding a project-local file now get the local file; pass `--config ~/.talon/talon.config.yaml` explicitly to keep the old behavior. Verify quickly: run `talon config show` in a directory with its own `talon.config.yaml`.
- **fix(gateway): Anthropic plain-string message content is now PII-redacted (#191).** The redactor only handled content-block arrays; the Messages API's plain-string `content` form reached the post-redaction verifier unredacted and failed closed in `redact` mode.
- **fix(server): `/v1/dashboard/governance-alerts` returns `"alerts": []` instead of JSON `null` when no alerts exist (#191).**

## [1.6.6] - 2026-06-30

### Added

- **feat(sovereignty): air-gap deployment mode with egress guard (#132, #185).** Operators in regulated EU environments can now deploy Talon with provable in-region operation: `sovereignty.deployment_mode: air_gap` implies `eu_strict`, applies deny-by-default gateway egress (EU/LOCAL only when no custom rules are set), wraps the upstream HTTP client with an allowlist derived from declared Ollama/gateway endpoints and optional `allowed_egress_hosts`, and **hard-fails startup** when `TALON_SECRETS_KEY` / `TALON_SIGNING_KEY` are missing or still the generated defaults. Verify quickly: `cp examples/airgap/talon.config.airgap.yaml ~/.talon/talon.config.yaml`, set explicit 64-hex keys, `talon doctor --gateway-config ~/.talon/talon.config.yaml --skip-upstream`. Docs: [air-gapped deployment guide](docs/guides/air-gapped-deployment.md), [examples/airgap](examples/airgap/README.md).
- **feat(compliance): `talon compliance sovereignty` posture report (#133, #186).** Security and DPO reviewers can now export a sovereignty posture document (HTML or JSON) that merges declared facts (`sovereignty.mode`, `deployment_mode`, gateway provider regions, operator env keys) with observed egress from signed evidence — including providers that were declared but excluded under `eu_strict` (`excluded_declared` / gateway `excluded` posture). Verify quickly: `talon compliance sovereignty --format html --output sovereignty.html --from 2020-01-01`. Docs: [configuration reference](docs/reference/configuration.md).
- **feat(demo): reproducible shortlist demo bundle (#107, #184).** A self-contained `examples/shortlist-demo/` bundle (config, agent policy, `demo.sh`, docker-compose) for repeatable buyer shortlist walkthroughs without ad-hoc setup. Verify quickly: `cd examples/shortlist-demo && ./demo.sh`.

### Changed

- **feat(sovereignty): non-fatal `eu_strict` provider gate with runtime gateway denial (#111, #188).** Under `eu_strict`, Talon no longer refuses startup when non-EU/LOCAL providers are declared alongside compliant ones — they are excluded from routing with ERROR logs and `talon.sovereignty.provider_excluded_total`, while EU/LOCAL providers keep the process running. The gateway denies direct requests to excluded providers at runtime (HTTP 403 + signed evidence + `talon.sovereignty.provider_denied_total`; shadow mode records violations but still forwards). Region-aware gating (Bedrock, Azure OpenAI, Vertex) uses the **configured region** (`AWS_REGION`, provider config) — e.g. `us-east-1` excludes Bedrock even when metadata lists EU regions. `talon doctor` **warns** (exit 0) when exclusions exist but something EU/LOCAL remains routable; it **fails** only when nothing is routable, with gateway vs native checks separated so a compliant native provider does not mask an all-US gateway. `serve` / `run` / `plan` call `ApplySovereigntyGate` instead of hard-failing `ValidateSovereignty`. **Breaking change:** operators who relied on startup failure to discover misconfigured US providers must now check ERROR logs, `talon doctor`, gateway 403 responses, or `talon compliance sovereignty`. Recommended: run `talon doctor --gateway-config ... --skip-upstream` in CI. Verify quickly: declare OpenAI (US) + Ollama (LOCAL), `talon serve --gateway` starts, OpenAI proxy returns 403, Ollama returns 200, doctor warns with exit 0. Docs: [air-gapped deployment guide](docs/guides/air-gapped-deployment.md#sovereigntymode-is-the-single-source-of-truth), [configuration reference](docs/reference/configuration.md).

## [1.6.5] - 2026-06-15

### Changed

- **feat(compliance): RoPA now distinguishes redacted from raw PII at each recipient, and cross-checks declared residency against observed transfers.** Two accuracy gaps surfaced during field testing. (1) Section 5 (Recipients) listed identifier types per destination (e.g. `email` → openai) without saying whether the raw values actually reached the recipient — misleading when `redact_pii` was on and the provider only ever received placeholders. Types that were redacted in *every* flow to a destination are now annotated `(redacted before egress)`; a type forwarded raw even once stays unannotated (no overstatement in either direction). The JSON export gains a `redacted_entity_types` field per destination. (2) Declaring `compliance.data_residency: eu` while running `llm.routing.data_sovereignty_mode: eu_preferred`/`global` let non-EU transfers happen silently relative to the declaration; the RoPA now adds a `consistency:` warning when EU residency is declared but non-EU/LOCAL destinations appear in the data-flow evidence, pointing at the two honest resolutions — enforce `eu_strict`, or document the transfer mechanism (SCCs/adequacy) with your DPO. Verify quickly: declare `data_residency: eu`, run traffic through a US provider, regenerate `talon compliance ropa` and see the warning; docs: [RoPA declarations guide](docs/guides/ropa-declarations.md#residency-consistency-warning), [configuration reference](docs/reference/configuration.md#gateway-egress-rules-destination--classification-allowdeny).
- **feat(cmd): `talon audit show` now renders the Data Flow section.** The `data_flow` evidence section was signed and exported but invisible in the human-readable view — operators had to fall back to `audit export --format signed-json` + `jq` to see where a request's data went. `audit show <id>` now prints one line per flow item: source → destination (kind, name, model, region), disposition (forwarded/redacted/blocked/surfaced), data tier, and detected entity types. The `PII Redacted` line now labels both directions (`input=… output=…`): it previously showed only the output flag, which read as a contradiction next to a `redacted` input flow ("PII Redacted: false" while the prompt was in fact redacted before egress).

- **feat(evidence): data-flow evidence now covers all governed traffic, not only classified data.** Previously the `data_flow` evidence section was recorded only when PII or tier > 0 data was detected, and only on the gateway path — so a clean `talon run` against OpenAI produced a RoPA with empty Recipients (Art. 30(1)(d)) and Transfers (Art. 30(1)(e)) sections despite real egress to a US provider. Now every request that egresses records at least its prompt → destination flow (provider, model, region): gateway requests, CLI/scheduled/webhook agent runs (new), and MCP proxy tool calls. Provider regions for agent runs resolve from registered provider metadata (e.g. openai → US, mistral → EU, ollama → LOCAL). Blocked flows are recorded as evidence but no longer counted as RoPA recipients/transfers — blocked data never reached the destination. Verify quickly: `talon run "hello"` then `talon compliance ropa --format html --output ropa.html` — Section 5 lists your provider and Section 6 flags non-EU transfers with the SCC/adequacy note. No migration impact: `data_flow` remains optional in the integrity spec (requests denied before egress still omit it); records signed under earlier spec versions verify unchanged.

### Added

- **feat(scanner): Epic #112 PII trust-path hardening (#182).** Talon now normalizes built-in and external scanner output through a Presidio-compatible boundary contract (byte-offset canonicalization, `classifier.Facade` seam) and enforces **fail-closed residual PII verification** (`VerifyEgress` / RedactGuard) on gateway, MCP proxy/server, and agent tool args/results — including blocks when redaction produces invalid JSON. Evidence spec **1.3** adds optional compact `entity_attributions` on data-flow items (field path + spans, no raw values). Tool-approval remediation (`re_redact_rescan`) re-scans before approval without bypassing residual blocks. Verify quickly: `make proof-gates`. Docs: [Presidio compatibility matrix](docs/reference/presidio-compatibility-matrix.md), [LIMITATIONS.md](LIMITATIONS.md#5-scanner-compatibility-boundary). Closes #112 and child issues #134–#137; external runtime adapters remain #181.
- **feat(ci): PII benchmark regression gate on every PR; `make proof-gates` on `main` push and nightly.** Committed `testdata/benchmarks/pii_scan_baseline.<goos>.<goarch>.json` artifacts are validated and enforced in CI (`make benchmark-regression` on `ubuntu-latest`); full Epic #112 proof gates (matrix, egress, fuzz, benchmark) run on `main` and on a 03:00 UTC schedule.
- **docs(plan-review): operator guide and phased E2E test case.** Step-by-step Plan Review operations (`plan-review-operators.md`, `plan-review-e2e-testcase.md`) for CLI, serve auto-dispatch, dashboard, and TC-PR-001–012 pass criteria.
- **feat(server): compliance HTTP API — `/v1/compliance/{coverage,ropa,annex-iv,report}` (#109).** The `talon compliance` generators are now exposed over admin-authenticated HTTP, so a DPO or an automation can pull framework coverage and auditor documents from a running server without CLI access to the host. All four endpoints accept `tenant`, `agent`, `from`/`to` (`YYYY-MM-DD`), and `format=html|json`; `report` additionally takes `framework=gdpr|eu-ai-act|nis2|dora|iso-27001`. Declarations are re-read from `talon.config.yaml` / the default agent policy on every request, so declaration edits apply without a restart. Every export records a signed control-plane evidence record (`compliance_export_ropa` / `_annex_iv` / `_report`) carrying the export format and scope — the act of generating an auditor document is itself auditable. Verify quickly: `curl -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" localhost:8080/v1/compliance/coverage | jq '.frameworks[].framework'`. Docs: [export runbook](docs/guides/compliance-export-runbook.md#if-you-prefer-the-dashboard-no-cli-needed), [auth and key scopes](docs/reference/authentication-and-key-scopes.md). Tenant keys and anonymous callers are rejected (admin-only); output remains supporting documentation, not a compliance determination.
- **feat(dashboard): compliance mode in `/dashboard` (#129).** The unified governance dashboard gains a **Compliance** tab so framework posture is reviewable where the evidence already lives: per-framework coverage cards (each control mapping with its article, Talon control, source, and supporting-evidence count), declaration warnings listing what is still missing for a complete RoPA / Annex IV pack, recent signed evidence in scope, and one-click exports (RoPA HTML/JSON, Annex IV HTML/JSON, framework-filtered report) that honor the active tenant/agent/date filters. Verify quickly: open `http://localhost:8080/dashboard?talon_admin_key=$TALON_ADMIN_KEY`, select **Compliance**, click **RoPA (HTML)**. Docs: [tutorial — turnkey compliance reports](docs/tutorials/turnkey-compliance-reports.md). Closes the gap where compliance posture required the CLI while everything else in the epic was dashboard-first.
- **feat(dashboard): unified FinOps view on `/dashboard` (#109).** The FinOps & Runtime tab now answers "which tenants / apps / agents are spending money" without leaving the governance dashboard: budget utilization and semantic-cache cards (hits, hit rate, cost saved), and spend breakdowns by caller, model, and provider — all mapped from the existing `/api/v1/metrics` snapshot (no second metrics pipeline). The Evidence tab's governance quadrant gains a store-wide denial summary from the new `GET /v1/dashboard/denials-by-reason` endpoint (`pii_block`, `policy_deny`, `attachment_block`, `tool_filtered`). `/gateway/dashboard` remains available as a deep link for full gateway telemetry. Verify quickly: run gateway traffic, open the FinOps tab, and cross-check `curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" localhost:8080/api/v1/metrics | jq .budget_status`. Docs: [gateway dashboard reference](docs/reference/gateway-dashboard.md#related-governance-dashboard-endpoints).
- **feat(init): EU-first compliance policy packs (#128).** `talon init` can now apply curated policy packs for GDPR, NIS2, DORA, and the EU AI Act on every init path: a multi-select step in the interactive wizard, `--compliance gdpr,nis2` (or `all`) with `--pack`/`--scaffold`/scripted init, and `--list-compliance` to browse the catalog. Each applied pack merges its policy defaults into the generated `agent.talon.yaml` and annotates the header with the articles it supports (`supports: gdpr Art. 30 — <source> (<control>)`), linked one-to-one to `internal/compliance/mapping.go` — a build-time link-integrity test fails if an annotation drifts from the mapping table, so generated policies cannot claim support that the coverage report would not back. Verify quickly: `talon init --scaffold --compliance gdpr,eu-ai-act --skip-verify && head -30 agent.talon.yaml`. Docs: [policy packs guide](docs/guides/policy-packs.md), [configuration reference](docs/reference/configuration.md). Packs configure controls that support these articles; they are not a certification or a compliance determination. No migration impact: omitting `--compliance` generates the same files as before.
- **feat(evidence): governance parity across all entry paths — MCP server and graph adapter now record data flow; a runtime guardrail prevents future drift.** Two paths lagged behind the consolidated data-flow posture and are now reconciled. (1) The embedded MCP server (`talon serve` → `POST /mcp`) classifies tool arguments and results for PII and records a `data_flow` section on every `tools/call` — including policy-denied calls (`disposition: blocked`) — with destination region `LOCAL` (embedded tools execute in-process). (2) The graph adapter (`POST /v1/graph/events`) records an orchestrator-reported `prompt → external:<framework>` flow on `run_end` whenever the external runtime reported a model or non-zero cost; content never transits Talon on this path, so the item carries no entity types and region `unknown` — Talon never guesses, and the unresolved region deliberately surfaces in RoPA Section 6 as a prompt to gateway the traffic. The shared contract is now enforced in three layers: `evidence.ValidateGovernedRecord` runs on every store and logs `governance_parity_violation` warnings (fail-open — evidence is never dropped), `TestGovernanceParity_EntryPathContract` enumerates all five entry paths in CI, and smoke section 29 verifies black-box that every model-call record in the live evidence DB carries `data_flow`. New reference doc: [Governance control matrix](docs/reference/governance-control-matrix.md) — which controls run on which path, by-design limitations, and the checklist for adding new entry paths. Verify quickly: call any embedded tool via `POST /mcp` and check `talon audit show <id>` for the `data_flow` section. No migration impact: `data_flow` remains optional in the integrity spec; existing signatures verify unchanged.
- **feat(compliance): `talon compliance annex-iv` — EU AI Act Annex IV technical-documentation pack (#126).** CTOs and DPOs preparing for the AI Act (high-risk obligations apply from 2 August 2026) can now generate an Annex IV-shaped pack (HTML or JSON) combining declared system facts (`compliance.declarations.system` in `agent.talon.yaml`: description, intended purpose, oversight arrangements) with runtime records from signed evidence: models/providers observed, policy denials and reasons (Art. 9 risk controls), plan-review human-oversight events (Art. 14), routing/egress decisions, audited memory writes, and post-market monitoring coverage (Art. 72). The pack explicitly lists items Talon cannot produce (model development process, performance metrics, declaration of conformity) with their owners — honest scoping for deployers. Verify quickly: `talon compliance annex-iv --format html --output annex-iv.html`, or see `examples/auditor-pack/annex-iv.html`. Docs: [export runbook](docs/guides/compliance-export-runbook.md#if-you-need-eu-ai-act-annex-iv-technical-documentation). Supporting documentation for Annex IV review, not a conformity assessment.
- **feat(compliance): `talon compliance ropa` — GDPR Art. 30 Record of Processing Activities export (#125).** DPOs and platform teams can now generate an Art. 30(1)-shaped RoPA (HTML print-to-PDF-ready, or JSON) that merges **declared facts** (controller identity from `talon.config.yaml` `compliance.controller`; purposes/retention/legal basis from `agent.talon.yaml` `compliance.declarations`) with **runtime facts** from the signed evidence store (processing activities observed, personal-data identifiers detected, recipients and regions, third-country transfers). Missing declarations never fail the export — they are listed as warnings and rendered as flagged "DECLARATION MISSING" sections so the document tells you what to complete before auditor handoff. Every document carries an evidence-linkage block (record count, sample IDs, `talon audit verify` command) and a claims-discipline footer: supporting records for review, not a legal filing. Verify quickly: `talon compliance ropa --format html --output ropa.html` after any governed traffic, or see the committed sample in `examples/auditor-pack/ropa.html`. Docs: [export runbook](docs/guides/compliance-export-runbook.md#generate-a-formatted-ropa), [configuration reference](docs/reference/configuration.md#compliance-declarations-auditor-exports). No migration impact: both declaration blocks are optional.

### Fixed

- **fix(dashboard): gateway link 404, unstable Blocked card, Detail implicitly verifying.** Three UX bugs from manual testing of the unified dashboard. (1) The "Gateway telemetry" links rendered even when the server ran without `--gateway`, navigating to a plain-text 404; the dashboard now probes `/api/v1/metrics` on load and, on a 404, hides the links and shows a restart hint instead (auth errors keep the links so a key fix restores access). (2) The Blocked card was recounted from the visible evidence rows, so clicking it — which applies the Denied filter — refilled the table and made the number jump (e.g. 22 → 50); it is now fed by the store-wide denied total from `/v1/dashboard/denials-by-reason`, relabeled **Blocked (all evidence)**, and stays stable while drilling down. (3) The Detail button fetched `/verify` alongside the record, flipping the Integrity column exactly like Verify; Detail is now read-only and the detail pane shows the already-known verification state or "Not checked (use the Verify button)". Verify quickly: start `talon serve` without `--gateway` and confirm the dashboard shows the hint instead of a dead link. Docs: [gateway dashboard reference](docs/reference/gateway-dashboard.md#unified-dashboard-semantics).
- **fix(classifier,agent): canonical types on normalization fallback and JSON validity after agent-tool redaction.** When Presidio normalization fails, fallback entities now use canonical type strings (`email`, not `EMAIL_ADDRESS`). Agent tool args/results match MCP fail-closed posture: block when redaction breaks valid JSON while `VerifyEgress` still passes.

## [1.6.0] - 2026-06-10

### Added

- **feat(gateway): egress allow/deny by destination and data classification (#130).** Operators can now declare which destinations (providers and/or regions) each data tier may egress to via `gateway.default_policy.egress` (per-caller override under `callers[].policy_overrides.egress`). Denials happen in the policy step — before secrets retrieval and before any bytes reach the upstream — return HTTP 403 with machine codes `egress_tier_destination_disallowed` / `egress_destination_disallowed`, and map to the new `POLICY_DENIED_EGRESS` explanation code. This supports data-transfer controls (e.g. GDPR Chapter V transfer policies) for CTO/DPO personas; Talon enforces and evidences the rule, it does not make the compliance determination. Verify quickly: add a tier_2 rule with `allowed_regions: ["EU", "LOCAL"]`, send a payload containing an IBAN to a US-region provider, and expect a 403 plus an `egress_decision` evidence section. Unconfigured deployments are unchanged (egress is not evaluated); in `shadow` mode violations are recorded but forwarded.
- **feat(evidence): `egress_decision` evidence section (integrity spec v1.2).** Signed evidence records now carry an optional `egress_decision` object (`tier`, `provider`, `region`, `decision`, `matched_rule`, `reason`) whenever an egress policy is configured. The field is additive and appended after `data_flow`: records signed under spec 1.0/1.1 verify unchanged.
- **feat(gateway): named data-tier aliases in config.** Tier fields in the gateway config (`egress.rules[].tier`, `callers[].policy_overrides.max_data_tier`) now accept `public`/`internal`/`confidential` (case-insensitive) interchangeably with `0`/`1`/`2`, following the ascending-sensitivity convention used by ISO 27001 practice and Microsoft Purview/AGT. This makes policies self-documenting for operators without changing tier semantics: evidence records, Rego inputs, and the JSON schema keep numeric tiers (schema accepts both forms). No migration needed — numeric configs remain valid.
- **feat(observability): egress decision telemetry.** New counter `talon.gateway.egress.decisions` (`tenant_id`, `tier`, `gen_ai.system`, `region`, `decision`) and `talon.egress.*` span attributes on gateway request spans; egress denials emit a structured `gateway_egress_denied` log line with `correlation_id`, `tenant_id`, tier, destination, and reason.

### Changed

- **fix(config): removed phantom config keys that the runtime never read.** `talon init` no longer generates `tenants:`, `evidence:`, `llm_provider:`, or `secrets_key_env:` blocks in `talon.config.yaml` — none of these were parsed by any loader, which misled operators into believing budgets/rate limits or evidence paths were configured there (they live in `agent.talon.yaml` and `{data_dir}/evidence.db` respectively). Existing configs with these keys keep working (keys are ignored, as before); regenerate with `talon init` or delete the blocks to clean up.
- **feat(config): `log_level` / `log_format` in `talon.config.yaml` now take effect.** Previously only the `--log-level`/`--log-format` flags worked and the YAML values were silently ignored. Precedence: flag > config file > default.
- **feat(cache): `cache.ttl_by_tier` is now enforced.** The documented per-tier TTL overrides (`public`/`internal`/`confidential`, seconds) were parsed but never applied; cache entries now use the tier-specific TTL and record their real data tier (previously always `public`). `talon doctor` validates the keys. Verify: set `ttl_by_tier.internal: 900`, store a tier-1 entry, and check its `expires_at`.
- **feat(policy): one canonical agent schema.** `talon validate` previously used an embedded schema that had drifted from the documented `schemas/agent.talon.schema.json`. The embedded schema (now `internal/policy/agent.talon.schema.json`) is canonical and backfilled with all parsed sections (`tool_policies`, `copaw`, `semantic_enrichment`, `session_limits`, `compliance.plan_review`, extended rate/resource limits, `destructive_patterns`); `schemas/agent.talon.schema.json` is an exact synced copy enforced by a test.
- **feat(policy): unknown-key warnings on policy load.** Misspelled or misplaced keys in `agent.talon.yaml` were silently ignored (e.g. `policies.plan_review` instead of `compliance.plan_review`). The loader now logs a structured warning naming the unknown field; loading still succeeds for backward compatibility. A test guards that all shipped examples and pack overlays are warning-free.
- **feat(schema): `talon.config.schema.json` now covers the full Go config surface** — top-level fields (`data_dir`, `secrets_key`, `signing_key`, `default_policy`, `max_attachment_mb`, `ollama_base_url`, `log_level`, `log_format`), the `cache` block, and previously missing gateway fields (`upstream_auth_mode`, `dashboard_listen`, `response_scanning`, `network_interception`, tool/attachment governance, full caller overrides).
- **fix(policy): proxy compliance accepts `data_residency: "eu"`.** The proxy Rego only matched the literal `"eu-only"`, so the `"eu"` token that `talon init` writes was silently unenforced. Both tokens now require EU upstream regions.
- **feat(otel): routing spans emit `talon.routing.*` attributes.** `llm.route`/`llm.graceful_route` spans now carry `talon.data.tier`, `talon.routing.sovereignty_mode`, `talon.provider.jurisdiction`, `talon.provider.region`, `talon.routing.rejected_count`, and `talon.routing.selection_reason` (constants existed but were never emitted; the old non-namespaced `data.tier` key is replaced).
- **docs: `model_routing.*.location` documented as declarative.** The field is informational; region enforcement comes from provider registry metadata + `llm.routing.data_sovereignty_mode` (and gateway egress rules). Documented defaults corrected: `audit.retention_days` (2555 when section omitted, not 90), `attachment_handling.mode` (`permissive` when omitted), memory defaults (`max_entries` 100, `max_entry_size_kb` 10, `mode: active` when enabled), `action_on_detection` value `log_only` (not `log`), and a new cache configuration reference section.

### Fixed

- **fix(policy): `compliance.plan_review.volume_threshold` and `mode` were silently dropped on load.** The YAML-facing `policy.PlanReviewConfig` lacked `volume_threshold`, so the documented volume-detection recipe never reached the runtime; the runner mapping also dropped `mode`. Both now flow through to plan review and `talon intent classify`.
- **fix(pack): EU AI Act overlay `require_for_tier: "2"` was a no-op.** The parser accepts `tier_0`/`tier_1`/`tier_2`; the overlay now uses `tier_2` so tier-based plan review actually triggers.
- **fix(schema): `talon.config.schema.json` caller field renamed `source_cidrs` → `source_ip_ranges`** to match what the gateway actually parses, and the gateway `mode` schema default corrected from `shadow` to `enforce` (the runtime default when `mode` is omitted).
- **docs: consistency fixes across config docs.** Quickstart demo claimed data tier 3 (tiers are 0–2; confidential = 2); policy cookbook caller example used nonexistent `api_key` (now `tenant_key`); `human_oversight` examples used invalid `on_demand` (canonical: `on-demand`); the tool-class governance recipe documented a nonexistent `policies.plan_review` path with unimplemented fields (now shows `compliance.plan_review` + built-in class defaults); `add-talon-to-existing-app` copy-paste config was missing the required `base_url` for the enabled openai provider.

## [1.5.5] - 2026-06-01

### Added

- **feat(evidence): signed export and offline file verification.** Added `talon audit export --format signed-json|signed-ndjson` and `talon audit verify --file <path>` so operators and compliance teams can verify evidence integrity outside the running instance. This matters for GDPR/NIS2 handoffs where auditors request portable, tamper-evident artifacts. Verify quickly with `talon audit export --format signed-json --output signed.json && talon audit verify --file signed.json`.
- **feat(dashboard): persistent evidence integrity UX.** Evidence rows now expose explicit integrity states (`Verified`, `Invalid`, `Not checked`, `Unable to verify`), with a persistent detail/signature block that shows signed fields and trust/spend context in one view. This makes integrity obvious to CTO/DPO users without requiring CLI-first workflows.

### Docs

- **docs(evidence): add 5-minute tamper-proof demo and signed export runbook updates.** Added `docs/tutorials/evidence-integrity-demo.md`, updated the 60-second demo and compliance export runbook to distinguish reduced reporting exports from signed integrity exports, and documented `/v1/evidence/{id}/verify` response shape in the evidence store reference.

## [1.5.0] - 2026-06-01

### Added

- **feat(serve): OpenAI-compatible quickstart proxy mode.** Added `talon serve --proxy-quickstart` for dev/local host-root compatibility (`POST /v1/chat/completions`, `POST /v1/responses`) without gateway YAML, while keeping policy, PII redaction, and evidence active.
- **feat(gateway): upstream auth mode support for quickstart.** Added provider `upstream_auth_mode` (`secret` default, `client_bearer` quickstart path) with client bearer forwarding, `OPENAI_API_KEY` fallback, and explicit 401 when no upstream key is available.
- **feat(evidence): quickstart upstream auth metadata.** Evidence records now include additive fields `upstream_auth_mode`, `upstream_key_source`, `upstream_key_fingerprint`, and `gateway_annotations` (backward compatible with existing records).
- **feat(metrics): periodic reconciliation loop and status telemetry.** Added bounded/idempotent collector reconciliation (`ReconcileFromStore` + loop), OTel reconcile metrics, and `/v1/status` fields for reconcile runs/recovered events/errors.
- **feat(server): consolidated SSOT gate suite.** Added `internal/server/ssot_gate_test.go` plus `make test-ssot-gate` and wired it into `make check` as an explicit release gate.
- **feat(events): sanitized `reasons[]` on operational events.** `/api/v1/events/recent` and `/api/v1/events/stream` now include deterministic, deduped, length-bounded `reasons[]` derived from policy decision reasons, explanation reasons, and execution errors. This improves operator context without exposing raw payloads. Verify quickly with `curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" "http://localhost:8080/api/v1/events/recent?limit=1" | jq '.events[0].reasons'`.

### Changed

- **change(server): dev-mode route relocation under quickstart.** When `--proxy-quickstart` is enabled, host-root OpenAI-compatible paths are handled by the quickstart facade. Tenant agent chat is available at `POST /v1/agents/chat/completions` only when the operator has configured real tenant keys; in default quickstart (no tenant keys), that route is not mounted and returns `404 Not Found` to preserve a strict facade-only boundary.
- **change(serve): quickstart no longer registers a synthetic tenant key.** Quickstart mode is strictly a host-root OpenAI-compatibility facade; it will not silently unlock tenant APIs. When tenant keys are configured, the relocated tenant endpoint sits behind standard tenant-auth middleware and returns `401 Unauthorized` without a valid key.
- **change(serve): `--gateway-config` exclusivity check uses explicit flag set.** `--proxy-quickstart` is rejected alongside `--gateway` or any explicitly passed `--gateway-config`, detected via `cobra.Flags().Changed` rather than the default string value.
- **change(gateway): quickstart `unsafe-listen` signal threaded via config.** The `quickstart_unsafe_listen` evidence annotation is driven by `GatewayConfig.QuickstartUnsafeListen`, populated from `--unsafe-listen` through `QuickstartOptions`, instead of a process environment variable.
- **change(events/metrics): evidence-first projection parity hardening.** Operational event reason fields now prefer deterministic explanation payloads, evidence/event ordering is stabilized on `timestamp DESC, id DESC`, and metrics conversion is unified through evidence-driven projection paths for stronger CLI/API/dashboard parity.
- **change(dashboard/cli): reliability signals surfaced in routine flows.** Dashboard and gateway pages now expose degraded/reliability warning chips, and `talon metrics` / `talon events tail` print preflight warnings when `/v1/status` reports degradation.
- **change(observability/events): SSOT scope contract locked.** `/api/v1/metrics` is documented as all-activity (gateway and agent-run evidence-backed runtime), and `/api/v1/events/*` is documented as one event per persisted evidence row, including terminal outcomes plus evidence-backed lifecycle subset records (`plan_review`, graph runtime). Endpoint shapes remain backward-compatible.
- **change(metrics/evidence): pragmatic SSOT live-feed unification.** Dashboard live metrics are now fed from `evidence.Store.Store()` post-commit observer notifications (all invocation types), while periodic reconciliation remains bounded/idempotent repair. Degraded evidence-write signaling is centralized in the evidence store path, and production serve wiring no longer double-emits via direct gateway metrics recorder attachment.

### Fixed

- **fix(session): auto-migrate legacy `sessions` schema on startup.** Session store initialization now adds missing `max_cost` and `reasoning` columns when older SQLite tables are detected, preventing run/session creation failures on upgraded installs. Verify with `go test ./internal/session -run MigratesLegacySessionsTable`.
- **fix(agent): preserve audit trail on evidence write failures.** Runner paths that previously ignored evidence/step write errors now log structured failures (`correlation_id`, `tenant_id`, `agent_id`) so silent audit-loss conditions are observable during denied, dry-run, cached, and tool-step flows.
- **fix(memory): redact low-risk PII before memory governance checks.** Memory observations now sanitize `person`/`location` entities before validation, allowing safe useful memories while sensitive PII still fails closed under governance policy.
- **fix(events): expand stream reliability telemetry.** Event stream handling now increments disconnect and backlog-drop counters (in addition to gap/replay signals) and exposes them in status output for faster operator diagnosis.
- **fix(gateway/metrics): no metrics emission without persisted evidence.** Gateway collector events are now emitted only after successful evidence persistence, preventing runtime telemetry drift when evidence writes fail.
- **fix(metrics): surface collector backpressure drops.** Collector channel overflow drops now increment `dropped_events`, emit OTel counter `talon.metrics.events_dropped.total`, and appear in `/v1/status` as `metrics_events_dropped`.

## [1.4.6] - 2026-04-14

### Added

- **feat(explanation): deterministic explanation normalization.** Added canonical normalization for deterministic policy explanation tokens so equivalent outcomes converge to stable, reusable phrasing across runs and audit surfaces. This helps operators compare evidence reliably and reduces explanation drift in dashboards and tests. Verify quickly with `go test ./internal/explanation/...`.

### Fixed

- **fix(explanation): stage taxonomy and token collapse consistency.** Aligned explanation stage taxonomy (including MCP PII semantics) and fixed edge cases where fully-collapsed tokens were not returned as a single deduplicated canonical token. This improves consistency between policy decisions and rendered explanations.

- **fix(gateway): canonical explanation stage propagation.** Gateway explanation output now uses the canonical explanation stage instead of pipeline-stage values, preventing mismatched stage labels in downstream evidence and UI surfaces.

- **fix(graphadapter): preserve graph evidence identity fields.** Graph adapter run evidence now retains session and model fields on graph execution paths, improving traceability for stateful graph runs and downstream audit analysis.

### Docs

- **docs(quickstart): add verification snippet.** Quickstart now includes an explicit verification snippet so operators can validate a governed setup immediately after onboarding with less ambiguity.

## [1.4.5] - 2026-04-12

### Added

- **feat(graphadapter): graph runtime governance control plane.** Added graph-aware governance execution with event-aware policy checks, lineage-aware evidence hooks, and integration points for LangChain/LangGraph stateful flows. Operators and framework integrators get first-class graph execution visibility while preserving existing run governance semantics. Verify quickly with `tests/smoke_sections/30_graph_events.sh` and `go test ./tests/integration -run Graph`.

- **feat(policy): graph governance Rego policies and tests.** Added dedicated graph governance policy modules and policy tests to enforce graph-specific constraints and deny handling at runtime, including deterministic explanation rendering for governance outcomes.

- **docs(integration): LangChain/LangGraph integration guide and examples.** Added end-to-end integration docs and runnable examples under `examples/langchain-integration/` to demonstrate stateless and stateful adapter usage patterns with Talon governance.

### Fixed

- **fix(graphadapter): tenant binding and denial propagation hardening.** Tightened tenant binding checks, stabilized run-end denial handling, and improved explanation/evidence consistency under denied branches and error paths.

- **fix(graphadapter): concurrency and lint hardening.** Addressed run-state race conditions, aligned request construction with context-aware patterns, and added regression tests for concurrent denial tracking and retry guardrails.

### Test

- **test(graphadapter): full graph governance test pyramid.** Added broad unit, handler, policy, integration, and smoke coverage for graph event execution and governance decisions, reducing regression risk for graph-enabled agent pipelines.

## [1.4.0] - 2026-03-31

### Added

- **feat(agent): operational control plane.** Run lifecycle state machine (QUEUED → RUNNING → COMPLETED|FAILED|TERMINATED|BLOCKED|DENIED) with structured failure taxonomy (`cost_exceeded`, `llm_error`, `tool_timeout`, `policy_deny`, `operator_kill`, etc.) in evidence records. New admin API surfaces: `GET /v1/runs` (list active), `POST /v1/runs/{id}/kill` (terminate), `POST /v1/runs/kill-all?tenant_id=X` (tenant-wide kill), `POST /v1/runs/{id}/pause` / `resume` (mid-execution pause). Operator overrides: `POST /v1/overrides/{tenant_id}/lockdown` (reject all new runs + kill active), dynamic tool disable (`/v1/overrides/{tenant_id}/tools/disable`), runtime policy tightening (`/v1/overrides/{tenant_id}/policy`). Pre-tool approval gates: tools listed in `resource_limits.require_approval` pause for human decision via `POST /v1/tool-approvals/{id}/decide` (5 min default timeout). Single-shot cost check catches expensive LLM calls that exceed per-request budget. Per-run tool failure escalation auto-disables tools after 3 consecutive failures. All new endpoints are admin-only (`X-Talon-Admin-Key`). See [Operational control plane reference](docs/reference/operational-control-plane.md).

- **feat(agent): input prompt PII redaction.** New `redact_input` / `redact_output` fields in `data_classification` config give granular control over when PII is redacted from prompt (before LLM) and response (before returning). The legacy `redact_pii` field is preserved as a shorthand that defaults both. Evidence now includes `input_pii_redacted` for audit. Schema, template, init merge, smoke test (section 26), and PII enrichment quality test updated.

- **feat(classifier): PII semantic enrichment.** Optional semantic attributes on PII placeholders: PERSON → gender (from title/honorific), LOCATION → scope (city/region/country). Canonical entity model and adapter from current detector; built-in enricher; Rego policy `semantic_enrichment.rego` (mode off/shadow/enforce, allowed_attributes). Placeholder renderer: legacy `[TYPE]` or XML-style `<PII type="..." id="..." .../>`. Config: `policies.semantic_enrichment` (enabled, mode, confidence_threshold, allowed_attributes). Metrics: `talon.pii.enrichment.attempts.total`, `talon.pii.enrichment.attributes.emitted.total`, `talon.pii.enrichment.fallback_unknown.total`. Smoke section 26 (5+5 runs with enrichment off/enforce). Docs: [PII semantic enrichment reference](docs/reference/pii-semantic-enrichment.md), policy cookbook snippet, Presidio migration note.

- **feat(evidence): deterministic policy explanations.** Policy explanation rendering is now deterministic across evidence generation and surfaces, reducing ordering drift and making repeated runs easier to compare in audits and tests.

- **chore(legal): add LICENSE file.** Repository now includes a root `LICENSE` file for explicit distribution terms.

### Fixed

- **fix(security): governance hardening.** Governance pipeline checks were tightened based on adversarial audit findings to reduce bypass risk under hostile or malformed inputs.

### Changed

- **fix(readme): improve trust signals.** Status and metadata links now render as badge images; the previous "Trust Signals" text block was removed for a more scannable project header.

### Test

- **test(classifier): enrichment quality comparison script.** Added a dedicated semantic enrichment quality comparison script to support repeatable validation of enrichment behavior.

## [1.3.0] - 2026-03-18

### Added

- **feat(dashboard): Mission Control UX.** Governance and Gateway dashboards unified under a shared Mission Control layout with consistent 3-band information architecture, new widgets (posture, interventions, fleet risk, drift/PII signals), session timeline and compliance report preview panels (#35).
- **feat(agent): intent governance tooling.** New `talon intent` CLI (classify/classes) backed by `internal/agent/intent.go` infers operation class, risk, and bulk signals from tool names and JSON params to determine plan review requirements (#36).
- **feat(agent): tool safety gaps T7, T8, T9.** T7: per-tool `max_row_count` and `require_dry_run` with Rego deny and pre-execution row count guard; T8: IdempotencyStore (SQLite) deduplicates tool calls by (agent_id, correlation_id, tool_name, argument_hash) with pending/completed lifecycle; T9: `forbidden_argument_values` in ToolPIIPolicy with Rego deny for specific argument values (e.g. `mode=overwrite`). Session governance Rego (cost, max_candidates, max_judge_calls), session store, evidence session/stage fields, tool registry schema validation (#37).
- **feat(agent): tool_governance idempotency config.** New `tool_governance` policy section for per-tool idempotency: scope (request_id/session_id), cache_ttl, duplicate handling (return_cached/fail), strict_mode. Runner applies idempotency only to listed tools; keys use correlation_id or session_id; cached results stored after PII redaction. IdempotencyStore supports TTL-based expiration (#38).

### Fixed

- **fix(agent):** Idempotency cache now stores PII-scanned results and handles pending status explicitly so cached results are redacted and non-idempotent tools are not double-executed on retry (#37).

### Changed

- **chore(build):** Go bumped to 1.25.8 for stdlib vulnerability fixes (govulncheck: GO-2026-4603, GO-2026-4602, GO-2026-4601).
- **feat(init):** Pack validation derived from `pack.ValidPackIDs()`, additional industry packs in wizard, dedicated langchain/generic agent templates (#36).
- **docs:** Policy cookbook update_records hardening example; talon intent output fields (#36, #37).

## [1.2.0] - 2026-03-13

### Added

- **feat(evidence): session_id in export and API.** Evidence records and audit export (CSV, JSON, NDJSON) now include `session_id` for lifecycle session correlation. Plan-gated runs and their auto-dispatch share the same session; export and `GET /v1/evidence/{id}` include it when present.

### Fixed

- **fix(smoke):** Section 24 plan-dispatch: accept HTTP 202 for plan_pending (human_oversight); use section-local response file and admin key for evidence read when serve runs without gateway; relax rate limit (requests_per_minute=300) to avoid OPA deny from shared evidence DB; capture plan execute stderr and dispatch evidence session_id diagnostics on failure.

### Changed

- **docs:** Evidence store: document session_id, fix HMAC key (TALON_SIGNING_KEY), retention in agent.talon.yaml, CSV/export columns. Auth: note that serve without --gateway has no tenant keys (admin key only). Agent planning: plan stores session_id, dispatcher reuses it. Compliance export runbook and config reference (TALON_ADMIN_KEY) updated.

## [1.1.0] - 2026-03-09

### Added

- **feat(cache): governed semantic cache.** Optional semantic cache for LLM requests: SQLite store, BM25 embedder, PII scrubber, OPA policy (`internal/cache`, `cache.rego`). Config section `cache` (disabled by default), wizard and doctor support, init templates. Integration in agent runner and gateway (lookup/store, policy, evidence). Evidence: `CacheHit`, `CacheEntryID`, `CacheSimilarity`, `CostSaved`; `CacheEvent` for erasure. CLI: `talon cache config|stats|list|erase`; `talon audit`, `talon costs`, `talon report` show cache savings. Docs: cache vs memory, policy cookbook, config reference; smoke test section for cache.

- **ci: CodeQL workflow.** `.github/workflows/codeql.yml` for Go analysis with advanced config; `.github/codeql-config.yml` to exclude go/weak-sensitive-data-hashing (SHA-2 used for cache key derivation, not secrets).

### Fixed

- **fix(cache):** Record actual similarity score in evidence instead of threshold; centralize cache key derivation in `cache.DeriveEntryKey`; gateway uses config-derived tenant ID for cache key (CodeQL taint); remove dead code and clarify cache key hashing docs.
- **fix(server):** HEAD support for dashboard so `curl -I` returns 200 (health checks / smoke tests).
- **fix(cmd):** Cache prompt (y/N) to match default `n` and `readLine [n]`.
- **fix(lint):** Resolve golangci-lint gosec and noctx (agent postBudgetAlert ctx, enforce path validation, mounts/retention nolint, gateway tests with `NewRequestWithContext`); gofmt gateway.go, noctx in otel chi_test and MCP tests.

### Changed

- **ci:** Coverage threshold lowered to 65%; enforce.go nolint G703 for validated path; response_pii_test noctx.
- **docs(gateway):** Clarify `cacheKeyHash` is cache lookup, not password hashing (CodeQL).

## [1.0.0] - 2026-03-06

### Added

- **feat(docs): self-adoption overhaul (Gates 1–5).** README hero shows `talon audit list` with blocked tool + blocked PII; one-line mechanism and inline 60-second demo. "What it stops" replaces "Why Talon?" with four failure-first bullets (LiteLLM, CloakLLM, DIY proxy). QUICKSTART simplified to 3-path job-to-be-done (existing app / new agent / understand first). New guide [Add Talon to your existing app](docs/guides/add-talon-to-existing-app.md) (Gate 4, first real request). Quickstart-demo: "What you just proved", "Now wire this to your app" (Python/Node/curl), "You're done". "You're done" + next-steps table added to all guides. New [comment-playbook](docs/community/comment-playbook.md) (internal Reddit/HN templates) and [Why not just a PII proxy?](docs/explanation/why-not-a-pii-proxy.md). Docs index updated; P8 buzzwords removed from reader-facing copy.

### Changed

- **chore(build):** `make test` and `make test-e2e` now run with `-count=1` so the test cache is disabled and results are always fresh.

## [0.9.5] - 2026-03-04

### Added

- **feat(copaw): CoPaw integration.** Govern CoPaw (AgentScope/Alibaba DAMO personal AI assistant) via Talon's LLM API gateway. One URL change in CoPaw (Base URL → Talon, API Key → caller key) routes all LLM traffic through Talon for PII scanning, cost limits, and audit. New init pack `talon init --pack copaw`, caller `copaw-main` / `talon-gw-copaw-001`, DashScope support in wizard, CoPaw dashboard tab and `/v1/copaw/stats`, `/v1/copaw/alerts` API, OTel span attributes `copaw.caller` and `copaw.channel`, MCP-to-CoPaw skill bridge (internal/copaw/bridge.go), memory governor (internal/copaw/memory_governor.go), Rego policy `copaw_skills.rego` and `.talon.yaml` `copaw.skills` schema. Docs: [CoPaw integration guide](docs/guides/copaw-integration.md), [Docker primer](docs/guides/copaw-talon-primer/docker-copaw-talon-primer.md), [examples/copaw](examples/copaw). Design doc: internal_docs/copaw_integration_design_doc.md.

### Fixed

- **fix(copaw):** `/v1/copaw/alerts` now returns `"alerts": []` instead of `"alerts": null` when no matching evidence records are found, consistent with the no-store path and clients expecting an array.

## [0.9.2] - 2026-03-03

### Added

- **feat(init): zero-config init wizard.** In a terminal, `talon init` runs an interactive wizard: choose workload type (agent/proxy), framework pack (OpenClaw, generic, etc.), primary LLM provider, region (if applicable), data residency (EU strict / preferred / global), and compliance features (PII, audit, cost, injection, EU AI Act, DORA). Non-interactive options: `talon init --scaffold` for quick defaults, `talon init --pack <id>` for starter packs, or scripted `talon init --provider openai --name my-agent` with optional `--data-sovereignty`, `--features`. New list commands: `--list-providers`, `--list-packs`, `--list-features`. When stdin is not a TTY, init prints guidance instead of running the wizard. Pack and feature registries (`internal/pack`, `internal/feature`) drive wizard choices; post-init verification reuses `talon doctor`; next steps are vault-first (TALON_SECRETS_KEY then `talon secrets set`).

### Fixed

- **fix(init):** gosec nolint for init wizard (G705/G703/G115 false positives). Unit tests added for coverage ≥70% (packName, providerName, dataResidencyLabel, readLine, readChoice, BuildConfigs branches, marshalWithHeader, WriteConfigs, PostInitVerify, runList*).

### Changed

- **docs:** All user-facing docs updated for init wizard (README, QUICKSTART, configuration reference, first-governed-agent tutorial, persona guides, OpenClaw guides, provider-registry, ADOPTION_SCENARIOS, ROADMAP).

## [0.9.1] - 2026-03-02

### Changed

- Version bump to 0.9.1.

## [0.9.0] - 2026-02-27

### Added

- **feat(community): implement PROMPT_10 launch track and quality track**. Full community adoption plan build-out with a launch-first approach — 36 new files across docs, examples, schemas, deploy templates, and community governance.

#### Launch Track (demo-first for HN virality)

- **Mock OpenAI provider** (`examples/docker-compose/mock-provider/main.go`): Standalone server with streaming + non-streaming support, realistic token counts, canned PII-triggering responses. No API key needed.
- **Docker Compose demo stack** (`examples/docker-compose/`): `docker compose up` starts Talon + mock provider. 60-second demo from clone to evidence record.
- **README hero rewrite**: Terminal output of `talon audit list` is now the first visible content. Proxy-as-hook framing, Flow 0 commands, CI/license badges. Compliance language moved below the fold.
- **Show HN post updated** (`internal_docs/show-hn.md`): Reframed around "intercept all AI API calls with one URL change" narrative.
- **Request lifecycle doc** (`docs/explanation/what-talon-does-to-your-request.md`): 10-step gateway pipeline breakdown, latency budget table (<15ms overhead), "What Talon Does NOT Do" section, streaming behavior, source code pointers.
- **Verification scripts**: `scripts/verify-flow0.sh` (automated end-to-end Flow 0 test) and `scripts/demo-recorder.sh` (generates 10 varied evidence records for screenshots/GIFs).

#### Quality Track (examples, docs, governance)

- **examples/gateway-minimal/**: Smallest working LLM gateway config with `run.sh` and README.
- **examples/mcp-proxy-minimal/**: Smallest working MCP proxy config with tool filtering.
- **examples/plan-review/**: Human-in-the-loop demo for EU AI Act Article 14 compliance.
- **examples/policies/**: Starter OPA/Rego library — cost-budget, pii-block, model-allowlist, data-residency.
- **docs/explanation/evidence-store.md**: HMAC signing, progressive disclosure, storage, export, compliance mapping.
- **docs/tutorials/quickstart-demo.md**: Flow 0 tutorial (no API key, Docker Compose).
- **schemas/**: JSON Schema for `talon.config.yaml` and `agent.talon.yaml` — enables editor autocomplete and CI validation.
- **deploy/**: systemd unit file (hardened, non-root) and production docker-compose (Talon + PostgreSQL + OTel Collector).
- **Community files**: `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1), `MAINTAINERS.md`, `ROADMAP.md`, `.github/CODEOWNERS`.
- **Makefile targets**: `demo-gateway`, `demo-full`, `demo-clean`, `verify-flow0`.
- **docs/README.md**: Updated index with all new tutorials, explanations, examples, and policy reference.

## [0.8.14] - 2026-02-26

### Added

- **feat(audit): show tool governance in `talon audit show`**. Gateway evidence records now display a "Tool Governance (gateway)" section with Requested, Filtered, and Forwarded tool names when the request included a tools array, so operators can verify which tools were stripped by `forbidden_tools` before the LLM saw them.
- **docs(gateway):** Added `gateway-default-policy-tool-governance-snippet.yaml` in the OpenClaw primer for pasting `forbidden_tools` and `tool_policy_action` into `talon.config.yaml`.

### Fixed

- **fix(gateway): persist tool governance when any of requested/filtered/forwarded is non-empty**. Previously `RecordGatewayEvidence` only set `tool_governance` when `ToolsRequested` had length; it now persists whenever any of the three slices is non-empty.

### Test

- **test(gateway):** `TestRecordGatewayEvidence_ToolGovernanceRoundTrip` ensures tool governance is stored and returned by `Get()` (same path as `talon audit show`).

## [0.8.13] - 2026-02-26

(No notable changes in this release.)

## [0.8.12] - 2026-02-26

### Added

- **feat(gateway): attachment scanning for base64-encoded file blocks** (#23). The gateway now detects base64-encoded file blocks in OpenAI (Chat Completions `file`/`image_url` + Responses API `input_file`) and Anthropic (`document`/`image` with `source.type: "base64"`) requests. Text is extracted from supported formats (PDF, TXT, CSV, HTML), scanned for PII and prompt injection, and governed by a new `attachment_policy` with four actions: `allow`, `warn` (default — log findings, forward unchanged), `strip` (remove file blocks before forwarding), `block` (reject request with HTTP 400). Per-caller overrides via `policy_overrides.attachment_policy`. Images are logged for evidence but skip text-based scanning.
- **feat(gateway): enforce PII actions on streaming responses**. `handleStreamingPIIScan` now buffers the SSE stream, scans the completed content, and either forwards as-is (`warn`), rewrites the SSE payload with redacted content (`redact`), or returns HTTP 451 (`block`). Default `response_pii_action` is `warn`.

### Changed

- **refactor(gateway): decompose `openclaw_incident_test.go` by testing pyramid**. The 1134-line monolith is now split into layered test files: `gateway_test_helpers_test.go`, `response_pii_test.go`, `extract_test.go`, `forward_test.go`, `gateway_integration_test.go`, `responses_api_test.go`, `evidence_test.go`.

### Test

- **test(gateway):** Extensive attachment scanning coverage: multi-file requests, size/type enforcement, Responses API `input_file`, Anthropic base64 document/image blocks, multi-turn string content tolerance, corrupt/empty/unsupported formats, warn/strip/block/allow modes, per-caller override propagation, and full gateway integration tests.
- **test(attachment):** PDF extraction tests with `buildTestPDF` helper generating valid PDFs; `ExtractBytesWithLimit` override tests.
- **test(gateway):** Streaming response PII tests covering warn/redact/block behaviours with real SSE format.

## [0.8.11] - 2026-02-26

### Fixed

- **fix(gateway): streaming response PII scanning no longer breaks SSE clients**. The v0.8.10 approach of forcing `stream:false` on upstream requests caused OpenClaw (and any SSE-expecting client) to hang — it received a plain JSON response but was waiting for SSE events. The gateway now buffers the full SSE stream from the upstream, extracts the completed response from the `response.completed` event (Responses API) or delta accumulation (Chat Completions), scans for PII, and either forwards the original buffered events (no PII) or returns a redacted response wrapped in valid SSE format. Streaming is preserved when PII action is `allow`.

### Test

- **test(gateway):** Replaced `disableStreaming`-based tests with SSE-native tests: `TestGateway_ResponsesAPI_StreamingResponsePIIRedacted` (redact mode with SSE), `TestGateway_ResponsesAPI_StreamingNoPII` (clean passthrough), `TestGateway_StreamingAllowed_WhenPIIActionAllow`, and `TestGateway_ResponsesAPI_StreamingPIIBlock`. All tests use real SSE response format.

## [0.8.10] - 2026-02-26

### Fixed

- **fix(gateway): response PII scanning now works when clients send `stream:true`** (superseded by v0.8.11 — see above). This version forced `stream:false` which broke SSE clients.

### Test

- **test(gateway):** Added streaming PII scanning tests (updated in v0.8.11).

## [0.8.9] - 2026-02-26

### Fixed

- **fix(gateway):** Refactored `extractResponseContentText` and `redactResponseContentFields` in `response_pii.go` to reduce cyclomatic complexity below the linter threshold (gocyclo > 15). Extracted Anthropic and Responses API parsing into dedicated helpers.
- **fix(gateway):** `redactOpenAIBody` no longer injects `content: null` into Responses API `input` array items that have no `content` field (e.g. `item_reference` entries). Previously this caused `400 Unknown parameter: 'input[N].content'` from OpenAI.
- **fix(gateway):** `openAIContentToText` and `redactOpenAIContent` now recognize `input_text` and `output_text` block types in addition to `text`, covering all Responses API content block formats.

### Test

- **test(gateway):** Added 8 full-pipeline integration tests for the Responses API path: request PII redaction (string input, array content, input_text blocks), item_reference preservation (no content:null injection), response PII redaction and blocking, clean passthrough, and block-mode request rejection. These tests exercise the complete gateway handler including routing, store:true injection, PII scanning, evidence recording, and upstream forwarding.

## [0.8.8] - 2026-02-26

### Fixed

- **fix(gateway):** PII scanning and redaction now handles the OpenAI Responses API format (`output[].content[].text` with `type: "output_text"`) in addition to Chat Completions (`choices[].message.content`) and Anthropic (`content[].text`). Previously, emails and other PII in Responses API output passed through unredacted.
- **fix(gateway):** Request-path PII extraction and redaction now handles the Responses API `input` field (string or array of message objects), in addition to Chat Completions `messages[]`. All other request fields (`store`, `previous_response_id`, etc.) are preserved during redaction.

### Test

- **test(gateway):** Added Responses API test cases for response PII scanning (email, IBAN in `output[].content`), content extraction (single/multiple outputs, non-text outputs ignored), request extraction (`input` as string/array/content blocks), and request redaction (string input, array input, field preservation).

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

[Unreleased]: https://github.com/dativo-io/talon/compare/v1.7.0...HEAD
[1.7.0]: https://github.com/dativo-io/talon/compare/v1.6.8...v1.7.0
[1.6.8]: https://github.com/dativo-io/talon/compare/v1.6.7...v1.6.8
[1.6.7]: https://github.com/dativo-io/talon/compare/v1.6.6...v1.6.7
[1.6.6]: https://github.com/dativo-io/talon/compare/v1.6.5...v1.6.6
[1.6.5]: https://github.com/dativo-io/talon/compare/v1.6.0...v1.6.5
[1.6.0]: https://github.com/dativo-io/talon/compare/v1.5.5...v1.6.0
[1.5.5]: https://github.com/dativo-io/talon/compare/v1.5.0...v1.5.5
[1.5.0]: https://github.com/dativo-io/talon/compare/v1.4.6...v1.5.0
[1.4.6]: https://github.com/dativo-io/talon/compare/v1.4.5...v1.4.6
[1.4.5]: https://github.com/dativo-io/talon/compare/v1.4.0...v1.4.5
[1.4.0]: https://github.com/dativo-io/talon/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/dativo-io/talon/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/dativo-io/talon/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/dativo-io/talon/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/dativo-io/talon/compare/v0.9.5...v1.0.0
[0.9.2]: https://github.com/dativo-io/talon/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/dativo-io/talon/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/dativo-io/talon/compare/v0.8.14...v0.9.0
[0.8.14]: https://github.com/dativo-io/talon/compare/v0.8.13...v0.8.14
[0.8.13]: https://github.com/dativo-io/talon/compare/v0.8.12...v0.8.13
[0.8.12]: https://github.com/dativo-io/talon/compare/v0.8.11...v0.8.12
[0.8.11]: https://github.com/dativo-io/talon/compare/v0.8.10...v0.8.11
[0.8.10]: https://github.com/dativo-io/talon/compare/v0.8.9...v0.8.10
[0.8.9]: https://github.com/dativo-io/talon/compare/v0.8.8...v0.8.9
[0.8.8]: https://github.com/dativo-io/talon/compare/v0.8.7...v0.8.8
[0.8.7]: https://github.com/dativo-io/talon/compare/v0.8.6...v0.8.7
[0.8.6]: https://github.com/dativo-io/talon/compare/v0.8.5...v0.8.6
[0.8.5]: https://github.com/dativo-io/talon/compare/v0.8.4...v0.8.5
[0.8.4]: https://github.com/dativo-io/talon/compare/v0.8.2...v0.8.4
[0.8.2]: https://github.com/dativo-io/talon/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/dativo-io/talon/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/dativo-io/talon/compare/v0.7.6...v0.8.0
[0.7.6]: https://github.com/dativo-io/talon/compare/v0.7.5...v0.7.6
[0.7.5]: https://github.com/dativo-io/talon/compare/v0.7.4...v0.7.5
[0.7.2]: https://github.com/dativo-io/talon/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/dativo-io/talon/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/dativo-io/talon/releases/tag/v0.7.0
