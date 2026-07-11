# Talon Security Boundaries & Limitations

Talon is a control plane for AI use cases: it provides policy enforcement, cost controls, routing controls, PII handling, and signed evidence records for the AI traffic routed through it. It does not determine legal compliance for an operator, and it does not prove that a downstream model, tool, or human decision was correct.

This document serves as an explicit boundaries guide so that operators and security teams can accurately evaluate Talon's trust model.

---

## Current Status Overview

| Capability | Status | Description |
| :--- | :--- | :--- |
| **Available Now** | ✅ | Proxy governance, input/output PII scan, policy decision, cost caps, policy-valid fallback, MCP tool-call interception, signed evidence, audit verify. |
| **Partial Today** | 🟡 | EU routing proof is currently deny/allow evidence, not silent rerouting; session budgets are soft caps. |
| **Roadmap** | ⏳ | Per-execution tool lifecycle evidence, same-provider retries with backoff, cost warning-threshold evidence + org webhooks, broader trust mesh/A2A. |

---

## 1. Compliance Boundary

**Talon provides supporting controls and evidence.**
- The operator remains entirely responsible for legal and compliance determinations.
- Talon produces cryptographic receipts that assist with audits. It does not make an organization automatically compliant with GDPR, NIS2, or the EU AI Act.

## 2. Evidence Boundary

**HMAC proves record integrity and tamper evidence.**
- The signature proves that the request passed through the gateway and that the logged payload was not maliciously altered after the fact.
- It **does not** prove that the policy configured was correct, that the model's response was safe or hallucination-free, or that the operator configured the right security controls.

## 3. Tool-Governance Boundary

**Today: Forbidden tools are filtered from request bodies before forwarding.**
- Talon prevents the model from ever seeing forbidden tools by stripping them from the initial request JSON.
- **Tool-related content is observed, not enforced.** PII inside tool_use inputs, tool_result outputs, and function-call arguments is scanned and recorded in signed evidence (`classification.tool_content`, evidence spec 1.5; `scan_tool_content: evidence_only` is the default) but does **not** block, redact, or otherwise change the request. Tool content cannot be redacted yet — acting on the signal would break agentic sessions — so treat this trail as visibility, not prevention (#212).
- **Not yet:** Talon does not currently provide runtime execution interception or full MCP tool-call governance. These are planned for future roadmap epics.

## 4. Isolation Boundary

**Talon provides process-level controls only.**
- Talon is **not** an OS-level or kernel sandbox. 
- External tools and providers remain completely separate trust boundaries and must be secured accordingly.

## 5. Scanner Compatibility Boundary

**Talon supports a Presidio-compatible result shape at the ingestion boundary.**
- Talon normalizes external scanner results to canonical internal entities and enforces byte-offset semantics for redaction and policy checks.
- This is a contract compatibility seam, **not** a claim of full Presidio behavioral parity across recognizer internals.
- HTTP and Unix-domain-socket adapters for Presidio-compatible engines are supported via the `scanner:` config block (see [external scanners](docs/reference/external-scanners.md)); the adapter protocol carries no authentication yet, so engines must be network-isolated. gRPC transports and Talon-managed sidecar lifecycles are not supported.
- Semantic enrichment is a built-in-regex-engine feature: when an external scanner engine is configured, enrichment is skipped and legacy `[TYPE]` placeholders are used.
- External engines report no Talon sensitivity levels. Known built-in labels (e.g. `IBAN_CODE`, `PASSPORT`, `CREDIT_CARD`) automatically get their registry sensitivity, so stock Presidio detections tier correctly; **unknown custom entity types** default to tier 1 unless the engine supplies `expected_sensitivity` per result (an explicit wire value always wins).
- Runtime remediation is intentionally minimal in MVP scope: Talon supports approval-flow re-redact/re-scan remediation for tool-approval decisions, but does not implement the full remediation workflow stack yet (tracked in follow-up epics).
- Residual PII enforcement remains fail-closed: remediation failures do not bypass policy blocks.

## 6. Deployment and Key-Management Assumptions

**Evidence signing depends on operator-controlled key handling.**
- The cryptographic guarantees of Talon's evidence records rely on the operator securing the signing keys.
- Provider registry and routing claims depend entirely on accurate provider configuration by the operator.
- Air-gapped deployments and full auditor-pack claims should be considered roadmap items unless marked as explicitly live.

## 7. Coding-Agent and Orchestration Boundary

Sharp edges of governing coding agents (Claude Code, Codex CLI, orchestrators) through the gateway (epic #192). Every entry below is shipped behavior stated honestly, with its backing test.

- **Client-asserted subagent identity is attribution, not authentication.** Orchestration metadata (`X-Talon-Session-ID`/`-Agent-ID`/`-Parent-Agent-ID`/`-Client` and the Claude Code / Codex vendor headers) distinguishes subagents *within an already-authenticated agent*; it does not authenticate them. Every value is recorded in signed evidence with `provenance: "client_asserted"` and is exactly as trustworthy as the agent whose key was presented. It is never a policy input — budgets bind to the agent and the agent-scoped session tuple, never to the asserted subagent id. Workload attestation is #149. *(Backed by `TestResolveOrchestration_*`, `TestPolicyInputParity_WithAssertedSession`.)*
- **Local tool execution is invisible.** Talon sees model API traffic and MCP-proxied calls. A coding agent's file edits, shell commands, and local tool runs happen on the developer's machine and never transit the gateway; evidence shows the model's tool_use *intentions* (per §3), not local execution.
- **Subscription/OAuth billing cannot be governed.** Pointing only `ANTHROPIC_BASE_URL` at Talon sends Claude Code's subscription OAuth token, which Talon rejects (not an agent key). Governed operation requires the agent-key + vault-injected provider-key model (#266); for the anthropic API family, vault-secret is the **only** upstream auth mode (`upstream_auth_mode: client_bearer` is rejected at config load). For Codex, never set `requires_openai_auth = true` on the Talon profile. *(Backed by the gateway config validation and conformance auth fixtures.)*
- **Response-PII actions other than `allow` buffer whole streams.** With `response_pii_action` set to `block`/`redact`/`warn`, the full SSE stream is buffered before release: time-to-first-token becomes total generation time — unusable for interactive coding. The coding-agents pack therefore defaults coding callers to `response_pii_action: allow` (input-side scanning still applies). Also raise `request_timeout` for coding callers: the 120s default hard-cuts long generations and Codex aborts idle streams ~300s (#217). The header wait defaults to `request_timeout` (tunable via `response_header_timeout`), so slow-TTFB non-streaming calls are no longer cut at `connect_timeout` (#230, fixed).
- **Chat Completions streams can still truncate silently.** When an upstream dies mid-stream, Talon emits the family-correct terminal event — Anthropic `event: error`, Responses `response.failed` (so Codex stops waiting for `response.completed`) — but the Chat Completions protocol has **no standard mid-stream error event**, so on that wire a dead upstream still looks like a truncated-but-ended stream. Talon does not fabricate `[DONE]`. *(Backed by `TestStreamCopy_MidStreamTerminalEvents`.)*
- **Cache pricing falls back to the input rate.** A pricing entry without `cache_read_per_1m`/`cache_write_per_1m` bills cache tokens at the full input rate (`pricing_basis: "cache_fallback_input_rate"`): cache reads over-counted (~10× their real price), Anthropic cache writes under-counted by up to 25%. Current models ship with rates; keep the table updated. *(Backed by `TestEstimateCached_*`.)*
- **Session budgets are soft caps.** `max_session_cost` denies a *new* request once accrued session spend + the pre-request estimate exceeds the limit. One in-flight request whose real cost exceeds the estimate can overshoot, and N concurrent first requests are bounded only by N × per-request cost. Atomic reservation is #144. *(Backed by `TestSessionBudget_SoftCapOvershoot`, `TestSessionBudget_ConcurrentBurstBound`.)*
- **Responses API `store` semantics.** Default `responses_store_mode: preserve` forwards the client's `store` field untouched (an explicit `store: false` is honored). `force_if_absent` injects `store: true` only when absent (needed for `previous_response_id` continuity). `force_true` reverses an explicit `store: false` and records that in signed evidence (`gateway_annotations: ["responses_store_overridden"]`) — the provider then retains data the client asked not to store. *(Backed by `TestConformanceResponses_StoreModes`.)*
- **Tool-content governance is detection + evidence, not enforcement** — see §3; the same boundary applies with extra force to coding agents, whose traffic is dominated by tool content.
