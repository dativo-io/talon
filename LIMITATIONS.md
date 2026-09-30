# Talon Security Boundaries & Limitations

Talon is a control plane for AI use cases: it provides policy enforcement, cost controls, routing controls, PII handling, and signed evidence records for the AI traffic routed through it. It does not determine legal compliance for an operator, and it does not prove that a downstream model, tool, or human decision was correct.

This document serves as an explicit boundaries guide so that operators and security teams can accurately evaluate Talon's trust model.

---

## Current Status Overview

| Capability | Status | Description |
| :--- | :--- | :--- |
| **Available Now** | ✅ | Proxy governance, input/output PII scan, policy decision, cost caps, policy-valid fallback, MCP tool-call interception, signed evidence, audit verify. |
| **Partial Today** | 🟡 | EU routing proof is currently deny/allow evidence, not silent rerouting; session-budget admission is estimate-based (reservation blocks concurrent overshoot, not estimation error). |
| **Roadmap** | ⏳ | Per-execution tool lifecycle evidence, side-effect-free policy-impact preview (#459), offline evidence replay (#441), broader trust mesh/A2A. (Same-provider retries shipped in 1.10.0, #139; cost warning-threshold evidence and the organization webhook shipped in 1.9.4, #144.) |

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
- **Shipped, but bounded:** MCP `tools/call` requests are intercepted and policy-forbidden calls are denied with signed denial evidence. **Not yet:** per-execution tool *lifecycle* evidence and destination egress governance (#146) — Talon does not intercept a governed tool's actual runtime execution or its outbound destinations. These remain roadmap.

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
- Air-gap deployment mode (`sovereignty.deployment_mode: air_gap`, with `talon doctor` preflight and the egress guard) and the auditor exports (audit pack, RoPA, Annex IV) are live — see the [air-gapped deployment guide](docs/guides/air-gapped-deployment.md); their claims remain supporting controls and evidence, never a compliance determination.

## 7. Coding-Agent and Orchestration Boundary

Sharp edges of governing coding agents (Claude Code, Codex CLI, orchestrators) through the gateway (epic #192). Every entry below is shipped behavior stated honestly, with its backing test.

- **Client-asserted subagent identity is attribution, not authentication.** Orchestration metadata (`X-Talon-Session-ID`/`-Agent-ID`/`-Parent-Agent-ID`/`-Client` and the Claude Code / Codex vendor headers) distinguishes subagents *within an already-authenticated agent*; it does not authenticate them. Every value is recorded in signed evidence with `provenance: "client_asserted"` and is exactly as trustworthy as the agent whose key was presented. It is never a policy input — budgets bind to the agent and the agent-scoped session tuple, never to the asserted subagent id. Per-agent attestation is #149. *(Backed by `TestResolveOrchestration_*`, `TestPolicyInputParity_WithAssertedSession`.)*
- **Local tool execution is invisible.** Talon sees model API traffic and MCP-proxied calls. A coding agent's file edits, shell commands, and local tool runs happen on the developer's machine and never transit the gateway; evidence shows the model's tool_use *intentions* (per §3), not local execution.
- **Subscription/OAuth billing cannot be governed.** Pointing only `ANTHROPIC_BASE_URL` at Talon sends Claude Code's subscription OAuth token, which Talon rejects (not an agent key). Governed operation requires the agent-key + vault-injected provider-key model (#266); for the anthropic API family, vault-secret is the **only** upstream auth mode (`upstream_auth_mode: client_bearer` is rejected at config load). For Codex, never set `requires_openai_auth = true` on the Talon profile. *(Backed by the gateway config validation and conformance auth fixtures.)*
- **Response PII `warn` observes streamed responses after delivery; only `redact`/`block` buffer.** With `response_pii_action: warn` an SSE stream is delivered as it arrives and scanned after it terminates: the scan is *post-delivery observation* — it cannot recall PII the client already received, and signed evidence says so (`classification.response_scan.enforcement: post_delivery_observation`, spec 1.10). The observation is bounded (4 MiB of raw SSE per response) and every gap — capture bound exceeded, upstream failure, idle abort, client cancel, scanner failure — is recorded as `status: incomplete` with a reason, never as a clean scan. `redact` and `block` remain preventive: the whole stream is held until the verdict, so time-to-first-token becomes total generation time by design. The coding-agents pack defaults to `warn` (#476; the pre-#476 `allow` workaround is no longer needed). *(Backed by `TestGateway_StreamingWarn_FirstChunkBeforeUpstreamCompletion`, `TestGateway_StreamingRedact_RemainsPreventiveAndBuffered`.)* Streams are bounded by silence, not total duration: a steadily-flowing SSE stream may run past `request_timeout`, while `stream_idle_timeout` (default 60s) aborts a silent stream with the family-correct terminal event (#217, fixed — non-streaming requests keep the `request_timeout` total bound). Raise `stream_idle_timeout` for slow local providers: CPU inference can pause >60s before the first token. The header wait defaults to `request_timeout` (tunable via `response_header_timeout`), so slow-TTFB non-streaming calls are no longer cut at `connect_timeout` (#230, fixed).
- **Chat Completions streams can still truncate silently.** When an upstream dies mid-stream, Talon emits the family-correct terminal event — Anthropic `event: error`, Responses `response.failed` (so Codex stops waiting for `response.completed`) — but the Chat Completions protocol has **no standard mid-stream error event**, so on that wire a dead upstream still looks like a truncated-but-ended stream. Talon does not fabricate `[DONE]`. *(Backed by `TestStreamCopy_MidStreamTerminalEvents`.)*
- **Cache pricing falls back to the input rate.** A pricing entry without `cache_read_per_1m`/`cache_write_per_1m` bills cache tokens at the full input rate (`pricing_basis: "cache_fallback_input_rate"`): cache reads over-counted (~10× their real price), Anthropic cache writes under-counted by up to 25%. Current models ship with rates; keep the table updated. *(Backed by `TestEstimateCached_*`.)*
- **Session budgets admit on estimates.** `max_session_cost` is enforced by atomic reservation (#144): each request's pre-request estimate is reserved before policy evaluation, so concurrent requests serialize against settled + in-flight spend — a burst can no longer slip past the cap by racing (a 5-request burst against a 3-request cap admits exactly 3). What remains is estimation error: admission is decided on the estimate, so ONE in-flight request whose real cost exceeds its own estimate can still overshoot; the next request is denied. A reservation leaked by a crash heals on the session's next touch after 15 minutes of inactivity. *(Backed by `TestSessionBudget_ConcurrentReservationHardBound`, `TestSessionBudget_SingleRequestEstimateOvershoot`, `TestSessionReservation_ConcurrentSerialization`.)*
- **Responses API `store` semantics.** Default `responses_store_mode: preserve` forwards the client's `store` field untouched (an explicit `store: false` is honored). `force_if_absent` injects `store: true` only when absent (needed for `previous_response_id` continuity). `force_true` reverses an explicit `store: false` and records that in signed evidence (`gateway_annotations: ["responses_store_overridden"]`) — the provider then retains data the client asked not to store. *(Backed by `TestConformanceResponses_StoreModes`.)*
- **Tool-content governance is detection + evidence, not enforcement** — see §3; the same boundary applies with extra force to coding agents, whose traffic is dominated by tool content.

## 8. Fleet Boundaries (#267 — multi-agent runtime shipped; these edges remain)

**Every execution surface resolves agents from ONE catalog** (#267, Fleet Operations v1): with `agents_dir` set, the gateway identity registry, native runs (`talon run --agent`), the server run API, and trigger dispatch all resolve any discovered agent's own compiled bundle (policy + OPA engine + PII scanner + router). A run captures one fleet generation at entry and completes under it. The remaining boundaries:

- **Unknown agents fail loudly, never silently as the default.** A native run, trigger, or server run request naming an agent not in the catalog errors with `unknown agent … discovered agents: …` before any lifecycle state exists — it never runs under another agent's budgets and tools (#290 doctrine, now catalog-wide). *(Backed by `TestRun_CatalogResolvesPerAgentBundle`.)*
- **Budget answers never guess.** With a running gateway, `/v1/costs/budget` answers `budget_source: unknown_agent` for an unregistered agent; offline, `talon costs --agent <other>` resolves caps from the default agent policy file only (#288). *(Backed by `TestCostsBudget_RuntimeResolvedContract`.)*
- **MCP/graph interception and the dashboard policy view remain single-policy** (built from the default policy file at startup) — they belong to the intercepted-actions pillar (#114/#146), not Fleet Operations v1.
- **Trigger/webhook DEFINITIONS are read at startup** for all discovered agents; changing them requires a restart (#297). Dispatch-time resolution still applies the current generation's policy to each firing.

## 9. External Containment Runtime Boundary (#482 — OpenShell reference composition, first slice)

Talon can be composed with an execution-containment runtime (reference: NVIDIA OpenShell v0.1.2) as that runtime's supervisor middleware: the runtime admits a sandboxed agent's model request, asks Talon to decide it, and injects the provider credential only after Talon answers. This is **DELEGATE** enforcement (#424): Talon decides, the runtime enforces. The boundaries that remain, each recorded in signed evidence (spec 1.11 `enforcement` / `workload_identity`):

- **Talon does not observe enforcement on the delegated path.** A delegated record carries `enforcement.observed: false`: Talon returned ALLOW/DENY/transform and relied on the runtime's documented hook contract (a DENY always blocks; an unavailable middleware blocks by default). Talon's HMAC proves Talon recorded its decision, not that the runtime honored it. *(Backed by `TestEvaluateDelegated_AllowRecordsProvenanceAndIdentity`.)*
- **The direct-to-provider bypass is prevented by the runtime, not by Talon.** Only the runtime's network policy keeps the agent from reaching a provider without Talon; if that policy admits the provider host without binding Talon, traffic flows ungoverned and Talon has **no record and no way to detect it**. Talon can only import the runtime's own denial log afterwards.
- **Imported containment facts are unverified.** `talon audit import-external` turns OpenShell's OCSF denials into `external_runtime_event` records labelled `external_runtime_enforced`, `mechanism: verify`, `observed: false`, `receipt.verified: false`, `workload_identity.status: asserted`. Talon never claims it saw the file, process or connection — it claims an operator imported the runtime's unsigned statement. *(Backed by `TestContainmentRecord_LabelsExternalEnforcementHonestly`.)*
- **Cost is estimate-only and the response is ungoverned on this path.** Talon does not see the provider response (no response-phase hook yet), so token counts are zero, `execution.cost` is the pre-request estimate, and response-side PII controls apply only to `/v1/proxy`.
- **Reliability is the runtime's.** Talon performs zero retries and zero fallback on the delegated path; each SDK retry inside the sandbox is a fresh Talon decision. Talon `retry`/`fallback` configuration is inert there.
- **Identity is as strong as the runtime's gateway.** Talon verifies the runtime gateway's signed extension token (issuer, audience, EdDSA key, lifetime, caller kind, sandbox consistency) and binds the verified subject through trusted agent configuration. A compromised runtime gateway can mint tokens for any sandbox; Talon does not claim host, kernel or gateway compromise resistance, and does not implement Landlock/seccomp/eBPF or any sandboxing itself. *(Backed by `TestEvaluate_IdentityFailuresNeverProduceAPrincipal`.)*
- **The live smoke against a real OpenShell gateway is not automated here.** `scripts/openshell-smoke.sh` proves Talon's side end to end against a fixture supervisor that replays the pinned v0.1.2 contract; the runtime's own behaviour is documented, not executed, in this repository's tests.
- **No Talon rule is compiled into runtime policy and no runtime rule into Talon YAML.** The single candidate (provider allowlist → endpoint allowlist) was rejected as non-equivalent (runtime admission is also keyed by binary, L7 rules and enforce/audit mode). Consequently the static capability-delta preview (#459) has nothing to cover for this integration.

## 10. Exact Action Governance Boundary (#458 — first end-to-end spine shipped; these edges remain)

Talon now binds one exact consequential action to an immutable operation (`internal/action`), evaluates `DENY > REQUIRE_APPROVAL > ALLOW`, persists the exact approval subject, lets only an authenticated approver decide, and lets only a runtime claim dispatch — at most one effect per operation, `unknown` when a dispatched request has no reliable outcome, all in signed, lifecycle-verified evidence. The boundaries:

- **One adapter so far.** The public Action Gateway (`/v1/action-operations`, `/v1/approvals`) is the only surface on the canonical spine. The MCP proxy, native runner tool calls and Plan Review still use their legacy paths (allow/deny only, in-memory tool approvals, correlation-keyed idempotency). They are not converged (#431/#430) and Talon does not claim exact-action semantics for them.
- **`talon_forwarded` only.** Talon dispatches every authorized attempt itself over HTTP to the catalogued destination. `externally_executed` (client claims, marks dispatch and reports), cancellation and operator reconciliation of `unknown` are not implemented; an `unknown` operation stays closed until a future reconciliation surface exists.
- **Approver groups are approver roles.** A reviewer is authenticated by the local approver credential (`talon approver add --role <group>`); the role is the group. There is no credential id/rotation/expiry, no group lifecycle, and no self-approval prevention (#428 scope).
- **Active payload is stored in plaintext.** The canonical argument payload lives in the operations table until purge is implemented; it never enters evidence (digest + reviewer projection only). Encryption at rest and bounded retention (#426) remain open.
- **Catalog and approval rules load at startup.** The Action Gateway is built from the runtime generation active when `talon serve` starts; a changed agent file takes effect at the next start. Binding/policy digests are checked at every claim, so an operation established under a superseded generation is refused (`approval_binding_stale`), never silently executed.
- **JSON Schema draft is not certified as 2020-12.** Argument schemas are validated with the existing draft-07-compatible library; 2020-12 keywords beyond it are rejected at catalog compile rather than silently ignored.
- **Dispatch boundary is Talon's client-side write.** `dispatch_observed` means Talon wrote the request (httptrace `WroteRequest`); it does not prove the destination processed it. That is exactly why a lost response is `unknown`, not `failed`.
- **DENY is persisted.** A denied operation is stored (`denied`) so an identical replay returns the same denial and a changed payload under the same id is still a conflict; nothing about it is dispatchable.

