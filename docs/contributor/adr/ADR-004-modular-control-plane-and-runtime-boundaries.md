# ADR-004: One modular in-process control plane and runtime boundaries

**Status:** Accepted
**Date:** 2026-10
**Context:** Freeze the hard-to-reverse architecture for Talon as the control layer for company AI use cases: one in-process control plane governing model calls and consequential actions across the HTTP gateway, native Talon, MCP and external runtimes ([#424](https://github.com/dativo-io/talon/issues/424)).

The living, detailed companion is [Control-plane boundaries](../../reference/control-plane-boundaries.md). This ADR holds only the decisions that a future change must supersede explicitly; the reference holds diagrams, dispositions and shipped-versus-target status and may evolve without a new ADR.

---

## Context

Talon is the **control layer for company AI use cases**: it turns company AI policy into enforceable, use-case-specific controls and records signed, verifiable evidence of its decisions, of the effects it directly observed, and of enforcement it delegated or received as external assertions, each with explicit provenance. The stable product object is the AI use case (`agent` in CLI and config), not a provider, model, MCP server, framework, workflow or sandbox. The value order is shared company control, then consequential-action control, then verifiable proof.

By the time of this decision the repository ships: one compiled multi-agent runtime generation with last-known-good reload; an always-enforced posture ([#442](https://github.com/dativo-io/talon/issues/442)); the MCP 2026-07-28 wire foundation ([#447](https://github.com/dativo-io/talon/issues/447)); a trusted action catalog with explicit and MCP-discovered definitions ([#427](https://github.com/dativo-io/talon/issues/427)); the exact, Talon-forwarded HTTP Action Gateway spine with local approver credentials and signed lifecycle evidence ([#458](https://github.com/dativo-io/talon/issues/458), [#483](https://github.com/dativo-io/talon/pull/483), [#484](https://github.com/dativo-io/talon/pull/484)); and the OpenShell v0.1.3 request-side delegated composition ([#482](https://github.com/dativo-io/talon/issues/482), [#490](https://github.com/dativo-io/talon/pull/490)).

Several surfaces still predate that spine: native tool approval and Plan Review use their own stores and approve-then-run paths; the native `/mcp` and `/mcp/proxy` routes govern tool calls with their own policy path rather than Action Governance; graph events emit allow or deny only. Without a frozen architecture, the remaining P0 work ([#372](https://github.com/dativo-io/talon/issues/372), [#431](https://github.com/dativo-io/talon/issues/431), [#448](https://github.com/dativo-io/talon/issues/448), [#430](https://github.com/dativo-io/talon/issues/430), [#434](https://github.com/dativo-io/talon/issues/434)) could converge on parallel implementations.

### Forces

- One company policy must produce the same decision for the same use case on every surface, or the proof is worthless.
- Consequential actions need exact, immutable authorization and honest outcome provenance, without Talon becoming a connector platform.
- External runtimes already own agent loops, workflows and sandboxes; Talon must compose with them, not replace them.
- Talon is one self-hosted Go binary on SQLite; operational simplicity is a product property.
- Every claim in docs and evidence must be true at the enforcement boundary Talon actually owns.

## Decision

### D1. One modular in-process control plane

Talon is one process containing modular domains that share one implementation: the compiled runtime generation and effective policy, the trusted action catalog, **ModelGovernance** (the governed model-call service), **ActionGovernance**, **approval and operation state** (one typed approval kernel plus logical operations and attempts), the native run controller, and **evidence** with its lifecycle verifier and projections, over repositories, provider and action dispatchers, cryptography and evidence sinks.

Adapters are thin: the provider-compatible HTTP model gateway, the native Talon runtime, the MCP 2026-07-28 adapter, the public Action Gateway HTTP API, the CLI, API and minimal reviewer surfaces, and external clients such as n8n or complementary runtimes such as OpenShell.

Dependency direction is fixed: **adapters → application/domain services → repositories and controlled dispatchers**. Domain and application packages do not depend on HTTP, Cobra, MCP, n8n or UI types. "Shared" means the same instantiated modules, generation, stores, clocks, transition rules and evidence writer, never parallel implementations with similar code. Interfaces exist only at real seams: repositories, clocks and IDs, identity resolution, dispatchers, cryptography, evidence sinks.

Not permitted in v1: internal HTTP or gRPC between Talon modules, one adapter calling another over localhost, queues, service discovery, sagas, distributed transactions, active-active coordination, a separate MCP approval engine, or a separate n8n authorization engine. Service extraction waits for a concrete scaling, availability, security-boundary or ownership need and a superseding ADR.

### D2. Native Talon is a complete runtime over the same domains

Native execution calls ModelGovernance and ActionGovernance directly in-process. It never loops back over localhost and never carries an alternate policy or action authority. Native Plan Review and native action approval are typed subjects of the shared approval kernel, not separate approval systems.

### D3. Model Governance and Action Governance are distinct boundaries

ModelGovernance owns provider and model eligibility and routing, the effective model, data, cost and reliability policy, prompt and response classification and transformation, cost reservation, retries and policy-valid fallback, preventive filtering of action discovery presented to a model, and model-call evidence. A model-emitted action proposal is context and evidence only.

ActionGovernance begins only when a runtime or client **attempts one concrete catalogued action** through a Talon-controlled boundary. It owns trusted definition resolution, exact normalized validation and digest, the logical operation, the final `DENY | REQUIRE_APPROVAL | ALLOW` verdict (DENY wins), approval creation and exact-operation authorization, attempt authorization, execution-profile selection from the catalog, outcome provenance and lifecycle evidence.

Normative chain: **visible ≠ proposed ≠ attempted ≠ authorized ≠ dispatched ≠ succeeded.** Discovery, `tools/list`, model output, a model-layer ALLOW or a Task or request identifier never authorizes a side effect or creates an approval. Discovery filtering is defense in depth; every concrete attempt re-enters ActionGovernance.

### D4. One immutable operation model with exact binding

One `operation_id` names one immutable intended business effect, unique within tenant plus use case. The digest binds the canonical action, the complete normalized material arguments, the trusted definition, schema, binding and projection identities, the execution profile, the material destination and the approval-relevant policy identity. Transport values are excluded; any exclusion is catalog-owned and versioned, never caller-chosen.

Same id with the same digest returns current state. Same id with changed material input fails closed with `operation_conflict` and mutates nothing. Material correction is a new operation. Before any effect the runtime or controller revalidates the current trusted definition and policy, claims exactly one attempt, and dispatches. An ambiguous post-dispatch result is `unknown`, is terminal for automatic retry, and waits for authorized reconciliation. Talon claims at most one effect per operation, not universal exactly-once execution.

### D5. Two execution profiles, one domain model

A trusted definition selects exactly one profile; callers cannot choose it.

- **`talon_forwarded`**: Talon authorizes, claims the attempt, owns network dispatch through a trusted dispatcher and records the outcome. Provenance is `observed` only when Talon actually observed the relevant outcome.
- **`externally_executed`**: an external runtime obtains exact-operation authorization, owns the downstream credential, transport, waiting and retries, performs the effect and reports an authenticated outcome. Talon owns identity, binding, approval, attempt permission, report validation and reconciliation. Provenance is `client_asserted` until reconciled through an explicitly supported mechanism. Talon never claims to have observed that effect.

Both profiles share operation, approval, attempt, idempotency and evidence contracts.

### D6. One typed approval kernel with two subjects

One shared approval kernel supports exactly two typed subjects, `plan_review` and `action_execution`. It owns the durable request and decision, authenticated and policy-authorized reviewer identity, expiry, invalidation and decision concurrency, safe projection linkage and mandatory lifecycle evidence. It does not own policy evaluation, plan or operation validity, workflow waiting or branching, dispatch, arbitrary forms or payloads, escalation, quorum, delegation, MCP input or generic tasks.

Decision lifecycle is `pending → approved | rejected | expired | cancelled | invalidated`. There is no `consumed` state. Approval records the human decision; authorization usability is rechecked at every claim; operation and attempt states record execution. A committed decision is an immutable historical fact; later policy or catalog change makes authorization unusable or requires a new cycle without rewriting `approved`. Reviewers approve or reject the exact bound subject and never transform it. A reviewer decision performs zero dispatch.

### D7. Continuation is owned by the runtime, never by the approval

An approval commit may emit a wake-up signal; the owning runtime reloads durable truth, revalidates, claims an attempt and dispatches. Native Talon persists a run checkpoint and recovers by scan after restart; wake-up is an optimization. External workflows own their waiting and polling of stable operation and approval resources; notifications never carry authorization truth. For MCP no HTTP request is held open for a human approval: a client that advertises the Tasks extension in the current request receives a Task that is protocol continuation and projection over canonical Talon state; a client without Tasks receives honest non-execution with zero dispatch. MRTR input (`input_required`, `requestState`, `inputResponses`) is non-authorizing protocol input and is never Talon human approval.

### D8. MCP is an adapter beneath ActionGovernance, 2026-07-28 only

The target MCP surface is one canonical governed `POST /mcp` for protocol 2026-07-28 only. Every request is self-describing. There is no `initialize` or `notifications/initialized` exchange (rejected), no `Mcp-Session-Id` (ignored, never minted), no previous-protocol compatibility, and no hidden capability memory. `server/discover` reports only what is implemented; `tools/list` projects one captured trusted catalog generation; `tools/call` is always re-authorized. Header and body disagreement is a protocol and security failure before business governance, with no governance evidence fabricated. MCP Task state is adapter continuation over canonical operation, approval and attempt state, never a fourth authorization state machine; Task and JSON-RPC identifiers are not operation identity and not bearer authorization.

### D9. Enforcement doctrine: INTERCEPT, DELEGATE, COMPILE, VERIFY

The company and use-case policy model is canonical; the mechanism is adapter-specific and must be the strongest honest one available. **INTERCEPT**: Talon owns the prevention boundary (HTTP model gateway; the governed MCP adapter once [#431](https://github.com/dativo-io/talon/issues/431) ships). **DELEGATE**: Talon decides and a trusted runtime enforces at its own pre-execution boundary (OpenShell supervisor middleware). **COMPILE**: a bounded rule is translated into a native enforceable primitive only when semantics are provably equivalent and versioned; no OpenShell mapping is certified. **VERIFY**: Talon consumes a fact enforced elsewhere; it is never preventive. Evidence records which mechanism and boundary applied and whether the outcome is Talon-enforced, delegated-expected, externally asserted or client-asserted; Talon never labels a delegated or imported fact as enforced by itself.

### D10. Identity classes stay distinct

AI use-case identity, verified workload or runtime principal, application and session attribution, human reviewer principal, platform operator, and protocol, request or task correlation are different authority classes. Attribution is not authentication; an operator is not an approver; a workload identity is not a reviewer; MCP `clientInfo` is not business identity; a session id confers no authority; a task id is no authorization. External verified workload identities enter only through the federation contract of [#457](https://github.com/dativo-io/talon/issues/457). Talon is not an identity provider, certificate authority, issuer or trust mesh.

### D11. Always-enforced posture

Live traffic has no global `shadow`, `log_only` or MCP `passthrough` posture; removal is owned by [#442](https://github.com/dativo-io/talon/issues/442) and shipped. Synthetic surfaces (policy test, offline replay, preview, detector record) are non-authorizing and cannot weaken live hard controls or create reusable authorization. Historical evidence written under older vocabulary stays readable.

### D12. Sessions stay correlation

Sessions adopt [#401](https://github.com/dativo-io/talon/issues/401): one `status` with `open | completed`, a `managed_by` attribution field, `source` as identity provenance only, no `lifecycle_owner`, no universal state machine, and no mapping of any MCP transport session into Talon session state. Runs, operations, approvals and attempts keep their own state machines.

### D13. Honest enforcement boundary

Talon controls only effects that cross a supported Talon or delegated boundary. It cannot prevent local shell commands, direct filesystem edits, browser automation, direct business API calls, alternate provider paths or local tool execution that bypass every controlled boundary. A complementary containment runtime can narrow those paths for its own sandbox; that does not make Talon a universal agent-control product, and no diagram may imply otherwise.

## Alternatives rejected

- **Internal microservices or an internal API between gateway, action and approval components.** Rejected: duplicates policy evaluation, adds distributed-failure modes to a single-binary product, and offers no scaling need today.
- **A generic workflow or task engine with configurable approval DSL, escalation and quorum.** Rejected: external orchestrators already own workflows; Talon's differentiator is exact authorization and proof, not orchestration.
- **Process-local customer business tools (`Tool.Execute`) as the public extension model.** Rejected: it makes Talon a connector ecosystem and executes effects Talon cannot attribute to a trusted catalog; removal is owned by #431.
- **A `consumed` approval status.** Rejected: it conflates the human decision with execution state and breaks safe retries.
- **MCP protocol session state as business authorization or a Talon-specific continuation model.** Rejected: current MCP Tasks and MRTR are the right transport primitives, and Talon session identity is correlation only.
- **Compiling Talon policy into OpenShell network policy.** Rejected for now: no candidate mapping is semantically equivalent (admission is also keyed by binary, L7 rules and enforce or audit mode), so it would create a second policy authority.
- **Labelling delegated or imported facts as Talon-enforced or verified.** Rejected: it overstates what Talon observed.

## Consequences

- #431, #448, #430 and #434 implement adapters and controllers over the shipped action domain instead of new authorities; #426 and #429 remain the state and API owners; #146 the lifecycle-evidence owner.
- Native tool approval and Plan Review converge on the typed kernel; the embedded tool registry stops being a product extension model.
- Docs and evidence must keep the shipped-versus-target split explicit; the living reference carries the disposition table and migration notes.
- Reversal of any decision above requires a superseding ADR, not an edit to this one.

## Non-goals

This ADR does not fix Go interfaces, package paths, SQL schema, HTTP route spelling, DTOs, JSON Schema canonicalization, UI layout, polling intervals, support for MCP versions before 2026-07-28, MCP Apps or other optional extensions, HA or managed deployment, a connector marketplace or endpoint agent, universal exactly-once execution, or control of actions that bypass Talon.

## Current-versus-target status

Shipped at the time of acceptance: one compiled runtime generation with generation-bound resolution; always-enforced posture; MCP 2026-07-28 wire foundation at `/mcp` and `/mcp/proxy`; trusted explicit and MCP-discovered catalog; Action Gateway exact `talon_forwarded` HTTP spine with local approver credentials and signed lifecycle evidence; OpenShell v0.1.3 request-side DELEGATE composition proven against the released runtime.

Target, not yet shipped: MCP `tools/call` through ActionGovernance and one canonical `POST /mcp` (#431); MCP Tasks continuation (#448); the `externally_executed` profile and n8n reference (#434); native convergence on the typed kernel (#430); the shared kernel as one implementation across plan review and action execution (#426); reviewer surfaces (#433); unknown-outcome reconciliation (#146); workload federation breadth (#457); OpenShell `HTTP_RESPONSE / PRE_RETURN` and WebSocket governance; full parity gate (#435). The reference keeps the authoritative table.

## References

- Living reference: [Control-plane boundaries](../../reference/control-plane-boundaries.md)
- Object model: [Talon object model](../../reference/object-model.md)
- Shipped spine: [Action Gateway](../../reference/action-gateway.md); [NVIDIA OpenShell composition](../../integration/openshell.md)
- Issues: [#424](https://github.com/dativo-io/talon/issues/424) (this decision), [#265](https://github.com/dativo-io/talon/issues/265) (roadmap), [#425](https://github.com/dativo-io/talon/issues/425), [#426](https://github.com/dativo-io/talon/issues/426), [#427](https://github.com/dativo-io/talon/issues/427), [#428](https://github.com/dativo-io/talon/issues/428), [#429](https://github.com/dativo-io/talon/issues/429), [#430](https://github.com/dativo-io/talon/issues/430), [#431](https://github.com/dativo-io/talon/issues/431), [#372](https://github.com/dativo-io/talon/issues/372), [#433](https://github.com/dativo-io/talon/issues/433), [#434](https://github.com/dativo-io/talon/issues/434), [#435](https://github.com/dativo-io/talon/issues/435), [#442](https://github.com/dativo-io/talon/issues/442), [#447](https://github.com/dativo-io/talon/issues/447), [#448](https://github.com/dativo-io/talon/issues/448), [#457](https://github.com/dativo-io/talon/issues/457), [#458](https://github.com/dativo-io/talon/issues/458), [#482](https://github.com/dativo-io/talon/issues/482), [#146](https://github.com/dativo-io/talon/issues/146), [#401](https://github.com/dativo-io/talon/issues/401)
- Earlier ADRs: [ADR-001](ADR-001-agent-planning-paradigm.md), [ADR-002](ADR-002-prompt-storage-data-minimization.md), [ADR-003](ADR-003-graph-runtime-governance.md) (ADR-003's parity claim for external runtimes is superseded by D3 and D13 of this record: graph events are context and telemetry, not enforcement authority)
