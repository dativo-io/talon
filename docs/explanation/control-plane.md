# Talon as a control plane

Talon is the **control plane for company AI use cases**: one self-hosted layer that operates and controls every AI use case **routed through it** — with budget caps, shared policy defaults, reliability and session visibility. This page defines what that means, the vocabulary the docs use, what is available today versus active direction, and what Talon deliberately is not.

For the normative relationship between agents, sessions, native runs, logical operations, approvals, attempts and evidence, see the [Talon object model](../reference/object-model.md).

## The problem it solves

Companies create more AI use cases than they can reliably operate. Each one — a support bot, a coding agent, an internal copilot — is typically operated independently and reinvents its own cost controls, retry behavior, data policy, visibility and incident trail. The next agentic project then stalls, because nobody can operate or control it with confidence. Talon replaces that per-app plumbing with one common operating layer.

## Four jobs, one proof layer

| Pillar | What it means | Shipped today |
|--------|---------------|---------------|
| **Cost control** | Spend is visible and capped per use case | Daily/monthly caps deny **before** the provider call; hard session caps by atomic reservation (estimate-based admission); threshold crossings as signed evidence + one org cost webhook; cache-aware, currency-labeled attribution |
| **Reliability** | One failure behavior instead of N | Same-provider retries with backoff for transient failures (evidence-visible), then error-driven fallback chains, every candidate policy-checked, fail-closed on exhaustion |
| **Shared policy** | Central policy defaults with explicit exceptions | Organization baseline + one explicit per-agent override for PII, tools, models, budgets, egress/sovereignty (#266) |
| **Session understanding** | Know what each use case did, spent, and why it failed | Session identity, session-scoped audit and cost rollups, dashboard drill-down |

Underneath all four sits the **proof layer**: every enforcement decision becomes an HMAC-signed, tamper-evident record you can verify (including offline) and export. Compliance reports (GDPR Art. 30 RoPA, EU AI Act Annex IV) are generated from that evidence — supporting controls and documentation, never a compliance determination. See [Evidence store](evidence-store.md).

## Available today vs. active direction

The category describes where the product is going as well as where it is. To keep claims honest, here is the split — the [roadmap](../../ROADMAP.md) tracks each target item by issue:

```
Available today
───────────────
Per-agent cost caps (deny before the provider call) + hard session caps (atomic reservation, #144)
Organization baseline + one explicit per-agent override (one effective-policy computation, #266)
Policy-valid, error-driven provider fallback
Session identity, session-scoped audit and cost rollups
MCP tool-call interception; tool schema filtering
Signed evidence: verify, export, compliance reports
agents_dir discovery: one agent.talon.yaml per use case, one process serving all (#267)
`talon agents` fleet attention queue (list/show/enable/disable) (#270)
agent.enabled + periodic safe config reload (#268/#269)
Same-provider retries with backoff, evidence-visible, then policy-valid fallback (#139)
Cost warning thresholds as signed evidence + one org cost webhook; hard session caps by atomic reservation (#144)
Session summary contract: talon session show over the shared evidence projection (#271)
AI use-case operating record: agent.use_case in the fleet view (#382)

Active MVP direction
────────────────────
Session simplification: status open/completed, managed_by attribution and evidence-derived failure attention (#401)
Shared model/action control-plane boundaries and canonical object linkage (#424)
Persistent typed approvals and exact logical operations (#426)
Durable native run checkpoints and approval waits (#430)
n8n/external runtime adapter over the same action and approval services (#434)
CLI-primary fleet operations; dashboard as a read-only projection of the same semantics (#143)
```

## Vocabulary

- **AI use case** — the public product term: one operated unit of AI usage (a bot, an agent, a copilot integration).
- **Agent** — the CLI/config object that represents one AI use case. One `agent.talon.yaml` describes one use case; `agent.name` is its operational identity in one Talon installation. Shipped model (#266): one active vault-bound Talon key per agent — the presented key IS the traffic identity, and `tenant_id` derives from it.
- **Operating record** (`agent.use_case`, #382) — the optional block in `agent.talon.yaml` naming what the use case is for, which department operates it, how critical it is, and who is accountable (business / technical / budget / risk owners as contact strings), plus pointers to external approval records. `talon agents show` and the fleet API project it as declared. Two identities, never conflated: the **Talon key authenticates the presenter of traffic**; the **owner metadata is attribution for humans** — it authenticates nobody and is never a policy input. Criticality is context; it maps to no enforcement unless an explicit policy does so.
- **Session** — the correlation, cost and understanding boundary for related activity through Talon. The settled target contract in #401 uses one field, `status`, with only `open | completed`, plus one manager field, `managed_by`. `open` means no explicit completion was observed, not necessarily currently executing. Approval, execution, failure and timeout lifecycles belong to runs, operations and approvals instead.
- **Native run** — a Talon-owned executable lifecycle with durable planning, waiting, execution and terminal states. It may be linked to a session but does not copy its state onto the session.
- **Logical operation** — one exact governed side effect with stable operation identity, bound inputs, approval when required, execution attempts and outcome/provenance.
- **Approval** — an authorization decision over one immutable plan version or exact logical operation. Approval state is distinct from operation execution state.
- **Execution attempt** — one transport/business attempt under a logical operation; retries remain under the same unchanged operation when safe.
- **Evidence** — the signed record of a decision, transition or observed/asserted result; the proof layer, not the front door and not mutable workflow state.

The full metadata, lifecycle and linkage rules are normative in the [object model reference](../reference/object-model.md).

## Lightweight lifecycle design

Talon avoids one universal state machine.

```text
agent/use case
  -> session: correlation, cost, timeline; status open/completed
       -> native run: Talon-owned execution lifecycle
       -> logical operation: exact governed side effect
            -> approval: authorization decision
            -> attempts: transport/business outcomes
```

A session may show **attention required** because it has a pending approval, unresolved operation or unrecovered provider failure. Those are shared projection facts linked to the session; they do not become new session statuses.

`managed_by` is the single session field that names the concrete runtime or orchestrator responsible for the session lifecycle—for example `talon`, `n8n`, `claude-code` or `codex`. The separate `source` field records only how Talon obtained the session identity. Neither field authenticates authority or changes policy, and Talon does not expose a separate `lifecycle_owner` concept.

## Operator model: CLI primary, dashboard secondary

The operator interface is the local `talon` CLI, run where Talon runs — there is no remote-administration requirement, and configuration in YAML is the source of truth. Today the CLI covers auditing, costs, sessions, providers, secrets and compliance exports; it also covers the fleet: `talon agents` is the shipped attention queue (STATE/HEALTH/COST/WHY columns, with `talon agents show <name>`) and `talon agents enable/disable` is the host-local kill switch (Fleet Operations v1).

The dashboard is the secondary surface, and its direction is a **read-only projection** for inspection, filtering, verification and export. A focused approval inbox is an explicit narrow exception for authorized human decisions; it does not turn the fleet dashboard into a generic workflow system.

The design rule for all surfaces: session status, run status, approval decision, operation status, attempt result, health, budget state and effective policy must be computed once and shared, never flattened or re-derived independently per interface. Parts of that already exist (the dashboard's metrics are rebuilt from the same evidence the CLI reads); completing it is tracked on the roadmap.

## Failure interpretation

Talon keeps failure facts visible without inventing session outcomes:

- a provider failure recovered by retry or policy-valid fallback remains visible but does not trigger the session/fleet failure signal;
- an unrecovered final provider/request failure contributes to the evidence-derived `sessions_with_recent_failures` projection;
- policy denial, budget denial and approval rejection are explicit decisions, not failed sessions;
- an upstream action-system failure belongs to the operation attempt;
- external orchestrator silence or inactivity is never interpreted as failure;
- client-reported outcomes remain explicitly client asserted.

## What Talon is not

- **Not a router/optimizer.** Routers optimize a single call for latency or price; Talon decides what is *allowed* to happen across the fleet, then proves it. Fallback never bypasses policy to keep traffic up.
- **Not an observability suite.** Observability shows what already happened; Talon enforces before the provider is called and keeps the signed trail as a by-product of enforcement.
- **Not endpoint security or universal agent control.** Talon governs only actions it can actually intercept: tool schemas in LLM requests, and MCP calls routed through it. Local shell commands, file edits, browser actions or direct API calls that bypass Talon are invisible to it — stated plainly in [LIMITATIONS.md](../../LIMITATIONS.md).
- **Not a workflow engine.** External systems such as n8n own their workflow waiting and resumption. Talon owns model/action policy, exact authorization, operation state and evidence at its controlled boundaries.
- **Not a compliance certification.** Evidence and generated reports support audits and reviews; they do not make a deployment compliant.

## Honest boundaries worth knowing up front

- Session-cap admission is **estimate-based**: concurrent bursts serialize against reserved+settled spend (#144), but one in-flight request whose real cost exceeds its own estimate can still overshoot.
- Client-asserted agent/session/client identity is **attribution, not authentication** — there is no request attestation yet.
- An externally managed session shown as **Open** may be idle or abandoned; Talon only knows that no explicit completion was recorded.
- Talon cannot infer that an external orchestrator failed merely because it stopped polling or sending requests.
- HMAC-signed evidence is **tamper-evident and verifiable**, not immutable.

The full list lives in [LIMITATIONS.md](../../LIMITATIONS.md); the active roadmap is [ROADMAP.md](../../ROADMAP.md).
