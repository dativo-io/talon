# Talon as a control plane

Talon is the **control plane for company AI use cases**: one self-hosted layer that operates and controls every AI use case **routed through it** — with budget caps, shared policy defaults, reliability and session visibility. This page defines what that means, the vocabulary the docs use, what is available today versus active direction, and what Talon deliberately is not.

## The problem it solves

Companies create more AI use cases than they can reliably operate. Each one — a support bot, a coding agent, an internal copilot — is typically operated independently and reinvents its own cost controls, retry behavior, data policy, visibility and incident trail. The next agentic project then stalls, because nobody can operate or control it with confidence. Talon replaces that per-app plumbing with one common operating layer.

## Four jobs, one proof layer

| Pillar | What it means | Shipped today |
|--------|---------------|---------------|
| **Cost control** | Spend is visible and capped per use case | Daily/monthly caps deny **before** the provider call; session budgets (soft caps); cache-aware, currency-labeled attribution |
| **Reliability** | One failure behavior instead of N | Error-driven fallback chains on transient failures, every candidate policy-checked, fail-closed on exhaustion |
| **Shared policy** | Central policy defaults with explicit exceptions | Organization baseline + one explicit per-agent override for PII, tools, models, budgets, egress/sovereignty (#266) |
| **Session understanding** | Know what each use case did, spent, and why it failed | Session identity, session-scoped audit and cost rollups, dashboard drill-down |

Underneath all four sits the **proof layer**: every enforcement decision becomes an HMAC-signed, tamper-evident record you can verify (including offline) and export. Compliance reports (GDPR Art. 30 RoPA, EU AI Act Annex IV) are generated from that evidence — supporting controls and documentation, never a compliance determination. See [Evidence store](evidence-store.md).

## Available today vs. active direction

The category describes where the product is going as well as where it is. To keep claims honest, here is the split — the [roadmap](../../ROADMAP.md) tracks each target item by issue:

```
Available today
───────────────
Per-agent cost caps (deny before the provider call) + session budgets (soft)
Organization baseline + one explicit per-agent override (one effective-policy computation, #266)
Policy-valid, error-driven provider fallback
Session identity, session-scoped audit and cost rollups
MCP tool-call interception; tool schema filtering
Signed evidence: verify, export, compliance reports

Active MVP direction
────────────────────
agents_dir discovery: one agent.talon.yaml per use case, one process serving all (#267)
`talon agents` fleet attention queue (list/show/enable/disable)
CLI-primary fleet operations; dashboard as a read-only projection of the same semantics
agent.enabled + periodic safe config reload
Same-provider retries; cost warning thresholds as signed evidence + org webhook
```

## Vocabulary

- **AI use case** — the public product term: one operated unit of AI usage (a bot, an agent, a copilot integration).
- **Agent** — the CLI/config object that represents one AI use case. One `agent.talon.yaml` describes one use case; `agent.name` is its operational identity in one Talon installation. Shipped model (#266): one active vault-bound Talon key per agent — the presented key IS the traffic identity, and `tenant_id` derives from it.
- **Evidence** — the signed record of a decision; the proof layer, not the front door.

## Operator model: CLI primary, dashboard secondary

The operator interface is the local `talon` CLI, run where Talon runs — there is no remote-administration requirement, and configuration in YAML is the source of truth. Today the CLI covers auditing, costs, sessions, providers, secrets and compliance exports; the fleet view (`talon agents` as an attention queue with enable/disable) is active roadmap, not shipped — today `talon agents` offers only an analytics score.

The dashboard is the secondary surface, and its direction is a **read-only projection** for inspection, filtering, verification and export. The design rule for both: health, budget state, session outcome and effective policy must be computed once and shared, never re-derived per interface. Parts of that already exist (the dashboard's metrics are rebuilt from the same evidence the CLI reads); completing it is tracked on the roadmap.

## What Talon is not

- **Not a router/optimizer.** Routers optimize a single call for latency or price; Talon decides what is *allowed* to happen across the fleet, then proves it. Fallback never bypasses policy to keep traffic up.
- **Not an observability suite.** Observability shows what already happened; Talon enforces before the provider is called and keeps the signed trail as a by-product of enforcement.
- **Not endpoint security or universal agent control.** Talon governs only actions it can actually intercept: tool schemas in LLM requests, and MCP calls routed through it. Local shell commands, file edits, browser actions or direct API calls that bypass Talon are invisible to it — stated plainly in [LIMITATIONS.md](../../LIMITATIONS.md).
- **Not a compliance certification.** Evidence and generated reports support audits and reviews; they do not make a deployment compliant.

## Honest boundaries worth knowing up front

- Session caps are **soft** today: in-flight requests can overshoot before the next request is denied.
- Client-asserted agent/session identity is **attribution, not authentication** — there is no request attestation yet.
- HMAC-signed evidence is **tamper-evident and verifiable**, not immutable.

The full list lives in [LIMITATIONS.md](../../LIMITATIONS.md); the active roadmap is [ROADMAP.md](../../ROADMAP.md).
