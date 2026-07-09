# Talon as a control plane

Talon is the **control plane for company AI use cases**: one self-hosted layer that operates and controls every AI use case a company runs — with shared budgets, policies, reliability and session visibility. This page defines what that means, the vocabulary the docs use, and what Talon deliberately is not.

## The problem it solves

Companies create more AI use cases than they can reliably operate. Each one — a support bot, a coding agent, an internal copilot — is typically operated independently and reinvents its own cost controls, retry behavior, data policy, visibility and incident trail. The next agentic project then stalls, because nobody can operate or control it with confidence. Talon replaces that per-app plumbing with one common operating layer.

## Four jobs, one proof layer

| Pillar | What it means | Shipped today |
|--------|---------------|---------------|
| **Cost control** | Spend is visible and capped per use case | Daily/monthly caps deny **before** the provider call; session budgets (soft caps); cache-aware, currency-labeled attribution |
| **Reliability** | One failure behavior instead of N | Error-driven fallback chains on transient failures, every candidate policy-checked, fail-closed on exhaustion |
| **Shared policy** | Write policy once; every use case inherits it | Org defaults + per-caller overrides for PII, tools, models, budgets, egress/sovereignty |
| **Session understanding** | Know what each use case did, spent, and why it failed | Session identity, session-scoped audit and cost rollups, dashboard drill-down |

Underneath all four sits the **proof layer**: every enforcement decision becomes an HMAC-signed, tamper-evident record you can verify (including offline) and export. Compliance reports (GDPR Art. 30 RoPA, EU AI Act Annex IV) are generated from that evidence — supporting controls and documentation, never a compliance determination. See [Evidence store](evidence-store.md).

## Vocabulary

- **AI use case** — the public product term: one operated unit of AI usage (a bot, an agent, a copilot integration).
- **Agent** — the CLI/config object that represents one AI use case. One `agent.talon.yaml` describes one use case; `agent.name` is its operational identity in one Talon installation. The intended model is one active Talon key per agent, so traffic separates cleanly by use case.
- **Caller / tenant** — implementation terms in today's gateway configuration (`gateway.callers[]`, `tenant_key`); they map onto the agent/use-case identity and will converge with it over time.
- **Evidence** — the signed record of a decision; the proof layer, not the front door.

## Operator model: CLI primary, dashboard secondary

The primary interface is the local `talon` CLI, run where Talon runs — there is no remote-administration requirement. The dashboard is a secondary, read-only-direction projection for inspection, filtering, verification and export. Both draw on the same internal semantics: health, budget state, session outcome and effective policy are computed once, not re-derived per interface. Configuration in YAML remains the source of truth.

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
