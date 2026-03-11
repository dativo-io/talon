# Dashboard Competitor Benchmark & Talon Decisions

This document maps the top 10 LLM governance and observability competitors to dashboard features and records Talon’s explicit product decisions for the unified governance + FinOps dashboard.

## Competitors and Feature Mapping

| Competitor | Primary focus | Key dashboard features | Talon adoption |
|------------|---------------|-------------------------|----------------|
| **Helicone** | Request traces, cost/latency | Request traces, cost/latency analytics, reportability, export | ✓ Evidence ledger + cost timelines; ✓ export + integrity (signature/verify) |
| **LiteLLM** | Proxy, key/team budgets | Key/team budgets, spend controls, usage logs | ✓ Cost limits + budget status in metrics; ✓ per-tenant/caller in gateway |
| **Credo AI** | Governance artifacts | Policy packs, audit evidence workflows, risk views | ✓ Policy decisions in evidence; ✓ plan review queue; ✓ governance tab |
| **Zenity** | AI agent posture | Agent inventory, posture/risk view, runtime controls | ✓ Tenants & Agents tab (replaces CoPaw); ✓ agent registry view |
| **Langfuse** | Traces + evals | Traces, evaluations, prompt/version analytics | ✓ Evidence + plans + memory as governance artifacts; no prompt versioning in MVP |
| **Portkey** | Gateway guardrails | Gateway guardrails, reliability, budget/usage dashboards | ✓ Gateway metrics (blocked, PII, tools, latency); ✓ budget utilization |
| **Arize Phoenix** | OSS traces/evals | Traces/evals workflow, debugging UX | ✓ Evidence timeline + filters; ✓ plan/memory review queues |
| **WhyLabs** | Policy/security | Policy rule outcomes, prompt-injection/PII guardrails | ✓ PII breakdown + denials by reason; ✓ attachment sandboxing in evidence |
| **Fiddler** | Compliance monitoring | Compliance-aligned monitoring, audit trail framing | ✓ Evidence by default; ✓ compliance overlays (GDPR/EU AI Act) in IA |
| **Humanloop** | Eval + approval | Eval + prompt lifecycle + approval loop patterns | ✓ Plan review gate; ✓ memory review queue; ✓ human oversight in governance |

## Talon Dashboard Decisions (Explicit)

1. **Single entry point**  
   One unified dashboard at `/dashboard` for governance, compliance, evidence, FinOps, and tenants/agents. Gateway telemetry is embedded or linked; `/gateway/dashboard` remains as an optional deep link.

2. **No CoPaw-specific tab**  
   CoPaw is removed from the primary information architecture. Tenants & Agents tab shows tenant overview (request volume, spend, denials, pending reviews) and agent registry (owner/team, model tier, last run, risk posture, budget usage), sourced from evidence + plans + metrics.

3. **Evidence-first compliance**  
   Every LLM call, secret access, and memory write produces signed evidence. Dashboard shows evidence ledger with filters (tenant, agent, model, policy decision), export, and integrity indicators. Compliance overlays (GDPR, EU AI Act, ISO) are metadata on evidence, not a separate product.

4. **Human oversight queues**  
   Plans Awaiting Review and Memory Review stay as first-class governance tabs. Plan approve/reject/modify and memory approve flows are the primary “approval loop” surface.

5. **FinOps from gateway metrics**  
   Cost, latency, error rate, model/caller breakdown, budget utilization, and cache stats come from the existing metrics collector and `/api/v1/metrics` (and SSE). These are exposed in the unified dashboard (Overview + FinOps/Runtime section).

6. **Tenant/agent scope**  
   All dashboard data is tenant-scoped when an API key or token is tenant-bound. Tenant/agent summary is derived from evidence store and plan review store; a dedicated summary API is added only if existing APIs are insufficient.

7. **Testing pyramid**  
   Unit tests for data mapping and handler edge cases; integration tests for dashboard API contract composition; minimal E2E/smoke for authenticated load, plans round-trip, evidence list/export, and gateway SSE.

## References

- Plan: `dashboard_consolidation_strategy_88af708d.plan.md`
- Legacy dashboard: `web/dashboard.html`
- Gateway dashboard: `web/gateway_dashboard.html`
- Server routes: `internal/server/server.go`
- Metrics snapshot: `internal/metrics/collector.go` (`Snapshot`, `CallerStat`, `BudgetStatus`)
