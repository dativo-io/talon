# ADR-003: Graph Runtime Governance — Framework-Agnostic Control Plane

**Status:** Accepted
**Date:** 2026-04
**Context:** Enable Talon to govern external agent runtimes (LangGraph, LangChain, OpenAI SDK, MCP clients) as a true runtime control plane, not just a gateway proxy.

---

## Context

Talon today provides deep governance for its **native Go runner** (policy evaluation, step-level evidence, tool access control, loop containment, plan review gate). However, external agent frameworks like LangGraph, LangChain, CrewAI, or custom OpenAI SDK scripts interact with Talon only through the **LLM gateway proxy** (`/v1/proxy/*`) or **MCP `tools/call`** endpoint.

This means:

- **LangGraph stateful graphs**: Talon sees individual LLM calls but not graph structure, node transitions, retry decisions, or branch paths.
- **LangChain stateless calls**: Talon can enforce per-request policy but has no session/run-level correlation or lineage from the client side.
- **Plan review**: Gates individual requests, not multi-step workflows.
- **Evidence**: Two separate correlation IDs for plan-review vs dispatch execution; no graph-level summary.

### Current integration boundaries

| Surface | What Talon sees | What Talon controls |
|---------|----------------|-------------------|
| Native runner (`Runner.Run`) | Full pipeline: policy, PII, tools, steps, evidence | Abort, budget, tool deny, plan gate, hooks |
| Gateway (`/v1/proxy/*`) | Single LLM request | Policy deny, PII redact, rate limit, model forward |
| MCP (`/mcp` tools/call) | Single tool invocation | Tool access policy, evidence |
| External LangGraph | Nothing beyond gateway traffic | Nothing beyond gateway traffic |

### Code touchpoints (as-is)

- Runner pipeline: `internal/agent/runner.go` — `Run()`, `executeLLMPipeline()`, agentic loop
- Policy engine: `internal/policy/engine.go` — `Evaluate`, `EvaluateToolAccess`, `EvaluateLoopContainment`
- Evidence: `internal/evidence/generator.go` — `Generate`, `GenerateStep`
- Plan gate: `internal/agent/plan.go`, `internal/agent/plan_review.go`
- Hooks: `internal/agent/hooks.go` — `HookPreTool`, `HookPostTool`, etc.
- Gateway: `internal/gateway/gateway.go` — 10-step proxy pipeline
- MCP server: `internal/mcp/server.go` — JSON-RPC tools/list + tools/call
- LangChain pack: `internal/pack/wizard.go` (init template only, no runtime code)

---

## Decisions

### 1. Framework-Agnostic Event Contract

**Decision:** Define a canonical set of governance events (`run_start`, `step_start`, `step_end`, `tool_call`, `retry`, `run_end`) that any external runtime can emit to Talon via HTTP. LangGraph is a flagship use case but the contract is not LangGraph-specific.

**Rationale:** Talon's target market uses diverse frameworks. Coupling to one creates adoption friction and maintenance burden.

### 2. HTTP Control Plane Endpoints

**Decision:** Add `/v1/graph/events` endpoint that accepts governance events and returns control decisions (allow, deny, override_model, mutate_args, require_review, abort). Events carry `graph_run_id`, `session_id`, `node_id`, `step_index`, and state metadata.

**Rationale:** HTTP is the universal transport for notebooks, standalone apps, and microservices. Keeps Talon as a Go binary; client-side integration is a thin HTTP wrapper.

### 3. Evidence Lineage Enhancement

**Decision:** Add `PlanID` and `GraphRunID` fields to `GenerateParams` and `StepParams`. Add a `GraphSummary` evidence record type for run-level graph metadata. Link plan review, execution, and steps through these fields.

**Rationale:** Auditors need one lineage from plan approval through graph execution to individual steps. Current split correlation IDs break this chain.

### 4. Graph-Aware Policy Evaluation

**Decision:** Add `EvaluateGraphGovernance` to the policy engine with Rego policy `graph_governance.rego`. Input includes node metadata, step counts, cost accumulation, retry state, and tool history. Output includes allow/deny plus control actions (model override, retry limit, budget abort).

**Rationale:** Existing `EvaluateLoopContainment` only checks iteration/cost/tool counts. Graph governance needs node-level, retry-aware, and branch-aware decisions.

### 5. Python-First Client SDK

**Decision:** Ship a minimal Python package (`talon-sdk`) that wraps HTTP calls to the graph events endpoint. Provide LangGraph callback adapter and LangChain base-URL configuration as first-class examples.

**Rationale:** LangGraph/LangChain users write Python. A 200-line SDK removes friction vs raw HTTP.

---

## Consequences

- External runtimes gain full governance parity with native runner for policy, evidence, and control.
- Evidence store grows by one table (`graph_summaries`) and two columns on existing tables.
- New Rego policy file adds graph-specific deny rules without changing existing policy behavior.
- Python SDK is out-of-tree but documented alongside Go binary releases.
