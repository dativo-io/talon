# ADR-001: Agent Planning Paradigm Decisions

**Status:** Accepted  
**Date:** 2026-02  
**Context:** European SMB compliance-first AI agent orchestration (Dativo Talon).

> **Note:** For a user-facing description of how agent planning works in Talon, see [Agent Planning](../../AGENT_PLANNING.md).

---

## Context

Talon is a single Go binary with embedded OPA, MCP-native tools, Plan Review Gate, governed memory, and evidence-by-default. We needed to align with state-of-the-art AI agent planning paradigms while staying within SMB constraints: limited DevOps maturity, cost sensitivity, compliance burden, and preference for simplicity over flexibility.

**Initial state:** Execution was single-pass (one LLM call per run; tools only from pre-specified `ToolInvocations`). No agentic loop, no step-level evidence, no loop containment policy, no tool-chain visibility for policy.

---

## Decisions

### 1. ReAct (Reason + Act) — **BUILD (scoped)**

- **Decision:** Implement a bounded agentic loop: read `llmResp.ToolCalls`, policy-check each tool, execute, append results to messages, re-invoke LLM until no tool calls or limits reached.
- **Rationale:** Multi-step tool use is the core agent value; hooks and per-tool policy already existed. Loop is restricted to OpenAI (only provider with tool-call API support) and capped by `max_iterations`.
- **Implemented:** `internal/agent/runner.go` agentic loop; `max_iterations` in `policies.resource_limits`; step-level evidence for each LLM call and tool call in the loop.

### 2. Plan-and-Execute (Two-Phase) — **EXTEND MINIMALLY**

- **Decision:** Keep existing Plan Review Gate (pre-execution human approval). Add optional `ProposedSteps []string` on `ExecutionPlan` for future capture of LLM-proposed task steps (Art. 11/13).
- **Rationale:** Plan Review Gate already satisfies EU AI Act Art. 14. Storing proposed steps is a small extension for transparency; we do not add a separate "planning LLM" call.
- **Implemented:** `ExecutionPlan.ProposedSteps` in `internal/agent/plan.go`.

### 3. Hierarchical Task Decomposition — **SKIP**

- **Decision:** Do not implement task trees, subtask-level governance, or partial-completion tracking.
- **Rationale:** SMB use cases are single-level tasks; hierarchical decomposition adds complexity and conflicts with single-binary simplicity. Defer to Phase 3+.

### 4. Tool-Use Planning (Toolformer-style) — **DESIGN INTERFACE ONLY**

- **Decision:** Add `tool_history` to OPA policy input for tool access evaluation. No Rego rules for tool-chain risk yet.
- **Rationale:** Enables future policies (e.g. deny "read_db" then "send_email"). Interface-only keeps complexity low for MVP.
- **Implemented:** `EvaluateToolAccess(ctx, toolName, params, toolHistory)`; runner passes accumulated tool history in the agentic loop.

### 5. Reflection / Self-Correction — **BUILD CONTAINMENT ONLY**

- **Decision:** Add loop containment limits (`max_iterations`, `max_tool_calls_per_run`, `max_cost_per_run`) and enforce in runner + OPA. Do not build a reflection/reasoning engine.
- **Rationale:** Prevents runaway cost and infinite loops; no generic "retry with correction" logic.
- **Implemented:** `policies.resource_limits` schema and `rego/resource_limits.rego`; runner enforces limits and calls `EvaluateLoopContainment` in the loop.

### 6. Graph-Based Planning (DAG Workflows) — **SKIP**

- **Decision:** No DAG model, node/edge metadata, or workflow orchestration.
- **Rationale:** High complexity and operational load; cron + webhooks cover SMB sequencing needs. Defer to Phase 3+.

---

## Identified Gaps (with phase assignments)

| Gap | Phase | Description |
|-----|--------|-------------|
| Agentic loop | **Done** | Bounded loop with `max_iterations`, OpenAI-only, per-step policy and hooks. |
| Step-level evidence | **Done** | `StepEvidence` and `GenerateStep`; stored and signed per step, linked by `correlation_id`. |
| Loop containment policy | **Done** | `max_iterations`, `max_tool_calls_per_run`, `max_cost_per_run` in schema and Rego. |
| Plan proposed steps | **Done** | `ExecutionPlan.ProposedSteps` field; population from LLM left to integration. |
| Tool-chain risk scoring | **Phase 2** | `tool_history` in OPA input; add Rego rules for dangerous sequences when needed. |
| Reflection containment | **Phase 2** | Optional: reflection detector, `max_retries`, cost-per-retry tracking. |
| Hierarchical decomposition | **Phase 3+** | Task trees, parent-child runs, partial completion. |
| DAG workflows | **Phase 3+** | Workflow engine, parallel execution, partial failure handling. |

---

## Roadmap summary

- **Phase 1 (MVP):** Bounded agentic loop, step evidence, loop containment, ProposedSteps field, tool_history input. **Implemented.**
- **Phase 2:** Tool-chain Rego rules, optional reflection containment (max_retries, cost limits).
- **Phase 3+:** Hierarchical tasks, DAG workflows; only if SMB demand and capacity justify the complexity.

---

## Constraints that shaped decisions

- **Cost sensitivity:** Per-request and per-run cost caps; no unbounded reflection.
- **Compliance:** EU AI Act Art. 11/13/14; evidence and plan review first, advanced planning second.
- **Simplicity:** Single binary, no workflow DSL or DAG scheduler in scope for MVP.
- **DevOps maturity:** Cron and webhooks over complex orchestration.

---

## Consequences

- **Users can:** Run policy-gated multi-step tool use (OpenAI), with step-level audit and loop limits.
- **Users cannot yet:** Rely on tool-chain deny rules (input is there; no default Rego), hierarchical or DAG workflows, or built-in reflection/retry.
- **Extension:** To add tool-chain policies, write Rego in `tool_access.rego` using `input.tool_history`. To add proposed steps to plans, set `ExecutionPlan.ProposedSteps` when creating the plan (e.g. from a planning LLM or template).

---

## References

- User doc: [Agent Planning](../../AGENT_PLANNING.md).
- Code: `internal/agent/runner.go`, `internal/evidence/store.go`, `internal/policy/engine.go`, `internal/policy/rego/resource_limits.rego`, `internal/agent/plan.go`.
