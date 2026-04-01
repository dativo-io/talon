# Graph Runtime Governance — Implementation Roadmap

**Status:** Active  
**ADR:** [ADR-003](adr/ADR-003-graph-runtime-governance.md)  
**Target:** Level 4 (Plan-aware) with partial Level 5 (Control plane) capabilities

---

## Week 1 — Runtime Contract + Evidence Lineage

### Deliverables

1. **Graph adapter package** (`internal/agent/graphadapter/`)
   - Event types: `run_start`, `step_start`, `step_end`, `tool_call`, `retry`, `run_end`
   - Decision types: `allow`, `deny`, `abort`, `override_model`, `mutate_args`, `require_review`
   - Adapter bridges events to policy engine and evidence store
   - HTTP handler for `/v1/graph/events` endpoint

2. **Evidence lineage fields**
   - `plan_id` and `graph_run_id` on `Evidence`, `StepEvidence`, `GenerateParams`, `StepParams`
   - `graph_summaries` table with HMAC-signed summary records
   - Indexes for graph_run_id lookups

3. **Transport contract**
   - Same JSON payload schema for notebook and standalone usage
   - Tenant authentication via existing `TenantKeyMiddleware`
   - Timeout/fail-closed behavior inherited from server config

### Test Strategy

- Unit tests for adapter (all event types, nil policy engine, nil evidence)
- Unit tests for HTTP handler (validation, error cases)
- Evidence package build verification (schema migration, new columns)

### Checkpoint

- `go build ./...` succeeds
- `go test ./internal/agent/graphadapter/... ./internal/policy/... ./internal/evidence/...` passes
- `/v1/graph/events` endpoint accepts POST, returns decisions

---

## Week 2 — Policy Control Surface + Reference Wrappers

### Deliverables

1. **Graph governance Rego policy** (`rego/graph_governance.rego`)
   - Step count limits (reuses `max_iterations`)
   - Cost accumulation limits (reuses `max_cost_per_run`)
   - Retry governance (`max_retries_per_node`, default 3)

2. **`EvaluateGraphGovernance`** method on policy engine
   - Input: event_type, step_index, retry_count, cost_so_far, node_id
   - Output: allow/deny with reasons

3. **Python reference wrappers** (`examples/`)
   - LangGraph callback adapter
   - LangChain stateless base-URL example
   - Notebook-ready snippets

4. **Draft integration docs**

### Test Strategy

- Policy engine tests with graph governance scenarios
- Integration test: full event sequence through HTTP handler
- Python examples verified manually (documented expected output)

### Checkpoint

- Graph governance policy fires correctly for over-limit scenarios
- Reference wrappers demonstrate both LangGraph and LangChain paths
- Docs draft reviewed

---

## Week 3 — Plan-Aware Governance + Hardening

### Deliverables

1. **Plan review integration with graph runs**
   - `ProposedSteps` populated from `run_start` event's `planned_steps`
   - Plan gate can hold graph execution pending approval
   - Evidence links plan approval -> graph execution -> steps

2. **Step/node-level approval triggers**
   - High-risk nodes (by policy config) trigger `require_review` decision
   - Tool approval store integration for graph tool calls

3. **End-to-end tests**
   - Retry runaway scenario (node retries past limit -> abort)
   - Budget runaway scenario (cost accumulates past limit -> abort)
   - Multi-step graph with plan review gate
   - Notebook session with restart/reconnect
   - Standalone worker with process restart

4. **Final documentation**
   - Tested, copy-paste-ready code snippets
   - "Other supported patterns" section (OpenAI SDK, MCP)
   - When-to-use guidance

### Test Strategy

- E2E tests in `tests/integration/`
- Smoke test sections for graph governance
- Manual verification of Python examples against running `talon serve`

### Checkpoint

- Full event lifecycle: plan -> approve -> run_start -> steps -> run_end with linked evidence
- Budget/retry abort decisions enforced
- Docs finalized with no pseudocode

---

## Success Criteria

- [ ] External runtimes emit events to `/v1/graph/events` and receive control decisions
- [ ] Evidence audit trail links plan_id -> graph_run_id -> correlation_id -> steps
- [ ] Policy can deny based on step count, cost, and retry limits
- [ ] Tool access control applies to graph tool_call events
- [ ] Documentation covers LangGraph, LangChain stateless, OpenAI SDK, and MCP patterns
- [ ] Both notebook and standalone app modes demonstrated with working code
