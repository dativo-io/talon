# Agent Planning in Talon

This document describes how Talon runs native `talon run` agents: execution model, plan review, step-level audit, and limits. Plan review is an **optional human-oversight gate** for native `talon run` agents — most Talon deployments (gateway proxying, coding agents) never enable it, and none of the four operating pillars depend on it. Where enabled, it provides supporting controls for EU AI Act Art. 14-style human oversight — not a compliance claim. This document is written for operators and integrators who configure and run Talon.

## Execution model

Each agent run follows a fixed pipeline:

1. **Load policy** — `.talon.yaml` for the agent
2. **Classify input** — PII detection and data tier
3. **Process attachments** — extract, scan for prompt injection, sandbox
4. **Evaluate policy** — OPA (cost, rate, time, tool access)
5. **Plan Review Gate** — optional human approval before LLM (EU AI Act Art. 14)
6. **Enrich context** — memory and shared mounts (if enabled)
7. **Run LLM** — one LLM call (no in-process tools; see below)
8. **Classify output** — PII on response
9. **Generate evidence** — HMAC-signed record; optional step-level records

Every run produces at least one signed evidence record, even on denial or failure.

## No in-process tools

A native run makes one LLM call. The in-process tool registry, the runner's agentic tool loop and pre-specified tool invocations were removed (#431); production never registered a tool. `policies.resource_limits` (`max_iterations`, `max_tool_calls_per_run`, `max_cost_per_run`) therefore no longer has an effect on native runs; graph-adapter events still evaluate it. `cost_limits` still apply.

A consequential tool of an MCP server is governed through Talon's one governed MCP endpoint, `POST /mcp`, as an Action Gateway operation: see [Governed MCP tools](guides/mcp-governed-tools.md). Native runner actions through the Action Gateway are a target ([#430](https://github.com/dativo-io/talon/issues/430)).

## Plan Review Gate

Before the LLM call, Talon can **gate** execution on human approval:

- When `compliance.human_oversight` is `always`, or when configured thresholds (cost, tier, tools) are met, an **execution plan** is created and stored.
- The run returns immediately with `PlanPending` set; no LLM is called until the plan is approved (via `talon plan approve` or `POST /v1/plans/{id}/approve`).
- The plan stores: selected model, data tier, tools available, cost estimate, policy decision, **session_id** (so dispatch reuses the same lifecycle session), and optional **proposed steps** for transparency (EU AI Act Art. 11/13).
- In `talon serve`, an internal dispatcher watches for newly approved plans and executes them once with the plan’s session_id (bypassing the review gate for that replay only). This approve-then-auto-dispatch behavior is the current legacy Plan Review path; the target ([#430](https://github.com/dativo-io/talon/issues/430)) makes Plan Review a typed subject of the shared approval kernel where the decision never starts execution and the run controller resumes from its checkpoint — see [Control-plane boundaries](reference/control-plane-boundaries.md).
- Outside `talon serve`, execute approved plans manually with `talon plan execute <plan-id> --tenant <id>`.

Step-by-step operator E2E (CLI, API, serve auto-dispatch, test matrix): [How to test and operate Plan Review](guides/plan-review-operators.md).

Plans can be approved, rejected, or modified (with annotations). This provides supporting controls for **EU AI Act Art. 14** (human oversight).

## Step-level evidence

Talon records **step evidence** in addition to the final request-level evidence: one record for the run's **LLM call** (type `llm_call`): output summary, duration, cost. (Earlier releases also wrote `tool_call` step records from the removed agentic loop.)

Steps are linked to the main evidence by `correlation_id`, stored in the same evidence store, and signed individually. Use the evidence API or `talon audit` to list and verify them.

## What Talon does not do (current scope)

- **Hierarchical task decomposition** — No task trees or subtask orchestration; each run is one top-level task.
- **DAG workflows** — No graph of steps, no parallel execution of sub-tasks. Use cron and webhooks for multi-run workflows.
- **Reflection / self-correction** — No automatic retry-with-reasoning. Errors are recorded in evidence.
- **In-process tool execution** — Removed (#431); see [No in-process tools](#no-in-process-tools).

## Configuration summary

Relevant `.talon.yaml` sections:

```yaml
agent:
  name: my-agent
  version: "1.0.0"

policies:
  cost_limits:
    per_request: 0.2
    daily: 10.0
    monthly: 100.0
  model_routing:
    tier_0:
      primary: gpt-4o

compliance:
  human_oversight: on-demand   # or "always" / "none"
```

## See also

- [Memory Governance](MEMORY_GOVERNANCE.md) — how agent memory is governed and audited
- [Governed MCP tools](guides/mcp-governed-tools.md) — tools of an MCP server governed through `POST /mcp`
- [QUICKSTART](QUICKSTART.md) — run your first agent
