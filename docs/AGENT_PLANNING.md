# Agent Planning in Talon

This document describes how Talon runs agents: execution model, multi-step tool use (agentic loop), plan review, step-level audit, and limits. It is written for operators and integrators who configure and run Talon.

## Execution model

Each agent run follows a fixed pipeline:

1. **Load policy** — `.talon.yaml` for the agent
2. **Classify input** — PII detection and data tier
3. **Process attachments** — extract, scan for prompt injection, sandbox
4. **Evaluate policy** — OPA (cost, rate, time, tool access)
5. **Plan Review Gate** — optional human approval before LLM (EU AI Act Art. 14)
6. **Enrich context** — memory and shared mounts (if enabled)
7. **Run LLM** — single call or **agentic loop** (see below)
8. **Classify output** — PII on response
9. **Generate evidence** — HMAC-signed record; optional step-level records

Every run produces at least one signed evidence record, even on denial or failure.

## Agentic loop (multi-step tool use)

When all of the following are true, Talon runs a **bounded agentic loop** (Reason–Act style):

- **OpenAI** is the selected provider (tool-call API is OpenAI-only today)
- **`max_iterations`** in `policies.resource_limits` is at least 2
- **`capabilities.allowed_tools`** lists one or more tools and those tools are registered

In that case:

1. The LLM receives the user prompt and the list of allowed tools.
2. If the model returns **tool calls**, Talon policy-checks each call, executes allowed tools, and appends the results as messages.
3. The LLM is called again with the extended conversation (user message + assistant message with tool calls + tool results).
4. This repeats until the model returns **no tool calls**, or a **loop limit** is reached.

So the model can use tools multiple times in one run, with policy enforced on every tool call.

### When the agentic loop is not used

- **Other providers** (Anthropic, Ollama, Bedrock): one LLM call per run; tools are only run if you pass them explicitly in `ToolInvocations` (legacy path).
- **`max_iterations`** 0 or 1: single LLM call.
- **No allowed tools** or empty registry: no tools are sent to the LLM.

## Loop limits

To avoid runaway cost or infinite loops, configure limits under `policies.resource_limits` in `.talon.yaml`:

| Option | Meaning | Default behavior |
|--------|--------|------------------|
| `max_iterations` | Maximum LLM turns in one run (e.g. 10) | 0 or 1 = single call, no loop |
| `max_tool_calls_per_run` | Maximum number of tool invocations per run | 0 = no limit |
| `max_cost_per_run` | Maximum cost (EUR) for a single run | 0 = no limit |

The **per-request** cost limit in `cost_limits.per_request` also applies: if the running total cost in the loop exceeds it, the loop stops.

Example:

```yaml
policies:
  resource_limits:
    max_iterations: 10
    max_tool_calls_per_run: 20
    max_cost_per_run: 0.50
  cost_limits:
    per_request: 0.20
    daily: 10.0
    monthly: 100.0
```

## Plan Review Gate

Before the first LLM call (and before the agentic loop starts), Talon can **gate** execution on human approval:

- When `compliance.human_oversight` is `always`, or when configured thresholds (cost, tier, tools) are met, an **execution plan** is created and stored.
- The run returns immediately with `PlanPending` set; no LLM is called until the plan is approved (e.g. via dashboard or API).
- The plan stores: selected model, data tier, tools available, cost estimate, policy decision, and optional **proposed steps** for transparency (EU AI Act Art. 11/13).

Plans can be approved, rejected, or modified (with annotations). This satisfies **EU AI Act Art. 14** (human oversight).

## Step-level evidence

When the agentic loop runs, Talon can record **step evidence** in addition to the final request-level evidence:

- One record per **LLM call** in the loop (type `llm_call`): output summary, duration, cost.
- One record per **tool call** (type `tool_call`): tool name, output summary, duration.

Steps are linked to the main evidence by `correlation_id`, stored in the same evidence store, and signed individually. Use the evidence API or `talon audit` to list and verify them.

## Tool access and tool history

- **Allowed tools:** Only tools listed in `capabilities.allowed_tools` may be invoked; the registry must have a matching implementation.
- **Per-call policy:** Each tool call is checked with `EvaluateToolAccess` (OPA); forbidden patterns (e.g. on parameters) can deny a call.
- **Tool history:** During the agentic loop, the sequence of tool calls in that run is passed into policy as `tool_history`. Rego can use this for future **tool-chain** rules (e.g. deny certain sequences); no such rules are shipped by default yet.

## What Talon does not do (current scope)

- **Hierarchical task decomposition** — No task trees or subtask orchestration; each run is one top-level task.
- **DAG workflows** — No graph of steps, no parallel execution of sub-tasks. Use cron and webhooks for multi-run workflows.
- **Reflection / self-correction** — No automatic retry-with-reasoning; only loop containment limits. Errors are recorded in evidence.
- **Tool-chain deny rules** — The **input** for chain-aware policy (`tool_history`) exists; you can add Rego rules. None are included by default.

## Configuration summary

Relevant `.talon.yaml` sections:

```yaml
agent:
  name: my-agent
  version: "1.0.0"

capabilities:
  allowed_tools: ["search", "notify"]   # only these can be used in the loop

policies:
  resource_limits:
    max_iterations: 10
    max_tool_calls_per_run: 20
    max_cost_per_run: 0.5
  cost_limits:
    per_request: 0.2
    daily: 10.0
    monthly: 100.0
  model_routing:
    tier_0:
      primary: gpt-4o    # OpenAI required for agentic loop

compliance:
  human_oversight: on-demand   # or "always" / "none"
```

## See also

- [Memory Governance](MEMORY_GOVERNANCE.md) — how agent memory is governed and audited
- [Architecture (MCP Proxy)](ARCHITECTURE_MCP_PROXY.md) — MCP and vendor integration
- [QUICKSTART](QUICKSTART.md) — run your first agent
