# Policy Cookbook

Practical examples for hardening tool policies in `.talon.yaml`.

## Hardening `update_records`-Style Tools

Database mutation tools are high-risk: a runaway agent can corrupt or delete
production data. Use the three tool-safety controls together:

```yaml
tool_policies:
  update_records:
    # Gap T7: Row count guard — hard cap on bulk operations
    max_row_count: 1000
    dry_run_threshold: 100
    require_dry_run: true

    # Gap T9: Forbidden argument values — block destructive modes
    forbidden_argument_values:
      mode: ["overwrite", "truncate", "replace_all"]

    # PII scanning: redact PII in query arguments, audit results
    arguments:
      query: redact
    result: audit
    timeout: "30s"
```

### What This Enforces

| Control | Rule | Effect |
|---------|------|--------|
| Row count guard | `max_row_count: 1000` | Blocks tool calls where `estimated_row_count > 1000` |
| Dry-run gate | `require_dry_run: true`, `dry_run_threshold: 100` | Requires `dry_run=true` param when `estimated_row_count > 100` |
| Forbidden values | `mode: [overwrite, truncate, replace_all]` | Blocks calls with these destructive mode values |
| PII redaction | `arguments.query: redact` | Strips PII from the `query` argument before execution |
| Result audit | `result: audit` | Logs PII found in the tool result without blocking |
| Timeout | `timeout: 30s` | Cancels execution if tool takes longer than 30 seconds |

### How It Works

1. **OPA policy evaluation** (Rego) checks `estimated_row_count`, `dry_run`,
   and argument values at the policy layer — before any tool code runs.
2. **Go-level guard** in the runner also enforces `max_row_count` and
   `require_dry_run` as a defense-in-depth check, covering tools that bypass
   OPA (e.g., legacy `executeToolInvocations` path).
3. **Idempotency key** (Gap T8) prevents duplicate tool execution on retry:
   the key is derived from `(agent_id, correlation_id, tool_name, sha256(args))`.
   If the same call already completed, the cached result is returned.

### Tool Implementation Contract

For these policies to be effective, tools that modify data should accept:

- `estimated_row_count` (int) — the agent's estimate of affected rows
- `dry_run` (bool) — when true, return what would happen without executing
- `mode` (string) — operation mode (`upsert`, `insert`, `overwrite`, etc.)

### Example: Agent Prompt That Triggers the Guard

```
Update all inactive customer records from Q3 2024 to status=archived.
Estimated: 4,200 records.
```

The LLM calls `update_records` with `estimated_row_count: 4200`. Because
`4200 > 1000`, the policy denies the call:

```
estimated_row_count 4200 exceeds policy limit 1000 for tool update_records
```

The agent must either split the batch or escalate to a human reviewer.

## Combining with Plan Review

For high-risk tools, combine tool policies with plan review:

```yaml
compliance:
  human_oversight: on-demand
  plan_review:
    require_for_tools: true
    cost_threshold: 0.50
    volume_threshold: 500
    timeout_minutes: 60
```

This forces human approval when the execution plan contains destructive
verbs near numbers exceeding `volume_threshold`.
