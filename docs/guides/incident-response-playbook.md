# Incident Response Playbook

This playbook covers common operational scenarios when running AI agents governed by Talon. Each scenario includes immediate actions, investigation steps, and remediation. Work through the steps in order — earlier steps contain or limit blast radius, later steps prevent recurrence.

> **Note on CLI commands:** Some CLI commands referenced below (marked with *planned*) are not yet implemented. Where a CLI command is planned, the equivalent Go API is available. See the code references for programmatic access.

---

## Scenario 1: Runaway Agent

An agent is executing more tool calls than expected, looping, or consuming excessive resources.

**Immediate containment:**

```bash
# Kill a specific run by correlation ID
curl -X POST http://localhost:8080/v1/runs/req_abc123/kill \
  -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY"

# Or kill all runs for a tenant
curl -X POST "http://localhost:8080/v1/runs/kill-all?tenant_id=acme" \
  -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY"

# Or lock down the entire tenant (kills active + blocks new)
curl -X POST http://localhost:8080/v1/overrides/acme/lockdown \
  -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY"
```

**Investigate:**

```bash
# List active runs to see what's still running
curl http://localhost:8080/v1/runs?tenant_id=acme \
  -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY"

# List recent evidence for the agent
talon audit list --agent <agent_name> --limit 20

# Show full detail for a specific evidence record
talon audit show <evidence_id>
```

**Remediate:**

1. Review the agent's `.talon.yaml` policy and tighten constraints:
   - Reduce `allowed_tools` to the minimum required set
   - Add patterns to `forbidden_patterns` that match the runaway behavior
   - Lower `rate_limits.requests_per_minute` and `rate_limits.concurrent_executions`
   - Reduce `timeout.agent_total` if the agent shouldn't run that long
2. Use runtime overrides for immediate policy tightening without redeploying:

```bash
# Disable specific tools at runtime
curl -X POST http://localhost:8080/v1/overrides/acme/tools/disable \
  -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tools": ["dangerous_tool"], "reason": "INC-2026-042"}'

# Set stricter cost/tool limits at runtime
curl -X POST http://localhost:8080/v1/overrides/acme/policy \
  -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"max_cost_per_run": 0.05, "max_tool_calls": 5}'
```

3. If the circuit breaker tripped, reset it after applying the fix:

```go
// Go API: reset the circuit breaker for the agent
circuitBreaker.Reset(tenantID, agentID)
```

4. Lift lockdown once the fix is in place:

```bash
curl -X DELETE http://localhost:8080/v1/overrides/acme/lockdown \
  -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY"
```

---

## Scenario 2: PII Leak Detected

A response or tool call contained PII that should have been caught. This may trigger GDPR notification obligations depending on severity.

**Identify scope:**

```bash
# Find all affected requests for the agent
talon audit list --agent <agent> --limit 50
# Look for evidence records with output_pii_detected in the classification field
```

**Export evidence for the DPO:**

```bash
talon audit export --from <start_time> --to <end_time> --format json
```

**Remediate:**

1. Escalate the `response_pii_action` in the agent's policy:
   - `"warn"` → `"redact"` (strips PII from responses, works for both streaming and non-streaming)
   - `"redact"` → `"block"` (rejects the entire response with HTTP 451)
2. Review `tool_policies` for any tools configured with `pii_action: "audit"` — determine whether they should be upgraded to `"redact"`.

---

## Scenario 3: Cost Overrun

An agent or tenant has exceeded expected spend, or is on track to blow through the monthly budget.

**Assess current spend:**

```bash
talon costs --tenant <tenant_id>
```

**Immediate containment (no restart required):**

```bash
# Set a stricter per-run cost cap at runtime
curl -X POST http://localhost:8080/v1/overrides/<tenant_id>/policy \
  -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"max_cost_per_run": 0.10}'
```

**Remediate:**

1. Lower cost limits in the agent's `.talon.yaml`:

```yaml
policies:
  cost_limits:
    per_request: 0.50
    daily: 25.00
    monthly: 500.00
```

2. Restart Talon to apply the new limits (or use runtime overrides above for immediate effect):

```bash
talon serve --config <path>
```

3. For gradual degradation instead of hard cutoffs, enable cost degradation:

```yaml
policies:
  degradation:
    enabled: true
```

This automatically routes to cheaper models as budget thresholds are approached.

---

## Scenario 4: Redaction Breaking a Business Process

A tool is receiving `[REDACTED:EMAIL]` or similar placeholders instead of real values, causing downstream failures (e.g., a CRM tool can't look up a customer).

**Identify the affected tool:**

```bash
# List recent evidence for the agent and look for [REDACTED:*] in tool arguments
talon audit list --agent <agent> --limit 20
```

**Remediate:**

1. In the agent's `tool_policies`, switch the specific tool from redaction to audit-only:

```yaml
tool_policies:
  - tool: "crm_lookup"
    pii_action: "audit"    # was: "redact"
```

2. Verify that evidence still records the PII finding — `pii_action: "audit"` logs the detection without altering the data, preserving the compliance trail.
3. No restart is needed if config reload is enabled. Otherwise restart Talon.

---

## Scenario 5: Circuit Breaker Tripped (False Positive)

An agent has stopped executing because repeated policy denials tripped the circuit breaker, but the denials were caused by a misconfigured policy rather than actual violations.

**Diagnose:**

```bash
# Check recent evidence for the agent — look for policy denial records
talon audit list --agent <agent> --limit 20
```

**Remediate:**

1. Fix the misconfigured policy in the agent's `.talon.yaml` (common causes: overly restrictive `allowed_tools`, incorrect `forbidden_patterns` regex, wrong time zone in `time_restrictions`).
2. Reset the circuit breaker:

```go
// Go API: reset the circuit breaker for the agent
circuitBreaker.Reset(tenantID, agentID)
```

3. Monitor the agent — it will resume normal execution with the corrected policy. Check new evidence with `talon audit list --agent <agent> --limit 10`.

---

## Quick Reference

| Symptom | Scenario | First Action |
|---|---|---|
| Agent looping or excessive tool calls | [Runaway Agent](#scenario-1-runaway-agent) | `POST /v1/runs/{id}/kill` or `POST /v1/overrides/{tenant}/lockdown` |
| `output_pii_detected` in evidence | [PII Leak Detected](#scenario-2-pii-leak-detected) | `talon audit list --agent <agent> --limit 50` |
| Budget alerts or unexpected spend | [Cost Overrun](#scenario-3-cost-overrun) | `POST /v1/overrides/{tenant}/policy` with `max_cost_per_run` |
| `[REDACTED:*]` in tool arguments | [Redaction Breaking Process](#scenario-4-redaction-breaking-a-business-process) | `talon audit list --agent <agent> --limit 20` |
| Agent stopped, circuit breaker open | [Circuit Breaker (False Positive)](#scenario-5-circuit-breaker-tripped-false-positive) | `talon audit list --agent <agent> --limit 20` |
| Need to pause an agent mid-execution | [Operational Control](#operational-control-plane) | `POST /v1/runs/{id}/pause` |
| Tool causing problems across agents | [Operational Control](#operational-control-plane) | `POST /v1/overrides/{tenant}/tools/disable` |

---

## You're done

You now have a playbook for containing and investigating runaway agents, PII leaks, cost overruns, redaction issues, and circuit breaker trips. Use the quick reference table to jump to the right scenario.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Export evidence after an incident | [How to export evidence for auditors](compliance-export-runbook.md) |
| Tighten policy to prevent recurrence | [Policy cookbook](policy-cookbook.md) |
| Cap cost per team or app | [How to cap daily spend per team or application](cost-governance-by-caller.md) |
| Use runtime overrides and kill switches | [Operational control plane](../reference/operational-control-plane.md) |
| Understand the evidence record | [Evidence store](../explanation/evidence-store.md) |
