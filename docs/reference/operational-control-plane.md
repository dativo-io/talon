# Operational control plane

Talon's operational control plane provides real-time visibility and intervention capabilities for running AI agents. All endpoints are **admin-only** (require `X-Talon-Admin-Key` or bearer fallback).

---

## Concepts

### Run lifecycle

Every agent execution follows a state machine:

```
QUEUED → RUNNING → COMPLETED
                 → FAILED (with failure_reason)
                 → TERMINATED (operator kill)
                 → BLOCKED (policy deny at runtime)
                 → DENIED (tenant lockdown)

RUNNING → PAUSED → RUNNING (resume)
                  → TERMINATED (kill while paused)
```

Terminal states: `completed`, `failed`, `terminated`, `blocked`, `denied`.

### Failure taxonomy

When a run ends in a non-success state, the evidence record includes a structured `failure_reason`:

| Reason | Meaning |
|--------|---------|
| `cost_exceeded` | Per-request or accumulated cost exceeded budget |
| `tool_timeout` | A tool execution timed out |
| `tool_failure` | A tool returned an error |
| `tool_escalation` | A tool was auto-disabled after 3 consecutive failures |
| `llm_error` | LLM provider returned an error |
| `llm_timeout` | LLM call timed out |
| `containment_deny` | Containment policy blocked execution |
| `circuit_breaker` | Circuit breaker tripped for this agent |
| `operator_kill` | Admin terminated the run via API |
| `context_timeout` | Overall agent timeout exceeded |
| `policy_deny` | OPA policy denied the request |
| `pii_block` | PII detected and policy is set to block |
| `hook_deny` | A lifecycle hook rejected execution |
| `internal_error` | Unexpected internal error |
| `max_steps_exceeded` | Agent exceeded max iteration count |

### Operator overrides

Runtime overrides take precedence over `.talon.yaml` policy. They are in-memory and reset on server restart. Use them for incident response — not permanent policy changes.

### Tool approval gates

Tools listed in `resource_limits.require_approval` pause execution and wait for human approval before proceeding. If no decision arrives within 5 minutes (default), the tool call is denied.

---

## Run management API

### List runs

```
GET /v1/runs[?tenant_id=X]
```

Returns all active (non-terminal) runs. Optional `tenant_id` query parameter filters by tenant.

**Response:**

```json
{
  "runs": [
    {
      "correlation_id": "req_abc123",
      "tenant_id": "acme",
      "agent_id": "support-bot",
      "status": "running",
      "started_at": "2026-03-28T10:00:00Z",
      "updated_at": "2026-03-28T10:00:05Z",
      "step_count": 3,
      "cost_accrued": 0.0042,
      "tool_calls": 2,
      "duration_ms": 5000
    }
  ],
  "count": 1
}
```

### Get run

```
GET /v1/runs/{id}
```

Returns the full state of a single run by correlation ID. Returns 404 if the run is not found.

### Kill run

```
POST /v1/runs/{id}/kill
```

Cancels the context of a running or paused run. The run transitions to `terminated` with `failure_reason: operator_kill`. Evidence is recorded.

**Response:**

```json
{"status": "terminated", "correlation_id": "req_abc123"}
```

### Kill all runs for tenant

```
POST /v1/runs/kill-all?tenant_id=X
```

Terminates all active runs for the specified tenant. The `tenant_id` query parameter is required.

**Response:**

```json
{"status": "terminated", "tenant_id": "acme", "killed": 3}
```

### Pause run

```
POST /v1/runs/{id}/pause
```

Pauses a running agent at the next loop iteration boundary. The run status transitions to `paused`. The agent will not make further LLM calls or tool executions until resumed or killed.

**Response:**

```json
{"status": "paused", "correlation_id": "req_abc123"}
```

### Resume run

```
POST /v1/runs/{id}/resume
```

Resumes a paused run. The run status transitions back to `running`.

**Response:**

```json
{"status": "running", "correlation_id": "req_abc123"}
```

---

## Override API

Overrides are in-memory and per-tenant. They take precedence over `.talon.yaml` policy for the duration of the server process.

### List overrides

```
GET /v1/overrides
```

Returns all active overrides, keyed by tenant ID.

### Get overrides for tenant

```
GET /v1/overrides/{tenant_id}
```

Returns the current override state for a specific tenant, or `{"status": "no overrides"}` if none are set.

### Tenant lockdown

```
POST /v1/overrides/{tenant_id}/lockdown
```

Activates lockdown mode: all new runs for this tenant are immediately denied (`status: denied`), and all currently active runs are killed.

**Response:**

```json
{"tenant_id": "acme", "lockdown": true, "runs_killed": 3}
```

### Lift lockdown

```
DELETE /v1/overrides/{tenant_id}/lockdown
```

Removes lockdown. New runs are allowed again.

**Response:**

```json
{"tenant_id": "acme", "lockdown": false}
```

### Disable tools

```
POST /v1/overrides/{tenant_id}/tools/disable
```

**Request body:**

```json
{"tools": ["bulk_delete_users", "send_email"], "reason": "INC-2026-042"}
```

Disabled tools are removed from the agent's available tool set at runtime. Any call to a disabled tool is rejected with a synthetic error.

**Response:**

```json
{"tenant_id": "acme", "disabled_tools": ["bulk_delete_users", "send_email"], "reason": "INC-2026-042"}
```

### Enable tools

```
POST /v1/overrides/{tenant_id}/tools/enable
```

**Request body:**

```json
{"tools": ["send_email"]}
```

Re-enables previously disabled tools.

### Policy override

```
POST /v1/overrides/{tenant_id}/policy
```

**Request body:**

```json
{"max_cost_per_run": 0.10, "max_tool_calls": 5}
```

Sets stricter runtime caps that override `.talon.yaml` values. Both fields are optional; omit a field to leave it unchanged.

### Clear all overrides

```
DELETE /v1/overrides/{tenant_id}
```

Removes all overrides (lockdown, disabled tools, policy caps) for the tenant.

---

## Tool approval API

### List pending approvals

```
GET /v1/tool-approvals
```

Returns all pending tool approval requests.

**Response:**

```json
{
  "pending": [
    {
      "id": "apr_xyz789",
      "correlation_id": "req_abc123",
      "tenant_id": "acme",
      "agent_id": "support-bot",
      "tool_name": "send_email",
      "tool_call_id": "call_001",
      "arguments": {"to": "customer@example.com", "subject": "..."},
      "status": "pending",
      "created_at": "2026-03-28T10:00:05Z"
    }
  ],
  "count": 1
}
```

### Get approval request

```
GET /v1/tool-approvals/{id}
```

Returns a specific approval request by ID. Returns 404 if not found.

### Decide on approval

```
POST /v1/tool-approvals/{id}/decide
```

**Request body:**

```json
{"decision": "approve", "reason": "Verified recipient"}
```

The `decision` field must be `"approve"` or `"deny"`. On approval, the paused agent resumes and executes the tool. On denial, the tool call is skipped with an error.

If no decision is made within the timeout (default 5 minutes), the request is automatically denied.

---

## Configuration

### require_approval (agent.talon.yaml)

To enable pre-tool approval gates, add `require_approval` to the `resource_limits` section of the agent policy:

```yaml
policies:
  resource_limits:
    require_approval:
      - send_email
      - bulk_delete_users
      - execute_sql
```

When the agent attempts to call a listed tool, execution pauses and a pending approval request appears in `GET /v1/tool-approvals`. The run's status becomes `paused` until an operator decides.

### Automatic tool failure escalation

No configuration is needed. When a tool fails 3 consecutive times within a single run, it is automatically removed from the agent's available tools for the remainder of that run. This prevents infinite retry loops. The failure count resets between runs.

### Single-shot cost check

For non-agentic (single-shot) LLM calls, Talon checks the estimated cost against `policies.cost_limits.per_request` after the LLM response and before returning it. If the cost exceeds the limit, the run is terminated with `failure_reason: cost_exceeded` and the response is not returned.

---

## Compliance alignment

| Regulation | Control plane feature | Article/Control |
|------------|----------------------|-----------------|
| EU AI Act Art. 14 | Pause/resume, kill, tool approval gates | Human oversight |
| EU AI Act Art. 9 | Override store, runtime policy tightening | Risk management |
| NIS2 Art. 21 | Tenant lockdown, kill-all | Incident response |
| DORA Art. 11 | Run lifecycle tracking, failure taxonomy in evidence | ICT incident evidence |
| ISO 27001 A.5.24 | Lockdown, tool disable, kill | Incident management |

---

## Related docs

- [Authentication and key scopes](authentication-and-key-scopes.md) — endpoint auth requirements
- [Configuration reference](configuration.md) — `agent.talon.yaml` and `talon.config.yaml`
- [Incident response playbook](../guides/incident-response-playbook.md) — operational runbooks
- [Gateway dashboard](gateway-dashboard.md) — real-time metrics
