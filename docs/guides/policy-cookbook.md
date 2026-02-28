# Policy cookbook

Copy-paste snippets for common policy needs. Use in `agent.talon.yaml` (agent policy, owned by governance/compliance) or in `talon.config.yaml` gateway block (infrastructure config, owned by DevOps). Each entry states the goal, the snippet, and where it goes.

---

## Enable governed memory

**Goal:** Let the agent persist learnings with governance (categories, PII scan, conflict detection). Memory is injected into later runs so the model can use stored context.

**Where:** `agent.talon.yaml` under `memory`.

```yaml
memory:
  enabled: true
  mode: active
  max_entries: 100
  max_prompt_tokens: 500
  allowed_categories:
    - domain_knowledge
    - factual_corrections
    - user_preferences
    - procedure_improvements
  governance:
    conflict_resolution: auto
```

Use `mode: shadow` to log what would be written without persisting. See [Memory governance](../MEMORY_GOVERNANCE.md) and [How to verify memory is used](memory-verification.md).

---

## Only allow specific models for tier_2

**Goal:** Restrict tier_2 (e.g. PII-bearing) requests to one or more models.

**Where:** `agent.talon.yaml` under `policies.model_routing`.

```yaml
policies:
  model_routing:
    tier_2:
      primary: "gpt-4o"
      bedrock_only: false
    # Or use allowed_models in agent/policy if your schema supports it
```

For **gateway** callers, set per-caller allowed models in the gateway config:

```yaml
gateway:
  callers:
    - name: "my-app"
      api_key: "..."
      tenant_id: "default"
      policy_overrides:
        allowed_models: ["gpt-4o", "gpt-4o-mini"]
```

---

## Block LLM use on weekends

**Goal:** Deny requests on weekends (e.g. reduce cost or enforce working hours).

**Where:** `agent.talon.yaml` under `policies.time_restrictions`.

```yaml
policies:
  time_restrictions:
    enabled: true
    timezone: "Europe/Berlin"
    weekends: false
    allowed_hours: "09:00-17:00"   # optional: only 9–17 on weekdays
```

---

## Cap daily spend at €10

**Goal:** Hard cap on daily spend.

**Where (native agent):** `agent.talon.yaml`

```yaml
policies:
  cost_limits:
    daily: 10.00
    monthly: 200.00
```

**Where (gateway caller):** Gateway config `callers[].policy_overrides`

```yaml
policy_overrides:
  max_daily_cost: 10.00
  max_monthly_cost: 200.00
```

---

## Redact PII in requests

**Goal:** Redact or block PII before it reaches the LLM.

**Where (native):** `agent.talon.yaml` — use classifier and policy PII action (e.g. in data_classification or capabilities).  
**Where (gateway):** Gateway `default_policy.default_pii_action` or per-caller `policy_overrides.pii_action`.

```yaml
# Gateway
gateway:
  default_policy:
    default_pii_action: "redact"   # warn | redact | block | allow
  callers:
    - name: "support"
      policy_overrides:
        pii_action: "block"
```

---

## Block runs when input contains PII

**Goal:** Deny the run (no LLM call) when the user prompt or any attachment content contains PII (e.g. email, IBAN). Both prompt and attachment text are scanned; if either has PII and `block_on_pii` is true, the run is denied and evidence is recorded.

**Where:** `agent.talon.yaml` under `policies.data_classification`.

```yaml
policies:
  data_classification:
    input_scan: true
    block_on_pii: true
  # ... cost_limits, model_routing, etc.
```

With `block_on_pii: true`, requests whose prompt or attachments contain detected PII (email, phone, IBAN, national IDs, etc.) are rejected before the LLM is called. Use `block_on_pii: false` or omit it to allow runs with PII (tier-based routing and evidence still apply).

---

## Require human approval for high-risk or tool use

**Goal:** Pause execution until a human approves (EU AI Act Art. 14 style).

**Where:** `agent.talon.yaml` under `compliance.human_oversight` and/or plan review configuration. When enabled, the runner generates an execution plan and waits for approval via dashboard or API (`POST /v1/plans/{id}/approve`).

```yaml
compliance:
  human_oversight: "on_demand"   # none | on_demand | always
```

See [Agent planning](../AGENT_PLANNING.md) for plan review details.

---

## Limit attachment handling (injection prevention)

**Goal:** Block or warn when attachments contain prompt-injection patterns.

**Where:** `agent.talon.yaml` under `attachment_handling`.

```yaml
attachment_handling:
  mode: "strict"
  scanning:
    detect_instructions: true
    action_on_detection: "block_and_flag"   # block_and_flag | warn | log
```

---

## Where to put snippets

| Snippet type | `agent.talon.yaml` (governance team) | `talon.config.yaml` gateway block (DevOps team) |
|--------------|--------------------------------------|--------------------------------------------------|
| Cost limits | `policies.cost_limits` | `gateway.callers[].policy_overrides.max_daily_cost` etc. |
| Model allow/block | `policies.model_routing` | `gateway.callers[].policy_overrides.allowed_models` / `blocked_models` |
| Time restrictions | `policies.time_restrictions` | -- |
| PII action | `policies.data_classification` | `gateway.default_policy.default_pii_action` or `gateway.callers[].policy_overrides.pii_action` |
| Block on PII | `policies.data_classification.block_on_pii` | -- |
| Human oversight | `compliance.human_oversight` | -- |
