# Policy cookbook

Copy-paste snippets for common policy needs. Use in `.talon.yaml` (native agents) or in gateway config (gateway callers). Each entry states the goal, the snippet, and where it goes.

---

## Only allow specific models for tier_2

**Goal:** Restrict tier_2 (e.g. PII-bearing) requests to one or more models.

**Where:** `.talon.yaml` under `policies.model_routing`.

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

**Where:** `.talon.yaml` under `policies.time_restrictions`.

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

**Where (native agent):** `.talon.yaml`

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

**Where (native):** `.talon.yaml` — use classifier and policy PII action (e.g. in default_policy or capabilities).  
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

## Require human approval for high-risk or tool use

**Goal:** Pause execution until a human approves (EU AI Act Art. 14 style).

**Where:** `.talon.yaml` under `compliance.human_oversight` and/or plan review configuration. When enabled, the runner generates an execution plan and waits for approval via dashboard or API (`POST /v1/plans/{id}/approve`).

```yaml
compliance:
  human_oversight: "on_demand"   # none | on_demand | always
```

See [Agent planning](../AGENT_PLANNING.md) for plan review details.

---

## Limit attachment handling (injection prevention)

**Goal:** Block or warn when attachments contain prompt-injection patterns.

**Where:** `.talon.yaml` under `attachment_handling`.

```yaml
attachment_handling:
  mode: "strict"
  scanning:
    detect_instructions: true
    action_on_detection: "block_and_flag"   # block_and_flag | warn | log
```

---

## Where to put snippets

| Snippet type | Native agents | Gateway |
|--------------|---------------|---------|
| Cost limits | `.talon.yaml` → `policies.cost_limits` | Gateway config → `callers[].policy_overrides.max_daily_cost` etc. |
| Model allow/block | `.talon.yaml` → `policies.model_routing` | Gateway → `callers[].policy_overrides.allowed_models` / `blocked_models` |
| Time restrictions | `.talon.yaml` → `policies.time_restrictions` | — |
| PII action | `.talon.yaml` (policy/default) | Gateway → `default_policy.default_pii_action` or `callers[].policy_overrides.pii_action` |
| Human oversight | `.talon.yaml` → `compliance.human_oversight` | — |
