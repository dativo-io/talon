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

**Cache vs memory:** Memory is agent-level learning (what the agent may remember). The semantic cache is infrastructure-level: it reuses LLM responses for similar prompts to save cost; it is configured in `talon.config.yaml` under `cache`, not in agent policy. See [Memory governance — Cache vs memory](../MEMORY_GOVERNANCE.md#cache-vs-memory).

---

## Enable governed semantic cache (infrastructure)

**Goal:** Reduce LLM cost and latency by serving similar queries from a GDPR-safe, PII-scrubbed cache. Cache is checked before each LLM call; hits return a cached response and skip the provider.

**Where:** `talon.config.yaml` (infrastructure — owned by DevOps), not in `agent.talon.yaml`.

```yaml
cache:
  enabled: true
  default_ttl: 3600              # 1 hour for public tier
  ttl_by_tier:
    public: 3600
    internal: 900                # 15 minutes
  similarity_threshold: 0.92      # 0–1; higher = stricter match
  max_entries_per_tenant: 10000
```

- Cache stores **embeddings/hashes** of prompts (not raw text) and **PII-scrubbed** responses only.
- Confidential/restricted data tier and high-severity PII requests are not cached (OPA policy).
- Tool calls and MCP messages are never cached.
- Use `talon cache erase --tenant <id>` for GDPR Article 17 erasure. See [Configuration reference](../reference/configuration.md) when the cache feature is available.

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

**Goal:** Redact or block PII before it reaches the LLM (input) and/or in the LLM response (output).

**Where (native):** `agent.talon.yaml` — use `data_classification` with granular `redact_input` / `redact_output` fields. The legacy `redact_pii` still works as a shorthand for both.  
**Where (gateway):** Gateway `default_policy.default_pii_action` or per-caller `policy_overrides.pii_action`.

```yaml
# Native agent — granular input/output control
policies:
  data_classification:
    input_scan: true
    output_scan: true
    redact_input: true          # redact PII from prompt before LLM sees it
    redact_output: true         # redact PII from LLM response before returning
    # redact_pii: true          # shorthand: sets both redact_input and redact_output

# Gateway
gateway:
  default_policy:
    default_pii_action: "redact"   # warn | redact | block | allow
  callers:
    - name: "support"
      policy_overrides:
        pii_action: "block"
```

`redact_input` / `redact_output` default to the value of `redact_pii` when not explicitly set. Explicit values override `redact_pii` (e.g. `redact_pii: true` + `redact_input: false` → only output is redacted).

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

## Enable PII semantic enrichment (gender, scope)

**Goal:** Redact PII with structured placeholders so downstream can use attributes (e.g. person gender, location scope) without seeing raw data. Requires `data_classification.redact_input: true` (or `redact_pii: true`) and `input_scan: true`.

**Where:** `agent.talon.yaml` under `policies.semantic_enrichment`.

```yaml
policies:
  data_classification:
    input_scan: true
    output_scan: true
    redact_input: true
    redact_output: true

  semantic_enrichment:
    enabled: true
    mode: enforce          # off | shadow | enforce
    allowed_attributes: ["gender", "scope"]
    confidence_threshold: 0.80
```

- **off:** No enrichment; placeholders stay `[PERSON]`, `[LOCATION]` (legacy).
- **shadow:** Enricher runs and attributes are logged only; placeholders stay legacy. Use to validate before enabling in output.
- **enforce:** Placeholders become XML-style, e.g. `<PII type="person" id="1" gender="female"/>`, `<PII type="location" id="2" scope="city"/>`.

PERSON and LOCATION are optional recognizers in the default EU patterns; they are enabled by default. To restrict which entity types are detected, use `data_classification.enabled_entities` / `disabled_entities`. See [PII semantic enrichment reference](../reference/pii-semantic-enrichment.md) and the Presidio migration note there.

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

## Govern tools by operation class (recommended over manual lists)

**Goal:** Require human review for destructive, bulk, or install operations without maintaining long `forbidden_tools` lists. Talon classifies tools by intent (delete, purge, bulk, execute, install); you declare which classes always need review.

**Where:** `agent.talon.yaml` under `policies.plan_review`.

```yaml
policies:
  plan_review:
    volume_threshold: 50              # Any operation affecting 50+ records requires review
    require_review_for_classes:       # These classes always require review
      - "delete"
      - "purge"
      - "bulk"
      - "execute"
      - "install"
    circuit_breaker:
      consecutive_denial_threshold: 5
      action: "require_human_review"
```

Unlike `forbidden_tools` lists, this works even with broad allowlists. Use `talon intent classify <tool-name>` to see the class and risk level for any tool. **Helps with:** EU AI Act Art. 14 (human oversight), ISO 27001 A.8.25.

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
| Input PII redaction | `policies.data_classification.redact_input` | -- |
| Output PII redaction | `policies.data_classification.redact_output` | -- |
| Block on PII | `policies.data_classification.block_on_pii` | -- |
| Human oversight | `compliance.human_oversight` | -- |
| Semantic cache (TTL, enabled) | — | `talon.config.yaml` only (`cache` section, infrastructure) |

---

## You're done

You now have copy-paste policy snippets for memory, models, cost, time, PII, and human oversight. Drop them into `agent.talon.yaml` or the gateway block as needed.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap cost per caller in the gateway | [How to cap daily spend per team or application](cost-governance-by-caller.md) |
| Verify memory is loaded and injected | [How to verify memory is used](memory-verification.md) |
| Add Talon in front of my app | [Add Talon to your existing app](add-talon-to-existing-app.md) |
| Understand the full config schema | [Configuration and environment](../reference/configuration.md) |

**Verify intent classification** (when intent governance is enabled):

```bash
talon intent classify email_delete '{"count": 100}'
# Expect fields: operation_class, risk_level, is_bulk, requires_review
# Example:
#   Operation class: bulk
#   Risk level:      critical
#   Bulk detected:   true
#   Plan review:     true

talon intent classes
# Shows full taxonomy — use to build require_review_for_classes lists
```
