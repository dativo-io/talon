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

Note: the optional `location` field on tier entries is declarative
documentation only — it is not enforced by the router. Region enforcement
comes from provider registry metadata + `llm.routing.data_sovereignty_mode`
(see [Keep PII inside the EU](#keep-pii-inside-the-eu-gateway-egress-rules)).

For **gateway** callers, set per-caller allowed models in the gateway config:

```yaml
gateway:
  callers:
    - name: "my-app"
      tenant_key: "..."
      tenant_id: "default"
      policy_overrides:
        allowed_models: ["gpt-4o", "gpt-4o-mini"]
```

---

## Keep PII inside the EU (gateway egress rules)

**Goal:** Block tier_2 (PII-bearing) gateway requests from leaving Talon for
non-EU destinations, with a signed evidence record for every decision. This
supports data-transfer controls (e.g. GDPR Chapter V transfer policies);
Talon enforces the rule and produces the evidence — it does not make the
compliance determination for you.

**Where:** `talon.config.yaml` under `gateway.default_policy.egress` (or
per-caller under `callers[].policy_overrides.egress`, which replaces the
default wholesale).

```yaml
gateway:
  providers:
    openai:
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
      region: "US"          # required for region-based rules on custom endpoints
    mistral-eu:
      base_url: "https://api.mistral.ai"
      secret_name: "mistral-api-key"
      region: "EU"
    ollama:
      base_url: "http://localhost:11434"
      region: "LOCAL"
  default_policy:
    egress:
      default_action: allow
      rules:
        - tier: public                      # or 0
          allowed_providers: ["*"]          # public data: any destination
        - tier: internal                    # or 1
          allowed_providers: ["openai", "mistral-eu"]
        - tier: confidential                # or 2
          allowed_regions: ["EU", "LOCAL"]  # PII never leaves EU/local
```

What happens:

- A tier_2 request to a US-region provider is denied with HTTP 403 and machine
  code `egress_tier_destination_disallowed` — **before** any bytes reach the
  upstream and before provider secrets are retrieved.
- Every evaluated request (allowed or denied) gets an `egress_decision`
  section in its signed evidence record; denials map to the
  `POLICY_DENIED_EGRESS` explanation code.
- A provider with an unknown region never matches `allowed_regions`
  (fail-closed) — set `region` explicitly for custom `base_url` providers.
- Use `default_action: deny` for a strict allowlist; in `shadow` mode
  violations are recorded but requests are forwarded.
- Running agents with `llm.routing.data_sovereignty_mode: eu_strict`? That
  control covers provider *selection* for agent runs; egress rules cover
  caller-chosen destinations at the gateway. Mirror them — see
  [Configuration reference](../reference/configuration.md#egress-rules-destination--data-classification)
  for the equivalent egress policy.

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

Egress protection is fail-closed: after redaction, Talon re-scans content before it leaves the process (gateway requests/responses, MCP tool args/results, agent tool output). If residual PII is still detected, Talon blocks egress and emits a remediation-required error. Human approval can approve remediation actions, but does not directly bypass residual PII blocks.

---

## Add custom recognizers safely

**Goal:** Extend detection for domain-specific identifiers while keeping deterministic validation and precedence.

**Where:** `agent.talon.yaml` under `policies.data_classification.custom_recognizers`.

```yaml
policies:
  data_classification:
    custom_recognizers:
      - name: "Ticket ID"
        supported_entity: "TICKET_ID"
        sensitivity: 2
        patterns:
          - name: "ticket-id"
            regex: "\\bTKT-\\d{5}\\b"
            score: 0.9
```

Validation and precedence rules:

- Layer precedence is **built-in < global < per-agent**; later layer override is allowed.
- Duplicate recognizer names in the same layer fail.
- Unsupported fields fail schema validation.
- Invalid regex or score outside `[0,1]` fails validation.
- Unknown built-in entity types fail. Custom entity types are allowed for global/per-agent recognizers.

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
  human_oversight: "on-demand"   # none | on-demand | always
```

See [Agent planning](../AGENT_PLANNING.md) for the execution model and [How to test and operate Plan Review](plan-review-operators.md) for operator E2E steps.

---

## Govern tools by operation class (recommended over manual lists)

**Goal:** Require human review for destructive, bulk, or install operations without maintaining long `forbidden_tools` lists. Talon classifies tools by intent (delete, purge, bulk, execute, install); you declare which classes always need review.

**Where:** `agent.talon.yaml` under `compliance.plan_review` (and `policies.rate_limits` for the circuit breaker).

```yaml
compliance:
  human_oversight: "on-demand"
  plan_review:
    require_for_tools: true     # Review whenever tools are used
    volume_threshold: 50        # Destructive verb + 50+ records requires review

policies:
  rate_limits:
    circuit_breaker_threshold: 5   # Trip after 5 consecutive failures
    circuit_breaker_window: "5m"
```

High-risk operation classes are enforced by built-in conservative defaults: `purge`, `execute`, and `install` operations always require review, and `delete` requires review when bulk signals are detected — even without any `plan_review` config. Unlike `forbidden_tools` lists, this works even with broad allowlists. Use `talon intent classify <tool-name>` to see the class and risk level for any tool. **Helps with:** EU AI Act Art. 14 (human oversight), ISO 27001 A.8.25.

---

## Limit attachment handling (injection prevention)

**Goal:** Block or warn when attachments contain prompt-injection patterns.

**Where:** `agent.talon.yaml` under `attachment_handling`.

```yaml
attachment_handling:
  mode: "strict"
  scanning:
    detect_instructions: true
    action_on_detection: "block_and_flag"   # block_and_flag | warn | log_only
```

---

## Govern coding agents (Claude Code, Codex CLI)

**Goal:** Per-session budgets, per-subagent audit, and credential detection for coding-agent traffic — without breaking streaming or coding UX.

**Where:** `talon.config.yaml` gateway callers (or scaffold everything with `talon init --pack coding-agents`).

```yaml
gateway:
  callers:
    - name: "claude-code"
      tenant_key: "talon-gw-claude-code-001"
      tenant_id: "default"
      policy_overrides:
        pii_action: "warn"           # input scan: evidence + warning, code keeps flowing
        response_pii_action: "allow" # anything else buffers whole SSE streams (LIMITATIONS.md §7)
        max_session_cost: 10.00      # SOFT cap per coding session (#198); reservation is #144
```

Credential recognizers go in `agent.talon.yaml` (high-precision only — PEM blocks, prefixed API keys; Talon is not a secret scanner, keep gitleaks/trufflehog in pre-commit):

```yaml
policies:
  data_classification:
    custom_recognizers:
      - name: "PEM private key block"
        supported_entity: "PRIVATE_KEY"
        sensitivity: 3
        patterns:
          - name: "pem_private_key"
            regex: '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'
            score: 0.95
```

Watch a session: `talon audit list --session <id>` (per-subagent rollup), `talon costs --session <id> --json`, or the dashboard's Coding Sessions panel — all three read the same signed evidence through the same aggregation. Full walk-through: [Governing coding agents](governing-coding-agents.md).

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
