# Policy cookbook

Copy-paste snippets for common policy needs. Use in `agent.talon.yaml` (agent policy, owned by governance/compliance) or in `talon.config.yaml` gateway block (infrastructure config, owned by DevOps). Each entry states the goal, the snippet, and where it goes.

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

For **gateway** traffic, set the agent's flat model lists in the same `agent.talon.yaml` (they replace the organization baseline when non-empty; `model_routing` above stays runner-side routing):

```yaml
agent:
  name: my-app
  key:
    secret_name: my-app-talon-key

policies:
  models:
    allowed: ["gpt-4o", "gpt-4o-mini"]
    # blocked: ["gpt-4.5-preview"]
```

---

## Keep PII inside the EU (gateway egress rules)

**Goal:** Block tier_2 (PII-bearing) gateway requests from leaving Talon for
non-EU destinations, with a signed evidence record for every decision. This
supports data-transfer controls (e.g. GDPR Chapter V transfer policies);
Talon enforces the rule and produces the evidence — it does not make the
compliance determination for you.

**Where:** `talon.config.yaml` under `gateway.organization_policy.egress` (or
per agent under `policies.egress` in the agent file — a second boundary
evaluated alongside the organization's: a destination must pass **both**).

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
  organization_policy:
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
  agent-chosen destinations at the gateway. Mirror them — see
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

**Where:** `agent.talon.yaml` — one snippet governs both native runs and gateway traffic for this agent.

```yaml
policies:
  cost_limits:
    daily: 10.00
    monthly: 200.00
```

On the gateway, these caps are the agent's override: each replaces the organization baseline (`gateway.organization_policy.max_daily_cost` / `max_monthly_cost`) when > 0. `talon costs --agent <name>` reports the same effective caps enforcement uses.

---

## Redact PII in requests

**Goal:** Redact or block PII before it reaches the LLM (input) and/or in the LLM response (output).

**Where:** `agent.talon.yaml` — `data_classification` with granular `redact_input` / `redact_output` fields (`redact_pii` still works as a shorthand for both). The organization-wide default lives in `gateway.organization_policy.default_pii_action`.

```yaml
# agent.talon.yaml — granular input/output control; the same booleans are the
# agent's gateway PII override (input_scan+redact_input → redact;
# block_on_pii → block; scan flags alone → no override, the org floor applies;
# the merge is monotonic — an agent can only TIGHTEN the org baseline, #266)
policies:
  data_classification:
    input_scan: true
    output_scan: true
    redact_input: true          # redact PII from prompt before LLM sees it
    redact_output: true         # redact PII from LLM response before returning
    # redact_pii: true          # shorthand: sets both redact_input and redact_output
```

```yaml
# talon.config.yaml — organization baseline for every agent without an override
gateway:
  organization_policy:
    default_pii_action: "redact"   # warn | redact | block | allow
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

## Harden `update_records`-style database tools

**Goal:** Stop a runaway agent from corrupting or deleting production data through a bulk mutation tool. Combine the three tool-safety controls — row-count guard, dry-run gate, and forbidden argument values — on the same tool.

**Where:** `agent.talon.yaml` under `tool_policies`.

```yaml
tool_policies:
  update_records:
    # Row count guard — hard cap on bulk operations
    max_row_count: 1000
    dry_run_threshold: 100
    require_dry_run: true

    # Forbidden argument values — block destructive modes
    forbidden_argument_values:
      mode: ["overwrite", "truncate", "replace_all"]

    # PII scanning: redact PII in query arguments, audit results
    arguments:
      query: redact
    result: audit
    timeout: "30s"
```

### What this enforces

| Control | Rule | Effect |
|---------|------|--------|
| Row count guard | `max_row_count: 1000` | Blocks tool calls where `estimated_row_count > 1000` |
| Dry-run gate | `require_dry_run: true`, `dry_run_threshold: 100` | Requires `dry_run=true` param when `estimated_row_count > 100` |
| Forbidden values | `mode: [overwrite, truncate, replace_all]` | Blocks calls with these destructive mode values |
| PII redaction | `arguments.query: redact` | Strips PII from the `query` argument before execution |
| Result audit | `result: audit` | Logs PII found in the tool result without blocking |
| Timeout | `timeout: 30s` | Cancels execution if tool takes longer than 30 seconds |

### How it works

1. **OPA policy evaluation** (Rego) checks `estimated_row_count`, `dry_run`,
   and argument values at the policy layer — before any tool code runs.
2. **Go-level guard** in the runner also enforces `max_row_count` and
   `require_dry_run` as a defense-in-depth check, covering tools that bypass
   OPA (e.g., legacy `executeToolInvocations` path).
3. **Idempotency:** for tools listed under `tool_governance`, the key is
   derived from `(agent_id, scope_id, tool_name, sha256(args))` where `scope_id` is
   `correlation_id` (per run) or `session_id` (cross-run). If the same call already
   completed within the configured `cache_ttl`, the cached result is returned (or an
   error when `on_duplicate: fail`). See [the idempotency recipe below](#tool-governance-idempotency-for-side-effecting-tools).

### Tool implementation contract

For these policies to be effective, tools that modify data should accept:

- `estimated_row_count` (int) — the agent's estimate of affected rows
- `dry_run` (bool) — when true, return what would happen without executing
- `mode` (string) — operation mode (`upsert`, `insert`, `overwrite`, etc.)

### Example: agent prompt that triggers the guard

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

---

## Combine tool policies with plan review

**Goal:** For high-risk tools, force human approval when the execution plan contains destructive verbs near numbers exceeding a volume threshold.

**Where:** `agent.talon.yaml` under `compliance.plan_review`.

```yaml
compliance:
  human_oversight: on-demand
  plan_review:
    require_for_tools: true
    cost_threshold: 0.50
    volume_threshold: 500
    timeout_minutes: 60
```

---

## Tool governance: idempotency for side-effecting tools

**Goal:** Retries are required for reliability but are dangerous for side-effecting tools (send email, charge card): if an upstream planner retries the whole sequence, the same action can run twice. Deduplicate repeated calls with the same parameters.

**Where:** `agent.talon.yaml` under `tool_governance`.

```yaml
tool_governance:
  send_notification_email:
    idempotency_key: request_id   # per run (correlation_id); use session_id for cross-run dedupe
    cache_ttl: "24h"             # treat cached result as stale after 24h
    on_duplicate: return_cached  # or "fail" to return an error instead of cached result
    strict_mode: true            # fail the tool call if idempotency store is unavailable
```

| Option | Values | Effect |
|--------|--------|--------|
| `idempotency_key` | `request_id` (default), `session_id` | Scope for dedup: per run vs same session across runs |
| `cache_ttl` | e.g. `24h`, `1h` | After this duration a completed entry is treated as expired (not found) |
| `on_duplicate` | `return_cached` (default), `fail` | When a completed call is found: return cached result or error |
| `strict_mode` | `true`, `false` | When true, fail the tool call if the idempotency check errors (e.g. DB down) |

Idempotency is applied only to tools listed under `tool_governance`. The key
includes `(agent_id, scope_id, tool_name, sha256(args))`; `scope_id` is
`correlation_id` when `idempotency_key` is `request_id`, or `session_id` when
`idempotency_key` is `session_id`.

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

**Where:** one `agent.talon.yaml` per coding tool (or scaffold everything with `talon init --pack coding-agents`, which generates `claude-code` as the primary agent plus `agents/codex.talon.yaml`).

```yaml
# agent.talon.yaml (claude-code)
agent:
  name: claude-code
  key:
    secret_name: claude-code-talon-key   # mint: talon secrets set claude-code-talon-key "$(openssl rand -hex 24)"

policies:
  session_limits:
    max_cost: 10.00        # SOFT cap per coding session (#198); reservation is #144
  data_classification:
    input_scan: true       # scan-only: evidence recorded, org floor decides the action
    redact_pii: false      # redaction mangles code
```

Streaming-honest response posture is set at the **organization baseline** — `allow` is deliberate, because any other response action buffers the entire SSE stream (LIMITATIONS.md §7), and a per-agent downgrade to `allow` is not expressible:

```yaml
gateway:
  organization_policy:
    default_pii_action: "warn"
    response_pii_action: "allow"
```

Credential recognizers go in the same `agent.talon.yaml` (high-precision only — PEM blocks, prefixed API keys; Talon is not a secret scanner, keep gitleaks/trufflehog in pre-commit):

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

**Cache vs memory:** Memory is agent-level learning (what the agent may remember). The semantic cache (experimental — see below) is infrastructure-level: it is configured in `talon.config.yaml` under `cache`, not in agent policy. See [Memory governance — Cache vs memory](../MEMORY_GOVERNANCE.md#cache-vs-memory).

---

## Experimental: governed semantic cache (not verified end-to-end)

> ⚠️ **Not a shipped control.** The semantic cache is scaffolded (config, CLI, PII scrubbing design) but its end-to-end serving path is **not verified** and the work is parked on the roadmap ([#141](https://github.com/dativo-io/talon/issues/141)). Do not rely on it to reduce cost today — the shipped cost controls are the caps and cache-aware pricing above. This section documents the intended design only.

**Intended goal:** reduce LLM cost and latency by serving similar queries from a PII-scrubbed cache, checked before each LLM call.

**Where (when enabled):** `talon.config.yaml` (infrastructure — owned by DevOps), not in `agent.talon.yaml`.

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

Design intent: store **embeddings/hashes** of prompts (not raw text) and **PII-scrubbed** responses only; never cache confidential/restricted tiers, high-severity PII requests, tool calls, or MCP messages; `talon cache erase --tenant <id>` supports GDPR Article 17 erasure.

---

## Where to put snippets

The agent file carries the agent's one override; the gateway block carries only the organization baseline. One semantic, one field:

| Snippet type | `agent.talon.yaml` (governance team) | `talon.config.yaml` gateway block (DevOps team) |
|--------------|--------------------------------------|--------------------------------------------------|
| Cost limits | `policies.cost_limits` (daily/monthly replace the baseline when > 0); `policies.session_limits.max_cost` | Baseline: `gateway.organization_policy.max_daily_cost` / `max_monthly_cost` |
| Model allow/block (gateway) | `policies.models.allowed` / `policies.models.blocked` | Provider destination constraints: `gateway.providers.<name>.allowed_models` / `blocked_models` |
| Model routing (runner) | `policies.model_routing` | -- |
| Provider allowlist | `policies.allowed_providers` | -- |
| Time restrictions | `policies.time_restrictions` | -- |
| PII action | `policies.data_classification` booleans (`input_scan`, `redact_input`, `block_on_pii`, …) | Baseline: `gateway.organization_policy.default_pii_action` / `response_pii_action` |
| Input PII redaction | `policies.data_classification.redact_input` | -- |
| Output PII redaction | `policies.data_classification.redact_output` | -- |
| Block on PII | `policies.data_classification.block_on_pii` | -- |
| Data tier cap | `policies.data_classification.max_data_tier` | -- |
| Egress rules | `policies.egress` (second boundary; a destination must pass both this AND the baseline) | Baseline: `gateway.organization_policy.egress` |
| Tool governance (gateway) | `capabilities.allowed_tools` / `forbidden_tools` / `tool_policy_action` | Baseline: `gateway.organization_policy.forbidden_tools` / `tool_policy_action` |
| Tool hardening (row caps, dry-run, forbidden args) | `tool_policies` | -- |
| Tool idempotency (dedupe retried side effects) | `tool_governance` | -- |
| Human oversight | `compliance.human_oversight` | -- |
| Attachment scanning (gateway) | — (baseline only in #266) | `gateway.organization_policy.attachment_policy` |
| Semantic cache (experimental, parked #141) | — | `talon.config.yaml` only (`cache` section, infrastructure) |

---

## You're done

You now have copy-paste policy snippets for models, cost, time, PII, tool hardening, human oversight, and memory. Drop them into `agent.talon.yaml` or the gateway block as needed.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap cost per agent in the gateway | [How to cap daily spend per team or application](cost-governance-by-agent.md) |
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
