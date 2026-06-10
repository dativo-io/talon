# Configuration reference

Talon uses **two configuration files** with distinct ownership and purpose. Understanding which file controls what is critical for clean separation between governance policy and infrastructure operations.

---

## Two configuration files

| | `agent.talon.yaml` | `talon.config.yaml` |
|---|---|---|
| **Purpose** | Agent policy — what the agent is allowed to do | Infrastructure config — how Talon runs |
| **Owner** | AI governance / compliance team | DevOps / platform team |
| **Contains** | Agent name and description, capabilities (allowed tools, forbidden patterns), memory governance, triggers (cron + webhooks), secrets ACL, attachment handling, compliance framework declarations, cost limits, audit settings | LLM provider connections (endpoint, key env var, region, timeout), gateway settings (callers, mode, rate limits), data directory, secrets encryption key, evidence storage path, observability, multi-tenant defaults |
| **Schema** | `schemas/agent.talon.schema.json` | `schemas/talon.config.schema.json` |
| **Created by** | `talon init` (wizard or `--scaffold` / `--pack`) | `talon init` (wizard or `--scaffold` / `--pack`) |
| **Loaded by** | `policy.LoadPolicy()` | `config.Load()` (Viper) + `gateway.LoadGatewayConfig()` |
| **CLI override** | `--policy <path>` | `--config <path>`, `--gateway-config <path>` |

**Rule of thumb:** if a change affects *what an agent may do*, edit `agent.talon.yaml`. If it affects *where traffic goes or how the platform is wired*, edit `talon.config.yaml`.

**Validation:** Agent policy (`agent.talon.yaml`) is validated by `talon validate`. Infrastructure config (`talon.config.yaml`), including the optional cache section, is checked by `talon doctor` — run `talon doctor` to verify infrastructure settings (e.g. cache, evidence path, gateway).

### How the files are created (`talon init`)

- **In a terminal (TTY):** `talon init` runs an interactive wizard: you choose workload type, framework pack (e.g. OpenClaw), LLM provider, data residency (EU strict / preferred / global), and compliance features. The wizard writes both `agent.talon.yaml` and `talon.config.yaml` and prints vault-first next steps.
- **Non-interactive:** Use `talon init --scaffold` for default templates, or `talon init --pack <id>` for a starter pack (e.g. `openclaw`, `fintech-eu`). For scripts you can also use `talon init --provider openai --name my-agent` (and optional `--data-sovereignty`, `--features`).
- **List options:** `talon init --list-providers`, `talon init --list-packs`, `talon init --list-features`.

---

## agent.talon.yaml (Agent Policy)

Defines governance rules for an individual agent. See the [Policy cookbook](../guides/policy-cookbook.md) for copy-paste snippets and the JSON schema (`schemas/agent.talon.schema.json`) for the full structure. That file is a synced copy of the canonical schema embedded in the binary (`internal/policy/agent.talon.schema.json`), which is what `talon validate` enforces — the two cannot drift (guarded by a test).

Key top-level sections:

| Section | Purpose |
|---------|---------|
| `agent` | Name, description, version, model tier |
| `capabilities` | Allowed tools, data sources, forbidden patterns |
| `policies` | Cost limits, rate limits, model routing, data classification (`redact_input`, `redact_output`, `block_on_pii`), time restrictions, resource limits (`require_approval` for tool approval gates) |
| `memory` | Governed self-improvement (categories, retention, dedup) |
| `triggers` | Cron schedules and webhook definitions |
| `secrets` | Allowed/forbidden secret names for this agent |
| `attachment_handling` | Prompt injection scanning, sandboxing mode. When the section is omitted, the runtime default is `mode: permissive` with content wrapping enabled; production templates set `strict`. |
| `audit` | Log level, retention, prompt/response inclusion, data minimization |
| `compliance` | Frameworks (GDPR, EU AI Act, ISO 27001, NIS2, DORA), data residency, risk level |
| `metadata` | Department, owner, tags |

### Audit configuration

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `audit.log_level` | `string` | `"detailed"` | Evidence detail: `minimal`, `detailed`, or `full`. |
| `audit.retention_days` | `int` | `2555` | Days to retain evidence records before automatic purge. The default (7 years, GDPR posture) applies only when the whole `audit` section is omitted; when you declare `audit`, set `retention_days` explicitly. |
| `audit.include_prompts` | `bool` | `false` | Persist prompt text in the prompt version store and step evidence summaries. |
| `audit.include_responses` | `bool` | `false` | Persist LLM response text in step evidence summaries. |
| `audit.include_original_prompts` | `bool` | `false` | When `true` **and** input PII redaction is active (`redact_input: true`), also persist the original pre-redaction prompt alongside the redacted version. Default `false` aligns with GDPR Art. 5(1)(c) data minimization. Enable only for forensic/legal-hold scenarios. See [ADR-002](../contributor/adr/ADR-002-prompt-storage-data-minimization.md). |
| `audit.observation_only` | `bool` | `false` | Shadow mode: log policy denials without enforcing them. |

See [Memory governance](../MEMORY_GOVERNANCE.md) for the full memory reference. Key memory options:

| Key | Purpose |
|-----|---------|
| `memory.enabled` | Turn memory on or off. Omitting the whole `memory` section disables memory. |
| `memory.mode` | `active` (persist + inject), `shadow` (log only, no persist), or `disabled`. Defaults to `active` when memory is enabled and `mode` is omitted. |
| `memory.allowed_categories` | Categories the agent may write (e.g. `domain_knowledge`, `factual_corrections`, `user_preferences`, `procedure_improvements`). |
| `memory.prompt_categories` | Categories to inject into prompts (empty = all allowed). |
| `memory.max_prompt_tokens` | Cap on memory tokens injected. With a run prompt, retrieval is relevance-scored; otherwise timestamp-ordered. Injected order is by trust (highest first). |
| `memory.governance.dedup_window_minutes` | When > 0, same input within the window does not create a new entry. 0 = disabled. |

---

## talon.config.yaml (Infrastructure Config)

Controls how Talon connects to providers, stores data, and serves requests. Read by Viper (merges env vars, config file, and defaults).

### Environment variables

All `TALON_*` environment variables map to fields in `talon.config.yaml`. Environment variables take precedence over the config file.

| Variable | Purpose | Default |
|----------|---------|---------|
| `TALON_DATA_DIR` | Base directory for state (vault, evidence, memory DBs). For project-scoped evaluation use `TALON_DATA_DIR=$(pwd)/.talon`. | `~/.talon` |
| `TALON_SECRETS_KEY` | AES-256 key: 32 raw bytes or 64 hex chars (256 bits). | Auto-derived per machine |
| `TALON_SIGNING_KEY` | HMAC key: >=32 raw bytes or 64+ hex chars (>=256 bits). | Auto-derived per machine |
| `TALON_DEFAULT_POLICY` | Filename of the agent policy file. | `agent.talon.yaml` |
| `TALON_MAX_ATTACHMENT_MB` | Max attachment size in MB. | `10` |
| `TALON_OLLAMA_BASE_URL` | Ollama endpoint. | `http://localhost:11434` |
| `TALON_ADMIN_KEY` | Admin key for control-plane and dashboard (serve only). | — |
| `OPENAI_API_KEY` | OpenAI key (dev fallback when not in vault). | -- |
| `OPENAI_BASE_URL` | OpenAI-compatible API base URL (e.g. for tests). | -- |
| `ANTHROPIC_API_KEY` | Anthropic key (dev fallback). | -- |
| `AWS_REGION` | AWS region for Bedrock. | -- |

### Crypto keys

On first run with no keys configured, Talon derives deterministic keys from the data directory path. This is fine for local development but **not for production**. Set explicit keys with full AES-256 / HMAC strength (256 bits). Keys may be given as **hex**: 64 hex characters decode to 32 bytes.

```bash
export TALON_SECRETS_KEY=$(openssl rand -hex 32)
export TALON_SIGNING_KEY=$(openssl rand -hex 32)
```

### LLM block

Optional. When present, the `llm:` block configures the provider registry and data sovereignty routing used by `talon run` and the agent runner.

| Section | Purpose |
|---------|---------|
| `llm.providers` | Map of provider IDs to `type`, `config`, and `enabled`. Used when building providers from config instead of env vars only. |
| `llm.routing.data_sovereignty_mode` | `eu_strict`, `eu_preferred`, or `global`. When set, the router evaluates each candidate with OPA `routing.rego` and records the selected provider and rejected candidates in evidence. |
| `llm.pricing_file` | Path to the LLM pricing table (default: `pricing/models.yaml`). Used for cost estimation in evidence and OTel; see [Provider registry — Cost estimation](provider-registry.md#cost-estimation). |

Example:

```yaml
llm:
  pricing_file: "pricing/models.yaml"
  routing:
    data_sovereignty_mode: eu_strict
  providers:
    openai:
      type: openai
      enabled: true
```

See [Provider registry](provider-registry.md) for the full reference.

---

### Cache block

Optional governed semantic cache (off by default). Validated by `talon doctor`.

| Key | Default | Purpose |
|-----|---------|---------|
| `cache.enabled` | `false` | Turn the semantic cache on. |
| `cache.default_ttl` | `3600` | Entry TTL in seconds. |
| `cache.ttl_by_tier` | — | Optional per-tier TTL overrides in seconds, keyed by `public`, `internal`, `confidential`; tiers not listed fall back to `default_ttl`. |
| `cache.similarity_threshold` | `0.92` | Match strictness (0–1; higher = stricter). |
| `cache.max_entries_per_tenant` | `10000` | Cap per tenant. |

```yaml
cache:
  enabled: true
  default_ttl: 3600
  ttl_by_tier:
    public: 3600
    internal: 900
  similarity_threshold: 0.92
  max_entries_per_tenant: 10000
```

Confidential-tier and high-severity-PII requests are not cached (OPA cache policy). See the [Policy cookbook](../guides/policy-cookbook.md#enable-governed-semantic-cache-infrastructure).

---

### Gateway block

When `talon serve --gateway` is used, the `gateway:` block in `talon.config.yaml` configures the LLM API proxy. Key sections:

| Section | Purpose |
|---------|---------|
| `gateway.mode` | `enforce`, `shadow`, or `log_only`. Runtime default when omitted: `enforce`. Generated starter configs set `shadow` explicitly for a safe rollout. |
| `gateway.providers` | LLM provider connections (base URL, secret name, allowed/blocked models) |
| `gateway.callers` | Application identities (tenant key, tenant, allowed providers, policy overrides) |
| `gateway.default_policy` | Server-wide defaults (PII action, cost caps, tool governance, attachment scanning, egress rules) |
| `gateway.rate_limits` | Global and per-caller request rate limits |
| `gateway.timeouts` | Connect, request, and stream idle timeouts |

Provider auth mode:

- `gateway.providers.<provider>.upstream_auth_mode`:
  - `secret` (default): read provider credential from Talon vault (`secret_name` required).
  - `client_bearer`: forward caller bearer upstream (quickstart profile only).

Quickstart note:

- `talon serve --proxy-quickstart` builds gateway config in memory (no YAML required).
- Use [proxy quickstart reference](proxy-quickstart.md) for quickstart flags/env and compatibility limits.

#### Egress rules (destination × data classification)

`gateway.default_policy.egress` restricts which destinations (providers and/or
regions) each data classification tier may leave Talon for. The check runs in
the policy evaluation step — before secrets are retrieved and before any
request bytes reach the upstream — and the decision is recorded in signed
evidence (`egress_decision`, evidence integrity spec v1.2). This supports
data-transfer controls (e.g. GDPR Chapter V transfer policies, ISO 27001
A.5.14 information transfer); Talon provides the enforcement and evidence,
not a compliance determination.

```yaml
gateway:
  providers:
    openai:
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
      region: "US"        # destination region used by egress rules
    mistral-eu:
      base_url: "https://api.mistral.ai"
      secret_name: "mistral-api-key"
      region: "EU"
  default_policy:
    egress:
      default_action: allow   # applied when no rule covers the request's tier
      rules:
        - tier: public                        # alias for 0
          allowed_providers: ["*"]            # public data: anywhere
        - tier: internal                      # alias for 1
          allowed_providers: ["openai", "mistral-eu"]
        - tier: confidential                  # alias for 2
          allowed_regions: ["EU", "LOCAL"]    # PII: EU/local destinations only
```

Behavior:

- Tiers may be written as numbers (`0`, `1`, `2`) or named aliases (`public`,
  `internal`, `confidential`; case-insensitive) — same ascending-sensitivity
  convention as ISO 27001 practice and Microsoft Purview/AGT. The aliases also
  work for `callers[].policy_overrides.max_data_tier`. Evidence records always
  store the numeric tier.

- A request is allowed when **any** rule for its tier matches the destination,
  either by provider name (`allowed_providers`, `"*"` = any) or by the
  provider's resolved region (`allowed_regions`).
- `allowed_providers` values are normalized to lowercase and `allowed_regions`
  to uppercase at load time (except `"*"` and `"unknown"`). Provider
  `region` fields follow the same uppercase convention.
- A destination with an **unknown region never matches** `allowed_regions`
  (fail-closed): set `gateway.providers.<name>.region` explicitly for custom
  `base_url` endpoints. Known providers fall back to registry metadata.
- `default_action: deny` turns the policy into an allowlist: tiers without a
  rule are denied.
- Per-caller override: `callers[].policy_overrides.egress` **replaces** the
  server default wholesale for that caller (most-specific wins). A future
  `merge` mode may allow layering caller rules on top of server defaults;
  until then, copy server rules into the override when you need both.
- When no `egress` block is configured at either level, egress is not
  evaluated and behavior is unchanged.
- Denials return HTTP 403 with machine code
  `egress_tier_destination_disallowed` (rule exists for the tier, destination
  not permitted) or `egress_destination_disallowed` (no rule for the tier,
  `default_action: deny`), and map to the `POLICY_DENIED_EGRESS` explanation
  code. In `shadow` mode violations are recorded as shadow violations and the
  request is forwarded.

**Relationship to `llm.routing.data_sovereignty_mode`:** the two controls are
complementary and share the same sources of truth, but govern different
planes:

- `data_sovereignty_mode` (`eu_strict` / `eu_preferred` / `global`) applies
  when **Talon selects the provider** — agent runs (`talon run`, triggers,
  agent chat). The router filters candidates via `routing.rego` and records
  the choice in the `routing_decision` evidence section.
- Gateway `egress` rules apply when **the caller has already chosen the
  provider** (it is in the proxy URL). The gateway cannot reroute; it can only
  allow or deny, recorded in the `egress_decision` evidence section.
- Both resolve a provider's location from the same registry metadata
  (`EU`/`US`/`LOCAL` jurisdictions), with an explicit per-provider `region`
  override taking precedence. Routing candidates always carry registry
  metadata; the gateway may face an unregistered upstream, in which case its
  region resolves to `unknown`, which never matches an `allowed_regions` list
  (fail closed).
- The gateway does **not** auto-derive egress rules from
  `data_sovereignty_mode`. If you run agents with `eu_strict`, mirror it at
  the gateway explicitly:

```yaml
gateway:
  default_policy:
    egress:
      default_action: deny
      rules:
        - tier: public
          allowed_regions: ["EU", "LOCAL"]
        - tier: internal
          allowed_regions: ["EU", "LOCAL"]
        - tier: confidential
          allowed_regions: ["EU", "LOCAL"]
```

  (`global` ≈ no egress block; `eu_preferred` has no egress equivalent — a
  preference order only makes sense when Talon picks the provider, not when
  it admits a caller-chosen one.)

### Gateway dashboard

When the gateway is enabled, Talon serves a real-time metrics dashboard. Access is controlled by `TALON_ADMIN_KEY` (`X-Talon-Admin-Key` header).

Dashboard endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /gateway/dashboard` | Single-page HTML dashboard with auto-refreshing charts. |
| `GET /api/v1/metrics` | Metrics snapshot as JSON (programmatic access). |
| `GET /api/v1/metrics/stream` | Server-Sent Events stream (one snapshot every 5 seconds). |

All three endpoints require the admin key:

- `X-Talon-Admin-Key: <TALON_ADMIN_KEY>` (preferred)
- or `Authorization: Bearer <TALON_ADMIN_KEY>` (fallback)

See [Gateway dashboard reference](gateway-dashboard.md) for the full API schema and snapshot field descriptions.

### Server and API

- **Admin key:** Set `TALON_ADMIN_KEY` to protect admin-only and dashboard/metrics endpoints.
- **Tenant keys:** Configure per-caller `gateway.callers[].tenant_key` values for gateway and tenant-scoped API access.
- **Gateway:** Enable with `--gateway` and `--gateway-config <path>`. See [How to choose your integration path](../guides/choosing-integration-path.md) and gateway guides.
- **MCP proxy:** Enable with `--proxy-config <path>`. See [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md).
- **Auth model:** See [Authentication and key scopes](authentication-and-key-scopes.md) for endpoint-to-key mapping (tenant keys vs admin key).
- **Operational control:** Run management, overrides, and tool approval gates are exposed via admin API. See [Operational control plane](operational-control-plane.md).

### Observability

| Variable | Purpose | Default |
|----------|---------|---------|
| `TALON_OTEL_ENABLED` | Enable OpenTelemetry traces and metrics export. | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint (e.g. `http://localhost:4317`). | stdout |

See [Observability](../OBSERVABILITY.md) for the full metrics catalogue and [examples/observability](../../examples/observability/) for a local Prometheus + Grafana stack.
