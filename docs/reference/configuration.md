# Configuration reference

Talon uses **two configuration files** with distinct ownership and purpose. Understanding which file controls what is critical for clean separation between governance policy and infrastructure operations.

---

## Two configuration files

| | `agent.talon.yaml` | `talon.config.yaml` |
|---|---|---|
| **Purpose** | Agent policy — what the agent is allowed to do | Infrastructure config — how Talon runs |
| **Owner** | AI governance / compliance team | DevOps / platform team |
| **Contains** | Agent identity (name, tenant, vault-bound traffic key), capabilities (allowed tools, forbidden patterns), memory governance, triggers (cron + webhooks), secrets ACL, attachment handling, compliance framework declarations, cost limits, audit settings | LLM provider connections (endpoint, key env var, region, timeout), gateway settings (providers, organization baseline policy, mode, rate limits), data directory, secrets encryption key, evidence storage path, observability |
| **Schema** | `schemas/agent.talon.schema.json` | `schemas/talon.config.schema.json` |
| **Created by** | `talon init` (wizard or `--scaffold` / `--pack`) | `talon init` (wizard or `--scaffold` / `--pack`) |
| **Loaded by** | `policy.LoadPolicy()` | `config.Load()` (Viper) + `gateway.LoadGatewayConfig()` |
| **CLI override** | `--policy <path>` | `--config <path>`, `--gateway-config <path>` |

**Rule of thumb:** if a change affects *what an agent may do*, edit `agent.talon.yaml`. If it affects *where traffic goes or how the platform is wired*, edit `talon.config.yaml`.

**Validation:** Agent policy (`agent.talon.yaml`) is validated by `talon validate`. Infrastructure config (`talon.config.yaml`), including the optional cache section, is checked by `talon doctor` — run `talon doctor` to verify infrastructure settings (e.g. cache, evidence path, gateway).

### How the files are created (`talon init`)

- **In a terminal (TTY):** `talon init` runs an interactive wizard: you choose workload type, framework pack (e.g. OpenClaw), LLM provider, data residency (EU strict / preferred / global), compliance features, and optional EU compliance policy packs (GDPR, NIS2, DORA, EU AI Act). The wizard writes both `agent.talon.yaml` and `talon.config.yaml` and prints vault-first next steps.
- **Non-interactive:** Use `talon init --scaffold` for default templates, or `talon init --pack <id>` for a starter pack (e.g. `openclaw`, `fintech-eu`). For scripts you can also use `talon init --provider openai --name my-agent` (and optional `--data-sovereignty`, `--features`).
- **Compliance policy packs:** `--compliance gdpr,nis2` (or `all`) merges curated EU policy packs into the generated `agent.talon.yaml` on every init path (wizard, `--pack`, `--scaffold`, scripted). Each applied pack annotates the output with the articles it supports, linked to `internal/compliance/mapping.go`. See the [Policy packs guide](../guides/policy-packs.md).
- **List options:** `talon init --list-providers`, `talon init --list-packs`, `talon init --list-features`, `talon init --list-compliance`.

---

## agent.talon.yaml (Agent Policy)

Defines governance rules for an individual agent. See the [Policy cookbook](../guides/policy-cookbook.md) for copy-paste snippets and the JSON schema (`schemas/agent.talon.schema.json`) for the full structure. That file is a synced copy of the canonical schema embedded in the binary (`internal/policy/agent.talon.schema.json`), which is what `talon validate` enforces — the two cannot drift (guarded by a test).

Key top-level sections:

| Section | Purpose |
|---------|---------|
| `agent` | Identity: `name` (unique per installation), `tenant_id`, `key.secret_name` (vault-bound traffic key), description, version, model tier, `accept_client_metadata` |
| `capabilities` | Allowed tools, forbidden tools, `tool_policy_action`, data sources, forbidden patterns |
| `policies` | Cost limits, session limits, rate limits, model routing (runner-side), gateway model lists (`models.allowed` / `models.blocked`), `allowed_providers`, `egress`, data classification (`redact_input`, `redact_output`, `block_on_pii`, `max_data_tier`), time restrictions, resource limits (`require_approval` for tool approval gates) |
| `memory` | Governed self-improvement (categories, retention, dedup) |
| `triggers` | Cron schedules and webhook definitions |
| `secrets` | Allowed/forbidden secret names for this agent |
| `attachment_handling` | Prompt injection scanning, sandboxing mode. When the section is omitted, the runtime default is `mode: permissive` with content wrapping enabled; production templates set `strict`. |
| `audit` | Log level, retention, prompt/response inclusion, data minimization |
| `compliance` | Frameworks (GDPR, EU AI Act, ISO 27001, NIS2, DORA), data residency, risk level |
| `metadata` | Department, owner, `team` (cost/evidence attribution), `tags` (telemetry classification) |

### Agent identity and key binding

**One `agent.talon.yaml` = one AI use case = one Talon traffic identity = one active vault-bound key.**

```yaml
agent:
  name: support-triage            # unique per installation
  tenant_id: acme                 # optional; omitted = "default"
  key:
    secret_name: support-triage-talon-key   # Talon vault reference — never a raw key
```

- `agent.name` — the agent's operational identity. Duplicate names (or two agents resolving to the same key) fail the identity-registry build with an error naming the offending files.
- `agent.tenant_id` — the tenant the agent belongs to (default `"default"`). The tenant is always derived `key → agent → tenant_id`; this is the only tenant derivation, authoritative for gateway traffic **and** native runs — `talon run --tenant` errors when the flag conflicts with the file.
- `agent.key.secret_name` — the vault secret holding the agent's one active traffic key. The schema accepts only a secret **name**, so raw inline key values are impossible and policy files stay safe to commit. Required for every agent loaded into the gateway (missing binding is a startup error); optional for native-only, non-traffic-bound runs.

Mint the key that clients of this agent will present to the gateway:

```bash
talon secrets set support-triage-talon-key "$(openssl rand -hex 24)"
```

**Rotation:** write a new value to the same secret name (`talon secrets set support-triage-talon-key <new>`) and restart `talon serve` (a secret-only change is not digest-detected, so rotation still needs a restart or a file-touch even with periodic reload running). There is never a window with two concurrently-active keys — one agent, one key.

### Gateway policy overrides (one agent, one override)

The agent file is also the agent's **one** policy override on top of the gateway's organization baseline (`gateway.organization_policy`). Overrides use the file's existing vocabulary — one semantic, one field:

| Agent-file field | Effective-policy semantic |
|---|---|
| `policies.cost_limits.daily` / `.monthly` | Replaces the baseline cap (`organization_policy.defaults.daily_cost` / `.monthly_cost`) when > 0; the org ceilings `constraints.max_daily_cost` / `.max_monthly_cost` are enforced in addition and can never be raised (#287) |
| `policies.session_limits.max_cost` | Replaces the per-session baseline (`organization_policy.defaults.session_cost`) when > 0; the org ceiling `constraints.max_session_cost` is enforced in addition (#283) |
| `policies.data_classification` input booleans | Input PII action: `block_on_pii` → block; `input_scan` + `redact_input` (or `redact_pii`) → redact; `input_scan` alone → scan only, no action override (the baseline applies) |
| `policies.data_classification` output booleans | Response PII action: `output_scan` + `block_on_pii` → block; `output_scan` + `redact_output` (or `redact_pii`) → redact; `output_scan` alone → scan only, no action override (the baseline applies) |
| `policies.data_classification.max_data_tier` | Caps the request's data classification tier when present |
| `policies.models.allowed` / `.blocked` | Flat gateway model lists; replace the baseline when non-empty (`model_routing` remains runner-side routing, not a gateway list) |
| `policies.allowed_providers` | Restricts which gateway providers this agent may reach (empty = all) |
| `policies.egress` | A second egress boundary evaluated alongside the organization's — a destination must pass **both** (logical intersection); the agent narrows within the org boundary, never widens or replaces it |
| `capabilities.allowed_tools` | Most-specific non-empty list wins; a tool must additionally pass the org hard allowlist `constraints.allowed_tools` when one is set (#282) |
| `capabilities.forbidden_tools` | Unioned with the org and provider lists |
| `capabilities.tool_policy_action` | `filter` or `block`; monotonic at the agent layer — an agent can tighten `filter` → `block` but never loosen `block` → `filter` (#287) |
| `metadata.team` | Attributes spend and evidence to a team (`talon costs --by-team`) |
| `metadata.tags` | Telemetry classification (e.g. `copaw` drives OTel/dashboard views) |

PII actions are **monotonic**: the organization baseline is a floor, and a per-agent override only takes effect when it is *stricter* (`block` > `redact` > `warn` > `allow`). An agent can tighten `warn` to `redact` or `block`, but nothing an agent file says — including turning on bare scan flags — can weaken the org floor. See [Identity resolution and effective policy](#identity-resolution-and-effective-policy) for the exact replace-vs-merge rules.

### PII recognizer layers and validation

Recognizer loading follows a fixed precedence: **built-in < global < per-agent**.

- **Built-in** recognizers ship in Talon default patterns.
- **Global** recognizers come from a process-level pattern file (when configured).
- **Per-agent** recognizers come from `policies.data_classification.custom_recognizers` in `agent.talon.yaml`.

Validation is fail-fast in `talon validate` and at startup:

- Duplicate recognizer names within one layer fail validation.
- Cross-layer overrides are allowed and deterministic (later layer wins).
- Invalid regex patterns fail validation.
- Pattern scores must be in `[0,1]`.
- Unsupported fields in recognizer YAML/custom recognizer objects fail validation.
- Unknown `supported_entity` values fail for built-in recognizers. Custom entity names are allowed for global/per-agent layers.

### Audit configuration

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `audit.log_level` | `string` | `"detailed"` | Evidence detail: `minimal`, `detailed`, or `full`. |
| `audit.retention_days` | `int` | `2555` | Days to retain evidence records before automatic purge. The default (7 years, GDPR posture) applies only when the whole `audit` section is omitted; when you declare `audit`, set `retention_days` explicitly. |
| `audit.include_prompts` | `bool` | `false` | Persist prompt text in the prompt version store and step evidence summaries. |
| `audit.include_responses` | `bool` | `false` | Persist LLM response text in step evidence summaries. |
| `audit.include_original_prompts` | `bool` | `false` | When `true` **and** input PII redaction is active (`redact_input: true`), also persist the original pre-redaction prompt alongside the redacted version. Default `false` aligns with GDPR Art. 5(1)(c) data minimization. Enable only for forensic/legal-hold scenarios. See [ADR-002](../contributor/adr/ADR-002-prompt-storage-data-minimization.md). |
| `audit.observation_only` | `bool` | `false` | Shadow mode: log policy denials without enforcing them. |

### Compliance declarations (auditor exports)

The optional `compliance.declarations` block holds per-agent **declared facts** used to populate auditor exports (`talon compliance ropa`, `talon compliance annex-iv`). These are business statements that cannot be derived from runtime evidence — why data is processed, how long it is retained, what the system is for. Runtime facts (PII observed, destinations, decisions) always come from the signed evidence store. Missing declarations render as flagged placeholders in exports, never failures.

```yaml
compliance:
  frameworks: [gdpr, eu-ai-act]
  data_residency: eu
  declarations:
    processing:                      # GDPR Art. 30(1) processing-record facts
      purposes: ["customer support triage"]
      data_subject_categories: ["customers"]
      personal_data_categories: ["contact details"]
      retention_period: "90 days"
      safeguards: "access restricted to support team"
      legal_basis: "contract"
    system:                          # EU AI Act Annex IV facts
      system_description: "LLM assistant for support ticket triage"
      intended_purpose: "Summarize and route inbound support tickets"
      oversight_description: "Support lead reviews flagged tickets daily"
```

Fill these in together with your DPO. The exports are supporting records for GDPR Art. 30 and EU AI Act Annex IV review — not a completed legal filing. The org-level controller identity lives in `talon.config.yaml` (see [Compliance block](#compliance-block-controller-identity)). Step-by-step help for clearing flagged sections: [How to clear DECLARATION MISSING blocks in RoPA exports](../guides/ropa-declarations.md).

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
| `llm.routing.data_sovereignty_mode` | `eu_strict`, `eu_preferred`, or `global`. When set, the router evaluates each candidate with OPA `routing.rego` and records the selected provider and rejected candidates in evidence. **Superseded by the top-level [`sovereignty.mode`](#sovereignty-block-data-residency--air-gap)** — when `sovereignty.mode` is set it is the source of truth and overrides this value (with a warning). |
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

### Sovereignty block (data residency & air-gap)

Optional. The top-level `sovereignty:` block is the **single source of truth** for
your data-sovereignty posture. When `sovereignty.mode` is set it supersedes
`llm.routing.data_sovereignty_mode` (a conflicting routing value is overridden
with a warning) and applies to **both** the `talon run` agent path and the
gateway. This is the recommended way to declare sovereignty — set it once here
rather than mirroring it under `llm.routing`.

| Field | Values | Purpose |
|-------|--------|---------|
| `sovereignty.mode` | `eu_strict`, `eu_preferred`, `global` | Data-sovereignty posture (source of truth). Under `eu_strict`, declared non-EU/LOCAL providers are **excluded from routing** (ERROR log at startup) and **denied at the gateway** (HTTP 403 + audit evidence). The process continues unless `deployment_mode: air_gap` is set without explicit crypto keys. Covers operator-keyed providers (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`), `llm.providers` entries, and enabled gateway upstreams. Region-aware providers (Bedrock, Azure OpenAI, Vertex) are gated on their **configured region**, not just metadata: e.g. `AWS_REGION=us-east-1` excludes Bedrock, while `AWS_REGION=eu-central-1` keeps it routable. Non-declared registry defaults are filtered silently. `eu_preferred` and `global` impose no hard gate. |
| `sovereignty.deployment_mode` | `standard`, `air_gap` | `air_gap` is a stricter sub-mode that **implies `eu_strict`** (a looser `mode` is rejected). It adds deny-by-default EU/LOCAL gateway egress, a transport-level egress allowlist guard, and rejects generated default crypto keys. See the [air-gapped deployment guide](../guides/air-gapped-deployment.md). |
| `sovereignty.allowed_egress_hosts` | list of host or URL strings | Optional extension to the air-gap transport allowlist (in addition to `ollama_base_url`, enabled gateway `base_url`s, and loopback). |

Precedence: `sovereignty.mode` (and `deployment_mode: air_gap`, which forces
`eu_strict`) wins over `llm.routing.data_sovereignty_mode`. When a `sovereignty`
block is present in a `--gateway-config` file, it is merged with the operator
config fail-safe (the stronger posture wins) before validation.

Example:

```yaml
sovereignty:
  mode: eu_strict                 # source of truth; excludes non-EU providers
  deployment_mode: air_gap        # optional: implies eu_strict + egress hardening
  allowed_egress_hosts:           # optional extra private EU endpoints
    - "llm.internal.example"
```

Validated by `talon doctor` (`sovereignty_providers` warns when exclusions exist but compliant providers remain; fails only when nothing EU/LOCAL is routable. Gateway and native routability are checked **independently** — with `--gateway-config`, the gateway must have at least one compliant enabled provider, and a compliant native/LLM provider does not mask an all-excluded gateway. `air_gap_crypto_keys` fails on default keys; `air_gap_egress_guard` transport probe). See the [air-gapped deployment guide](../guides/air-gapped-deployment.md).

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

### Scanner block (external PII engines)

Optional. Selects **one** globally active PII scanner engine per Talon
instance. When absent, the built-in regex scanner is used — zero config, no
runtime dependency. An external engine **replaces** the built-in scanner (no
result merging) and is **fail-closed**: a scan timeout or error blocks egress
in enforce mode.

| Key | Default | Purpose |
|-----|---------|---------|
| `scanner.type` | `regex` | `regex` (built-in), `presidio` (Presidio analyzer REST sidecar), `http` (custom engine speaking the Presidio wire format), or `llm` (OpenAI-compatible endpoint prompted for NER, e.g. Ollama). |
| `scanner.endpoint` | — | `http(s)://host:port` or `unix:///path/to.sock`. Required for `presidio`/`http`; defaults to `ollama_base_url` + `/v1` for `llm`. |
| `scanner.timeout` | `10s` | Per-scan deadline. No retries — a timeout is an engine failure and blocks in enforce mode. |
| `scanner.min_score` | `0.5` | Entities below this confidence are discarded. |
| `scanner.language` | `en` | Forwarded in Presidio `/analyze` requests. |
| `scanner.offset_encoding` | per type | Override the offset encoding the engine reports: `byte` or `rune`. Defaults: `presidio` → `rune` (stock Presidio reports codepoint offsets), `http` → `byte`. |
| `scanner.name` | engine type | Detector identity recorded in evidence. |
| `scanner.engine_version` | — | Operator-declared version recorded in evidence. |
| `scanner.entities` | — | Optional entity-type list. presidio/http: forwarded in each `/analyze` request. llm: replaces the policy-derived list in the NER prompt — the lever for shrinking prompt size (and CPU scan latency) to just the types you govern. |
| `scanner.health_check` | `true` | Eager startup probe; Talon refuses to start when the engine is unreachable. |
| `scanner.llm.model` | — | Model id for `type: llm` (required), e.g. `llama3.1:8b`. |
| `scanner.llm.confidence` | `0.8` | Confidence assigned to LLM-detected entities. |

```yaml
scanner:
  type: presidio
  endpoint: "http://localhost:5002"
  timeout: "10s"
  name: "presidio-prod"
  engine_version: "2.2.354"
```

Under `sovereignty.deployment_mode: air_gap`, only provably local endpoints
are accepted (unix sockets, loopback, private/link-local addresses). See
[External scanner engines](external-scanners.md) for the wire protocol,
fail-closed semantics, and deployment patterns.

---

### Compliance block (controller identity)

Optional. Org-level declared facts for auditor exports, owned by the platform team together with the DPO. The controller identity populates GDPR Art. 30(1)(a) in the RoPA export; per-agent processing declarations live in `agent.talon.yaml` (see above).

```yaml
compliance:
  controller:
    name: "Example GmbH"
    contact: "privacy@example.eu"
    dpo_contact: "dpo@example.eu"
    address: "Examplestr. 1, 10115 Berlin, Germany"
    # representative: "Example EU Rep B.V."   # where applicable (GDPR Art. 27)
```

---

### Gateway block

When `talon serve --gateway` is used, the `gateway:` block in `talon.config.yaml` configures the LLM API proxy. Key sections:

| Section | Purpose |
|---------|---------|
| `gateway.mode` | `enforce`, `shadow`, or `log_only`. Runtime default when omitted: `enforce`. Generated starter configs set `shadow` for a safe rollout. **Two control classes (#266):** HARD platform boundaries — authentication, agent identity, and data-sovereignty `eu_strict` — block in **every** mode. OBSERVABLE governance controls — PII, tools, attachments, provider/model allowlists, budgets, ordinary egress — block only in `enforce`; `shadow` evaluates and records their would-be decision without blocking, and `log_only` additionally skips OPA policy evaluation (records detections only). So `eu_strict` still blocks a non-EU provider even in shadow/log_only — forwarding EU-resident data merely to observe would itself breach residency. |
| `gateway.providers` | LLM provider connections (base URL, secret name, region, allowed/blocked models — destination constraints) |
| `gateway.organization_policy` | The organization policy every agent inherits, split into two explicit classes (#287): `defaults:` — per-agent starting values an agent override may **replace** (`pii_action`, `response_pii_action`, `daily_cost` / `monthly_cost` / `session_cost`, `tool_policy_action`, `attachment_policy`) — and `constraints:` — organization-wide **hard bounds** an agent may only tighten within, never escape (`allowed_providers`, `allowed_models` / `blocked_models`, `allowed_tools`, `forbidden_tools`, `max_daily_cost` / `max_monthly_cost` / `max_session_cost`, `max_data_tier`, `egress`). Org-owned observability scalars stay top-level: `log_prompts` / `log_responses` / `log_response_preview_chars`, `scan_tool_content`. Renamed from `default_policy` (#266). |
| `gateway.rate_limits` | `global_requests_per_min` and `per_agent_requests_per_min` |
| `gateway.organization_policy.scan_tool_content` | Observation-only PII scan of tool-related request content: `evidence_only` (default) records findings in signed evidence (`classification.tool_content`) without influencing enforcement; `off` disables it. A top-level `organization_policy` key (not under `defaults:`/`constraints:` — it is org-owned observability with no agent interaction). Enforcement on tool content is not offered until per-block-type tool redaction exists (#212). |
| `gateway.timeouts` | Upstream timeout budgets, one per request phase (see below) |

**Traffic identity is not configured in this file — but fleet membership is.** Agents are defined in `agent.talon.yaml` files (one per AI use case), each bound to a vault key via `agent.key.secret_name` — see [Agent identity and key binding](#agent-identity-and-key-binding). At startup the gateway builds an immutable identity registry from them and requires at least one keyed agent. Two membership modes:

- **`agents_dir` (fleet mode, #267):** set the top-level `agents_dir:` key (or `TALON_AGENTS_DIR`) to a directory that is scanned recursively at startup — every file named exactly `agent.talon.yaml` under it is one loaded agent with its own key. When set, the directory is **authoritative for fleet membership**: `default_policy` no longer defines an agent (no mode merging). The scan is **fail-closed**: a schema-invalid file, an unknown key (typo), or two files sharing an `agent.name` reject the whole scan with an error naming the offending paths — startup refuses rather than serving a partial fleet. Hidden (dot-prefixed) directories are skipped; symlinked directories are not followed. Validate the directory with `talon validate --dir <dir>` (or just `talon validate` when `agents_dir` is configured); `talon doctor` preflights the identical scan + registry dry-run.
- **Single-file mode (default):** without `agents_dir`, exactly one agent policy is loaded — selected via `TALON_DEFAULT_POLICY` (default `agent.talon.yaml`) or `--policy`.

**Periodic safe reload (`agents_reload_interval`, #269).** `talon serve` re-scans the agent source (single-file or `agents_dir`) on this cadence (default `30s`; `"0"` disables; a negative value is a config error, not a silent disable; sub-second values are floored to 1s; an unchanged scan is a digest compare — no vault I/O, no evidence). A valid change activates as **one atomic generation swap** (catalog + compiled bundles + identity registry together), records a signed `config_reload` fact naming the generation, and rolls the swap back if that record cannot be written. Registry construction is **mode-aware and vault-independent for unchanged bindings**: an unchanged agent key is reused from the previous generation, so an emergency `disable` (or any policy edit) never depends on re-reading the vault binding it is changing; single-file native-only agents (no key binding) reload without a registry. An **invalid edit never takes a working fleet offline**: the last-known-good generation keeps serving, the rejection is logged loudly and recorded once per distinct broken state — a failed rejection-evidence write is retried on the next tick so a temporary outage never loses the record — and reverting the edit clears the rejection. In-flight requests and runs finish on the generation they captured at entry. `GET /v1/agents/fleet` (admin) reports the active generation, membership with `enabled` flags, and the most recent rejection with per-path causes from **one coherent read** (a rolled-back generation is never reported active) — the running server is the operational source of truth.

**Removed-agent data lifecycle (`orphan_retention_days`, #269).** Memory and session rows whose agent has left the catalog (removed by a reload) age out under this fixed org-level floor (default `90`), independent of any live agent policy — so orphaned data can never persist indefinitely. Rows for agents still in the catalog follow that agent's own `audit.retention_days` / `memory.retention_days`.

**Hot vs restart-required.** Hot-reloadable: agent file contents (`enabled`, identity metadata, key binding *name*, policy overrides) and `agents_dir` membership. Restart-required: trigger/webhook **definitions** (#297 — dispatch still re-resolves the current generation, so `enabled` and policy edits govern the next firing), `gateway:` block (organization policy, providers, mode), listeners/ports, scanner infrastructure, pricing and sovereignty. **Key rotation** via `talon secrets set` alone is not detected (the file digest is unchanged) — rotate = set the secret + restart, or touch the agent file. **Secret deletion/revocation of an *enabled* agent is likewise NOT a hot revocation:** the reload cannot build a valid registry for that agent, so the whole generation is rejected and last-known-good keeps the old key serving. To revoke access, **disable** the agent — that IS hot: the disabled generation activates with the prior key carried forward as a *denial-only* identity (the gateway returns an attributed 403; the tenant-API surface rejects it), so the old credential authorizes nothing — or restart.

**`talon agents enable|disable <name>` (#268).** The config-backed kill switch: `enabled: false` denies NEW work for that agent (gateway requests → attributed 403 `agent_disabled` in **every** mode including shadow; native runs and trigger dispatch → refused before any lifecycle state) while in-flight work finishes. The command is **host-local by design** (it edits the YAML on this machine; remote administration is out of scope), rewrites the file atomically via a structural YAML edit that preserves comments, and records **intent + completion** as signed evidence in the agent's tenant — a failed completion record rolls the file back so recorded and actual state never diverge. A running `talon serve` applies the change within the reload interval.

```
talon.config.yaml
└── agents_dir: ./agents

./agents/
├── customer-support/agent.talon.yaml
├── coding/agent.talon.yaml
└── summarizer/agent.talon.yaml
```

**Every execution surface resolves the same fleet (#267).** Each discovered agent gets a **compiled runtime bundle** — its own OPA engine, policy-aware PII scanner, and router (routing rules + cost limits over the shared provider clients) — published as ONE atomic generation. The gateway identity registry, `talon run --agent <name>`, the server run API (`/v1/agents/run`, native chat), and trigger dispatch all resolve agents from that catalog, so an agent can never execute under another agent's engine or routing; a run captures one generation at entry and completes under it. Schedules and webhooks register at startup for every discovered agent (definition changes are restart-required, #297); memory retention runs per agent under that agent's own policy. Naming an unknown agent errors explicitly, listing the discovered agents (#290; see LIMITATIONS.md §8 for the remaining single-policy edges: MCP/graph interception, offline `talon costs` caps).

**Removed keys fail validation** (breaking changes, #266/#287): `gateway.callers[]` (with `tenant_key`), `gateway.default_policy`, `organization_policy.require_caller_id`, `identify_by: source_ip`, `trusted_proxy_cidrs`, and `rate_limits.per_caller_requests_per_min` are rejected at config load with an explicit error naming the replacement. The flat `organization_policy` keys are likewise rejected with migration errors naming each key's new home (#287): `default_pii_action` → `defaults.pii_action`, `response_pii_action` → `defaults.response_pii_action`, `max_daily_cost` / `max_monthly_cost` → `defaults.daily_cost` / `defaults.monthly_cost` (the per-agent baselines the old keys were) or `constraints.max_daily_cost` / `max_monthly_cost` (new: org ceilings no agent can exceed), `tool_policy_action` → `defaults.tool_policy_action`, `attachment_policy` → `defaults.attachment_policy`, and `allowed_providers`, `allowed_models` / `blocked_models`, `max_data_tier`, `forbidden_tools`, `egress` → the same names under `constraints.`. A config written for a removed layout never runs silently ungoverned.

**Unknown keys fail load** (strict decoding, #266): the entire `gateway:` block is decoded with unknown-field rejection, because several of its settings enforce security boundaries — a typo like `allowed_provider:` must fail loudly rather than silently disable an intended organization hard constraint. Gateway settings must live under a top-level `gateway:` block: the old root-layout form (gateway fields at the file root) is removed and fails load with a migration error, because it could only ever be decoded permissively. The accepted surface is published as `schemas/talon.config.schema.json` and kept in lockstep with the runtime by a parity test (`TestConfigSchema_RuntimeParity`).

**Model-less requests fail closed under model policies**: the OpenAI-compatible extractor does not require a `model` field, and some compatible endpoints apply a server-side default. When any model allowlist/blocklist (agent or organization) is active, a request that omits its model is denied with `model_required_for_policy_evaluation` — the prompt never crosses the provider boundary unevaluated, and `blocked_models: ["*"]` genuinely blocks every request.

#### Identity resolution and effective policy

Every request to the proxy presents an agent key (`Authorization: Bearer <key>` or `x-api-key: <key>`). The gateway matches it against the identity registry in constant time; an unknown or missing key is rejected with `401 Invalid or missing agent key`. There is no source-IP identity and no anonymous fallback — the only non-key path is the explicit synthetic identity injected in-process by `talon serve --proxy-quickstart`.

```
presented key ──► known agent? ──yes──► agent identity ─► org baseline + agent override ─► effective policy
                        │ no
                        ▼
                     reject      (only exception: explicit quickstart synthetic identity)
```

The effective policy for one request is: **organization baseline (`organization_policy.defaults`) → the agent's one override → provider destination constraints**. Provider constraints (`allowed_models` / `blocked_models`, `forbidden_tools`, `tool_policy_action` on the provider entry) are hard constraints applied to the already-resolved policy — not a second override layer. The organization additionally declares its own hard constraints (`organization_policy.constraints`: `allowed_providers`, `allowed_models` / `blocked_models`, `allowed_tools`, `forbidden_tools`, budget ceilings, `max_data_tier`, `egress`) that bind every agent regardless of its override. One function (`ResolveEffectivePolicy`, `internal/gateway/effective.go`) computes this for enforcement, failover candidate checks, `talon costs`, and the dashboard budget endpoint; nothing re-derives baseline + override independently.

Per-field contract (mirrors `internal/gateway/effective.go`; the code and this table are kept in sync):

| Field | Contract |
|---|---|
| `defaults.daily_cost` / `defaults.monthly_cost` | override replaces when > 0 |
| `defaults.session_cost` | override replaces when > 0 (#283) |
| `constraints.max_daily_cost` / `max_monthly_cost` / `max_session_cost` | org budget **ceilings**: enforced by their own Rego rules alongside the resolved per-agent cap; an override can never raise them; deny reasons name the organization (#287/#283); 0 = no ceiling |
| `defaults.pii_action` | monotonic: the baseline is a floor and the override applies only when **stricter** (`block` > `redact` > `warn` > `allow`); a weaker override is ignored |
| `defaults.response_pii_action` | baseline level: falls back to `defaults.pii_action`; override level: same monotonic tighten-only rule — and the override's **input** `pii_action` does **not** cascade to the response action |
| allowed / blocked models | override replaces when non-empty; organization lists (`constraints.allowed_models` / `.blocked_models`) and provider lists are hard constraints the override never escapes |
| `constraints.allowed_providers` | agent list narrows within the organization hard constraint; empty = unrestricted at that level; a provider must pass **both** lists |
| `constraints.max_data_tier` | organization cap is a ceiling; the agent override applies only when **lower** (tighter) |
| `allowed_tools` | most-specific non-empty list wins; `constraints.allowed_tools` is a **hard** org allowlist checked in addition — a tool must pass both (#282) |
| `constraints.forbidden_tools` | union of org ∪ provider ∪ override |
| `defaults.tool_policy_action` | operator layers merge most-specific (provider > org default); the agent layer is monotonic — an agent can tighten `filter` → `block` but never loosen `block` → `filter` (#287) |
| `defaults.attachment_policy` | baseline only (#266) |
| `constraints.egress` | logical intersection: the organization egress and the agent egress are both evaluated and a destination must pass **both** — the agent narrows within the org boundary, never widens or replaces it |

Timeout phases (`gateway.timeouts`):

| Key | Default | Bounds |
|-----|---------|--------|
| `connect_timeout` | `10s` | Connection establishment: TCP dial + TLS handshake. |
| `response_header_timeout` | `request_timeout` | Wait for upstream response headers (time-to-first-byte) after the request is sent. Non-streaming LLM calls with large inputs routinely take >10s before headers — keep this at least as generous as your longest expected generation. |
| `request_timeout` | `120s` | Entire request lifecycle for non-streaming responses, including reading the full body. Also bounds a streaming request until the response is identified as SSE; from that point `stream_idle_timeout` takes over (#217). Raise for long non-streaming generations. |
| `stream_idle_timeout` | `60s` | Maximum silence between upstream stream chunks. A live SSE stream may run past `request_timeout` as long as chunks keep arriving; silence longer than this aborts the stream with the family-correct terminal error event. `0` disables idle enforcement. Raise for slow local providers (CPU inference can pause >60s before the first token). |

Provider auth mode:

- `gateway.providers.<provider>.upstream_auth_mode`:
  - `secret` (default): read provider credential from Talon vault (`secret_name` required).
  - `client_bearer`: forward the presented bearer token upstream. **Rejected at config load outside `--proxy-quickstart`** — in a normal gateway the presented bearer is a Talon agent key, and forwarding it upstream would leak workload credentials (#266). The quickstart profile is built in-process, so no YAML config can enable this mode.

Responses API store handling:

- `gateway.providers.<provider>.responses_store_mode` controls the OpenAI Responses API `store` field:
  - `preserve` (default): forward the client's `store` intent untouched — an explicit `store: false` is honored for every client. This is the right choice for Codex CLI (which sends `store: false` and resends the full transcript each turn).
  - `force_if_absent`: set `store: true` only when the client sent no `store` field. Opt-in for clients that reference `previous_response_id` across turns (e.g. OpenClaw) — stored items are required or follow-up turns 404.
  - `force_true`: always set `store: true`, overriding an explicit client `store: false`. Any such override is recorded in signed evidence (gateway annotation `responses_store_overridden`), because it reverses the client's stated retention intent.

Quickstart note:

- `talon serve --proxy-quickstart` builds gateway config in memory (no YAML required).
- Use [proxy quickstart reference](proxy-quickstart.md) for quickstart flags/env and compatibility limits.

#### Egress rules (destination × data classification)

`gateway.organization_policy.constraints.egress` restricts which destinations (providers
and/or regions) each data classification tier may leave Talon for. The check runs in
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
  organization_policy:
    constraints:
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
  work for `policies.data_classification.max_data_tier` in agent files.
  Evidence records always store the numeric tier.

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
- Per-agent layer: `policies.egress` in the agent file is a **second
  boundary evaluated alongside** the organization policy — a destination must
  be permitted by **both** (logical intersection). The agent can only narrow
  within the organization boundary; it can never widen or replace it.
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
planes. (Note: `data_sovereignty_mode` is itself set by the top-level
[`sovereignty.mode`](#sovereignty-block-data-residency--air-gap) when present —
declare the posture there once.)

- `data_sovereignty_mode` (`eu_strict` / `eu_preferred` / `global`) applies
  when **Talon selects the provider** — agent runs (`talon run`, triggers,
  agent chat). The router filters candidates via `routing.rego` and records
  the choice in the `routing_decision` evidence section.
- Gateway `egress` rules apply when **the agent has already chosen the
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
  organization_policy:
    constraints:
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
  it admits an agent-chosen one.)

#### Provider fallback chains (error-driven failover)

**Scope: this is same-wire-format failover, not cross-provider translation.**
A chain moves traffic between endpoints that speak the same API — an
OpenAI-compatible endpoint to another OpenAI-compatible endpoint, or an
Anthropic-compatible endpoint to another Anthropic-compatible one. Talon does
not translate request/response schemas between families (e.g. OpenAI ↔
Anthropic); the body is forwarded as-is except for an optional model rewrite,
and cross-family chains are rejected at config load.

On a **transient** upstream failure (timeout, connection failure, HTTP 429 or
5xx) Talon retries the request against the ordered fallback chain. A
permanent error from the **primary** (401/403/4xx) passes through unchanged —
it never triggers failover. Once failover **is** engaged, only a successful
response ends the chain: a fallback candidate that fails for any reason
(including a permanent 401 from a misconfigured secret) is recorded as a
failed attempt and the walk continues to the next candidate. When the chain
is exhausted the request **fails closed**: the client gets an error and the
refusal is recorded as a governance outcome — a failed fallback is never
evidenced as "the provider actually used".

Every candidate passes a filter pipeline before dispatch:

- **Sovereignty (hard invariant):** under `sovereignty.mode: eu_strict` a
  non-EU/LOCAL candidate is skipped in every gateway mode, shadow included —
  Talon never dispatches outside EU/LOCAL under eu_strict.
- **Agent provider allowlist (hard):** a candidate outside the agent's
  `policies.allowed_providers` is never dispatched.
- **Target tool policy and gateway policy (mode-aware):** each candidate
  re-runs the target provider's tool policy and the full gateway policy with
  the candidate's provider, model, recomputed cost estimate, destination
  region, and session context — the same input surface as the primary. In
  `enforce` mode a denial skips the candidate; in `shadow` mode the would-be
  denial is recorded as a shadow violation and the dispatch proceeds (shadow
  never changes runtime behavior).

Gateway (proxy path) — chain per provider; all members must share the
provider's API family. The family defaults by name (`anthropic` → Anthropic
Messages API, everything else → OpenAI-compatible); set `api_family`
explicitly for aliased endpoints — it drives request parsing, PII redaction,
tool filtering, provider-native error shape, chain validation, and upstream
auth conventions (x-api-key + anthropic-version vs bearer):

```yaml
gateway:
  providers:
    openai:
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
      region: "EU"
      fallback:
        - provider: "mistral-eu"        # tried in order on transient failure
          model: "mistral-large-latest" # optional: rewrite the body's model field
    mistral-eu:
      base_url: "https://api.mistral.ai"
      secret_name: "mistral-api-key"
      region: "EU"
    anthropic-eu:
      base_url: "https://eu.anthropic.example.com"
      secret_name: "anthropic-eu-key"
      region: "EU"
      api_family: "anthropic"   # anthropic-compatible alias: joins anthropic chains
```

Agent runs (`talon run`) — chain per routing tier; candidates are re-checked
against the compliance routing policy (sovereignty) before dispatch:

```yaml
policies:
  model_routing:
    tier_1:
      primary: gpt-4o
      fallback_chain:        # supersedes the legacy single `fallback` for error-driven failover
        - mistral-large-latest
        - llama3:70b
```

Evidence: each failed attempt is a separate signed record
(`gateway_failover_attempt` / `llm_failover_attempt`, `failover.role:
failed_attempt`), and each failover engagement gets exactly one terminal
record — the fallback decision (`failover.role: fallback_decision` with the
provider actually used and links to the failed attempts) or the fail-closed
outcome (`failover.role: fail_closed`). For gateway requests the terminal
lives on the request's final record; agent runs persist a dedicated
`llm_failover_decision` record per engagement. All records of one engagement
share a `failover_group_id` — an agentic run makes many LLM calls under one
correlation ID, and each call's chain verifies independently. Verify with
`talon audit verify --failover [correlation-id]`. OTel spans expose
`talon.provider.original`, `talon.provider.selected`, and
`talon.provider.fallback_reason`.

**Relationship to `compliance.data_residency` (agent policy):** that field is
a *declaration*, not an enforcement knob — it is stamped into evidence and
used by auditor exports. If you declare `data_residency: eu` but run with
`data_sovereignty_mode: eu_preferred` or `global`, non-EU providers remain
reachable and `talon compliance ropa` adds a `consistency:` warning when
non-EU destinations appear in the data-flow evidence. To make enforcement
match the declaration, set `data_sovereignty_mode: eu_strict` (and configure
an EU or local provider).

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
- **Agent keys:** each agent's vault-bound traffic key (`agent.key.secret_name`) authenticates `/v1/proxy` **and** the tenant-scoped evidence/costs/status APIs, scoped to the agent's derived tenant.
- **Gateway:** Enable with `--gateway` and `--gateway-config <path>`. See [How to choose your integration path](../guides/choosing-integration-path.md) and gateway guides.
- **MCP proxy:** Enable with `--proxy-config <path>`. See [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md).
- **Auth model:** See [Authentication and key scopes](authentication-and-key-scopes.md) for endpoint-to-key mapping (agent keys vs admin key).
- **Operational control:** Run management, overrides, and tool approval gates are exposed via admin API. See [Operational control plane](operational-control-plane.md).

#### Tool approval remediation hook

The admin approval endpoint supports a minimal remediation mode that performs
re-redact/re-scan before approval is finalized:

```json
POST /v1/tool-approvals/{id}/decide
{
  "decision": "approve",
  "reason": "apply remediation",
  "remediation": { "mode": "re_redact_rescan" }
}
```

Behavior:

- If remediation passes verification, approval is recorded with remediation metadata.
- If remediation fails, the request remains pending (no bypass) and returns `422`.

### Observability

| Variable | Purpose | Default |
|----------|---------|---------|
| `TALON_OTEL_ENABLED` | Enable OpenTelemetry traces and metrics export. | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint (e.g. `http://localhost:4317`). | stdout |

See [Observability](../OBSERVABILITY.md) for the full metrics catalogue and [examples/observability](../../examples/observability/) for a local Prometheus + Grafana stack.
