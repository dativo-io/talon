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
| `gateway.mode` | `enforce`, `shadow`, or `log_only`. Runtime default when omitted: `enforce`. Generated starter configs set `shadow` explicitly for a safe rollout. |
| `gateway.providers` | LLM provider connections (base URL, secret name, allowed/blocked models) |
| `gateway.callers` | Application identities (tenant key, tenant, allowed providers, policy overrides) |
| `gateway.default_policy` | Server-wide defaults (PII action, cost caps, tool governance, attachment scanning, egress rules) |
| `gateway.rate_limits` | Global and per-caller request rate limits |
| `gateway.default_policy.scan_tool_content` | Observation-only PII scan of tool-related request content: `evidence_only` (default) records findings in signed evidence (`classification.tool_content`) without influencing enforcement; `off` disables it. Enforcement on tool content is not offered until per-block-type tool redaction exists (#212). |
| `gateway.timeouts` | Upstream timeout budgets, one per request phase (see below) |

Timeout phases (`gateway.timeouts`):

| Key | Default | Bounds |
|-----|---------|--------|
| `connect_timeout` | `10s` | Connection establishment: TCP dial + TLS handshake. |
| `response_header_timeout` | `request_timeout` | Wait for upstream response headers (time-to-first-byte) after the request is sent. Non-streaming LLM calls with large inputs routinely take >10s before headers — keep this at least as generous as your longest expected generation. |
| `request_timeout` | `120s` | Entire request lifecycle, including reading the full response body. Raise for long non-streaming generations. |
| `stream_idle_timeout` | `60s` | Reserved for gaps between stream chunks (not yet enforced, #217). |

Provider auth mode:

- `gateway.providers.<provider>.upstream_auth_mode`:
  - `secret` (default): read provider credential from Talon vault (`secret_name` required).
  - `client_bearer`: forward caller bearer upstream (quickstart profile only).

Responses API store handling:

- `gateway.providers.<provider>.responses_store_mode` controls the OpenAI Responses API `store` field:
  - `preserve` (default): forward the client's `store` intent untouched — an explicit `store: false` is honored for every client. This is the right choice for Codex CLI (which sends `store: false` and resends the full transcript each turn).
  - `force_if_absent`: set `store: true` only when the client sent no `store` field. Opt-in for clients that reference `previous_response_id` across turns (e.g. OpenClaw) — stored items are required or follow-up turns 404.
  - `force_true`: always set `store: true`, overriding an explicit client `store: false`. Any such override is recorded in signed evidence (gateway annotation `responses_store_overridden`), because it reverses the client's stated retention intent.

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
planes. (Note: `data_sovereignty_mode` is itself set by the top-level
[`sovereignty.mode`](#sovereignty-block-data-residency--air-gap) when present —
declare the posture there once.)

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
is exhausted the request **fails closed**: the caller gets an error and the
refusal is recorded as a governance outcome — a failed fallback is never
evidenced as "the provider actually used".

Every candidate passes a filter pipeline before dispatch:

- **Sovereignty (hard invariant):** under `sovereignty.mode: eu_strict` a
  non-EU/LOCAL candidate is skipped in every gateway mode, shadow included —
  Talon never dispatches outside EU/LOCAL under eu_strict.
- **Caller provider allowlist (hard):** a candidate outside the caller's
  `allowed_providers` is never dispatched.
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
- **Tenant keys:** Configure per-caller `gateway.callers[].tenant_key` values for gateway and tenant-scoped API access.
- **Gateway:** Enable with `--gateway` and `--gateway-config <path>`. See [How to choose your integration path](../guides/choosing-integration-path.md) and gateway guides.
- **MCP proxy:** Enable with `--proxy-config <path>`. See [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md).
- **Auth model:** See [Authentication and key scopes](authentication-and-key-scopes.md) for endpoint-to-key mapping (tenant keys vs admin key).
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
