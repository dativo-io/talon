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
| **Created by** | `talon init` | `talon init` |
| **Loaded by** | `policy.LoadPolicy()` | `config.Load()` (Viper) + `gateway.LoadGatewayConfig()` |
| **CLI override** | `--policy <path>` | `--config <path>`, `--gateway-config <path>` |

**Rule of thumb:** if a change affects *what an agent may do*, edit `agent.talon.yaml`. If it affects *where traffic goes or how the platform is wired*, edit `talon.config.yaml`.

---

## agent.talon.yaml (Agent Policy)

Defines governance rules for an individual agent. See the [Policy cookbook](../guides/policy-cookbook.md) for copy-paste snippets and the JSON schema (`schemas/agent.talon.schema.json`) for the full structure.

Key top-level sections:

| Section | Purpose |
|---------|---------|
| `agent` | Name, description, version, model tier |
| `capabilities` | Allowed tools, data sources, forbidden patterns |
| `policies` | Cost limits, rate limits, model routing, data classification, time restrictions |
| `memory` | Governed self-improvement (categories, retention, dedup) |
| `triggers` | Cron schedules and webhook definitions |
| `secrets` | Allowed/forbidden secret names for this agent |
| `attachment_handling` | Prompt injection scanning, sandboxing mode |
| `audit` | Log level, retention, prompt/response inclusion |
| `compliance` | Frameworks (GDPR, EU AI Act, ISO 27001, NIS2, DORA), data residency, risk level |
| `metadata` | Department, owner, tags |

See [Memory governance](../MEMORY_GOVERNANCE.md) for the full memory reference. Key memory options:

| Key | Purpose |
|-----|---------|
| `memory.enabled` | Turn memory on or off. |
| `memory.mode` | `active` (persist + inject), `shadow` (log only, no persist), or `disabled`. |
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

### Gateway block

When `talon serve --gateway` is used, the `gateway:` block in `talon.config.yaml` configures the LLM API proxy. Key sections:

| Section | Purpose |
|---------|---------|
| `gateway.mode` | `enforce`, `shadow`, or `log_only` |
| `gateway.providers` | LLM provider connections (base URL, secret name, allowed/blocked models) |
| `gateway.callers` | Application identities (API key, tenant, allowed providers, policy overrides) |
| `gateway.default_policy` | Server-wide defaults (PII action, cost caps, tool governance, attachment scanning) |
| `gateway.rate_limits` | Global and per-caller request rate limits |
| `gateway.timeouts` | Connect, request, and stream idle timeouts |

### Server and API

- **API keys:** Set `TALON_API_KEYS` as comma-separated entries; each entry is a key or `key:tenant_id`.
- **Gateway:** Enable with `--gateway` and `--gateway-config <path>`. See [How to choose your integration path](../guides/choosing-integration-path.md) and gateway guides.
- **MCP proxy:** Enable with `--proxy-config <path>`. See [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md).
