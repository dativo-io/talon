# Configuration and environment

This reference describes environment variables and configuration used by Talon. For policy structure (e.g. `.talon.yaml` schema) see the [Policy cookbook](../guides/policy-cookbook.md) and the example files in the repository.

---

## Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `TALON_DATA_DIR` | Base directory for state (vault, evidence, memory DBs). For project-scoped evaluation use `TALON_DATA_DIR=$(pwd)/.talon`. | `~/.talon` |
| `TALON_SECRETS_KEY` | AES-256 key: 32 raw bytes or 64 hex chars (256 bits). | Auto-derived per machine |
| `TALON_SIGNING_KEY` | HMAC key: ≥32 raw bytes or 64+ hex chars (≥256 bits). | Auto-derived per machine |
| `TALON_DEFAULT_POLICY` | Default policy filename. | `agent.talon.yaml` |
| `TALON_MAX_ATTACHMENT_MB` | Max attachment size in MB. | `10` |
| `TALON_OLLAMA_BASE_URL` | Ollama endpoint. | `http://localhost:11434` |
| `OPENAI_API_KEY` | OpenAI key (dev fallback when not in vault). | — |
| `OPENAI_BASE_URL` | OpenAI-compatible API base URL (e.g. for tests). | — |
| `ANTHROPIC_API_KEY` | Anthropic key (dev fallback). | — |
| `AWS_REGION` | AWS region for Bedrock. | — |

---

## Crypto keys

On first run with no keys configured, Talon derives deterministic keys from the data directory path. This is fine for local development but **not for production**. Set explicit keys with full AES-256 / HMAC strength (256 bits). Keys may be given as **hex**: 64 hex characters decode to 32 bytes.

```bash
# 64 hex chars → 32 bytes = 256 bits (full AES-256 strength)
export TALON_SECRETS_KEY=$(openssl rand -hex 32)
export TALON_SIGNING_KEY=$(openssl rand -hex 32)
```

---

## Server and API

- **API keys:** Set `TALON_API_KEYS` as comma-separated entries; each entry is a key or `key:tenant_id`.
- **Gateway:** Enable with `--gateway` and `--gateway-config <path>`. See [How to choose your integration path](../guides/choosing-integration-path.md) and gateway guides.
- **MCP proxy:** Enable with `--proxy-config <path>`. See [Vendor integration guide](../VENDOR_INTEGRATION_GUIDE.md).

---

## Memory and policy (.talon.yaml)

See [Memory governance](../MEMORY_GOVERNANCE.md) for full reference. Key options:

| Key | Purpose |
|-----|---------|
| `memory.enabled` | Turn memory on or off. |
| `memory.mode` | `active` (persist + inject), `shadow` (log only, no persist), or `disabled`. |
| `memory.allowed_categories` | Categories the agent may write (e.g. `domain_knowledge`, `factual_corrections`, `user_preferences`, `procedure_improvements`). |
| `memory.prompt_categories` | Categories to inject into prompts (empty = all allowed). |
| `memory.max_prompt_tokens` | Cap on memory tokens injected. With a run prompt, retrieval is relevance-scored; otherwise timestamp-ordered. Injected order is by trust (highest first). |
| `memory.governance.dedup_window_minutes` | When > 0, same input within the window does not create a new entry. 0 = disabled. |
