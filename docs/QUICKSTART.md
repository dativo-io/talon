# Talon Quick Start

Get from zero to a policy-enforced AI agent in under 5 minutes.

## Prerequisites

- Go 1.22+ (for building from source) or a pre-built binary
- An LLM API key (OpenAI, Anthropic) or a local Ollama instance

## 1. Install

Talon needs Go 1.22+ and CGO (for SQLite).

```bash
# From source (any branch: clone then build)
git clone https://github.com/dativo-io/talon.git && cd talon
make build    # → bin/talon
# or: make install   # → $GOPATH/bin/talon

# Or install a released version
go install github.com/dativo-io/talon/cmd/talon@latest
```

**macOS:** If `go install` or `go build` fails with `unsupported tapi file type '!tapi-tbd'`, use `make build` (it uses the system Clang), or run `CC=/usr/bin/clang CGO_ENABLED=1 go build -o bin/talon ./cmd/talon/`.

## 2. Initialize a Project

```bash
mkdir my-agents && cd my-agents
talon init
```

Optional: `talon init --name my-agent --owner you@company.com` to set agent name and owner. This creates `agent.talon.yaml` and `talon.config.yaml` with sensible defaults: cost limits, PII detection enabled, and model routing.

## 3. Configure an LLM Provider

**Option A — Environment variable (quickstart / dev):**

```bash
export OPENAI_API_KEY=sk-proj-...
# Or: export ANTHROPIC_API_KEY=ant-...
# Or: nothing needed for Ollama (runs on localhost:11434)
```

**Option B — Secrets vault (recommended for production):**

```bash
talon secrets set openai-api-key "sk-proj-..."
```

Vault-stored keys are encrypted at rest (AES-256-GCM), scoped per tenant/agent via ACLs, and every access is audit-logged. The runner tries the vault first and falls back to env vars.

## 4. Run Your First Agent

**First run without AWS?** The default `talon init` template sets **tier_2** (used for PII-bearing inputs) to a Bedrock-only model. If you only have an OpenAI or Anthropic API key and no AWS Bedrock, either use the **telecom-eu** pack (`talon init --pack telecom-eu`) or edit `agent.talon.yaml`: set `policies.model_routing.tier_2.bedrock_only: false` and set `primary` (and optional `fallback`) to an OpenAI or Anthropic model (e.g. `gpt-4o`, `gpt-4o-mini`). Otherwise tier-2 requests will fail with "provider bedrock: provider not available".

```bash
talon run "Summarize the key trends in European AI regulation"
```

Output:

```
✓ Policy check: ALLOWED

The European Union has been at the forefront of AI regulation...

✓ Evidence stored: req_xxxxxxxx
✓ Cost: €0.0018 | Duration: 1250ms
```

What happened behind the scenes:

1. **Policy loaded** from `agent.talon.yaml`
2. **Input classified** — PII scanner checked for IBAN, email, phone, etc.
3. **Policy evaluated** — OPA checked cost budgets, data tier, time restrictions
4. **LLM routed** — tier-based model selection (public data → cheaper models)
5. **API key resolved** — vault lookup, then env-var fallback
6. **Response classified** — output scanned for PII leakage
7. **Evidence stored** — HMAC-SHA256 signed record in SQLite

## 5. Try a Dry Run

See the policy decision without making an LLM call:

```bash
talon run --dry-run "What is the company revenue?"
# ✓ Policy check: ALLOWED (dry run, no LLM call)
```

## 6. Try a Policy Block

Edit `agent.talon.yaml` and set a very low daily budget:

```yaml
policies:
  cost_limits:
    daily: 0.001
```

Run again:

```bash
talon run "Summarize EU regulation trends"
# ✗ Policy check: DENIED
#   Reason: budget_exceeded
```

The denial is still recorded as evidence — proof that the policy engine caught it.

## 7. Process Attachments

Attachments are automatically scanned for prompt injection and sandboxed:

```bash
talon run --attach report.pdf "Summarize this document"
```

If injection patterns are detected, the policy controls what happens: `block_and_flag`, `warn`, or `log`.

## 8. Manage Secrets

```bash
# Store a secret (encrypted at rest)
talon secrets set anthropic-api-key "ant-..."

# List secrets (values never shown)
talon secrets list
#   - openai-api-key (accessed 3 times)
#   - anthropic-api-key (accessed 0 times)

# View access audit log
talon secrets audit
#   2026-02-18 14:30:00 | ✓ ALLOWED | default/default | openai-api-key

# Rotate (re-encrypt with fresh nonce)
talon secrets rotate openai-api-key
```

## 9. Query the Audit Trail

```bash
# List recent evidence records
talon audit list --limit 10
#   ✓ req_xxxxxxxx | 2026-02-18 14:30:00 | default/default | gpt-4o-mini | €0.0018 | 1250ms

# Show full evidence record (HMAC-verified; includes classification, PII, policy reasons)
talon audit show <evidence-id>

# Verify signature integrity and see compact summary (tier, PII, policy)
talon audit verify <evidence-id>
#   ✓ Evidence <evidence-id>: signature VALID (HMAC-SHA256 intact)
#   2026-02-21T11:28:45+01:00 | default/slack-support-bot | gpt-4o-mini | €0.0000 | 909ms
#   Policy: ALLOWED | Tier: 2→0 | PII: EMAIL_ADDRESS | Redacted: true

# Export for compliance (CSV/JSON include input_tier, output_tier, pii_detected, policy_reasons, etc.)
talon audit export --format csv --from 2026-02-01 --to 2026-02-28
talon audit export --format json --limit 1000
```

## 10. Run the HTTP Server and Dashboard

Start the full API server with embedded dashboard:

```bash
# Optional: set API keys (comma-separated; each entry is key or key:tenant_id)
export TALON_API_KEYS="your-api-key:default"

# Start server (default port 8080)
talon serve

# Or with options
talon serve --port 8080 --dashboard
```

- **Health:** `curl http://localhost:8080/health` or `http://localhost:8080/v1/health?detail=true`
- **Dashboard:** Open `http://localhost:8080/dashboard` in a browser. Set `window.TALON_API_KEY = 'your-api-key'` in the console if you use API key auth.
- **Agent run via API:** `curl -X POST http://localhost:8080/v1/agents/run -H "X-Talon-Key: your-key" -H "Content-Type: application/json" -d '{"prompt":"Hello"}'`
- **OpenAI-compatible chat:** `POST /v1/chat/completions` with `X-Talon-Key` and body `{ "model": "gpt-4", "messages": [{"role":"user","content":"..."}] }`

**MCP proxy (vendor integration):** To route a third-party vendor (e.g. Zendesk AI) through Talon for audit and PII redaction:

```bash
talon serve --port 8080 --proxy-config examples/vendor-proxy/zendesk-proxy.talon.yaml
```

Point the vendor at `https://your-talon-host/mcp/proxy`. See [VENDOR_INTEGRATION_GUIDE.md](VENDOR_INTEGRATION_GUIDE.md).

## 11. Multi-Tenant Usage

Scope everything by tenant:

```bash
talon run --tenant acme --agent sales-analyst "Q4 revenue analysis"
talon audit list --tenant acme
talon secrets set openai-api-key "sk-acme-..." # per-tenant key in vault
```

## Configuration Reference

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `TALON_DATA_DIR` | Base directory for state (vault, evidence, memory DBs). For **project-scoped onboarding** or evaluation, use `TALON_DATA_DIR=$(pwd)/.talon` so each project has its own vault and audit data. | `~/.talon` |
| `TALON_SECRETS_KEY` | AES-256 key: 32 raw bytes or 64 hex chars (256 bits) | Auto-derived per machine |
| `TALON_SIGNING_KEY` | HMAC key: ≥32 raw bytes or 64+ hex chars (≥256 bits) | Auto-derived per machine |
| `TALON_DEFAULT_POLICY` | Default policy filename | `agent.talon.yaml` |
| `TALON_MAX_ATTACHMENT_MB` | Max attachment size | `10` |
| `TALON_OLLAMA_BASE_URL` | Ollama endpoint | `http://localhost:11434` |
| `OPENAI_API_KEY` | OpenAI key (dev fallback) | — |
| `OPENAI_BASE_URL` | OpenAI-compatible API base URL (e.g. mock server for tests) | — |
| `ANTHROPIC_API_KEY` | Anthropic key (dev fallback) | — |
| `AWS_REGION` | Bedrock region | — |

### Crypto Key Warning

On first run with no keys configured, Talon derives deterministic keys from your data directory path. This is fine for local development but **not for production**. Set explicit keys with full AES-256 / HMAC strength (256 bits). Keys may be given as **hex**: 64 hex characters decode to 32 bytes.

```bash
# 64 hex chars → 32 bytes = 256 bits (full AES-256 strength)
export TALON_SECRETS_KEY=$(openssl rand -hex 32)
export TALON_SIGNING_KEY=$(openssl rand -hex 32)
```

## 12. Agent Memory

Agent memory is **off by default**. The default `talon init` config does not include a `memory:` block, so `talon memory list` and `talon memory health` will be empty until you enable memory in your policy (see [MEMORY_GOVERNANCE.md](MEMORY_GOVERNANCE.md)).

When enabled, agents automatically compress each run into governed observations. Memory is controlled via policy:

```yaml
# In agent.talon.yaml
memory:
  enabled: true
  mode: active              # active | shadow | disabled
  max_entries: 1000         # cap per agent (oldest evicted)
  max_entry_size_kb: 16     # reject oversized entries
  max_prompt_tokens: 2000   # cap memory tokens in LLM prompts
  retention_days: 90        # auto-purge old entries
  prompt_categories:        # which categories enter LLM context (empty = all)
    - domain_knowledge
    - procedure_improvements
```

Use **shadow mode** during evaluation: all governance checks run and results are logged, but no data is persisted. Switch to `active` when ready.

Browse and manage memory via the CLI:

```bash
# Browse memory index
talon memory list --agent sales-analyst

# Full-text search across entries
talon memory search "revenue target"

# Full entry detail
talon memory show mem_a1b2c3d4

# Trust distribution and conflicts
talon memory health --agent sales-analyst

# Rollback to a specific version
talon memory rollback --agent sales-analyst --to-version 5 --yes

# Evidence chain verification
talon memory audit --agent sales-analyst
```

Every memory write passes through a multi-layer governance pipeline (hardcoded forbidden categories, max size, OPA policy, category validation, PII scan, policy override detection, provenance tracking, conflict detection) and links to an HMAC-signed evidence record. Memory reads injected into LLM prompts are recorded in evidence for traceability.

See [MEMORY_GOVERNANCE.md](MEMORY_GOVERNANCE.md) for full details.

## 13. Shared Enterprise Context

Mount read-only company knowledge into agent prompts:

```yaml
# In agent.talon.yaml
context:
  shared_mounts:
    - name: company-procedures
      path: ./context/procedures.md
      classification: tier_0
```

Use `<private>...</private>` tags in context files to exclude sensitive content from memory persistence. Use `<classified:tier_N>...</classified>` to propagate data tiers to model routing.

## 14. Triggers (Cron & Webhooks)

Run agents on a schedule or in response to events:

```yaml
# In agent.talon.yaml
triggers:
  schedule:
    - cron: "0 9 * * 1-5"
      prompt: "Generate the daily compliance report"
      description: "Weekday morning compliance run"
  webhooks:
    - name: jira-update
      source: jira
      prompt_template: "Analyze JIRA update: {{.payload.issue.key}} — {{.payload.issue.fields.summary}}"
      require_approval: false
```

Start the trigger server:

```bash
talon serve --port 8080
```

Webhooks are available at `POST /v1/triggers/{name}`. The server also runs a daily retention loop that purges expired memory entries and enforces `max_entries`.

## Next Steps

- Edit `agent.talon.yaml` to tune cost limits, model routing, and compliance frameworks
- See [PERSONA_GUIDES.md](PERSONA_GUIDES.md) for role-based workflows (Compliance Officer, CTO, SecOps, FinOps, DevOps)
- See [MEMORY_GOVERNANCE.md](MEMORY_GOVERNANCE.md) for memory governance details
- See [VENDOR_INTEGRATION_GUIDE.md](VENDOR_INTEGRATION_GUIDE.md) to wrap existing AI vendors
- See [ADOPTION_SCENARIOS.md](ADOPTION_SCENARIOS.md) for migration paths
- See [ARCHITECTURE_MCP_PROXY.md](ARCHITECTURE_MCP_PROXY.md) for proxy mode details
