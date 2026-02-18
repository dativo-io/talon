# Talon Quick Start

Get from zero to a policy-enforced AI agent in under 5 minutes.

## Prerequisites

- Go 1.22+ (for building from source) or a pre-built binary
- An LLM API key (OpenAI, Anthropic) or a local Ollama instance

## 1. Install

```bash
# From source
go install github.com/dativo-io/talon/cmd/talon@latest

# Or download a release binary
curl -sSL https://get.talon.dativo.io | sh
```

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

# Verify signature integrity (use an ID from run output or audit list)
talon audit verify <evidence-id>
#   ✓ Evidence <evidence-id>: signature VALID (HMAC-SHA256 intact)
```

## 10. Multi-Tenant Usage

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
| `TALON_DATA_DIR` | Base directory for state | `~/.talon` |
| `TALON_SECRETS_KEY` | AES-256 encryption key (32 bytes) | Auto-derived per machine |
| `TALON_SIGNING_KEY` | HMAC signing key (≥32 bytes) | Auto-derived per machine |
| `TALON_DEFAULT_POLICY` | Default policy filename | `agent.talon.yaml` |
| `TALON_MAX_ATTACHMENT_MB` | Max attachment size | `10` |
| `TALON_OLLAMA_BASE_URL` | Ollama endpoint | `http://localhost:11434` |
| `OPENAI_API_KEY` | OpenAI key (dev fallback) | — |
| `ANTHROPIC_API_KEY` | Anthropic key (dev fallback) | — |
| `AWS_REGION` | Bedrock region | — |

### Crypto Key Warning

On first run with no keys configured, Talon derives deterministic keys from your data directory path. This is fine for local development but **not for production**. Set explicit keys:

```bash
export TALON_SECRETS_KEY=$(openssl rand -hex 16)   # 32 hex chars = 32-byte string
export TALON_SIGNING_KEY=$(openssl rand -hex 16)
```

## Next Steps

- Edit `agent.talon.yaml` to tune cost limits, model routing, and compliance frameworks
- See [VENDOR_INTEGRATION_GUIDE.md](VENDOR_INTEGRATION_GUIDE.md) to wrap existing AI vendors
- See [ADOPTION_SCENARIOS.md](ADOPTION_SCENARIOS.md) for migration paths
- See [ARCHITECTURE_MCP_PROXY.md](ARCHITECTURE_MCP_PROXY.md) for proxy mode details
