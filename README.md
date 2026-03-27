# Dativo Talon

```
$ talon audit list
ID          TIME                 CALLER        PII              COST(€)  MODEL         DECISION
evt_a1b2c3  2026-03-15T10:23:45  support-bot   email(1)         0.003    gpt-4o-mini   allowed
evt_d4e5f6  2026-03-15T10:24:12  hr-assistant  iban(2)          0.000    gpt-4o        blocked:pii
evt_x9y0z1  2026-03-15T10:24:45  eng-tools     none             0.000    —             blocked:tool
evt_g7h8i9  2026-03-15T10:25:01  eng-tools     none             0.012    claude-3.5    allowed
evt_j0k1l2  2026-03-15T10:25:30  support-bot   email(1),phone   0.004    gpt-4o-mini   allowed:redacted
```

One URL change. PII scan, tool block, tamper-proof record. No code rewrites.

Talon is a single Go binary in front of OpenAI, Anthropic, and Bedrock. Point your app at `localhost:8080/v1/proxy/openai` instead of `api.openai.com` — same API, same response. Every call is policy-checked, PII-scanned, cost-tracked, and logged. Works with Slack bots, OpenClaw, CoPaw, and other OpenAI-compatible clients. Built for EU teams that need strong governance signals (GDPR, NIS2, DORA, EU AI Act); Apache 2.0.

---



[CI](https://github.com/dativo-io/talon/actions/workflows/ci.yml)
[CodeQL](https://github.com/dativo-io/talon/actions/workflows/codeql.yml)
[Release](https://github.com/dativo-io/talon/actions/workflows/release.yml)
[Latest Release](https://github.com/dativo-io/talon/releases/latest)
[Go Report Card](https://goreportcard.com/report/github.com/dativo-io/talon)
[License](LICENSE)

### Trust Signals

- Release cadence: [23 tagged releases](https://github.com/dativo-io/talon/releases) (latest: `v1.3.0`, 2026-03-18)
- Supply-chain: [CodeQL](https://github.com/dativo-io/talon/actions/workflows/codeql.yml) + [security workflow](https://github.com/dativo-io/talon/actions/workflows/security.yml) + [GoReleaser](.goreleaser.yml)
- Verifiable evidence: `talon audit verify <evidence-id>`
- Social preview asset: [`web/social-preview.svg`](web/social-preview.svg) (set in repo settings as Open Graph image)

### Install Options (pick one)

- **Go (fastest):** `go install github.com/dativo-io/talon/cmd/talon@latest`
- **Release binary (checksummed):** [GitHub Releases](https://github.com/dativo-io/talon/releases/latest) + `checksums.txt`
- **Container image:** `ghcr.io/dativo-io/talon:latest` (also `:vX.Y.Z`, `:X.Y`)
- **Install script (checksum verification included):** `curl -sSL https://install.gettalon.dev | sh`

Note: GitHub may still show `Packages 0` in the sidebar. Use the release artifacts and GHCR image coordinates above as the source of truth.

Artifact verification quick check:

```bash
# verify release assets exist
LATEST=$(gh release view --json tagName -q .tagName)
gh release view "$LATEST" --json assets -q '.assets[].name'

# verify GHCR image is published
docker pull ghcr.io/dativo-io/talon:latest
```

### 60-Second Demo (no API key needed)

```bash
git clone https://github.com/dativo-io/talon && cd talon
cd examples/docker-compose && docker compose up

# In another terminal — send a request with PII:
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My email is jan@example.com and my IBAN is DE89370400440532013000. Help me reset my password."}]}'

# See the record (PII detected, cost, decision):
docker compose exec talon /usr/local/bin/talon audit list
```

The mock provider handles the LLM call. Evidence appears immediately — PII detected, cost logged, HMAC-signed record. [What exactly does Talon do to your request?](docs/explanation/what-talon-does-to-your-request.md)

### Proof In 30 Seconds

```bash
cd examples/docker-compose
docker compose up -d
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"my email is jan@example.com and iban DE89370400440532013000"}]}'
docker compose exec talon /usr/local/bin/talon audit list --limit 1
docker compose exec talon /usr/local/bin/talon audit show <evidence-id>
```

Expected outcome:
- request is accepted or policy-blocked based on your config
- evidence row includes PII types + decision
- `talon audit verify <evidence-id>` returns valid signature

Visual capture workflow (for release notes/social posts):

```bash
# generate deterministic sample records for screenshots/GIF capture
bash scripts/demo-recorder.sh
```



---

## What it stops

- **Your agent called `bulk_delete_users`.** A PII-only proxy (e.g. CloakLLM, or a DIY FastAPI proxy) never sees tool names — the LLM talks directly to your backend. Talon sits in front of the LLM and the tool layer: MCP `tools/call` and gateway requests are policy-checked before execution. Forbidden tools are blocked; every call is logged. You get a record nobody can quietly edit.
- **A prompt contained an IBAN and the model replied with it.** Logging after the fact does not stop the leak. Talon scans input (and optionally response) before the call completes; you can block, redact, or restrict to EU-only models when PII is detected. Budget is evaluated before the call, not after — unlike LiteLLM-style post-spend alerts.
- **You have no proof of what ran.** Spreadsheets and ad-hoc logs are easy to alter. Talon writes an HMAC-signed evidence record per request to SQLite; verify with `talon audit verify`. Export to CSV for your compliance officer.
- **Third-party AI (Zendesk, Intercom) is a black box.** You are liable even if they say they are compliant. Route them through Talon's MCP proxy: you get the same PII scan, tool filter, and tamper-proof record without the vendor rewriting their stack.

See also: [Why not just a PII proxy?](docs/explanation/why-not-a-pii-proxy.md)

## Three Ways to Adopt Talon

### 1. Already Using Third-Party AI Vendors? (MCP Proxy)

**Scenario:** You pay Many €/month for Zendesk AI Agent, Intercom, or HubSpot AI. It works great, but you can't prove GDPR compliance.

**Solution:** Route vendor through Talon's MCP proxy (30 minutes setup).

```yaml
# Point vendor to Talon, gain full visibility
agent:
  name: "zendesk-vendor-proxy"
  type: "mcp_proxy"

proxy:
  upstream: "https://zendesk-ai-agent.com"

pii_handling:
  redaction_rules:
    - field: "customer_email"
      method: "hash"
    - field: "customer_phone"
      method: "mask_middle"

compliance:
  frameworks: ["gdpr", "nis2"]
  audit_retention: 365
```

**Result:**

- ✅ Vendor keeps working (transparent proxy)
- ✅ You have a tamper-proof record (GDPR Article 30 exports)
- ✅ PII redacted before vendor access
- ✅ Can block forbidden operations

**See:** [VENDOR_INTEGRATION_GUIDE.md](docs/VENDOR_INTEGRATION_GUIDE.md)

---

### 2. Already Have Custom AI Automation? (Wrap with Talon)

**Scenario:** You built a Slack bot 6 months ago. Works great, but compliance officer needs verifiable records.

**Solution:** Add 5 lines of code to route through Talon (4 hours setup).

```python
# BEFORE (ungoverned)
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": query}]
)

# AFTER (governed) - 5 lines changed
response = requests.post("http://localhost:8081/v1/chat/completions", json={
    "agent_id": "slack-support-bot",
    "model": "gpt-4",
    "messages": [{"role": "user", "content": query}]
})
```

**Result:**

- ✅ Bot keeps working (same UX)
- ✅ Stronger GDPR + NIS2 control coverage with auditable records
- ✅ No rewrite needed
- ✅ Audit-ready in 1 day

**See:** [ADOPTION_SCENARIOS.md](docs/ADOPTION_SCENARIOS.md)

---

### 3. Building New AI Agents? (Native Talon)

**Scenario:** Greenfield project, want governance controls from Day 1.

**Solution:** Use Talon from the start (2 minutes to first agent).

```bash
# Install
go install github.com/dativo-io/talon/cmd/talon@latest
# macOS: if you see "unsupported tapi file type" or clang linker error, use:
#   CC=/usr/bin/clang go install github.com/dativo-io/talon/cmd/talon@latest
# or: curl -sSL https://install.gettalon.dev | sh

# Initialize (interactive wizard in a terminal; use --scaffold for quick defaults)
mkdir my-agents && cd my-agents
talon init

# Configure secrets (or use env: export OPENAI_API_KEY=sk-proj-...)
talon secrets set openai-api-key "sk-proj-..."

# Run first governed agent
talon run "Summarize EU AI regulation trends"
```

**Result:**

- ✅ Compliant from Day 1
- ✅ No custom policy code
- ✅ Policy-as-code in YAML
- ✅ Audit trail automatic

**See:** [QUICKSTART.md](docs/QUICKSTART.md)

---

## Install

Talon requires **Go 1.22+** and **CGO** (for SQLite). Standard options:

**From source (any branch, recommended for development):**

```bash
git clone https://github.com/dativo-io/talon.git
cd talon
git checkout main   # or feat/your-branch
make build          # → bin/talon
# or: make install  # → $GOPATH/bin/talon
```

On **macOS**, `make build` / `make install` use the system Clang by default so CGO linking works. If you use `go build` or `go install` directly and see `unsupported tapi file type '!tapi-tbd'`, set the compiler: `CC=/usr/bin/clang CGO_ENABLED=1 go build -o bin/talon ./cmd/talon/`.

**From a released version (stable):**

```bash
go install github.com/dativo-io/talon/cmd/talon@latest
# or a specific tag: ...@v1.0.0
```

**macOS:** If `go install` fails with `unsupported tapi file type '!tapi-tbd'` (Homebrew LLVM vs Apple SDK), use system Clang: `CC=/usr/bin/clang go install github.com/dativo-io/talon/cmd/talon@latest`. Or clone the repo and run `make install` (Makefile forces system Clang).

**Note:** You cannot install a branch with `go install ...@branch-name`; Go expects a module version (tag or pseudo-version). To run a branch, clone the repo and use `make build` or `make install` from that branch.

---

## Quick Start (2 minutes)

```bash
# Install (see Install section above), then:
mkdir my-agents && cd my-agents
talon init          # Interactive wizard (in a terminal); or: talon init --scaffold for quick defaults

# Set your LLM provider key (or use vault: talon secrets set openai-api-key "sk-...")
export OPENAI_API_KEY=sk-your-key
# Or: talon secrets set openai-api-key "sk-..."
# Also supports: ANTHROPIC_API_KEY, AWS_REGION (for Bedrock), Ollama (local, no key needed)

# Run your first governed agent
talon run "Summarize the key trends in European AI regulation"
```

You'll see:

```
✓ Policy check: ALLOWED

[Agent response appears here]

✓ Evidence stored: req_xxxxxxxx
✓ Cost: €0.0018 | Duration: 1250ms
```

Try a policy block — set `daily: 0.001` in your `agent.talon.yaml`, run again, and watch the policy engine deny the request:

```
✗ Policy check: DENIED
  Reason: budget_exceeded
```

Inspect and verify the evidence:

```bash
talon audit list --limit 10                    # List recent evidence
talon audit show <evidence-id>                 # Full record (classification, PII, HMAC status)
talon audit verify <evidence-id>               # Verify signature + compact summary
talon audit export --format csv --from ... --to ...  # Export for compliance (includes pii_detected, tiers)
```

(Evidence IDs are shown in run output, e.g. `req_xxxxxxxx`.)

## HTTP API Server

Run the full REST API, MCP server, and embedded dashboard:

```bash
# Set admin key (for admin + dashboard/metrics endpoints)
export TALON_ADMIN_KEY="replace-with-strong-admin-key"

# Start server (dashboard at / and /dashboard)
talon serve --port 8080

# With MCP proxy for vendor compliance (e.g. Zendesk AI)
talon serve --port 8080 --proxy-config examples/vendor-proxy/zendesk-proxy.talon.yaml

# With LLM API gateway (proxy mode: route OpenAI/Anthropic/Ollama traffic through Talon)
talon serve --port 8080 --gateway --gateway-config examples/gateway/talon.config.gateway.yaml
```

Endpoints include: `GET /v1/health`, `GET /v1/status`, `POST /v1/agents/run`, `POST /v1/chat/completions` (OpenAI-compatible), `GET /v1/evidence`, `GET /v1/costs`, `GET /v1/plans/pending` (plan review), `POST /mcp` (native MCP), `POST /mcp/proxy` (when proxy is configured), and `**POST /v1/proxy/{provider}/v1/chat/completions**` (LLM API gateway when `--gateway` is set; caller auth via `Authorization: Bearer <tenant-key>`). Tenant-scoped API routes use `Authorization: Bearer <tenant-key>`. Admin-only routes use `X-Talon-Admin-Key: <key>` (or bearer fallback).

For browser navigation to dashboards, include the admin key in the URL once:

- `http://localhost:8080/dashboard?talon_admin_key=YOUR_TALON_ADMIN_KEY`
- `http://localhost:8080/gateway/dashboard?talon_admin_key=YOUR_TALON_ADMIN_KEY`

Dashboard links preserve this key automatically for subsequent navigation.

**See:** [QUICKSTART.md](docs/QUICKSTART.md) for serve and dashboard usage.

## Vendor Integration (MCP Proxy)

Route third-party AI vendors (Zendesk, Intercom, HubSpot) through Talon for independent audit and PII redaction:

1. Create a proxy config (see `examples/vendor-proxy/zendesk-proxy.talon.yaml`).
2. Start Talon with `--proxy-config`:
  ```bash
   talon serve --port 8080 --proxy-config path/to/proxy.talon.yaml
  ```
3. Point the vendor at `https://your-talon-host/mcp/proxy`.

Talon intercepts MCP traffic, enforces policy, redacts PII, and records evidence. Modes: **intercept** (block forbidden), **passthrough** (log only), **shadow** (audit without blocking).

**See:** [VENDOR_INTEGRATION_GUIDE.md](docs/VENDOR_INTEGRATION_GUIDE.md) and [ARCHITECTURE_MCP_PROXY.md](docs/ARCHITECTURE_MCP_PROXY.md).

## LLM API Gateway (Proxy Mode)

Route raw LLM API traffic (OpenAI, Anthropic, Ollama) through Talon so desktop apps, Slack bots, and scripts get the same controls without code changes:

1. Create a gateway config (see `examples/gateway/talon.config.gateway.yaml`) with providers, caller tenant keys, and optional policy overrides (allowed models, cost limits).
2. Start Talon with `--gateway` and `--gateway-config`:
  ```bash
   talon serve --port 8080 --gateway --gateway-config path/to/gateway.yaml
  ```
3. Point your app at `https://your-talon-host/v1/proxy/ollama/v1/chat/completions` (or `openai`, `anthropic`) and send `Authorization: Bearer <caller-key>`.

Talon identifies the caller, enforces per-caller model and cost policy, records evidence, and forwards to the configured upstream. Costs appear in `GET /v1/costs` for the caller's tenant.

**See:** [OpenClaw integration](docs/guides/openclaw-integration.md), [CoPaw integration](docs/guides/copaw-integration.md), [Slack bot integration](docs/guides/slack-bot-integration.md), [Desktop apps](docs/guides/desktop-app-governance.md).

## Features

**Policy-as-Code** — Define agent policy in `agent.talon.yaml` files. Cost limits, data classification, model routing, tool access, time restrictions — all declarative, version-controlled, auditable.

**MCP-Native** — Talon speaks Model Context Protocol. Connect any MCP-compatible agent or tool. Every MCP tool call passes through the policy engine. Works as transparent proxy for third-party vendors.

**Vendor Integration** — Route third-party AI vendors (Zendesk, Intercom, HubSpot) through Talon's MCP proxy. Gain tamper-proof records, PII redaction, and policy enforcement without vendor rewrites. This supports audit readiness even with black-box SaaS.

**LLM API Gateway** — Route raw LLM API traffic (OpenAI, Anthropic, Ollama) through Talon at `/v1/proxy/`*. Desktop apps, Slack bots, and scripts use caller API keys; Talon enforces per-caller model and cost policy and records evidence. Same controls as native agents, zero app code changes beyond base URL.

**Audited Secrets Vault** — API keys encrypted at rest (AES-256-GCM). Per-agent ACLs. Every secret retrieval logged. Upgrade path to Infisical for rotation and SAML.

**Prompt Injection Prevention** — PDF/DOCX/HTML attachments are sandboxed automatically. Instruction-detection scanner flags injection attempts. Configurable: block, warn, or log.

**Agent Memory** — Agents write learnings to an audited soul directory. Every memory write passes through a multi-layer pipeline (hardcoded forbidden categories, OPA policy, PII scan, conflict detection) and is HMAC-signed. Shadow mode lets operators observe memory behavior before enabling writes. Retention policies auto-purge expired entries. Prompt injection controls filter which memories enter LLM context. Rollback to any previous state if memory poisoning is detected. Unlike MemOS or mem0, Talon's memory is a compliance asset — not just a developer convenience.

**Scheduled & Event-Driven** — Cron schedules and webhook triggers. Same policy enforcement whether an agent runs manually, on schedule, or from a GitHub webhook.

**Shared Enterprise Context** — Read-only company knowledge mounts. All agents share the same org facts. Data classification tier propagates to model routing.

**Multi-LLM** — OpenAI, Anthropic, AWS Bedrock (EU), Ollama (local). Tier-based routing: public data → cheap models, sensitive data → EU-only models.

**OpenTelemetry-Native** — Traces, metrics, and logs export via OTel. GenAI semantic conventions for LLM observability. Upgrade path to Langfuse + LGTM stack.

## How It Compares


| Capability             | Talon                              | MemOS                                 | OpenClaw | LangChain | CrewAI  |
| ---------------------- | ---------------------------------- | ------------------------------------- | -------- | --------- | ------- |
| Policy enforcement     | Yes (OPA)                          | No                                    | No       | No        | No      |
| Cost control           | Yes (per-request)                  | No                                    | No       | No        | No      |
| PII detection          | Yes (EU patterns, configurable)    | No                                    | No       | No        | No      |
| Signed evidence record | Yes (HMAC-signed)                  | No                                    | No       | No        | No      |
| EU data stays in EU    | Yes (EU routing)                   | No                                    | No       | No        | No      |
| MCP support            | Yes (native)                       | Yes                                   | Partial  | Partial   | No      |
| **Vendor proxy**       | **Yes (MCP proxy)**                | **No**                                | **No**   | **No**    | **No**  |
| **LLM API gateway**    | **Yes (/v1/proxy/)**               | **No**                                | **No**   | **No**    | **No**  |
| Secrets vault          | Yes (audited)                      | No                                    | No       | No        | No      |
| Prompt injection prev. | Yes (3-layer)                      | No                                    | No       | No        | No      |
| Agent memory           | Yes (policy-controlled)            | Yes (advanced: KV-cache, graph, LoRA) | No       | No        | Partial |
| **Memory controls**    | **Yes (PII scan, HMAC, rollback)** | **No**                                | **No**   | **No**    | **No**  |
| Multi-tenant           | Yes                                | No                                    | No       | No        | No      |
| Open source            | Apache 2.0                         | Apache 2.0                            | Yes      | Yes       | Yes     |
| EU AI Act alignment    | Yes                                | No                                    | No       | No        | No      |


**Key differentiator:** Talon is the only platform that adds compliance to existing third-party AI vendors without rewriting them. Your Zendesk AI Agent, Intercom bot, or custom Slack automation becomes audit-ready in hours.

## Architecture

```
   ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
   │              │          │              │          │              │
   │  Agent/User  │──────────│    Talon     │──────────│  LLM/Tools   │
   │              │          │   (Proxy)    │          │  (Vendors)   │
   └──────────────┘          └──────────────┘          └──────────────┘
                                    │
                         ┌──────────┴──────────┐
                         │                     │
                         ▼                     ▼
              ┌──────────────────┐  ┌──────────────────┐
              │ Policy Engine    │  │  Evidence Store  │
              │ (OPA + Rego)     │  │  (SQLite/PG)     │
              └──────────────────┘  └──────────────────┘

Single Go Binary (no microservices, no Kubernetes)
```

Detailed view:

```
   ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
   │              │          │              │          │              │
   ↓              ↓          ↓              ↓          ↓              ↓
   ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
   │   Policy     │          │   MCP Server │          │   Secrets    │
   │   Engine     │          │   + LLM      │          │   Vault      │
   │   (OPA)      │          │   Router     │          │   (AES-GCM)  │
   └──────────────┘          └──────────────┘          └──────────────┘
          │                          │                          │
          ─                          ─                          ─
   ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
   │ Attachment   │          │  Evidence    │          │   Agent      │
   │ Scanner      │          │  Store       │          │   Memory     │
   │ (Injection   │          │  (SQLite +   │          │   (Soul Dir) │
   │  Prevention) │          │   OTel + HMAC)│          │              │
   └──────────────┘          └──────────────┘          └──────────────┘
          │                          │
          ─                          ─
   ┌──────────────┐          ┌──────────────────────┐
   │ agent.talon  │          │  LLM Providers       │
   │  .yaml       │          │  OpenAI/Anthropic    │
   │              │          │  Bedrock/Ollama      │
   └──────────────┘          └──────────────────────┘
```

## CLI Commands

```bash
# Project setup
talon init                                   # Interactive wizard (TTY); creates agent + infra config
talon init --scaffold                        # Quick defaults without wizard (e.g. in CI/scripts)
talon init --pack openclaw                   # Starter pack (openclaw, fintech-eu, etc.)
talon init --list-providers                  # List LLM providers; --list-packs, --list-features
talon validate                               # Validate agent.talon.yaml

# Agent execution
talon run "query"                            # Run agent with policy enforcement
talon run --dry-run "query"                  # Show policy decision without LLM call
talon run --attach report.pdf "Summarize"    # Process attachments (injection-scanned)
talon run --agent sales --tenant acme "..."  # Specify agent and tenant
talon run --policy custom.talon.yaml "..."   # Use explicit policy file

# Audit trail
talon audit list                             # List evidence records
talon audit list --tenant acme --limit 50    # Filter by tenant with limit
talon audit show <evidence-id>               # Full record (Layer 3: classification, PII, HMAC)
talon audit verify <evidence-id>             # Verify HMAC-SHA256 + compact summary
talon audit export --format csv|json|ndjson|html [--from YYYY-MM-DD] [--to YYYY-MM-DD]  # HTML is self-contained
talon compliance report --framework gdpr --format html --output gdpr-report.html          # Article-level mapping report

# Secrets vault
talon secrets set <name> <value>             # Store encrypted secret (AES-256-GCM)
talon secrets list                           # List secrets (metadata only, values hidden)
talon secrets audit                          # View secret access log
talon secrets rotate <name>                  # Re-encrypt with fresh nonce

# Agent memory
talon memory list [--agent name]             # Browse memory index
talon memory show <entry-id>                 # Full entry detail
talon memory search "query"                  # Full-text search
talon memory rollback <mem_id> --yes                     # Rollback to entry (soft-delete newer)
talon memory health [--agent name]           # Trust distribution + conflicts
talon memory audit [--agent name]            # Evidence chain verification

# Trigger server
talon serve [--port 8080]                    # Start HTTP server + cron scheduler

# Plan review
talon plan pending [--tenant acme]           # List pending plans for review
talon plan approve <plan-id> [--tenant acme] # Approve pending plan
talon plan reject <plan-id> [--tenant acme]  # Reject pending plan
talon plan execute <plan-id> [--tenant acme] # Execute an approved plan in non-serve mode
talon approver add --name "Jane Doe" --role team_lead      # Generate approver bearer key
talon approver list                                          # List approver identities
talon monitor --tenant acme                                  # Drift signals (cost/denial/PII z-scores)
talon prompt history --tenant acme --agent support-bot       # Prompt versions (when audit.include_prompts=true)
talon agents score --tenant acme --agent support-bot         # Governance maturity score
talon costs --tenant acme --by-team                          # Team-level cost attribution

# Sessions
talon session list --tenant acme             # List execution sessions
talon session show <session-id>              # Show session details
talon session trace <session-id>             # Show linked lifecycle evidence
```

### Optional request enrichment headers

For OpenAI-compatible and agent-run HTTP endpoints, Talon accepts optional governance headers:

- `X-Talon-Reasoning`: agent-provided decision rationale (stored in signed evidence as `agent_reasoning`)
- `X-Talon-Session-ID`: join an existing governed execution session (or Talon creates one)
- `X-Talon-Agent-Signature` + `X-Talon-Agent-Timestamp`: optional per-agent HMAC request attestation

## PII and pattern configuration

PII detection uses **Presidio-compatible** recognizer definitions. Defaults are embedded (EU-focused: email, phone, IBAN, credit card, VAT, SSNs, IP, passport). You can extend or override them without recompiling:

- **Global overrides:** Put a `patterns.yaml` file in `~/.talon/` or the project directory. Same YAML format as the built-in `patterns/pii_eu.yaml`. Later layers override earlier (embedded → global → per-agent).
- **Per-agent:** In `agent.talon.yaml` under `policies.data_classification` set `enabled_entities` (whitelist), `disabled_entities` (blacklist), and/or `custom_recognizers` (extra patterns). See the commented block in `talon init --scaffold` or wizard-generated output.

Attachment (prompt-injection) patterns are configured the same way; see `patterns/injection.yaml` for the default set.

**Semantic enrichment (optional):** Redacted PII placeholders can include attributes (e.g. person gender, location scope) so downstream systems get structure without raw data. Enable in `policies.semantic_enrichment`; see [PII semantic enrichment](docs/reference/pii-semantic-enrichment.md).

## Compliance Coverage


| Framework | Status     | Key Talon Features                                                     |
| --------- | ---------- | ---------------------------------------------------------------------- |
| GDPR      | ✅ Core     | PII detection, data residency, right to erasure, tamper-proof record   |
| ISO 27001 | ✅ Core     | Secrets management (A.8.24), logging (A.8.15), access control (A.5.15) |
| NIS2      | ✅ Core     | Incident evidence, supply chain controls, risk management              |
| DORA      | ⚡️ Partial | ICT incident logging, cost tracking, third-party risk                  |
| EU AI Act | ✅ Core     | Risk classification, human oversight, transparency, documentation      |
| SOC 2     | ⚡️ Partial | Trust services criteria via evidence + signed record                   |


Talon supports these controls but does not, by itself, certify regulatory compliance. Final compliance depends on your full process, legal interpretation, and operating environment.

**GDPR Article 30 Exports:** Generate processing records in one command. Shows what data was processed, by which agent, and when.

**NIS2 Article 21 Evidence:** Signed incident/event logs with timestamps and policy decisions to support risk management and reporting workflows.

**DORA ICT Risk Controls:** Cost governance, evidence retention, and third-party routing controls provide auditable input for operational resilience programs.

**EU AI Act Articles 9, 13, 14:** Risk management policies, transparency logs, and human oversight gates as supporting controls.

## Real-World Adoption Paths

### Spanish Telecom (150 employees)

**Before:** Custom Slack bot for eSIM support. Works great, but no verifiable record.
**After:** Added Talon in 4 hours (5 lines of code). Added auditable GDPR + NIS2 support controls.
**ROI:** €15,000 saved (avoided rewrite) + eliminated fine risk.

### German Healthcare (400 employees)

**Before:** Zendesk AI Agent (€3,000/month). Black box, no visibility.
**After:** Routed through Talon MCP proxy in 1 week. Full tamper-proof record.
**ROI:** €100,000 saved (kept vendor) + stronger GDPR audit evidence.

### French FinTech (80 employees)

**Before:** Building custom AI support from scratch.
**After:** Used Talon from Day 1. Compliant without custom policy code.
**ROI:** €25,000 saved (didn't build compliance layer) + faster time to market.

**See:** [ADOPTION_SCENARIOS.md](docs/ADOPTION_SCENARIOS.md) for detailed timelines.

## Examples

See `examples/` for ready-to-use agent configurations:

- `examples/sales-analyst/` — Financial data analysis with PII redaction
- `examples/support-agent/` — Customer support with EU data routing
- `examples/code-reviewer/` — Code review with tool access controls
- `examples/vendor-proxy/` — Third-party vendor compliance wrapper

## Upgrade Path

Talon is designed for progressive complexity — start simple, add sophistication via configuration:


| Component       | MVP (Free)     | Growth (Self-hosted)    | Enterprise                   |
| --------------- | -------------- | ----------------------- | ---------------------------- |
| Storage         | SQLite         | PostgreSQL              | PostgreSQL + S3 WORM         |
| Secrets         | Embedded vault | Infisical (self-hosted) | Infisical Enterprise / Vault |
| Observability   | OTel → stdout  | LGTM stack + Langfuse   | Datadog / Elastic            |
| Agent isolation | Process        | Docker / gVisor         | Firecracker MicroVMs         |
| Protocols       | MCP            | MCP + A2A               | MCP + A2A + custom           |
| Auth            | API key        | OIDC                    | SAML / SSO                   |


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AI_ASSISTANCE.md](AI_ASSISTANCE.md).

Quick ways to help:

- New contributors: [`good first issue`](https://github.com/dativo-io/talon/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
- Larger tasks: [`help wanted`](https://github.com/dativo-io/talon/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
- Start here issue: [Roadmap + how to contribute](https://github.com/dativo-io/talon/issues/54)
- Roadmap context: [ROADMAP.md](ROADMAP.md)
- Share a deployment story: [case study template](docs/ADOPTION_SCENARIOS.md#case-study-template-for-community-contributions)
- Maintainer response target: first response within 72 hours (best effort)

## Release Notes That Teach

For notable releases, we document:

- problem solved,
- who should care,
- how to verify quickly,
- upgrade impact,
- one share artifact (screenshot/GIF/snippet) when relevant.

See [CHANGELOG.md](CHANGELOG.md) and [Releases](https://github.com/dativo-io/talon/releases).

## License

Apache 2.0 — See [LICENSE](LICENSE)

## Links

- **Documentation:** [docs/](docs/)
- **Quick Start:** [QUICKSTART.md](docs/QUICKSTART.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Code of Conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **Security Policy:** [SECURITY.md](SECURITY.md)
- **Persona Guides:** [PERSONA_GUIDES.md](docs/PERSONA_GUIDES.md) — How Compliance, CTO, SecOps, FinOps, and DevOps use Talon
- **Memory Governance:** [MEMORY_GOVERNANCE.md](docs/MEMORY_GOVERNANCE.md)
- **Vendor Integration:** [VENDOR_INTEGRATION_GUIDE.md](docs/VENDOR_INTEGRATION_GUIDE.md)
- **Adoption Paths:** [ADOPTION_SCENARIOS.md](docs/ADOPTION_SCENARIOS.md)
- **Website:** [https://talon.dativo.io](https://talon.dativo.io)
- **Issues:** [https://github.com/dativo-io/talon/issues](https://github.com/dativo-io/talon/issues)

---

**EU AI Act enforcement: August 2026. Do you have evidence and human-oversight controls for your AI operations?**

**Already using AI vendors? Add policy enforcement and signed evidence in hours, not months.**