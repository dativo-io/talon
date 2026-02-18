# Dativo Talon

**Policy-enforced AI agents for European businesses. Governed, audited, compliant by default.**

Talon is a single Go binary that wraps your AI agents in compliance guardrails — cost control, PII detection, data sovereignty, prompt injection prevention, and an immutable audit trail. It speaks MCP natively, works with any LLM provider, and maps directly to ISO 27001, GDPR, NIS2, DORA, and the EU AI Act.

**Works with existing AI automation.** Already using Zendesk AI Agent, Intercom, custom Slack bots, or OpenAI Assistants? Talon adds compliance in hours, not months. No rewrite needed.

> "OpenClaw lets AI do things. Talon makes sure it does them safely — for your entire company."

## Why Talon?

European SMBs face five simultaneous compliance mandates but only 28% have a dedicated security officer. Talon exists because:

- **AI agents need governance.** CrowdStrike warned that ungoverned AI agents can be weaponized. Talon enforces policy-as-code on every agent action.
- **EU AI Act enforcement starts August 2026.** Talon implements Articles 9 (risk management), 13 (transparency), and 14 (human oversight) as code.
- **Data sovereignty isn't optional.** Talon routes sensitive data only to EU-hosted models. No data leaves your configured region.
- **Compliance shouldn't cost €50K/year.** Open-source core, single binary, zero infrastructure to start.
- **Third-party vendors are black boxes.** You're liable even if they claim compliance. Talon gives you independent audit trails.

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
- ✅ You have audit trail (GDPR Article 30 exports)
- ✅ PII redacted before vendor access
- ✅ Can block forbidden operations

**See:** [VENDOR_INTEGRATION_GUIDE.md](docs/VENDOR_INTEGRATION_GUIDE.md)

---

### 2. Already Have Custom AI Automation? (Wrap with Talon)

**Scenario:** You built a Slack bot 6 months ago. Works great, but compliance officer needs audit trails.

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
- ✅ Now GDPR + NIS2 compliant
- ✅ No rewrite needed
- ✅ Audit-ready in 1 day

**See:** [ADOPTION_SCENARIOS.md](docs/ADOPTION_SCENARIOS.md)

---

### 3. Building New AI Agents? (Native Talon)

**Scenario:** Greenfield project, want to build compliant from Day 1.

**Solution:** Use Talon from the start (2 minutes to first agent).

```bash
# Install
curl -sSL https://get.talon.dativo.io | sh

# Initialize
mkdir my-agents && cd my-agents
talon init --org "MyCompany" --compliance "gdpr,nis2"

# Configure secrets
talon secrets set OPENAI_API_KEY "sk-proj-..."

# Run first governed agent
talon run "Summarize EU AI regulation trends"
```

**Result:**
- ✅ Compliant from Day 1
- ✅ No custom governance code
- ✅ Policy-as-code in YAML
- ✅ Audit trail automatic

**See:** [QUICKSTART.md](docs/QUICKSTART.md)

---

## Quick Start (2 minutes)

```bash
# Install
curl -sSL https://get.talon.dativo.io | sh
# Or: go install github.com/dativo-io/talon/cmd/talon@latest

# Initialize a project
mkdir my-agents && cd my-agents
talon init

# Set your LLM provider key (or use vault: talon secrets set openai-api-key "sk-...")
export OPENAI_API_KEY=sk-your-key
# Also supports: ANTHROPIC_API_KEY, AWS_REGION (for Bedrock), Ollama (local, no key needed)

# Run your first governed agent
talon run "Summarize the key trends in European AI regulation"
```

You'll see:
```
✓ Policy check: ALLOWED

[Agent response appears here]

✓ Evidence stored: ev_a1b2c3d4e5f6
✓ Cost: €0.0018 | Duration: 1250ms
```

Try a policy block — set `daily: 0.001` in your `.talon.yaml`, run again, and watch the policy engine deny the request:
```
✗ Policy check: DENIED
  Reason: budget_exceeded
```

Verify evidence integrity at any time:
```bash
talon audit verify ev_a1b2c3d4e5f6
# ✓ Evidence ev_a1b2c3d4e5f6: signature VALID (HMAC-SHA256 intact)
```

## Features

**Policy-as-Code** — Define agent governance in `.talon.yaml` files. Cost limits, data classification, model routing, tool access, time restrictions — all declarative, version-controlled, auditable.

**MCP-Native** — Talon speaks Model Context Protocol. Connect any MCP-compatible agent or tool. Every MCP tool call passes through the policy engine. Works as transparent proxy for third-party vendors.

**Vendor Integration** — Route third-party AI vendors (Zendesk, Intercom, HubSpot) through Talon's MCP proxy. Gain audit trails, PII redaction, and policy enforcement without vendor rewrites. You stay compliant even with black-box SaaS.

**Audited Secrets Vault** — API keys encrypted at rest (AES-256-GCM). Per-agent ACLs. Every secret retrieval logged. Upgrade path to Infisical for rotation and SAML.

**Prompt Injection Prevention** — PDF/DOCX/HTML attachments are sandboxed automatically. Instruction-detection scanner flags injection attempts. Configurable: block, warn, or log.

**Governed Agent Memory** — Agents write learnings to an audited soul directory. Every memory write is PII-scanned, policy-checked, and HMAC-signed. Constitutional AI governance: agents learn facts but never alter policies. Rollback to any previous state if memory poisoning is detected. Unlike MemOS or mem0, Talon's memory is a compliance asset — not just a developer convenience.

**Scheduled & Event-Driven** — Cron schedules and webhook triggers. Same policy enforcement whether an agent runs manually, on schedule, or from a GitHub webhook.

**Shared Enterprise Context** — Read-only company knowledge mounts. All agents share the same org facts. Data classification tier propagates to model routing.

**Multi-LLM** — OpenAI, Anthropic, AWS Bedrock (EU), Ollama (local). Tier-based routing: public data → cheap models, sensitive data → EU-only models.

**OpenTelemetry-Native** — Traces, metrics, and logs export via OTel. GenAI semantic conventions for LLM observability. Upgrade path to Langfuse + LGTM stack.

## How It Compares

| Capability | Talon | MemOS | OpenClaw | LangChain | CrewAI |
|-----------|-------|-------|----------|-----------|--------|
| Policy enforcement | Yes (OPA) | No | No | No | No |
| Cost control | Yes (per-request) | No | No | No | No |
| PII detection | Yes (EU patterns, configurable) | No | No | No | No |
| Audit trail | Yes (HMAC-signed) | No | No | No | No |
| Data sovereignty | Yes (EU routing) | No | No | No | No |
| MCP support | Yes (native) | Yes | Partial | Partial | No |
| **Vendor proxy** | **Yes (MCP proxy)** | **No** | **No** | **No** | **No** |
| Secrets vault | Yes (audited) | No | No | No | No |
| Prompt injection prev. | Yes (3-layer) | No | No | No | No |
| Agent memory | Yes (governed) | Yes (advanced: KV-cache, graph, LoRA) | No | No | Partial |
| **Memory governance** | **Yes (PII scan, HMAC, rollback)** | **No** | **No** | **No** | **No** |
| Multi-tenant | Yes | No | No | No | No |
| Open source | Apache 2.0 | Apache 2.0 | Yes | Yes | Yes |
| EU AI Act alignment | Yes | No | No | No | No |

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
   │  .talon.yaml │          │  LLM Providers       │
   │  policies    │          │  OpenAI/Anthropic    │
   │              │          │  Bedrock/Ollama      │
   └──────────────┘          └──────────────────────┘
```

## CLI Commands

```bash
# Agent execution
talon run "query"                            # Run agent with policy enforcement
talon run --dry-run "query"                  # Show policy decision without LLM call
talon run --attach report.pdf "Summarize"    # Process attachments (injection-scanned)
talon run --agent sales --tenant acme "..."  # Specify agent and tenant
talon run --policy custom.talon.yaml "..."   # Use explicit policy file

# Project setup
talon init                                   # Scaffold new project
talon validate                               # Validate .talon.yaml

# Audit trail
talon audit list                             # List evidence records
talon audit list --tenant acme --limit 50    # Filter by tenant with limit
talon audit verify <evidence-id>             # Verify HMAC-SHA256 signature

# Secrets vault
talon secrets set <name> <value>             # Store encrypted secret (AES-256-GCM)
talon secrets list                           # List secrets (metadata only, values hidden)
talon secrets audit                          # View secret access log
talon secrets rotate <name>                  # Re-encrypt with fresh nonce

# Coming soon
talon costs [--tenant acme]                  # Cost and budget summary
talon memory list [--agent name]             # View agent learnings
talon serve [--port 8080] [--dashboard]      # Start HTTP + MCP server
```

## PII and pattern configuration

PII detection uses **Presidio-compatible** recognizer definitions. Defaults are embedded (EU-focused: email, phone, IBAN, credit card, VAT, SSNs, IP, passport). You can extend or override them without recompiling:

- **Global overrides:** Put a `patterns.yaml` file in `~/.talon/` or the project directory. Same YAML format as the built-in `patterns/pii_eu.yaml`. Later layers override earlier (embedded → global → per-agent).
- **Per-agent:** In `.talon.yaml` under `policies.data_classification` set `enabled_entities` (whitelist), `disabled_entities` (blacklist), and/or `custom_recognizers` (extra patterns). See the commented block in `talon init` output.

Attachment (prompt-injection) patterns are configured the same way; see `patterns/injection.yaml` for the default set.

## Compliance Coverage

| Framework | Status | Key Talon Features |
|-----------|--------|-------------------|
| GDPR | ✅ Core | PII detection, data residency, right to erasure, audit trail |
| ISO 27001 | ✅ Core | Secrets management (A.8.24), logging (A.8.15), access control (A.5.15) |
| NIS2 | ✅ Core | Incident evidence, supply chain controls, risk management |
| DORA | ⚡️ Partial | ICT incident logging, cost tracking, third-party risk |
| EU AI Act | ✅ Core | Risk classification, human oversight, transparency, documentation |
| SOC 2 | ⚡️ Partial | Trust services criteria via evidence + audit trail |

**GDPR Article 30 Exports:** Generate processing records in one command. Proves what data was processed, by which agent, when, and with what legal basis.

**NIS2 Article 21 Evidence:** Complete incident logs with timestamps, policy decisions, and audit trails. Required for cyber incident reporting.

**EU AI Act Articles 9, 13, 14:** Risk management system (OPA policies), transparency logs (evidence store), human oversight (plan review UI).

## Real-World Adoption Paths

### Spanish Telecom (150 employees)

**Before:** Custom Slack bot for eSIM support. Works great, but no audit trail.
**After:** Added Talon in 4 hours (5 lines of code). Now GDPR + NIS2 compliant.
**ROI:** €15,000 saved (avoided rewrite) + eliminated fine risk.

### German Healthcare (400 employees)

**Before:** Zendesk AI Agent (€3,000/month). Black box, no visibility.
**After:** Routed through Talon MCP proxy in 1 week. Full audit trail.
**ROI:** €100,000 saved (kept vendor) + GDPR compliance proven.

### French FinTech (80 employees)

**Before:** Building custom AI support from scratch.
**After:** Used Talon from Day 1. Compliant without custom governance code.
**ROI:** €25,000 saved (didn't build compliance layer) + faster time to market.

**See:** [ADOPTION_SCENARIOS.md](docs/ADOPTION_SCENARIOS.md) for detailed timelines.

## Examples

See `examples/` for ready-to-use agent configurations:
- `examples/sales-analyst/` — Financial data analysis with PII redaction
- `examples/support-agent/` — Customer support with data sovereignty
- `examples/code-reviewer/` — Code review with tool access controls
- `examples/vendor-proxy/` — Third-party vendor compliance wrapper

## Upgrade Path

Talon is designed for progressive complexity — start simple, add sophistication via configuration:

| Component | MVP (Free) | Growth (Self-hosted) | Enterprise |
|-----------|-----------|---------------------|------------|
| Storage | SQLite | PostgreSQL | PostgreSQL + S3 WORM |
| Secrets | Embedded vault | Infisical (self-hosted) | Infisical Enterprise / Vault |
| Observability | OTel → stdout | LGTM stack + Langfuse | Datadog / Elastic |
| Agent isolation | Process | Docker / gVisor | Firecracker MicroVMs |
| Protocols | MCP | MCP + A2A | MCP + A2A + custom |
| Auth | API key | OIDC | SAML / SSO |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow.

## License

Apache 2.0 — See [LICENSE](LICENSE)

## Links

- **Documentation:** [docs/](docs/)
- **Vendor Integration:** [VENDOR_INTEGRATION_GUIDE.md](docs/VENDOR_INTEGRATION_GUIDE.md)
- **Adoption Paths:** [ADOPTION_SCENARIOS.md](docs/ADOPTION_SCENARIOS.md)
- **Website:** https://talon.dativo.io
- **Community:** https://github.com/dativo-io/talon/discussions

---

**EU AI Act enforcement: August 2026. Are your AI agents compliant?**

**Already using AI vendors? Make them compliant in hours, not months.**
