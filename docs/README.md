# Talon Documentation

This documentation is organised around the [Diátaxis](https://diataxis.fr/) framework: four types of documentation for different user needs.

| Type | When to use it |
|------|----------------|
| **Tutorial** | You are learning; you want a guided, step-by-step experience. |
| **How-to guide** | You have a goal; you want directions to get something done. |
| **Reference** | You need accurate, neutral facts (commands, config, API). |
| **Explanation** | You want context and understanding (why, architecture, adoption). |

---

## Quick start

**New to Talon?** Start here:

- [QUICKSTART.md](QUICKSTART.md) — Short entry point; links to the tutorial and other docs.

---

## Documentation index

### Tutorial (learning-oriented)

| Doc | Description |
|-----|-------------|
| [Your first governed agent](tutorials/first-governed-agent.md) | A single-path lesson: install → init → run → see evidence. |

### How-to guides (goal-oriented)

| Doc | Description |
|-----|-------------|
| [How to choose your integration path](guides/choosing-integration-path.md) | Pick MCP proxy vs LLM gateway vs native Talon. |
| [How to govern OpenClaw with Talon](guides/openclaw-integration.md) | Route OpenClaw LLM traffic through the gateway. |
| [How to add compliance to your Slack bot](guides/slack-bot-integration.md) | Route your Slack bot's LLM calls through Talon. |
| [How to govern ChatGPT/Claude Desktop (enterprise)](guides/desktop-app-governance.md) | Route desktop app traffic via DNS/TLS and gateway. |
| [How to cap daily spend per team or application](guides/cost-governance-by-caller.md) | Gateway callers and policy overrides for cost limits. |
| [How to export evidence for auditors](guides/compliance-export-runbook.md) | Export, verify, and hand off audit evidence. |
| [How to run governed LLM calls in CI/CD](guides/cicd-pipeline-governance.md) | Use Talon from GitHub Actions or GitLab CI. |
| [How to run a first-line support agent with Talon](guides/internal-support-agent.md) | Ticket summarization with PII and cost controls. |
| [How to verify memory is used](guides/memory-verification.md) | CLI steps to confirm memory is written and injected into prompts. |
| [How to offer Talon to multiple customers (multi-tenant/MSP)](guides/multi-tenant-msp.md) | Tenant isolation, API keys, and gateway callers. |

### Reference (technical description)

| Doc | Description |
|-----|-------------|
| [Configuration and environment](reference/configuration.md) | Environment variables, crypto keys, and config reference. |

### Explanation (understanding-oriented)

| Doc | Description |
|-----|-------------|
| [Adoption scenarios](ADOPTION_SCENARIOS.md) | Greenfield, brownfield custom, brownfield vendor; timelines and ROI. |
| [Persona guides](PERSONA_GUIDES.md) | Who uses Talon (DevOps, Compliance, CTO, SecOps, FinOps) and what they do. |
| [Vendor integration guide](VENDOR_INTEGRATION_GUIDE.md) | Why vendor compliance matters; MCP proxy and patterns. |
| [Architecture: MCP proxy](ARCHITECTURE_MCP_PROXY.md) | How the MCP proxy fits in; related LLM API gateway. |
| [Memory governance](MEMORY_GOVERNANCE.md) | Governed agent memory, categories, and retention. |
| [Agent planning](AGENT_PLANNING.md) | Execution plans and plan review gate. |
| [Observability](OBSERVABILITY.md) | Logging, tracing, and metrics. |

### Policy reference

| Doc | Description |
|-----|-------------|
| [Policy cookbook](guides/policy-cookbook.md) | Copy-paste policy snippets for common needs. |
