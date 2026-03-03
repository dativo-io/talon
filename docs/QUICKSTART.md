# Talon Quick Start

Get from zero to a policy-enforced AI agent in under 5 minutes. This page is your entry point; it points to the right doc for what you want to do.

---

## 5-minute path

If you want a single guided path (install → init → run → see evidence), follow the **tutorial**:

- **[Your first governed agent](tutorials/first-governed-agent.md)** — One path, step by step. By the end you will have run a governed agent and seen the audit trail.

---

## I want to…

| Goal | Doc |
|------|-----|
| **Learn by doing** (one guided path) | [Your first governed agent](tutorials/first-governed-agent.md) (Tutorial) |
| **Pick the right way to use Talon** (MCP proxy vs gateway vs native) | [How to choose your integration path](guides/choosing-integration-path.md) |
| **Route OpenClaw / Slack bot / desktop app** through Talon | [OpenClaw](guides/openclaw-integration.md) (bidirectional PII scanning, tool-aware redaction, rate limiting, kill switch), [Slack bot](guides/slack-bot-integration.md), [Desktop apps](guides/desktop-app-governance.md) |
| **Look up config and env vars** | [Configuration and environment](reference/configuration.md) (Reference) |
| **Cap cost per team or app** | [How to cap daily spend per team or application](guides/cost-governance-by-caller.md) |
| **Export evidence for auditors** | [How to export evidence for auditors](guides/compliance-export-runbook.md) |
| **Use Talon from CI/CD** | [How to run governed LLM calls in CI/CD](guides/cicd-pipeline-governance.md) |
| **Copy policy snippets** (cost limits, time restrictions, etc.) | [Policy cookbook](guides/policy-cookbook.md) |
| **Understand adoption paths and ROI** | [Adoption scenarios](ADOPTION_SCENARIOS.md) |
| **See who uses Talon and how** | [Persona guides](PERSONA_GUIDES.md) |
| **Wrap a third-party AI vendor** (Zendesk, Intercom) | [Vendor integration guide](VENDOR_INTEGRATION_GUIDE.md) |

---

## Minimal commands (if you already know Talon)

```bash
# Install (from repo)
make build    # → bin/talon

# New project
mkdir my-agents && cd my-agents && talon init

# Set key and run
export OPENAI_API_KEY=sk-proj-...
talon run "Your query here"   # Uses agent name from policy when --agent omitted

# Server (API + dashboard + optional gateway/proxy)
export TALON_API_KEYS="your-key:default"
talon serve --port 8080
# With LLM gateway: talon serve --gateway --gateway-config examples/gateway/talon.config.gateway.yaml
# With MCP proxy:   talon serve --proxy-config path/to/proxy.yaml
```

For full configuration and options see [Configuration and environment](reference/configuration.md).

---

## Documentation index

All user-facing docs are listed by type (Tutorial, How-to, Reference, Explanation) in the **[documentation index](README.md)**. The project follows the [Diátaxis](https://diataxis.fr/) framework so you can find learning-oriented, task-oriented, or reference material quickly.
