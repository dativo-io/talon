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

**New to Talon?** Start with the 60-second demo (no API key needed):

- [60-Second Demo](tutorials/quickstart-demo.md) — Docker Compose demo: `docker compose up`, send a curl request, see evidence immediately.
- [QUICKSTART.md](QUICKSTART.md) — Short entry point for native Talon (requires Go).

## Start Here (jobs-to-be-done)

Choose the shortest path for your situation:

1. **"I already have an app calling OpenAI/Anthropic and want controls fast."**
   - Start: [Add Talon to your existing app](guides/add-talon-to-existing-app.md)
   - Then: [How to export evidence for auditors](guides/compliance-export-runbook.md)
2. **"I need to govern a third-party AI vendor."**
   - Start: [Vendor integration guide](VENDOR_INTEGRATION_GUIDE.md)
   - Then: [Architecture: MCP proxy](ARCHITECTURE_MCP_PROXY.md)
3. **"I want to understand exactly what Talon enforces."**
   - Start: [What Talon does to your request](explanation/what-talon-does-to-your-request.md)
   - Then: [Why not just a PII proxy?](explanation/why-not-a-pii-proxy.md)

---

## Documentation index

### Tutorials (learning-oriented)

| Doc | Description |
|-----|-------------|
| [60-Second Demo (no API key)](tutorials/quickstart-demo.md) | Docker Compose demo with mock provider — see governance in action in 60 seconds. |
| [Your first governed agent](tutorials/first-governed-agent.md) | Install → init → run → see evidence. Native Talon (requires Go + API key). |

### How-to guides (goal-oriented)

| Doc | Description |
|-----|-------------|
| [How to choose your integration path](guides/choosing-integration-path.md) | Pick MCP proxy vs LLM gateway vs native Talon. |
| [Add Talon to your existing app](guides/add-talon-to-existing-app.md) | Point your existing app (Python, Node, curl) at Talon in a few minutes; first real request and evidence. |
| [How to govern OpenClaw with Talon](guides/openclaw-integration.md) | Route OpenClaw LLM traffic through the gateway. |
| [Docker primer: OpenClaw + Talon (cloud-ready)](guides/openclaw-talon-primer/docker-openclaw-talon-primer.md) | Predefined Docker setup to run Talon gateway for OpenClaw; deploy in the cloud. |
| [How to add compliance to your Slack bot](guides/slack-bot-integration.md) | Route your Slack bot's LLM calls through Talon. |
| [How to govern ChatGPT/Claude Desktop (enterprise)](guides/desktop-app-governance.md) | Route desktop app traffic via DNS/TLS and gateway. |
| [How to cap daily spend per team or application](guides/cost-governance-by-caller.md) | Gateway callers and policy overrides for cost limits. |
| [How to export evidence for auditors](guides/compliance-export-runbook.md) | Export, verify, and hand off audit evidence. |
| [How to run governed LLM calls in CI/CD](guides/cicd-pipeline-governance.md) | Use Talon from GitHub Actions or GitLab CI. |
| [How to run a first-line support agent with Talon](guides/internal-support-agent.md) | Ticket summarization with PII and cost controls. |
| [How to verify memory is used](guides/memory-verification.md) | CLI steps to confirm memory is written and injected into prompts. |
| [How to offer Talon to multiple customers (multi-tenant/MSP)](guides/multi-tenant-msp.md) | Tenant isolation, API keys, and gateway callers. |
| [Incident response playbook](guides/incident-response-playbook.md) | Common operational scenarios when running AI agents. |

### Reference (technical description)

| Doc | Description |
|-----|-------------|
| [Configuration and environment](reference/configuration.md) | Environment variables, crypto keys, and config reference. |
| [Authentication and key scopes](reference/authentication-and-key-scopes.md) | Which keys authenticate which endpoint families (gateway vs control plane vs dashboard). |
| [Gateway dashboard](reference/gateway-dashboard.md) | Dashboard endpoints, metrics API schema, snapshot fields, and authentication. |

### Explanation (understanding-oriented)

| Doc | Description |
|-----|-------------|
| [What Talon does to your request](explanation/what-talon-does-to-your-request.md) | Full request lifecycle: every check, every byte transformation, latency budget. |
| [Why not just a PII proxy?](explanation/why-not-a-pii-proxy.md) | Five failure scenarios: what a PII-only proxy misses, what Talon does, and how to verify. |
| [Evidence store](explanation/evidence-store.md) | Evidence record structure, session_id, HMAC signing (TALON_SIGNING_KEY), progressive disclosure, storage, and export (CSV/JSON columns). |
| [Adoption scenarios](ADOPTION_SCENARIOS.md) | Greenfield, brownfield custom, brownfield vendor; timelines and ROI. |
| [Persona guides](PERSONA_GUIDES.md) | Who uses Talon (DevOps, Compliance, CTO, SecOps, FinOps) and what they do. |
| [Vendor integration guide](VENDOR_INTEGRATION_GUIDE.md) | Why vendor compliance matters; MCP proxy and patterns. |
| [Architecture: MCP proxy](ARCHITECTURE_MCP_PROXY.md) | How the MCP proxy fits in; related LLM API gateway. |
| [Memory governance](MEMORY_GOVERNANCE.md) | Governed agent memory, categories, and retention. |
| [Agent planning](AGENT_PLANNING.md) | Execution plans and plan review gate. |
| [Observability](OBSERVABILITY.md) | Logging, tracing, and metrics. |

### Proof Pack (trust and verification)

| Doc | Description |
|-----|-------------|
| [What Talon does to your request](explanation/what-talon-does-to-your-request.md) | Pipeline, latency, threat boundaries, and reproducible checks. |
| [Why not just a PII proxy?](explanation/why-not-a-pii-proxy.md) | Control-plane vs scrubber differentiation with proof commands. |
| [Evidence store](explanation/evidence-store.md) | HMAC integrity model and verification flow. |
| [Security policy](../SECURITY.md) | Vulnerability reporting process and security scope. |
| [Docker Compose demo](../examples/docker-compose/README.md) | Fastest no-key proof loop. |

### Policy reference

| Doc | Description |
|-----|-------------|
| [Policy cookbook](guides/policy-cookbook.md) | Copy-paste policy snippets for common needs. |
| [Starter policy library](../examples/policies/README.md) | Ready-to-use Rego policies for cost, PII, model allowlists, data residency. |

### Community / internal

| Doc | Description |
|-----|-------------|
| [Comment playbook (Reddit/HN)](community/comment-playbook.md) | Internal: human-written response guidance with evidence-first links. |

### Release reliability

- [CHANGELOG.md](../CHANGELOG.md): includes the "why this matters" framing for notable changes.
- [Release workflow](../.github/workflows/release.yml): GoReleaser + GHCR publish path.
- [CodeQL workflow](../.github/workflows/codeql.yml) and [security workflow](../.github/workflows/security.yml): continuous supply-chain/security checks.

### EU controls mapping (supporting controls)

Talon supports these control objectives; it is not a compliance certification by itself.

| Framework | Example Talon support |
|-----------|-----------------------|
| GDPR Art. 30 | Evidence export and processing records |
| NIS2 Art. 21 | Policy enforcement, incident evidence, risk visibility |
| DORA | ICT risk evidence, caller-level cost and control telemetry |
| EU AI Act (9/13/14) | Risk controls, transparency logs, human-oversight gates |

### Examples

| Example | Description |
|---------|-------------|
| [Docker Compose demo](../examples/docker-compose/README.md) | Full demo stack with mock provider — no API key needed. |
| [Gateway minimal](../examples/gateway-minimal/README.md) | Smallest working LLM gateway config. |
| [MCP proxy minimal](../examples/mcp-proxy-minimal/README.md) | Smallest working MCP proxy config. |
| [Plan review](../examples/plan-review/README.md) | Human-in-the-loop demo (EU AI Act Art. 14). |
| [Starter policies](../examples/policies/README.md) | OPA/Rego policies for common governance scenarios. |
| [Observability stack](../examples/observability/README.md) | Local OTel Collector + Prometheus + Grafana with pre-built Talon dashboard. |
