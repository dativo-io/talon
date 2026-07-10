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

## New here?

Pick the path that matches your goal. For what Talon is **not** building, read [Roadmap & focus](../ROADMAP.md) early.

### Evaluator (~15 minutes)

1. [60-second demo](tutorials/quickstart-demo.md) — Docker Compose, mock provider, evidence in SQLite. No API key.
2. [Governed session demo](../examples/governed-session/README.md) — the control-plane proof: one real session under budget caps, policy, fallback routing, and session-level audit. Read the recorded walkthrough with no keys, or run it with your own keys (≈ $0.03).
3. [Evidence integrity 5-minute proof](tutorials/evidence-integrity-demo.md) — verify, export, tamper, fail verification. No API key.

When you need the proof layer for an auditor or customer review, continue with the [sample auditor pack](../examples/auditor-pack/README.md) (`make auditor-pack`).

### Builder (native binary, cold start)

1. [Install matrix](../README.md#install) — `make install` or `go install` on macOS/arm64; linux/amd64 release tarball or install script.
2. Set `TALON_SECRETS_KEY`, then `talon init --scaffold --name my-agent`, then `talon run --dry-run "hello"`.
3. [Your first governed agent](tutorials/first-governed-agent.md) — live LLM run and audit trail.

Smoke-check the builder path: `make verify-newcomer` (from repo root).

## Start Here (jobs-to-be-done)

Choose the shortest path for your situation:

1. **"I need to operate my AI use cases: budgets, reliability, one policy, session visibility."**
   - Cost: [Cap AI spend per caller](guides/cost-governance-by-caller.md)
   - Reliability: [Provider fallback chains](reference/configuration.md#provider-fallback-chains-error-driven-failover)
   - Policy: [Policy cookbook](guides/policy-cookbook.md) · [Policy packs](guides/policy-packs.md)
   - Sessions: [Governing coding agents](guides/governing-coding-agents.md) · [Manual governed session](tutorials/manual-governed-session.md)
   - The big picture: [Talon as a control plane](explanation/control-plane.md)
2. **"I already have an app calling OpenAI/Anthropic and want controls fast."**
   - Start: [Add Talon to your existing app](guides/add-talon-to-existing-app.md)
   - Third-party vendor: [Vendor integration guide](VENDOR_INTEGRATION_GUIDE.md), then [Architecture: MCP proxy](ARCHITECTURE_MCP_PROXY.md)
3. **"I need to prove what happened — to a customer, auditor, or my own board."**
   - Start: [Sample auditor pack](../examples/auditor-pack/README.md)
   - Learn the flow: [Turnkey compliance reports](tutorials/turnkey-compliance-reports.md) — init with EU policy packs to a downloaded RoPA in ~15 minutes
   - Verify everything: [How to verify turnkey compliance reports](guides/verify-turnkey-compliance-reports.md) — full checklist before a demo or release
   - Then: [How to export evidence for auditors](guides/compliance-export-runbook.md) · [How to clear DECLARATION MISSING blocks](guides/ropa-declarations.md)
4. **"I want to understand exactly what Talon enforces."**
   - Start: [What Talon does to your request](explanation/what-talon-does-to-your-request.md)
   - Then: [Why not just a PII proxy?](explanation/why-not-a-pii-proxy.md)

---

## Documentation index

### Tutorials (learning-oriented)

| Doc | Pillar | Description |
|-----|--------|-------------|
| [60-Second Demo (no API key)](tutorials/quickstart-demo.md) | Integrate | Docker Compose demo with mock provider — see the full pipeline in action in 60 seconds. |
| [Evidence integrity 5-minute proof](tutorials/evidence-integrity-demo.md) | Proof | End-to-end tamper-proof demo: verify in dashboard, export signed evidence, tamper one field, verify failure with CLI. |
| [Your first governed agent](tutorials/first-governed-agent.md) | Integrate | Install → init → run → see evidence. Native Talon (requires Go + API key). |
| [Manual governed session](tutorials/manual-governed-session.md) | Sessions | Reproduce a governed session by hand: tools, enforcement, sovereignty, session budgets, tamper check. |
| [Turnkey compliance reports](tutorials/turnkey-compliance-reports.md) | Proof | Init with EU policy packs → dashboard Compliance tab → signed RoPA / Annex IV exports, each leaving evidence. No API key needed. |

### How-to guides (goal-oriented)

| Doc | Pillar | Description |
|-----|--------|-------------|
| [Cap AI spend for a Slack/support bot in 10 minutes](guides/cost-governance-by-caller.md) | Cost | Fast path to caller-level daily/monthly hard caps, budget-deny proof, and evidence-backed cost attribution. |
| [How to run a first-line support agent with Talon](guides/internal-support-agent.md) | Cost | Ticket summarization with PII and cost controls. |
| [Incident response playbook](guides/incident-response-playbook.md) | Reliability | Common operational scenarios when running AI agents. |
| [How to govern coding agents](guides/governing-coding-agents.md) | Sessions | Govern a fleet of coding agents; orchestration metadata contract, session attribution, cost rollups. |
| [Claude Code integration](guides/claude-code-integration.md) | Sessions | Route Claude Code through Talon: setup, session attribution, limits. |
| [Codex CLI integration](guides/codex-cli-integration.md) | Sessions | Route Codex CLI through Talon: setup, conformance notes, limits. |
| [How to govern OpenClaw with Talon](guides/openclaw-integration.md) | Policy | Route OpenClaw LLM traffic through the gateway. |
| [How to govern ChatGPT/Claude Desktop (enterprise)](guides/desktop-app-governance.md) | Policy | Route desktop app traffic via DNS/TLS and gateway. |
| [How to offer Talon to multiple customers (multi-tenant/MSP)](guides/multi-tenant-msp.md) | Policy | Tenant isolation, API keys, and gateway callers. |
| [EU policy packs](guides/policy-packs.md) | Policy | Ready-made policy baselines with framework annotations (GDPR/NIS2/DORA/EU AI Act) as proof-layer metadata. |
| [Air-gapped deployment](guides/air-gapped-deployment.md) | Policy | Provable in-region / offline operation: egress guard, local models, sovereignty posture. |
| [Local scanner engines](guides/local-scanner-engines.md) | Policy | Run PII scanning on a local LLM (Ollama) or Presidio sidecar — no data leaves the host. |
| [How to verify memory is used](guides/memory-verification.md) | Policy | CLI steps to confirm memory is written and injected into prompts (optional layer). |
| [How to test and operate Plan Review](guides/plan-review-operators.md) | Policy | Human oversight gate for native agents (optional layer): configure, trigger, approve, dispatch, verify evidence. |
| [Plan Review E2E test case](guides/plan-review-e2e-testcase.md) | Policy | Feature inventory (F1–F30) and phased testcase TC-PR-001–012 with pass criteria. |
| [How to choose your integration path](guides/choosing-integration-path.md) | Integrate | Pick MCP proxy vs LLM gateway vs native Talon. |
| [Add Talon to your existing app](guides/add-talon-to-existing-app.md) | Integrate | Point your existing app (Python, Node, curl) at Talon in a few minutes; first real request and evidence. |
| [Docker primer: OpenClaw + Talon (cloud-ready)](guides/openclaw-talon-primer/docker-openclaw-talon-primer.md) | Integrate | Predefined Docker setup to run Talon gateway for OpenClaw; deploy in the cloud. |
| [Slack bot integration](guides/slack-bot-integration.md) | Integrate | Route your Slack bot's LLM calls through Talon for cost caps, PII controls, and an audit trail. |
| [How to run governed LLM calls in CI/CD](guides/cicd-pipeline-governance.md) | Integrate | Use Talon from GitHub Actions or GitLab CI. |
| [How to export evidence for auditors](guides/compliance-export-runbook.md) | Proof | Export, verify, and hand off audit evidence. |
| [How to verify turnkey compliance reports](guides/verify-turnkey-compliance-reports.md) | Proof | End-to-end checklist: policy packs, compliance API, dashboard Compliance tab, FinOps, auth matrix, smoke section 34. |
| [How to clear DECLARATION MISSING blocks in RoPA exports](guides/ropa-declarations.md) | Proof | Fill `talon.config.yaml` and `agent.talon.yaml` declarations; regenerate RoPA/Annex IV without placeholders. |

### Reference (technical description)

| Doc | Description |
|-----|-------------|
| [Configuration and environment](reference/configuration.md) | Environment variables, crypto keys, and config reference. |
| [Evidence integrity specification](reference/evidence-integrity-spec.md) | Normative signed-record spec: fields, canonical serialization, HMAC-SHA256 signing, and the independent verification procedure. |
| [Presidio compatibility matrix](reference/presidio-compatibility-matrix.md) | Scanner boundary contract: Presidio-shaped result ingress, canonical mapping, and byte-offset normalization rules. |
| [Threat model](reference/threat-model.md) | STRIDE-style attack surface, trust boundaries, threats/mitigations, and key-management assumptions for the gateway path. |
| [Governance control matrix](reference/governance-control-matrix.md) | Which controls run on each entry path (runner, gateway, MCP server/proxy, graph adapter), by-design limitations, and the parity contract that prevents posture drift. |
| [Conformance suite & count](reference/conformance.md) | What counts as a conformance test for the evidence + policy paths, and how to reproduce the published count with `make conformance`. |
| [Reproducible benchmarks](reference/benchmarks.md) | Gateway pipeline overhead, PII scan latency, and evidence write throughput (`make benchmarks`). |
| [Authentication and key scopes](reference/authentication-and-key-scopes.md) | Which keys authenticate which endpoint families (gateway vs control plane vs dashboard). |
| [Gateway dashboard](reference/gateway-dashboard.md) | Dashboard endpoints, metrics API schema, snapshot fields, and authentication. |
| [Operational control plane](reference/operational-control-plane.md) | Run management (list/kill/pause/resume), tenant lockdown, runtime overrides, tool approval gates. |

### Explanation (understanding-oriented)

| Doc | Description |
|-----|-------------|
| [Talon as a control plane](explanation/control-plane.md) | What the control plane for AI use cases means: four pillars, proof layer, vocabulary, what Talon is not. |
| [What Talon does to your request](explanation/what-talon-does-to-your-request.md) | Full request lifecycle: every check, every byte transformation, latency budget. |
| [Why not just a PII proxy?](explanation/why-not-a-pii-proxy.md) | Five failure scenarios: what a PII-only proxy misses, what Talon does, and how to verify. |
| [Evidence store](explanation/evidence-store.md) | Evidence record structure, session_id, HMAC signing (TALON_SIGNING_KEY), progressive disclosure, storage, and export (CSV/JSON columns). |
| [Roadmap & focus](../ROADMAP.md) | Shipped-vs-target status by pillar, the active MVP roadmap, and public anti-goals. |
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
| [Evidence integrity specification](reference/evidence-integrity-spec.md) | Byte-exact spec so a third party can independently verify a record. |
| [Conformance suite & count](reference/conformance.md) | Reproducible passing-test count for the evidence + policy paths (`make conformance`). |
| [Reproducible benchmarks](reference/benchmarks.md) | `make benchmarks` — gateway overhead, PII scan, evidence write on your hardware. |
| [Roadmap & focus](../ROADMAP.md) | Shipped-vs-target honesty table and published anti-goals — what Talon will not build. |
| [Sample auditor pack](../examples/auditor-pack/README.md) | Generated signed export + compliance report + RoPA + Annex IV pack for handoff review. |
| [Evidence integrity 5-minute proof](tutorials/evidence-integrity-demo.md) | Fast proof moment for auditors/operators, including offline signed-export verification. |
| [Threat model](reference/threat-model.md) | Attack surface, trust boundaries, and what the HMAC signature does and does not prove. |
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

### EU controls mapping (proof layer)

Talon's evidence layer supports these control objectives; it is not a compliance certification by itself.

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
