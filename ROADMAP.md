# Roadmap & focus (EMEA SMB)

**Who this is for.** European and EMEA organisations in roughly the **200–1,000 employee** range — regulated mid-market companies with a small platform or DevOps team, a DPO or compliance function, and growing use of LLMs and vendor AI tools. You do not have a dedicated “AI platform” division; you need **defensible controls** without replatforming every app.

**What you are buying.** Proof that AI traffic was governed **inside your region**, with records you can hand to an auditor, customer security review, or board — not another model catalog or agent framework.

> **Portkey helps you operate AI. AGT helps you build governed agents. Talon helps you prove your AI traffic was governed — inside Europe, with signed evidence.**

Talon is one self-hosted Go binary on the **network path** in front of OpenAI-compatible and MCP traffic. Change a base URL; keep your SDKs. Every call is policy-checked, PII-scanned, and stored as an HMAC-signed evidence record.

For what Talon does *not* claim (compliance outcomes, signatures, tool execution), see [LIMITATIONS.md](LIMITATIONS.md).

---

## What EMEA SMB teams need from us

| Role | Job to be done | How Talon helps today |
|------|----------------|------------------------|
| **CTO / Head of Engineering** | Pass customer and board scrutiny on AI use without a 12-month platform project | Drop-in gateway, cost caps, EU routing posture, signed audit trail |
| **Compliance / DPO** | Show **supporting controls and evidence** for GDPR, NIS2, DORA, EU AI Act — not a “trust us” slide | Framework-mapped exports, `talon audit verify`, regulator-oriented report scaffolding |
| **Platform / DevOps** (often 2–10 people) | Run governance without Kubernetes complexity or per-app SDK work | Single binary, SQLite default, `talon init`, Docker demo, optional linux/amd64 release |
| **SecOps** | Stop PII and spend before it hits the provider; know which agent did what | Input/output PII scan, pre-forward policy deny, evidence per caller/agent |

**Success for our ICP:** your auditor or enterprise customer accepts a Talon evidence pack with little manual rework — and your team can operate it without a managed US control plane.

---

## Near-term focus (the wedge)

We optimize for **“make the auditor and enterprise customer comfortable without leaving the EU”**:

- **Signed evidence** — tamper-evident records and offline verification (`talon audit verify`), not generic logs.
- **EU egress posture** — `eu_strict` / `eu_preferred` routing; non-compliant paths denied with signed proof (see [limitations](LIMITATIONS.md) for proxy vs `talon run` behavior).
- **Self-host on your terms** — on-prem or EU cloud; air-gap friendly; no required Talon SaaS.
- **Drop-in for existing apps** — sales copilots, support bots, internal tools already on OpenAI-compatible APIs.

We are **not** optimizing for maximum model count, a polished multi-tenant SaaS, or greenfield agent frameworks.

---

## Roadmap by outcome (not feature laundry)

### Now — trust you can show in a review

What we are shipping so a skeptical EU technical buyer can complete a **10-minute proof** and a light audit:

- Public trust docs: [limitations](LIMITATIONS.md), [threat model](docs/reference/threat-model.md), [evidence integrity spec](docs/reference/evidence-integrity-spec.md), [conformance](docs/reference/conformance.md), [benchmarks](docs/reference/benchmarks.md).
- Richer **auditor-oriented packs** — RoPA / EU AI Act Annex IV-style output on top of `talon compliance report` (today: control-mapping summary).
- Clearer **data-flow / egress** story for “where did this prompt leave the building?”

### Next — production confidence for regulated traffic

What SMB platform teams ask for once Talon is on the critical path:

- **Reliability** — retry/fallback and failover so governance does not become the outage.
- **Runtime tool governance** — deny dangerous MCP/tool *execution*, not only strip tools from the request body.
- **Per-agent identity** — evidence that answers “which bot or integration made this call?” for NIS2-style accountability.

### Later — scale across teams and vendors

- Stronger attachment / injection testing for document-heavy workflows (HR, legal, support).
- Cross-session and workflow-level governance as agent chains mature.
- EMEA **case studies**, DE/FR docs, and named adopters in regulated verticals (financial services, health, B2B SaaS selling into enterprise).

---

## Anti-goals (what we will not build for 2.0)

These protect a small EMEA team from “platform creep.” If your primary need is below, another product is likely a better lead.

| We are **not** building | Why it matters for EMEA SMB |
|-------------------------|-----------------------------|
| **Multi-language SDKs** | Your apps already speak HTTP; we govern at the gateway, not inside every codebase. |
| **Full agent-to-agent trust mesh** | Rare at 200–1k scale; lightweight per-agent identity comes first. |
| **Kubernetes operator / gVisor** | Most ICP teams want systemd or Docker Compose, not another cluster abstraction. |
| **Managed Talon cloud (yet)** | Data residency and procurement often rule out US-hosted control planes; self-host first. |
| **1,600-model catalogs** | You need **EU-relevant providers done well**, not every frontier model on day one. |
| **“AI governance platform” as the headline** | You need **provable records** for GDPR / EU AI Act / customer DPAs — not another vague category. |

Commodity gateway features (caching, dashboards, budgets) exist **in service of the wedge**, not as the reason to buy.

---

## When to choose Talon (and when not to)

| Your situation (EMEA SMB) | Recommendation |
|-------------------------|----------------|
| Enterprise customers or regulators ask **how you govern existing** ChatGPT/Copilot/vendor AI traffic | **Talon** — network proof point |
| You are **building a new agent platform** and need deep in-process tool hooks | **Microsoft AGT** (Talon can sit in front for egress evidence) |
| You need **US-centric AI ops**: broad routing, prompt CMS, largest model matrix | **Portkey** |
| You need **both** deep in-process tool policy **and** EU egress evidence | **AGT + Talon** — complementary layers |
| You only need log shipping / cost dashboards, not signed per-request evidence | Observability stack may suffice; validate against your DPA |

---

## Already available

Policy engine (OPA), EU PII patterns, HMAC evidence store, LLM gateway proxy, MCP server, `talon init`, Docker no-key demo, compliance report scaffolding. See [CHANGELOG.md](CHANGELOG.md) and [releases](https://github.com/dativo-io/talon/releases).

**Persona workflows:** [Persona guides](docs/PERSONA_GUIDES.md) · **Adoption paths:** [Adoption scenarios](docs/ADOPTION_SCENARIOS.md)

---

## How to influence the roadmap

We prioritize EMEA SMB outcomes: **evidence depth**, **EU deployment realism**, then community demand.

- [Feature request](https://github.com/dativo-io/talon/issues/new?template=feature_request.yml) — describe your sector, size, and review type (customer DPA, ISO, EU AI Act, etc.).
- 👍 on existing issues.
- [GitHub Discussions](https://github.com/dativo-io/talon/discussions)
