# Roadmap & focus

> **Portkey helps you operate AI. AGT helps you build governed agents. Talon helps you prove your AI traffic was governed — inside Europe, with signed evidence.**

Talon is a single Go binary that sits on the **network path** in front of LLM and MCP traffic. Change one URL and every call is policy-checked, PII-scanned, and written to an HMAC-signed evidence record you can export for auditor review. We are not trying to be a general AI platform, a model catalog, or an in-process agent SDK.

This page is the public "no" list and where we are headed. For operational boundaries (signatures, tool filter vs execution, keys), see [LIMITATIONS.md](LIMITATIONS.md).

---

## What we are optimizing for (2.0 wedge)

**Make the auditor happy without leaving the EU** — the near-term bet:

- Signed, regulator-mapped evidence exports (GDPR Art. 30, EU AI Act traceability, NIS2/DORA supporting controls).
- EU-sovereign routing and egress posture in the gateway path (`eu_strict` / `eu_preferred`).
- Self-hosted, air-gappable deployment — one binary, no managed control plane required.
- Drop-in proxy: zero per-agent instrumentation for existing OpenAI-compatible clients.

Success looks like a design-partner auditor accepting a Talon-generated evidence pack with minimal manual rework — not winning a "most models" bake-off.

---

## Anti-goals (what we are **not** building for 2.0)

These are deliberate. If you need them as primary value, another product may fit better (see [buyer fit](#who-should-choose-talon) below).

| We are **not** building | Why |
|-------------------------|-----|
| **Multi-language SDKs** | The gateway is language-agnostic by design; per-language SDKs copy high-maintenance surfaces and dilute the message. |
| **Full trust mesh / A2A protocol** | Interfaces only for now; lightweight per-agent identity is enough for "which agent did this?" in our ICP. |
| **Kubernetes operator / CRDs / gVisor** | Single-binary, process-level isolation is the MVP promise — not a cluster operator or kernel sandbox. |
| **Managed cloud / SaaS tier** | Self-host first; managed offering is a later commercial decision, not a 2.0 feature. |
| **Provider-count race** | We support EU-relevant providers well; we do not chase 1,600-model catalogs. |
| **Leading with generic "AI governance"** | The category is crowded; we lead with **prove + EU + signed evidence**. |

We still ship commodity gateway features (routing, budgets, dashboards) **only as much as the wedge requires** — not as the headline.

---

## Phased direction

### Now — credibility & EU compliance moat

- Trust surface: [LIMITATIONS.md](LIMITATIONS.md), [threat model](docs/reference/threat-model.md), [evidence integrity spec](docs/reference/evidence-integrity-spec.md), [conformance count](docs/reference/conformance.md), [benchmarks](docs/reference/benchmarks.md).
- Compliance report depth (RoPA / Annex IV rendering on top of `talon compliance report`).
- Data-flow / egress governance and in-region self-host hardening.

### Next — parity & narrowing AGT

- Reliability layer (retry/fallback, failover) on the gateway path.
- Runtime tool-call governance via MCP proxy (deny at execution, not only filter in the request body).
- Per-agent identity / attestation for evidence attribution.

### Later — expansion

- Red-team CLI and attachment-sandbox maturation.
- Cross-session / workflow governance.
- Named adopters, case studies, and additional EU-language docs.

---

## Who should choose Talon

| Your primary need | Better fit |
|-------------------|------------|
| Best general-purpose AI gateway: routing, caching, model breadth, polished observability | Portkey |
| Building a new agent system with deep in-process tool/action governance | Microsoft AGT |
| EU-sovereign LLM egress, PII controls, signed evidence, auditor exports on **existing** traffic | **Talon** |
| Deep tool governance **and** EU egress evidence | AGT + Talon together |
| Pass a DPO / security review for current AI usage with verifiable records | **Talon** (when evidence maturity matches your bar) |

---

## Shipped foundation

Core MVP capabilities (policy engine, PII scanning, evidence store, gateway proxy, MCP server, `talon init`, Docker demo) are in production use today. See [CHANGELOG.md](CHANGELOG.md) and [GitHub Releases](https://github.com/dativo-io/talon/releases) for version history.

---

## How to influence the roadmap

- Open a [feature request](https://github.com/dativo-io/talon/issues/new?template=feature_request.yml) with your use case.
- Vote on existing issues with a 👍 reaction.
- Join [GitHub Discussions](https://github.com/dativo-io/talon/discussions).

Priorities: (1) EU evidence / compliance depth, (2) community demand on the wedge, (3) engineering feasibility for a small team.
