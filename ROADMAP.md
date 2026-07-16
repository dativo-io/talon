# Roadmap & focus

Talon is the **control plane for company AI use cases**: operate and control your AI use cases with budget caps, shared policy defaults, reliability and session visibility, on one self-hosted binary you point your existing apps at. Every enforcement decision leaves a signed, verifiable evidence record — the proof layer under the operations. For what Talon does *not* claim (compliance outcomes, immutability, control over actions it cannot intercept), see [LIMITATIONS.md](LIMITATIONS.md); for what "control plane" means here, see [Talon as a control plane](docs/explanation/control-plane.md).

The active roadmap lives on GitHub: the [MVP milestone](https://github.com/dativo-io/talon/milestone/3) and the pinned [control-plane MVP epic (#265)](https://github.com/dativo-io/talon/issues/265).

---

## Shipped today (by pillar)

Everything below is current, code-verified behavior — see [CHANGELOG.md](CHANGELOG.md) and [releases](https://github.com/dativo-io/talon/releases).

- **Cost control** — per-agent daily/monthly caps that deny **before** the provider call; cross-provider session budgets (soft caps); cache-aware pricing with ISO currency labels; cost attribution and rollups by tenant/agent/session.
- **Reliability** — error-driven provider fallback chains triggered only by transient failures (timeout, connection, 429, 5xx), with every candidate re-checked against sovereignty, model and budget policy, failing closed on exhaustion; connect vs response-header timeout separation; provider-native error envelopes.
- **Shared policy** — an organization baseline with one explicit per-agent override; PII scanning (regex/Presidio/HTTP/local-LLM) on prompts, attachments, tool arguments and responses; tool allowlists and forbidden globs filtered or blocked before the model; egress and sovereignty rules (`eu_strict`/`eu_preferred`/`global`), air-gap mode.
- **Session understanding** — session identity (explicit `X-Talon-Session-ID` → vendor header → synthetic evidence-only); session-scoped audit, cost rollups and verification; dashboard session drill-down; metrics API, SSE stream, OTel GenAI traces.
- **Fleet operations** — a multi-agent native runtime where one `agent.talon.yaml` = one AI use case = one active key, discovered by an `agents_dir` scan (duplicate names fail closed); `agent.enabled` plus `talon agents enable/disable`; periodic safe config reload (default 30s) with last-known-good; the `talon agents` attention queue — STATE/HEALTH/COST/WHY — and `talon agents show <name>`.
- **Proof layer** — HMAC-SHA256 signed evidence per decision; `talon audit list/show/verify/export` incl. offline signed-file verification; compliance report generators (GDPR Art. 30 RoPA, EU AI Act Annex IV) built on the evidence; reproducible conformance suite and benchmarks.
- **Differentiators** — single self-hosted Go binary (SQLite default, no required SaaS); provider registry with jurisdiction/EU-region metadata across 10 providers; MCP server and MCP proxy interception; `talon init` packs (incl. coding agents).

---

## Active MVP roadmap

The gaps between today and the MVP contract, each tracked by an issue in the [MVP milestone](https://github.com/dativo-io/talon/milestone/3):

- **Cost-control contract** — warning thresholds as signed evidence (once per crossing), one organization webhook delivered after evidence commit, session-cap hardening ([#144](https://github.com/dativo-io/talon/issues/144))
- **Same-provider retries with backoff** — transient failures only, cost-counted, evidence-visible ([#139](https://github.com/dativo-io/talon/issues/139))
- **Stream idle timeout enforcement** ([#217](https://github.com/dativo-io/talon/issues/217)) and the **error contract** with stable machine codes ([#142](https://github.com/dativo-io/talon/issues/142), [#195](https://github.com/dativo-io/talon/issues/195))
- **Session summary contract** for `talon session show` ([#271](https://github.com/dativo-io/talon/issues/271))
- **Per-execution tool lifecycle evidence + tool-destination egress** on the MCP path ([#146](https://github.com/dativo-io/talon/issues/146))
- **Read-only operations dashboard** over the same semantics the CLI uses ([#143](https://github.com/dativo-io/talon/issues/143))

---

## Shipped vs target (honesty table)

| Capability | Today | Target |
|---|---|---|
| Budget hard caps | Deny before the provider call | — (shipped) |
| Session caps | **Soft** — in-flight requests can overshoot | Atomic reservation, or an explicit documented soft-cap decision ([#144](https://github.com/dativo-io/talon/issues/144)) |
| Cost warnings | OTel metric only | Signed evidence fact + org webhook ([#144](https://github.com/dativo-io/talon/issues/144)) |
| Provider failure handling | Policy-valid fallback chains (error-driven) | + same-provider retries with backoff ([#139](https://github.com/dativo-io/talon/issues/139)) |
| Tool schemas in LLM requests | Filtering/blocking **shipped** | — |
| MCP `tools/call` routed through Talon | Runtime interception with signed denial evidence **shipped** | Per-execution lifecycle evidence + destination egress ([#146](https://github.com/dativo-io/talon/issues/146)) |
| Local shell/filesystem/direct actions bypassing Talon | **Invisible and uncontrolled** | Permanently out of scope — Talon governs only what it can intercept |
| Agent identity | Client-asserted = **attribution, not authentication** | Attestation (parked, [#149](https://github.com/dativo-io/talon/issues/149)) |
| Dashboard | Read-only views + admin-API write endpoints | Read-only secondary projection ([#143](https://github.com/dativo-io/talon/issues/143)) |

---

## Explicitly postponed

Parked with no delivery commitment (milestone ["Parked — not on active roadmap"](https://github.com/dativo-io/talon/milestone/4), tracked under [#116](https://github.com/dativo-io/talon/issues/116)): generic context/memory layer, remote administration, proactive provider health probes, automatic model downgrade, generic tool risk tiers, full runtime cancellation, dashboard write actions, team-level policy inheritance, provider-breadth/routing-optimizer parity, broad GRC platform behavior, HITL approval gates for runtime tools, per-agent attestation, red-team CLI, workflow/cross-session governance, agent-to-agent (A2A) trust-mesh governance, semantic caching.

## Anti-goals (what we will not build)

These protect a small team from platform creep. If your primary need is below, another product is likely a better lead.

| We are **not** building | Why |
|-------------------------|-----|
| **Multi-language SDKs** | Your apps already speak HTTP; Talon governs at the boundary, not inside every codebase. |
| **Full agent-to-agent trust mesh** | Rare at typical scale; lightweight identity and attribution come first. |
| **Kubernetes operator / gVisor** | Most teams want systemd or Docker Compose, not another cluster abstraction. |
| **Managed Talon cloud (yet)** | Data residency and procurement often rule out hosted control planes; self-host first. |
| **1,600-model catalogs** | You need your actual providers done well — typically OpenAI, Anthropic, and local Ollama — not every frontier model on day one. |
| **Category creep into a GRC platform** | Talon operates and proves AI use cases; it does not certify compliance programs. |

---

## When to choose Talon

- You have a **growing number of AI use cases** (bots, agents, copilots) and need per-use-case budget caps, one set of policy defaults, and per-session visibility across them — Talon is built for exactly this.
- You have **one app with a growing bill** — start with [per-agent cost caps](docs/guides/cost-governance-by-agent.md) and grow from there.
- You need **provable records** of how AI traffic was handled (customer security reviews, DPAs, audits) — the evidence layer generates them from operations you run anyway.
- You only need log shipping or cost dashboards, not enforcement before the provider — a plain observability stack may suffice.

---

## How to influence the roadmap

We prioritize by impact on the four pillars, onboarding credibility, and community demand.

- [Feature request](https://github.com/dativo-io/talon/issues/new?template=feature_request.yml) — describe your use cases, stack, and the first control you need.
- 👍 on existing issues.
- [GitHub Discussions](https://github.com/dativo-io/talon/discussions)
