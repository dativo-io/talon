# Roadmap & focus

Talon is the **control plane for company AI use cases**: operate and control your AI use cases with budget caps, shared policy defaults, reliability and session visibility, on one self-hosted binary you point your existing apps at. Every enforcement decision leaves a signed, verifiable evidence record — the proof layer under the operations. For what Talon does *not* claim (compliance outcomes, immutability, control over actions it cannot intercept), see [LIMITATIONS.md](LIMITATIONS.md); for what "control plane" means here, see [Talon as a control plane](docs/explanation/control-plane.md). The canonical relationship between agents, sessions, native runs, operations, approvals, attempts and evidence is defined in the [Talon object model](docs/reference/object-model.md).

The active roadmap lives on GitHub: the [MVP milestone](https://github.com/dativo-io/talon/milestone/3) and the pinned [control-plane MVP epic (#265)](https://github.com/dativo-io/talon/issues/265).

---

## Shipped today (by pillar)

Everything below is current, code-verified behavior — see [CHANGELOG.md](CHANGELOG.md) and [releases](https://github.com/dativo-io/talon/releases).

- **Cost control** — per-agent daily/monthly caps that deny **before** the provider call; cross-provider session budgets enforced by atomic reservation (#144); cache-aware pricing with ISO currency labels; cost attribution and rollups by tenant/agent/session.
- **Reliability** — same-provider retries with backoff+jitter for transient failures (timeout, connection, 429, 5xx; evidence-visible, org baseline + per-agent override, #139), then error-driven provider fallback chains, with every candidate re-checked against sovereignty, model and budget policy, failing closed on exhaustion; connect vs response-header timeout separation; stream idle-timeout enforcement (healthy streams outlive `request_timeout`, silent ones abort with a terminal event); provider-native error envelopes.
- **Shared policy** — an organization baseline with one explicit per-agent override; PII scanning (regex/Presidio/HTTP/local-LLM) on prompts, attachments, tool arguments and responses; tool allowlists and forbidden globs filtered or blocked before the model; egress and sovereignty rules (`eu_strict`/`eu_preferred`/`global`), air-gap mode.
- **Session understanding** — session identity (explicit `X-Talon-Session-ID` → vendor header → synthetic evidence-only); session-scoped audit, cost rollups and verification; dashboard session drill-down; metrics API, SSE stream, OTel GenAI traces.
- **Fleet operations** — a multi-agent native runtime where one `agent.talon.yaml` = one AI use case = one active key, discovered by an `agents_dir` scan (duplicate names fail closed); `agent.enabled` plus `talon agents enable/disable`; periodic safe config reload (default 30s) with last-known-good; the `talon agents` attention queue — STATE/HEALTH/COST/WHY — and `talon agents show <name>`.
- **Proof layer** — HMAC-SHA256 signed evidence per decision; `talon audit list/show/verify/export` incl. offline signed-file verification; compliance report generators (GDPR Art. 30 RoPA, EU AI Act Annex IV) built on the evidence; reproducible conformance suite and benchmarks.
- **Differentiators** — single self-hosted Go binary (SQLite default, no required SaaS); provider registry with jurisdiction/EU-region metadata across 10 providers; MCP server and MCP proxy interception; `talon init` packs (incl. coding agents).

---

## Active MVP roadmap

The gaps between today and the MVP contract, each tracked by an issue in the active milestones:

### Current correctness gate

- **Lightweight session model** — `status = open | completed`, explicit terminal/idempotent completion, one `managed_by` manager field and evidence-derived recent failure attention ([#401](https://github.com/dativo-io/talon/issues/401))
- **Operator-event evidence classification** — keep lifecycle/operator events out of request traffic statistics ([#423](https://github.com/dativo-io/talon/issues/423))

### Controlled actions and approvals

- **Shared control-plane architecture ADR** — explicit ownership across Model Gateway, Action Gateway, native runtime and external adapters ([#424](https://github.com/dativo-io/talon/issues/424))
- **Configuration and trusted action contracts** ([#425](https://github.com/dativo-io/talon/issues/425), [#427](https://github.com/dativo-io/talon/issues/427))
- **Persistent approvals and logical operations** with exact subject binding and restart-safe state ([#426](https://github.com/dativo-io/talon/issues/426))
- **Approver identity and authorization** ([#428](https://github.com/dativo-io/talon/issues/428))
- **Canonical Action Gateway API** ([#429](https://github.com/dativo-io/talon/issues/429))
- **Native run integration and durable checkpoints** ([#430](https://github.com/dativo-io/talon/issues/430))
- **MCP convergence and shared model governance** ([#431](https://github.com/dativo-io/talon/issues/431), [#432](https://github.com/dativo-io/talon/issues/432))
- **Signed action lifecycle and execution receipts** ([#146](https://github.com/dativo-io/talon/issues/146))
- **Approval CLI/API/focused reviewer UI** ([#433](https://github.com/dativo-io/talon/issues/433))
- **n8n reference adapter and external runtime profile** ([#434](https://github.com/dativo-io/talon/issues/434))
- **End-to-end native+n8n+MCP proof** ([#435](https://github.com/dativo-io/talon/issues/435))

### Remaining operational work

- **Per-execution tool lifecycle evidence + tool-destination egress** on the MCP path ([#146](https://github.com/dativo-io/talon/issues/146))
- **Read-only operations dashboard** over the same semantics the CLI uses ([#143](https://github.com/dativo-io/talon/issues/143))

---

## Canonical lightweight object boundaries

The active design avoids one heavyweight universal state machine:

```text
agent / AI use case
  -> session: correlation, cost, timeline; status open/completed
       -> native run: Talon-owned executable lifecycle
       -> logical operation: one exact governed side effect
            -> approval: authorization decision
            -> attempt: transport/business result

signed evidence records decisions and observed/asserted results
```

Key rules:

- a session is not a workflow execution;
- pending approval is a session-linked attention fact, not a session status;
- provider/action failures remain evidence and request/operation facts;
- recovered failures remain visible but do not trigger the recent-failure signal;
- external inactivity or stopped polling is not interpreted as orchestrator failure;
- `managed_by` is the only field naming the session manager and never grants authority;
- `source` records session-identity provenance only;
- native and external runtimes use the same approval/operation services without Talon becoming a workflow engine.

---

## Shipped vs target (honesty table)

| Capability | Today | Target |
|---|---|---|
| Budget hard caps | Deny before the provider call | — (shipped) |
| Session caps | **Hard** against concurrency by atomic reservation (#144); admission is estimate-based | — (shipped; estimate-quality caveat stated in LIMITATIONS.md) |
| Cost warnings | Signed `budget_threshold` evidence once per crossing + org webhook after commit (#144) **shipped** | — |
| Provider failure handling | Same-provider retries with backoff (#139), then policy-valid fallback chains **shipped** | Evidence-derived recovered/unrecovered session summary and fleet signal (#401) |
| Session status | Current implementation exposes the older status vocabulary | Canonical `open | completed`; explicit terminal/idempotent completion (#401) |
| Session manager attribution | Existing session source records how identity was obtained; request metadata may include client attribution | Persist/expose one informational `managed_by` field using existing client/vendor attribution; keep `source` as provenance only and add no `lifecycle_owner` field (#401) |
| Pending human approval | Existing Plan Review/tool paths are separate and partly process-local | Canonical approval/run/operation status linked as session attention, never a session status (#426, #430, #433) |
| External workflow completion | No unified official adapter completion contract | Explicit external completion; completed session IDs cannot be reopened/reused (#401, #434) |
| Tool schemas in LLM requests | Filtering/blocking **shipped** | — |
| MCP `tools/call` routed through Talon | Runtime interception with signed denial evidence **shipped** | Per-execution lifecycle evidence + destination egress ([#146](https://github.com/dativo-io/talon/issues/146)) |
| Local shell/filesystem/direct actions bypassing Talon | **Invisible and uncontrolled** | Permanently out of scope — Talon governs only what it can intercept |
| Agent/client identity | Client-asserted = **attribution, not authentication** | Attestation (parked, [#149](https://github.com/dativo-io/talon/issues/149)) |
| Dashboard | Read-only views + admin-API write endpoints | Read-only fleet projection plus a narrow authenticated approval surface (#143, #433) |

---

## Execution order

1. #401 and #423 correctness fixes.
2. #424 architecture ADR.
3. #425 and #427 contracts in parallel.
4. #426 and #428 persistent state/identity in parallel.
5. #429 Action Gateway API.
6. #432, #431, #430 and #146 runtime/evidence integration.
7. #433 and #434 operator/integration surfaces.
8. #435 release proof, followed by buyer/technical demo cuts #437/#438.

---

## Explicitly postponed

Parked with no delivery commitment (milestone ["Parked — not on active roadmap"](https://github.com/dativo-io/talon/milestone/4), tracked under [#116](https://github.com/dativo-io/talon/issues/116)): generic context/memory layer, remote administration, proactive provider health probes, automatic model downgrade, generic tool risk tiers, full runtime cancellation, dashboard write actions beyond the focused approval surface, team-level policy inheritance, provider-breadth/routing-optimizer parity, broad GRC platform behavior, generic workflow/task management, multi-stage/quorum/batch approvals, per-agent attestation, red-team CLI, workflow/cross-session governance, agent-to-agent (A2A) trust-mesh governance, semantic caching.

## Anti-goals (what we will not build)

These protect a small team from platform creep. If your primary need is below, another product is likely a better lead.

| We are **not** building | Why |
|-------------------------|-----|
| **Generic workflow engine** | Talon owns governance, exact authorization, operation state and evidence at its boundaries; n8n/LangGraph/custom runtimes own workflow orchestration. |
| **Universal session state machine** | Sessions stay lightweight correlation/summary containers; runs, operations and approvals own their own lifecycles. |
| **Multi-language SDK ecosystem** | Existing apps already speak HTTP; a small supported action client/reference adapter is enough for the governed boundary. |
| **Full agent-to-agent trust mesh** | Rare at typical scale; lightweight identity and attribution come first. |
| **Kubernetes operator / gVisor** | Most teams want systemd or Docker Compose, not another cluster abstraction. |
| **Managed Talon cloud (yet)** | Data residency and procurement often rule out hosted control planes; self-host first. |
| **1,600-model catalogs** | You need your actual providers done well — typically OpenAI, Anthropic, and local Ollama — not every frontier model on day one. |
| **Category creep into a GRC platform** | Talon operates and proves AI use cases; it does not certify compliance programs. |

---

## When to choose Talon

- You have a **growing number of AI use cases** (bots, agents, copilots) and need per-use-case budget caps, one set of policy defaults, controlled side effects and per-session visibility across them — Talon is built for exactly this.
- You have **one app with a growing bill** — start with [per-agent cost caps](docs/guides/cost-governance-by-agent.md) and grow from there.
- You need **provable records** of how AI traffic and governed actions were handled (customer security reviews, DPAs, audits) — the evidence layer generates them from operations you run anyway.
- You only need log shipping or cost dashboards, not enforcement before the provider/action boundary — a plain observability stack may suffice.

---

## How to influence the roadmap

We prioritize by impact on the four pillars, onboarding credibility, and community demand.

- [Feature request](https://github.com/dativo-io/talon/issues/new?template=feature_request.yml) — describe your use cases, stack, and the first control you need.
- 👍 on existing issues.
- [GitHub Discussions](https://github.com/dativo-io/talon/discussions)
