# Roadmap & focus

Talon is the **control layer for company AI use cases**: it turns company AI policy into enforceable, use-case-specific controls and proves what was enforced. The stable product object is the **AI use case**, not the provider, model, agent framework or workflow runtime. Talon applies the strongest honest enforcement mechanism available for each environment — **INTERCEPT, DELEGATE, COMPILE or VERIFY** — while external runtimes keep ownership of their agent loop, workflow, sandbox and business-process state. The value order is **shared company control → consequential-action control → verifiable proof**; cost, reliability, attribution and session understanding remain important supporting capabilities rather than the category itself. Talon remains one self-hosted operating layer rather than a router, workflow engine, MCP-only product or GRC suite. For what Talon does *not* claim (compliance outcomes, immutability, control over actions it cannot intercept), see [LIMITATIONS.md](LIMITATIONS.md); for what "control plane" means here, see [Talon as a control plane](docs/explanation/control-plane.md). The canonical relationship between agents, sessions, native runs, operations, approvals, attempts and evidence is defined in the [Talon object model](docs/reference/object-model.md).

The active roadmap lives on GitHub: [Control-plane MVP / milestone 3](https://github.com/dativo-io/talon/milestone/3), [Action Gateway core / milestone 8](https://github.com/dativo-io/talon/milestone/8), and the pinned [control-plane MVP epic (#265)](https://github.com/dativo-io/talon/issues/265). Post-core hardening and integrations sit in [milestone 9](https://github.com/dativo-io/talon/milestone/9); parked bets remain isolated in milestone 4.

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

The active roadmap is optimized for one near-term outcome: **qualified activation** — a real company puts at least one non-demo AI use case into Talon's active control path and keeps Talon there.

### P0 — front door, policy truth and single-node production

- **Published install path** — native release artifacts and post-release smoke ([#359](https://github.com/dativo-io/talon/issues/359))
- **60-second published-image quickstart** — no clone, no build and no provider key ([#463](https://github.com/dativo-io/talon/issues/463))
- **Verifiable OCI distribution** — multi-arch image, signatures, provenance and SBOM ([#464](https://github.com/dativo-io/talon/issues/464))
- **Executable onboarding documentation** — every promoted getting-started path runs in CI against published artifacts ([#473](https://github.com/dativo-io/talon/issues/473))
- **Streaming first-run truth** — response PII warn/record preserves real streaming and is described honestly as post-delivery observation ([#476](https://github.com/dativo-io/talon/issues/476))
- **Effective policy visibility** — show the compiled use-case policy, rule provenance and bounded recent facts ([#305](https://github.com/dativo-io/talon/issues/305))
- **Safe rollout preview** — policy-impact preview without reintroducing global live shadow/log-only posture ([#459](https://github.com/dativo-io/talon/issues/459))
- **Use-case registration and inheritance** — make use case #2 registration, not another policy/integration project ([#472](https://github.com/dativo-io/talon/issues/472))
- **Always-enforced posture** — remove global `shadow`, `log_only` and MCP passthrough from the active product surface ([#442](https://github.com/dativo-io/talon/issues/442))
- **Single-node production contract** — persistence, backup/restore, recovery, degradation and operations for the OSS v1 topology ([#465](https://github.com/dativo-io/talon/issues/465))

### P0 — exact-action authorization spine

- **Control-plane/runtime boundary ADR** — one canonical policy/authorization model with `INTERCEPT | DELEGATE | COMPILE | VERIFY` enforcement choices ([#424](https://github.com/dativo-io/talon/issues/424))
- **Company/use-case policy compiler** — constrained authoring model, source attribution and effective rules; no generic policy DSL ([#425](https://github.com/dativo-io/talon/issues/425))
- **Trusted action catalog and exact binding** — schema validation, material-argument binding and reviewer-safe projection ([#427](https://github.com/dativo-io/talon/issues/427))
- **MCP 2026-07-28 clean cutover** — current protocol only, request metadata integrity and no legacy compatibility track ([#447](https://github.com/dativo-io/talon/issues/447))
- **Minimal durable authorization correctness** — immutable subject/decision, operation identity, attempt claim/dispatch boundary and conservative unknown outcomes ([#426](https://github.com/dativo-io/talon/issues/426))
- **Local approver authority** — canonical principals/groups and policy-authorized decisions ([#428](https://github.com/dativo-io/talon/issues/428))
- **Privileged management permissions** — explicit operator authorization, separate from reviewer/runtime identity ([#446](https://github.com/dativo-io/talon/issues/446))
- **Canonical Action Gateway API** — evaluate → decide → claim/consume → report ([#429](https://github.com/dativo-io/talon/issues/429))
- **Signed lifecycle proof** — exact subject, decision, approval, dispatch/attempt and known/unknown outcome ([#146](https://github.com/dativo-io/talon/issues/146))
- **MCP governance/evidence references** ([#372](https://github.com/dativo-io/talon/issues/372))
- **MCP enforcement convergence** — route governed MCP actions through the Action Gateway and remove alternate business-action authority ([#431](https://github.com/dativo-io/talon/issues/431))
- **MCP Tasks/MRTR bounded approval continuation** only where the selected first proof requires it ([#448](https://github.com/dativo-io/talon/issues/448))
- **Authenticated decision surface** — reviewer-safe projection plus CLI/API sufficient for the first exact-action proof ([#433](https://github.com/dativo-io/talon/issues/433))
- **Early exact-action proof gate** — one consequential action is prevented/approved/released at most once with verifiable evidence ([#458](https://github.com/dativo-io/talon/issues/458))

### P1 — breadth and hardening after the P0 spine

- **Argument-aware authorization** over trusted material action fields ([#205](https://github.com/dativo-io/talon/issues/205))
- **Session and operator truth** — lightweight sessions, `managed_by`, failure attention and correct operator-event classification ([#401](https://github.com/dativo-io/talon/issues/401), [#423](https://github.com/dativo-io/talon/issues/423), [#383](https://github.com/dativo-io/talon/issues/383))
- **Native/HTTP model-governance parity** ([#432](https://github.com/dativo-io/talon/issues/432))
- **Native run parity** — durable Plan Review/action waits without changing the core authorization model ([#430](https://github.com/dativo-io/talon/issues/430))
- **n8n/external workflow reference** ([#434](https://github.com/dativo-io/talon/issues/434))
- **Full native+n8n+MCP conformance** after the early proof, not before it ([#435](https://github.com/dativo-io/talon/issues/435))
- **Buyer/technical proof cuts** generated from the real authorization harness ([#437](https://github.com/dativo-io/talon/issues/437), [#438](https://github.com/dativo-io/talon/issues/438))
- **Install/readiness, upgrade, Helm and client compatibility** ([#466](https://github.com/dativo-io/talon/issues/466)–[#469](https://github.com/dativo-io/talon/issues/469))
- **Short-lived upstream workload credentials** where providers support workload identity/token exchange ([#474](https://github.com/dativo-io/talon/issues/474))
- **OTLP export** into existing customer observability systems ([#475](https://github.com/dativo-io/talon/issues/475))
- **Federated inbound workload identity** — OIDC/JWT, mTLS and SPIFFE mapped into normalized Talon principals ([#457](https://github.com/dativo-io/talon/issues/457))
- **Richer historical policy replay** — separate from the narrow P0 preview ([#441](https://github.com/dativo-io/talon/issues/441))
- **Pi** remains the preferred first external coding-agent proof after the core authorization contract is stable ([#453](https://github.com/dativo-io/talon/issues/453)–[#456](https://github.com/dativo-io/talon/issues/456))
- **OSS application composition seam** for the official Enterprise superset remains active architecture work but is not an OSS activation blocker ([#445](https://github.com/dativo-io/talon/issues/445))

### P2 / demand-gated

- **Read-only Talon dashboard** after OTLP/existing-observability integration ([#143](https://github.com/dativo-io/talon/issues/143))
- **Hermes support** only after demonstrated demand ([#449](https://github.com/dativo-io/talon/issues/449)–[#452](https://github.com/dativo-io/talon/issues/452))
- **Vercel eve integration research** only after demonstrated demand ([#461](https://github.com/dativo-io/talon/issues/461))
- **Homebrew** after the native artifact contract is stable ([#470](https://github.com/dativo-io/talon/issues/470))
- **One cloud IaC reference** only when a named customer selects the target ([#471](https://github.com/dativo-io/talon/issues/471))

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
| Agent/client identity | Client-asserted = **attribution, not authentication** | Existing workload identity may be federated through #457; stronger exact-request cryptographic attestation/anti-replay remains parked in [#149](https://github.com/dativo-io/talon/issues/149) |
| Dashboard | Read-only views + admin-API write endpoints | Read-only fleet projection plus a narrow authenticated approval surface (#143, #433) |

---

## Execution order

1. Make the product reachable and truthful: #359, #463, #464, #473 and #476.
2. Make company/use-case policy visible and safe to roll out: #305, #459, #472 and #442.
3. Lock the authorization architecture and compiler: #424, #425, #427 and #447.
4. Implement the minimal exact-action correctness kernel: #426, #428, #446, #429, #146 and #372.
5. Converge the primary enforcement surface: #431 plus only the #448/#433 slices required by the first proof.
6. Ship **#458** as the first differentiated exact-action activation gate.
7. In parallel, complete the OSS **single-node production contract #465**.
8. After the P0 spine is usable, add argument-aware rules, native/n8n parity, production hardening, identity and telemetry: #205, #401/#423/#383, #432/#430/#434, #466–#469, #474/#475 and #457.
9. Require **#435** only before claiming full native+n8n+MCP parity.
10. Run Pi or another design-partner integration only after the canonical authorization contract is stable; keep Hermes/eve demand-gated.

---

## Explicitly postponed

Parked with no delivery commitment (milestone ["Parked — not on active roadmap"](https://github.com/dativo-io/talon/milestone/4), tracked under [#116](https://github.com/dativo-io/talon/issues/116)): semantic caching, generic lifecycle hooks, stronger exact-request attestation, red-team/attachment-sandbox maturation, workflow/cross-session governance, verified multi-agent delegation, provider operational-facts intelligence, streaming response-PII observation beyond the immediate first-run fix, hot trigger/webhook reconciliation, Article 50 artifact-receipt integration, context budgeting/compression, and hot credential revocation. None of these may shape active architecture until the activation protocol in #116 is satisfied.

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

- Your company has **AI policies that different AI use cases implement inconsistently** and you need one constrained control model with explicit use-case-specific effective rules.
- You have **one consequential AI use case** and need Talon to prevent or authorize an exact action before the effect happens; that first use case must have standalone value even before fleet expansion.
- You expect to add more use cases and want use case #2 to inherit company controls rather than rebuild governance around a new runtime/provider.
- You need **provable records** of how AI traffic and governed actions were handled (customer security reviews, DPAs, audits) — the evidence layer generates them from operations you run anyway.
- You only need log shipping or cost dashboards, not enforcement before the provider/action boundary — a plain observability stack may suffice.

---

## How to influence the roadmap

We prioritize by impact on the four pillars, onboarding credibility, and community demand.

- [Feature request](https://github.com/dativo-io/talon/issues/new?template=feature_request.yml) — describe your use cases, stack, and the first control you need.
- 👍 on existing issues.
- [GitHub Discussions](https://github.com/dativo-io/talon/discussions)
