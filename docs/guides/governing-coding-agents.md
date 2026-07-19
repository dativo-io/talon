# How to govern a coding-agent fleet with Talon

This guide shows how to govern an orchestrated coding-agent fleet — Claude Code subagents and Codex executors fanning out across two providers — through one Talon gateway, with per-session budgets, per-subagent attribution, and signed evidence. It is also the **canonical reference for the neutral orchestration-metadata contract**. Allow about 20 minutes.

For single-tool setup without orchestration, start with the [OpenClaw guide](openclaw-integration.md) — the gateway mechanics (vault, agent identity, policy) are identical.

## The scenario

A platform team runs an orchestrator that plans a change, then fans out:

- **Claude Code subagents** (planner, generator, reviewer) call Anthropic's Messages API.
- **Codex executors** call OpenAI's Responses API.
- One logical coding session spans **both providers** and a tree of subagents.

### Terminology: the roles are labels, not Talon concepts

Every role name in this guide — *orchestrator*, *planner*, *generator*, *reviewer*, *executor*, *judge* — is an **illustration, not a vocabulary Talon knows**:

- An **orchestrator** is simply whatever client code coordinates the work (a lead agent session, a script, a CI job) and passes one session id to everything it spawns. Talon never sees a role called "orchestrator" — it sees a Talon agent identity (which key authenticated), a session id, and per-request subagent labels.
- **`X-Talon-Agent-ID` / `X-Talon-Parent-Agent-ID` / `X-Talon-Client` values are free-form strings you choose.** Talon does not validate them against any known set, assigns them no semantics, and never uses them in policy — it records them as attribution (`provenance: client_asserted`) and rolls costs up by them. Name your subagents whatever your fleet calls them.
- **The one enforced vocabulary is `X-Talon-Stage`**: exactly `generation` (producing candidate work), `judge` (evaluating or selecting between candidates), or `commit` (finalizing the chosen result). Any other value is silently dropped at ingestion — the request proceeds, no stage is recorded.
- **Talon agent ≠ tenant ≠ subagent id.** A *Talon agent* is a traffic identity defined by one `agent.talon.yaml`, authenticated by its vault-bound agent key (e.g. one agent per tool); a *tenant* is the owning account, derived from the agent (`key → agent → tenant_id`); a *subagent id* is the client-asserted runtime label above. Budgets and policy bind to Talon agents and tenants — never to subagent ids.
- A **wire family** (`api_family`) is the provider's HTTP API shape — `anthropic` (Messages API) or `openai` (Chat Completions / Responses) — which determines how Talon parses, redacts, and prices traffic on that route.

In practice: with **Claude Code** and **Codex CLI**, the vendor adapters pick up whatever session/subagent headers the tools emit — nothing to invent. With a **custom orchestrator**, you choose the labels and set the generic headers yourself; if a tool version doesn't emit identity headers, set the generic ones from the process that launches it.

The platform team wants three things:

1. **Budgets** — a runaway session stops burning money, no matter which provider route it uses.
2. **Attribution** — every request traceable to a session, a subagent, and its parent.
3. **Signed evidence** — one queryable, integrity-checkable record of what happened.

## How Talon sees it

Talon sits between the fleet and both providers as a gateway. Every request carries orchestration metadata in HTTP headers; Talon validates it, records it in signed evidence, and rolls it up:

| The fleet does | Talon records |
|---|---|
| Orchestrator picks a session id and passes it to every subagent | One session grouping all requests with that id, across both provider routes (`TestGatewayOrchestration_CrossProviderAndIsolation`) |
| Each subagent identifies itself and its parent | `agent_id` / `parent_agent_id` per request, rolled up per subagent in the session summary |
| Spend accumulates on both wires | One session cost total; `max_session_cost` denies on either route (`TestSessionBudget_CrossProviderDeny`) |
| A client asserts identity | Evidence with `provenance: "client_asserted"` — attribution, **not** authentication (see [Limitations](#what-talon-does-not-see-limitations)) |

## Prerequisites

- Talon installed (`go install github.com/dativo-io/talon/cmd/talon@latest` or `curl -sL https://install.gettalon.dev | sh`). macOS linker errors: `CC=/usr/bin/clang go install ...@latest`.
- Claude Code, Codex CLI, or any orchestrator/client that can set HTTP headers on its LLM requests.
- Real Anthropic and OpenAI API keys (for governed traffic; the [demo](#6-run-the-offline-demo) needs none).

## Steps

### 1. Generate the coding-agents pack

```bash
mkdir talon-coding && cd talon-coding
talon init --pack coding-agents --name coding-gateway
```

This creates `agent.talon.yaml`, `agents/codex/agent.talon.yaml`, `talon.config.yaml`, and `pricing/models.yaml` pre-configured for coding traffic (source of truth: `internal/pack/templates/coding-agents/`; the pricing table is a copy of the embedded default). The defaults are deliberate:

- **Two agents, one per tool** — `claude-code` (the primary `agent.talon.yaml`, Anthropic route) and `codex` (`agents/codex/agent.talon.yaml`, OpenAI route), each its own AI use case with its own vault-bound agent key, `metadata.team: coding`, `policies.allowed_providers`, and its own budgets. Budgets and audit attribute **per tool**. To serve both from one `talon serve`, set `agents_dir: "."` (#267, shipped; the pack ships it commented out) — discovery matches the exact filename `agent.talon.yaml` and fails closed on duplicate `agent.name`. Without `agents_dir`, `talon serve` runs the single default `agent.talon.yaml`.
- **Shadow mode** — would-have-denied decisions are recorded in signed evidence while nothing blocks. Flip to `mode: "enforce"` once the dashboard looks right.
- **`response_pii_action: allow`** (organization baseline) — the honest streaming default: any other value buffers the *entire* SSE stream before the first token reaches the developer (see [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary)). Input-side scanning (`input_scan: true` → warn) still applies, and a per-agent downgrade to `allow` is deliberately not expressible.
- **Long timeouts** (`request_timeout: 600s`) — the 120s default hard-cuts long coding generations (#230).
- **Credential recognizers** — high-precision patterns for PEM private keys, AWS `AKIA...` ids, GitHub tokens, and `sk-ant-`/`sk-proj-` LLM keys. Talon is not a secret scanner; run gitleaks/trufflehog in pre-commit for repository hygiene — these cover prompt/response traffic only.
- **`session_limits.max_cost: 10.00`** per agent — the per-session soft cap (see [step 4](#4-set-budgets)).

**Identity topology choice** (this determines what "one session" means — see [session semantics](#session-semantics-what-one-session-means)):

| Topology | Effect | When |
|---|---|---|
| One agent per tool (pack default) | Per-tool budgets and attribution; a session id asserted under both agents is **two** sessions | Independent tools, per-team chargeback |
| One agent for the whole orchestrator, allowed on both providers (`policies.allowed_providers`) | One session spans both provider routes; subagent attribution via subagent ids | Orchestrated fan-out with a single fleet budget (this is what the [demo](#6-run-the-offline-demo) does) |

### 2. Store both provider keys and start the gateway

```bash
export TALON_SECRETS_KEY=$(openssl rand -hex 32)   # keep it; same value at serve time
talon secrets set anthropic-api-key "sk-ant-..."
talon secrets set openai-api-key "sk-..."

# Mint each tool's Talon agent key (bound via agent.key.secret_name)
talon secrets set claude-code-talon-key "$(openssl rand -hex 24)"
talon secrets set codex-talon-key       "$(openssl rand -hex 24)"

talon serve --gateway
```

Each tool authenticates with its **agent key**; Talon resolves the key to the agent, derives the tenant, and injects the real provider key upstream. For the Anthropic provider family, vault-stored keys are the **only** upstream auth mode — `upstream_auth_mode: client_bearer` is rejected at config load. This also means subscription/OAuth billing cannot be governed: pointing only `ANTHROPIC_BASE_URL` at Talon sends Claude Code's OAuth token, which Talon rejects. See [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary).

Point each tool's base URL at the gateway (`http://localhost:8080/v1/proxy/anthropic` for the Anthropic SDK; `http://localhost:8080/v1/proxy/openai/v1` for OpenAI-SDK/Codex clients, which append their own path — the trailing `/v1` matters, #235) with its agent key as the bearer token. Per-tool walk-throughs: [Claude Code](claude-code-integration.md), [Codex CLI](codex-cli-integration.md).

### 3. Send orchestration metadata — the neutral contract

This section is the canonical reference for the contract (implementation: `internal/gateway/orchmeta.go`, #194/#192).

#### Generic headers (work on every provider route)

| Header | Meaning |
|---|---|
| `X-Talon-Session-ID` | Groups requests into one coding session |
| `X-Talon-Agent-ID` | The subagent making this request |
| `X-Talon-Parent-Agent-ID` | The subagent that spawned it |
| `X-Talon-Client` | Client label recorded in evidence (e.g. `my-orchestrator`) |

Any client that can set headers participates fully — **no Talon change needed**. Example fan-out (orchestrator sets the same session id on both wires):

```bash
# Claude Code subagent → Anthropic route ($CLAUDE_CODE_KEY = the value minted
# into claude-code-talon-key)
curl -s -X POST http://localhost:8080/v1/proxy/anthropic/v1/messages \
  -H "Authorization: Bearer $CLAUDE_CODE_KEY" \
  -H "X-Talon-Session-ID: sess-feature-4711" \
  -H "X-Talon-Agent-ID: generator" \
  -H "content-type: application/json" -d '{...}'

# Codex executor → OpenAI route, child of generator
curl -s -X POST http://localhost:8080/v1/proxy/openai/v1/responses \
  -H "Authorization: Bearer $CODEX_KEY" \
  -H "X-Talon-Session-ID: sess-feature-4711" \
  -H "X-Talon-Agent-ID: executor" \
  -H "X-Talon-Parent-Agent-ID: generator" \
  -H "content-type: application/json" -d '{...}'
```

#### Vendor adapters are data, not code

Clients that already emit their own headers are mapped onto the same neutral contract by an adapter **table entry** (`vendorAdapters` in `internal/gateway/orchmeta.go`) — never a code branch in the request path. Two adapters ship today:

| Client | Session header | Agent header | Parent header |
|---|---|---|---|
| `claude-code` | `X-Claude-Code-Session-Id` | `X-Claude-Code-Agent-Id` | `X-Claude-Code-Parent-Agent-Id` |
| `codex` | `Session-Id` | `X-Openai-Subagent` | — (none; use the generic header for parent attribution) |

The first adapter with any populated header wins. Onboarding a new client is exactly one of: (a) the client sends the generic `X-Talon-*` headers — zero Talon changes — or (b) one new entry in the adapter table.

#### Precedence and provenance

- **Precedence per field: generic > vendor > synthetic.** If both `X-Talon-Session-ID` and a vendor session header are present *with different values*, the generic value is recorded and the vendor value is ignored — per field, so a generic session id can coexist with a vendor-asserted agent id (`TestResolveOrchestration_Precedence`).
- **`session_source`** records how the session id was obtained: `client_asserted` (generic header), `vendor_asserted` (adapter header), or `synthetic` (no client assertion; Talon derives `sess_<correlation-id>`).
- **`provenance` is always `client_asserted`.** Orchestration identity distinguishes subagents *within an already-authenticated agent*; it does not authenticate them. It is exactly as trustworthy as the workload that presented the agent key.
- **Identity is never a policy input.** Budgets bind to the Talon agent and the agent-scoped session tuple, never to subagent `agent_id` labels (`TestPolicyInputParity_WithAssertedSession`). Acting on client-asserted identity waits for workload attestation (#149).
- **Per-agent opt-out**: `agent.accept_client_metadata: false` in the agent file ignores asserted subagent/parent/client identity and vendor session headers (the generic `X-Talon-Session-ID` still resolves the session id). Default is `true`; the flag gates *recording* only (`TestGatewayOrchestration_FlagOff`). Requests without any asserted session id get a synthetic `sess_<correlation-id>` in evidence either way — synthetic ids never create session-store state or budgets.
- Optional `X-Talon-Stage` tags a request's pipeline stage; only `generation`, `judge`, `commit` are accepted — anything else is dropped at ingestion (`TestNormalizeStage`).

#### Header hygiene

Every orchestration value must be RFC 7230 token charset and at most **128 bytes**. Violations are **rejected with HTTP 400 — never truncated** — so hostile client-asserted strings never reach signed evidence or operator dashboards (`TestResolveOrchestration_Hygiene`, `TestGatewayOrchestration_HygieneRejectedAtGateway`).

#### Session semantics: what "one session" means

One session id groups requests **across providers**, scoped per **(tenant, agent)**. Two different agents asserting the same session id get **separate sessions and separate session budgets** — a session id is not a cross-tenant or cross-agent join key (`TestSessionBudget_AgentAndTenantIsolation`). Synthetic session ids are evidence-only and never create session state or budget rows (`TestSessionBudget_SyntheticSessionsCreateNoRows`).

### 4. Set budgets

Per agent, in its `agent.talon.yaml` — the agent's one override over the organization baseline:

```yaml
policies:
  session_limits:
    max_cost: 10.00   # soft cap per coding session
  cost_limits:
    daily: 50.00
    monthly: 500.00
```

How the session cap (`session_limits.max_cost`) behaves — precisely:

- A **new** request is denied once accrued session spend + the pre-request estimate exceeds the limit. The denial is HTTP 403 with a **provider-native error body** (`session_budget_exceeded: session spend 6.00 + estimate 1.00 exceeds limit 5.00`), so clients surface it like any provider error. One documented exception: errors emitted **before routing** (e.g. a request for an unknown provider prefix) use the OpenAI error shape, since no provider — and therefore no wire family — was resolved yet (#195).
- Spend accumulates **per session, not per provider** — the same session is denied on the other provider's route too (`TestSessionBudget_CrossProviderDeny`).
- It is a **soft cap**: one in-flight request whose real cost exceeds the estimate can overshoot, and N concurrent first requests are bounded only by N × per-request cost. Atomic reservation is #144 (`TestSessionBudget_SoftCapOvershoot`, `TestSessionBudget_ConcurrentBurstBound`).
- Session denies carry a **structured evidence detail** (limit, spent, estimate) — populated only for session-budget denies, not other reasons (`TestSessionBudgetDetail_OnlyOnSessionDeny`).
- In **shadow mode** the would-have-denied request proceeds and the deny is recorded as a shadow violation in signed evidence (`TestSessionBudget_ShadowMode`).
- If the session store fails, the budget check **fails open** and the gap is annotated in signed evidence (`session_budget_unavailable`, `TestSessionBudget_FailOpenAnnotated`).

### 5. Watch it: audit, costs, dashboard

All session surfaces read the same signed evidence through one aggregation (`evidence.BuildSessionSummary`) — the CLI, the export, and the dashboard cannot disagree.

```bash
# Per-session summary + the session's records (per-subagent rollup)
talon audit list --session sess-feature-4711

# Verify HMAC integrity of every record in the session
talon audit verify --session sess-feature-4711

# Export only this session's records (for hand-off). Cache-aware cost columns
# (cache_read_tokens, cache_write_tokens, pricing_basis) are included.
talon audit export --session sess-feature-4711

# Per-session cost rollup, machine-readable
talon costs --session sess-feature-4711 --json
```

Scoping: without `--tenant`/`--agent` these session commands are **unscoped** (they show the whole session, whichever tenant owns it — local CLI access implies DB access anyway); pass `--tenant` and/or `--agent` to filter. Note `talon costs`' *calendar* rollups (no `--session`) default to tenant `default` — the session forms do not.

The dashboard (`talon serve`) has a **Coding Sessions (orchestration)** panel showing active sessions with per-subagent attribution and `denials_by_reason` — budget trips show up as `session_budget_exceeded` counts.

### 6. Run the offline demo

The whole scenario — one session, two providers, subagent tree, PII warn, session budget trip, signed evidence — runs offline in about 30 seconds:

```bash
make coding-agents-demo        # from the repo root
# or: cd examples/coding-agents-demo && docker compose up -d --build && ./demo.sh all
```

The mock provider speaks both the Anthropic Messages wire and the OpenAI Responses wire (including SSE with cache-token usage), so no real API key exists anywhere in the stack. The same sequence is smoke-run in CI: `go test -tags=integration ./tests/integration -run TestCodingAgentsDemo_EndToEnd`. See [examples/coding-agents-demo/README.md](../../examples/coding-agents-demo/README.md).

---

## Failure mode → defense mapping

| Failure mode | Talon defense | Control / backing |
|---|---|---|
| Runaway spend inside one coding session | Per-session soft cap; new requests denied 403 with provider-native `session_budget_exceeded` | `max_session_cost`; `TestSessionBudget_SoftCapOvershoot` |
| Session shifts spend to the other provider's route | Session spend accumulates cross-provider; denied on both routes | `TestSessionBudget_CrossProviderDeny` |
| Two teams collide on the same session id | Sessions scoped per (tenant, agent) — separate sessions, separate budgets | `TestSessionBudget_AgentAndTenantIsolation` |
| Hostile header value aimed at evidence or dashboards | Hygiene gate: token charset, ≤128 bytes, reject 400 (never truncate) | `TestGatewayOrchestration_HygieneRejectedAtGateway` |
| Junk stage strings bloating session state | Fixed stage set (`generation`/`judge`/`commit`); others dropped at ingestion | `TestNormalizeStage` |
| Subagent forges its identity | Attribution, not authentication: `provenance: client_asserted`; identity never a policy input; budgets bind to the Talon agent | `TestPolicyInputParity_WithAssertedSession`; [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary) |
| Session store outage | Budget check fails open; gap annotated in signed evidence (`session_budget_unavailable`) | `TestSessionBudget_FailOpenAnnotated` |
| Budget denials disrupting rollout | Shadow mode records would-have-denied as shadow violations while traffic flows | `mode: "shadow"`; `TestSessionBudget_ShadowMode` |
| Credentials pasted into prompts | High-precision recognizers (PEM, `AKIA...`, GitHub tokens, `sk-ant-`/`sk-proj-`) evidenced via `pii_action: warn` | pack `agent.talon.yaml` `custom_recognizers` |
| Evidence tampering | HMAC verification over every record in the session | `talon audit verify --session <id>` |

---

## What Talon does not see (limitations)

[LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary) is the honest boundary statement for this whole scenario. In one breath:

- **Local tool execution is invisible** — file edits, shell commands, and local tool runs never transit the gateway; evidence shows the model's tool_use *intentions*, not local execution.
- **Client-asserted identity is attribution, not authentication** — attestation is #149.
- **Subscription/OAuth billing cannot be governed** — governed operation requires the agent-key + vault-injected-key model.
- **Session budgets are soft caps** — atomic reservation is #144.
- **Response-PII actions other than `allow` buffer whole streams** — which is why the pack's organization baseline sets `response_pii_action: allow`.
- **Cache pricing falls back to the input rate** when a pricing entry lacks cache rates.

## Summary

| Before | After |
|---|---|
| Orchestrator → two providers directly | Orchestrator → Talon → both providers |
| Spend per API key, unattributed | Per-session soft caps + per-agent daily/monthly caps |
| No idea which subagent did what | Per-subagent attribution in one session view |
| Logs you hope are intact | Signed evidence; `talon audit verify --session` |

---

## You're done

Your fleet's traffic now flows through one gateway: every request carries session and subagent attribution, session budgets deny runaway spend on either provider route, and one aggregation feeds the CLI, the export, and the dashboard.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| See the whole scenario run offline | [Coding-agents demo](../../examples/coding-agents-demo/README.md) (`make coding-agents-demo`) |
| Cap daily spend per team | [Cost governance by agent](cost-governance-by-agent.md) |
| Hand evidence to an auditor | [Compliance export runbook](compliance-export-runbook.md) |
| Copy-paste policy recipes | [Policy cookbook](policy-cookbook.md) |
| Know exactly where the boundary is | [LIMITATIONS.md §7](../../LIMITATIONS.md#7-coding-agent-and-orchestration-boundary) |
