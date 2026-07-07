# Governed session demo — real providers, one budget, signed evidence (#107)

One agent session against **real** Anthropic + OpenAI APIs (and a local model
for the sovereignty act), end to end through Talon — one visible
`X-Talon-Session-ID`, one signed evidence trail. Two cuts share one renderer:

- **`./demo.sh hero`** — the ~15s acquisition cut, 5 acts:
  ✅ allowed · 🛠 tool stripped · 🔒 PII blocked · 🇪🇺 routed (US → local) · 💶 budget.
- **`./demo.sh all`** — the ~1-min deep cut, 11 acts (adds cache economics,
  redaction, model governance, tamper detection, RoPA export).

This is not a mock: token counts, cache hits, costs, and routing decisions come
from the providers' and the runner's own outputs, parsed and priced by Talon;
every decision — allowed or denied — is an HMAC-signed evidence record.

## The sovereignty act — data classification drives execution placement

The strongest beat: a **confidential** prompt (it contains an IBAN → data
tier 2) goes through Talon's policy-aware **agent runner**
(`/v1/agents/chat/completions`), not the proxy. The routing policy evaluates the
US model first, **rejects** it ("confidential tier requires LOCAL provider
only"), and **selects** a local Llama — for the same request. Zero calls leave
for the US provider; the signed `RoutingDecision` records both the rejected and
selected candidates. It's the same IBAN the gateway blocks outright in the PII
act: **policy, not the data alone, decides the outcome** — here, run it, but
keep it local. Under `sovereignty.mode: eu_preferred` the US provider stays in
the candidate pool so it's genuinely *rejected*, not silently absent.

## Prerequisites

- Docker (compose v2), `curl`, `jq`
- Real API keys. A full run uses cheap models and is session-capped:
  **≈ $0.06 per run**.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
```

The keys go into Talon's encrypted secret vault inside the container and are
used only for upstream auth — never logged, never stored in evidence.
`log_prompts`/`log_responses` are off: prompt bodies stay out of storage.

**For the sovereignty-routing act** (`route` / `all`), a local Ollama is needed.
It is opt-in via a compose profile so a normal run never pulls a multi-GB model:

```bash
docker compose --profile routing-demo up -d
docker compose exec ollama ollama pull llama3.2
```

Without it, the routing act notes Ollama is unavailable and skips its
local-serve half instead of failing the demo.

## Run it

```bash
make governed-session          # from repo root: builds + starts + waits for health
cd examples/governed-session
./demo.sh hero                 # the 5-act acquisition cut (~15s)
./demo.sh all                  # the 11-act deep cut (~1 min)
```

Individual acts: `allowed`, `tool`, `pii`, `route`, `budget`, `planner-write`,
`planner-read`, `executor`, `redact`, `routing-deny`, `money`, `verify`.

## The money story (why naïve cost math misleads)

Both providers discount cached prompt tokens — Anthropic bills cache **writes**
at 1.25× the input rate and cache **reads** at ~0.1×; OpenAI discounts
`cached_tokens`. A naïve `input_tokens × input_rate` total therefore misprices
exactly the workloads agents create (long shared prefixes, many calls).

Talon parses `cache_creation_input_tokens` / `cache_read_input_tokens`
(Anthropic) and `prompt_tokens_details.cached_tokens` (OpenAI) into evidence
(`cache_write` / `cache_read`), prices them with the per-model cache rates in
[pricing/models.yaml](../../pricing/models.yaml), and enforces the session
budget against that **corrected** number. `./demo.sh money` prints both totals
from your live run and leaves the signed export in `out/session-evidence.json`
so you can recompute them yourself.

Costs display in the pricing table's declared `currency:` (USD for the shipped
table). Budget caps (`max_session_cost`, `max_daily_cost`) are denominated in
the same unit.

## What the 11 acts show (`./demo.sh all`)

| # | Act | Signal |
|---|-----|--------|
| 1 | Orchestrator cache write | `audit show`: `cache_write > 0`, pricing basis `table` |
| 2 | Orchestrator cache read | `cache_read > 0` — naïve math is already wrong here |
| 3 | Executor runs the plan | the OpenAI executor consumes the planner's returned plan (real orchestration) |
| 4 | Tool governance | `admin_purge_records` requested + filtered; `search_kb` forwarded |
| 5 | Redaction | email scrubbed, request still forwards (redact, not block) |
| 6 | PII stop | HTTP 400, `POLICY_DENIED_PII_INPUT`, zero upstream cost |
| 7 | Model governance | HTTP 403, `POLICY_DENIED_ROUTING` — model not in caller allowlist |
| 8 | Sovereignty routing | runner: US model rejected (confidential → LOCAL only), local Llama selected; `RoutingDecision` shows both |
| 9 | Session budget gate | HTTP 403, `session_budget_exceeded` with `SessionBudget{limit, spent, estimate}` evidence |
| 10 | Money story + tamper | naïve vs corrected totals; flipping a byte breaks the signature |
| 11 | Verify + RoPA | `audit verify --session` → 0 invalid; `compliance ropa` auditor pack |

The `hero` cut is acts 1(allowed)/tool/PII/route/budget in acquisition order.
Because the traffic is real, per-run numbers vary a little (output lengths,
cache warm-up). The budget gate is a bounded loop — it runs until the gate
actually closes — so the demo is robust to that variance.

Talon provides enforceable controls and supporting evidence for your
GDPR / EU AI Act / NIS2 reviews; compliance itself remains your
organization's determination.

## Cleanup

```bash
cd examples/governed-session && docker compose down -v
```
