# Governed session demo — real providers, one budget, signed evidence (#107 Act II)

One agent session against **real** Anthropic and OpenAI APIs, end to end through
Talon's enforce-mode gateway:

```
session begins (X-Talon-Session-ID)
  ↓  Anthropic planner call    — cache_control prefix → real prompt-cache WRITE
  ↓  Anthropic planner call 2  — same prefix → real prompt-cache READ (~0.1× rate)
  ↓  OpenAI executor calls     — shared prefix → cached_tokens reads; admin_* tool stripped
  ↓  PII probe                 — IBAN denied before any provider call (HTTP 400)
  ↓  executor loop             — REAL cross-provider spend accumulates per session
  ↓  next estimated request    — 403 session_budget_exceeded, pre-forward
  ↓  money story               — misleading naïve total vs Talon's cache-aware corrected total
  ↓  talon audit verify --session → N record(s), N valid, 0 invalid
```

This is not a mock: token counts, cache hits, and costs come from the providers'
own usage fields, parsed and priced by Talon, and every decision (including both
denials) is an HMAC-signed evidence record in one session trail.

## Prerequisites

- Docker (compose v2), `curl`, `jq`
- Real API keys. A full run uses cheap models and is session-capped:
  **≈ $0.05 per run**.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
```

The keys go into Talon's encrypted secret vault inside the container and are
used only for upstream auth — never logged, never stored in evidence.
`log_prompts`/`log_responses` are off: prompt bodies stay out of storage.

## Run it

```bash
make governed-session          # from repo root: builds + starts + waits for health
cd examples/governed-session
./demo.sh all                  # the full narrated session (~2 minutes)
```

Individual acts: `planner-write`, `planner-read`, `executors`, `pii-probe`,
`budget-gate`, `money-story`, `verify`.

## The money story (why naïve cost math misleads)

Both providers discount cached prompt tokens — Anthropic bills cache **writes**
at 1.25× the input rate and cache **reads** at ~0.1×; OpenAI discounts
`cached_tokens`. A naïve `input_tokens × input_rate` total therefore misprices
exactly the workloads agents create (long shared prefixes, many calls).

Talon parses `cache_creation_input_tokens` / `cache_read_input_tokens`
(Anthropic) and `prompt_tokens_details.cached_tokens` (OpenAI) into evidence
(`cache_write` / `cache_read`), prices them with the per-model cache rates in
[pricing/models.yaml](../../pricing/models.yaml), and enforces the session
budget against that **corrected** number. `./demo.sh money-story` prints both
totals from your live run and leaves the signed export in
`out/session-evidence.json` so you can recompute them yourself.

Costs display in the pricing table's declared `currency:` (USD for the shipped
table). Budget caps (`max_session_cost`, `max_daily_cost`) are denominated in
the same unit.

## What each proof shows

| # | Proof | Signal |
|---|-------|--------|
| 1 | Planner cache write | `audit show`: `cache_write > 0`, pricing basis `table` |
| 2 | Planner cache read | `cache_read > 0` — naïve math is already wrong here |
| 3 | Executors + tool governance | `ToolGovernance`: `admin_purge_records` requested, filtered; `search_kb` forwarded |
| 4 | PII stop | HTTP 400, `POLICY_DENIED_PII_INPUT`, zero upstream cost |
| 5 | Session budget gate | HTTP 403, `session_budget_exceeded: session spend … + estimate … exceeds limit …` with `SessionBudget{limit, spent, estimate}` evidence |
| 6 | Money story | naïve vs corrected totals from the signed export |
| 7 | Verify | `audit verify --session` → all records valid, 0 invalid |

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
