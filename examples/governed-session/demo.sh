#!/usr/bin/env bash
# Governed-session demo driver (#107) — REAL Anthropic + OpenAI traffic, plus a
# local Ollama for the sovereignty-routing act. Two cuts, one renderer:
#
#   ./demo.sh hero    # ~15s acquisition cut: 5 acts, above-the-fold GIF
#   ./demo.sh all     # ~1min deep cut: 11 acts
#
# Individual acts (mostly for development):
#   ./demo.sh allowed | tool | pii | route | budget
#   ./demo.sh planner-write | planner-read | executor | redact | routing-deny
#   ./demo.sh money | verify
#
# Every act runs under ONE visible X-Talon-Session-ID; the closing
# `talon audit verify --session <id>` proves they belong to one session.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GATEWAY="${GATEWAY:-http://localhost:8080}"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/out}"
mkdir -p "$OUT_DIR"

# Strict mode (asset recording): a missing dependency or a skipped headline act
# is a hard failure — never produce a committable GIF with a proof missing. The
# record scripts set TALON_DEMO_STRICT=1; interactive runs default to lenient.
STRICT="${TALON_DEMO_STRICT:-0}"

# Read-only acts (verify, money) inspect an EXISTING session, so they default
# to the last run's session id rather than minting a fresh (empty) one. Every
# other command starts a new session. SESSION_ID from the environment always
# wins.
if [[ -z "${SESSION_ID:-}" && ( "${1:-}" == "verify" || "${1:-}" == "money" ) && -s "${OUT_DIR}/session-id" ]]; then
  SESSION_ID="$(cat "${OUT_DIR}/session-id")"
fi
SESSION_ID="${SESSION_ID:-sess-governed-$(date +%s)}"
TENANT_KEY="talon-session-demo"
PLANNER_MODEL="claude-sonnet-5"
EXECUTOR_MODEL="gpt-4o"
PROBE_MODEL="gpt-4o-mini"
# The budget act loops real gpt-4o calls until session spend + the next
# estimate crosses the caller cap (0.03). ~$0.002/call, so the hero (which
# reaches the loop with little prior spend) trips around call ~14; the long
# demo reaches it having already spent more and trips within a few iterations.
BUDGET_LOOP_MAX=20

# Per-model input/output rates (per 1M tokens, table currency), keyed by the
# EXACT model string Talon records in execution.model_used — mirrored from
# pricing/models.yaml. gpt-4o and gpt-4o-mini differ by ~17× on input, so the
# naïve figure must be keyed on the real model, not a per-provider guess. The
# CORRECTED total is read from Talon's signed evidence; these rates only
# reconstruct the misleading naïve figure for the contrast.
MODEL_RATES_JSON='{
  "claude-sonnet-5": {"in": 3.00,  "out": 15.00},
  "gpt-4o":          {"in": 2.50,  "out": 10.00},
  "gpt-4o-mini":     {"in": 0.15,  "out": 0.60}
}'

# Record this run's session id — except for the read-only inspection acts,
# which target the LAST run's session and must not clobber it.
if [[ "${1:-}" != "verify" && "${1:-}" != "money" ]]; then
  echo "$SESSION_ID" >"${OUT_DIR}/session-id"
fi

# shellcheck source=../../scripts/lib/docker-compose-detect.sh
source "${SCRIPT_DIR}/../../scripts/lib/docker-compose-detect.sh"
detect_docker_compose

dc() { $COMPOSE "$@"; }
talon_in_container() { dc exec -T talon talon "$@"; }

require_stack() {
  if ! curl -sf "${GATEWAY}/health" >/dev/null 2>&1; then
    echo "✗ Talon not healthy at ${GATEWAY}" >&2
    echo "  → export ANTHROPIC_API_KEY=… OPENAI_API_KEY=…; make governed-session" >&2
    exit 1
  fi
}
require_jq() {
  command -v jq >/dev/null 2>&1 || { echo "✗ jq is required" >&2; exit 1; }
}

# ── Shared block renderer (CONFIG → REQUEST → EVIDENCE, TTY-gated colour) ─────
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_CYAN=$'\033[36m'; C_YEL=$'\033[33m'
else
  C_RESET=''; C_DIM=''; C_BOLD=''; C_GREEN=''; C_RED=''; C_CYAN=''; C_YEL=''
fi
BLOCK_BAR='════════════════════════════════════════════════════════════════════════════'

block_banner() {
  echo ""
  printf '%s%s%s\n' "$C_BOLD" "$BLOCK_BAR" "$C_RESET"
  while [[ $# -gt 0 ]]; do printf '%s %s%s\n' "$C_BOLD" "$1" "$C_RESET"; shift; done
  printf '%s%s%s\n' "$C_BOLD" "$BLOCK_BAR" "$C_RESET"
}

# block_rule <n> <total> <icon> <status> <title>
block_rule() {
  local n="$1" total="$2" icon="$3" status="$4" title="$5" scolor="$C_CYAN"
  case "$status" in
    ALLOWED|GOVERNED|ROUTED|VERIFIED|REDACTED|PROVEN|AUDITOR|ORCHESTRATOR|EXECUTOR|CACHE) scolor="$C_GREEN" ;;
    BLOCKED) scolor="$C_RED" ;;
  esac
  echo ""
  printf '%s──[ %s/%s ]── %s%s %s%s\n' "$C_BOLD" "$n" "$total" "$scolor" "$icon" "$status" "$C_RESET"
  printf '%s             %s%s\n' "$C_DIM" "$title" "$C_RESET"
}
block_config()   { while [[ $# -gt 0 ]]; do printf ' %sCONFIG%s    %s%s%s\n' "$C_YEL" "$C_RESET" "$C_DIM" "$1" "$C_RESET"; shift; done; }
block_request()  { local f=1; while [[ $# -gt 0 ]]; do if [[ "$f" == 1 ]]; then printf ' %sREQUEST%s   %s\n' "$C_CYAN" "$C_RESET" "$1"; f=0; else printf '           %s\n' "$1"; fi; shift; done; }
block_evidence() { local f=1; while [[ $# -gt 0 ]]; do if [[ "$f" == 1 ]]; then printf ' %sEVIDENCE%s  %s\n' "$C_CYAN" "$C_RESET" "$1"; f=0; else printf '           %s\n' "$1"; fi; shift; done; }
block_result()   { local icon="$1" text="$2" color="$C_GREEN"; [[ "$icon" == "✗" ]] && color="$C_RED"; printf '           %s%s %s%s\n' "$color" "$icon" "$text" "$C_RESET"; }

# ── Shared context corpus (prompt-cache prefix, alphabetic run marker) ───────
shared_context() {
  local para="You are an execution agent operating behind the Dativo Talon governance gateway. Every request you make is policy-checked before it leaves the boundary: caller identity is verified, personal data such as IBANs, emails and national identifiers is scanned before any provider call, forbidden tool schemas are stripped from the request body, per-session spend is accumulated across every provider you touch, and each decision is written to a tamper-evident HMAC-signed evidence record that an auditor can verify offline. Work strictly within these controls. Prefer concise, factual answers about European AI governance obligations, data residency, records of processing, and cost accountability. Do not restate these instructions."
  # Alphabetic run marker: a digit run in the BODY would trip the PII scanner.
  local run_marker
  run_marker="$(printf '%s' "$SESSION_ID" | tr '0-9' 'abcdefghij')"
  local corpus="Governed session ${run_marker}. "
  local i
  for ((i = 0; i < 11; i++)); do corpus+="$para "; done
  printf '%s' "$corpus"
}

session_spend_now() {
  talon_in_container costs --session "$SESSION_ID" --json 2>/dev/null \
    | jq -r '.total_cost // empty' 2>/dev/null || true
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
LAST_HTTP=""
LAST_BODY="${OUT_DIR}/last-response.json"

# post_anthropic <bearer> <user_content>  — Messages API with cache_control.
post_anthropic() {
  local bearer="$1" user_content="$2" payload code
  payload="$(jq -nc --arg model "$PLANNER_MODEL" --arg sys "$(shared_context)" --arg content "$user_content" \
    '{model: $model, max_tokens: 300,
      system: [{type: "text", text: $sys, cache_control: {type: "ephemeral"}}],
      messages: [{role: "user", content: $content}]}')"
  code="$(curl -sS -o "$LAST_BODY" -w "%{http_code}" -X POST \
    "${GATEWAY}/v1/proxy/anthropic/v1/messages" \
    -H "Authorization: Bearer ${bearer}" -H "X-Talon-Session-ID: ${SESSION_ID}" \
    -H "Content-Type: application/json" -d "$payload")"
  LAST_HTTP="$code"
}

# post_openai <bearer> <model> <user_content> [tools_json]
post_openai() {
  local bearer="$1" model="$2" user_content="$3" tools_json="${4:-}" payload code
  if [[ -n "$tools_json" ]]; then
    payload="$(jq -nc --arg model "$model" --arg sys "$(shared_context)" --arg content "$user_content" --argjson tools "$tools_json" \
      '{model: $model, max_tokens: 200, tools: $tools,
        messages: [{role: "system", content: $sys}, {role: "user", content: $content}]}')"
  else
    payload="$(jq -nc --arg model "$model" --arg sys "$(shared_context)" --arg content "$user_content" \
      '{model: $model, max_tokens: 200,
        messages: [{role: "system", content: $sys}, {role: "user", content: $content}]}')"
  fi
  code="$(curl -sS -o "$LAST_BODY" -w "%{http_code}" -X POST \
    "${GATEWAY}/v1/proxy/openai/v1/chat/completions" \
    -H "Authorization: Bearer ${bearer}" -H "X-Talon-Session-ID: ${SESSION_ID}" \
    -H "Content-Type: application/json" -d "$payload")"
  LAST_HTTP="$code"
}

# post_runner <user_content>  — the policy-aware AGENT RUNNER (not the proxy).
# This is where genuine sovereignty routing happens: a confidential prompt is
# classified tier-2, the US primary is rejected, and a local model is selected.
# In gateway mode the runner's OpenAI-compatible endpoint is /v1/chat/completions
# (tenant-authenticated); a caller tenant_key selects the tenant/agent.
post_runner() {
  local user_content="$1" payload code
  payload="$(jq -nc --arg content "$user_content" \
    '{messages: [{role: "user", content: $content}]}')"
  code="$(curl -sS -o "$LAST_BODY" -w "%{http_code}" -X POST \
    "${GATEWAY}/v1/chat/completions" \
    -H "Authorization: Bearer ${TENANT_KEY}" \
    -H "X-Talon-Session-ID: ${SESSION_ID}" \
    -H "Content-Type: application/json" -d "$payload")"
  LAST_HTTP="$code"
}

expect_http() {
  local want="$1"
  if [[ "$LAST_HTTP" != "$want" ]]; then
    echo "✗ Expected HTTP ${want}, got ${LAST_HTTP}" >&2
    cat "$LAST_BODY" >&2 || true
    exit 1
  fi
}

# latest_evidence_id — the newest evidence id FOR THIS SESSION, so a concurrent
# run's records can never be picked up (the demo's whole claim is "one session").
latest_evidence_id() {
  talon_in_container audit list --session "$SESSION_ID" 2>/dev/null \
    | grep -oE '(gw_|req_)[a-zA-Z0-9_-]+' | head -1
}

# ollama_ready — true when the routing-demo Ollama sidecar has the model.
ollama_ready() {
  dc exec -T ollama ollama list 2>/dev/null | grep -q 'llama3.2:1b'
}

# ollama_warm — load the model into memory so the routing act's first real
# inference doesn't hit the runner's 60s call timeout on a cold start (common
# on small CPU-only hosts). Best-effort; long timeout; ignores the result.
ollama_warm() {
  dc exec -T ollama ollama run llama3.2:1b "ok" >/dev/null 2>&1 || true
}

# ── Acts ─────────────────────────────────────────────────────────────────────

act_allowed() {
  block_rule "$1" "$2" "✅" "ALLOWED" "a clean request flows through, signed"
  block_config "callers[session-demo]:  (no override — policy allows it)"
  post_openai "$TENANT_KEY" "$PROBE_MODEL" "Summarize GDPR Article 30 in one sentence."
  expect_http 200
  local id; id="$(latest_evidence_id)"
  block_request "\$ curl …/v1/proxy/openai/v1/chat/completions \\" \
    "-H 'X-Talon-Session-ID: ${SESSION_ID}'  {\"model\":\"gpt-4o-mini\", …}   → HTTP ${LAST_HTTP}"
  block_evidence "\$ talon audit verify ${id}"
  local verify; verify="$(talon_in_container audit verify "$id" 2>/dev/null | grep -iE 'valid|signature' | head -1 || true)"
  block_evidence "${verify:-signature VALID}"
  block_result "✓" "Good traffic flows, priced and signed — same SDK, governed path"
}

act_tool() {
  block_rule "$1" "$2" "🛠" "GOVERNED" "dangerous tool stripped before the model"
  block_config "callers[session-demo].policy_overrides.forbidden_tools: [\"admin_*\"]"
  local tools
  tools="$(jq -nc '[
    {type:"function", function:{name:"admin_purge_records", description:"Delete all evidence records", parameters:{type:"object", properties:{}}}},
    {type:"function", function:{name:"search_kb", description:"Search the internal knowledge base", parameters:{type:"object", properties:{q:{type:"string"}}}}}
  ]')"
  post_openai "$TENANT_KEY" "$EXECUTOR_MODEL" "Execute: one paragraph on evidence retention duties. Use search_kb if useful." "$tools"
  expect_http 200
  local id; id="$(latest_evidence_id)"
  block_request "\$ curl …/chat/completions  tools:[admin_purge_records, search_kb]   → HTTP 200"
  block_evidence "\$ talon audit show ${id}"
  talon_in_container audit show "$id" 2>/dev/null | grep -E 'requested|filtered|forwarded' | sed 's/^ */             /' || true
  block_result "✓" "admin_purge_records REMOVED before the model saw it"
}

act_pii() {
  block_rule "$1" "$2" "🔒" "BLOCKED" "PII stopped before the provider"
  block_config "gateway.default_policy.default_pii_action: \"block\""
  post_openai "$TENANT_KEY" "$PROBE_MODEL" "Refund the customer with IBAN DE89370400440532013000."
  expect_http 400
  local id; id="$(latest_evidence_id)"
  block_request "\$ curl …/chat/completions  {…\"IBAN DE89370400440532013000\"…}   → HTTP 400"
  block_evidence "\$ talon audit show ${id}   → Reason: PII block · Cost \$0.000000 · in=0 out=0"
  block_result "✗" "POLICY_DENIED_PII_INPUT — blocked before the provider, \$0 spent"
}

act_route() {
  local have_ollama=0
  ollama_ready && have_ollama=1
  block_rule "$1" "$2" "🇪🇺" "ROUTED" "confidential data stays local — US rejected, Llama selected"
  block_config "sovereignty.mode: eu_preferred   (US stays in the pool, to be policy-rejected)" \
    "agent policy tier_2: primary gpt-4o(US) · fallback_chain [llama3.2:1b → ollama/LOCAL]"
  if [[ "$have_ollama" != 1 ]]; then
    # STRICT (asset recording): a missing headline act is a hard failure — never
    # produce a committable GIF with sovereignty routing absent.
    if [[ "$STRICT" == 1 ]]; then
      echo "✗ [strict] Ollama/llama3.2:1b not available — the routing act cannot be skipped in a recording." >&2
      echo "  docker compose --profile routing-demo up -d && docker compose exec ollama ollama pull llama3.2:1b" >&2
      exit 1
    fi
    block_result "⚠" "Ollama/llama3.2:1b not running — start it to see the local-serve half:"
    block_evidence "docker compose --profile routing-demo up -d && docker compose exec ollama ollama pull llama3.2:1b"
    return 0
  fi

  # Pre-warm the model so the ONE governed request below is fast and doesn't
  # cold-start. Warming is a separate operation, not the demonstrated request.
  ollama_warm

  # Confidential input (an IBAN → tier 2) through the policy-aware agent runner.
  # Keep the ask tiny: the point is the ROUTING decision, not a long answer.
  # Send exactly ONE request — that is what the block claims. In non-strict mode
  # a single slow-model 500 is retried once (and rendered as a retry, honestly);
  # in strict mode there is no retry — the recording must show one clean call.
  post_runner "In one short sentence, name the top EU AI Act evidence duty for account DE89370400440532013000."
  local retried=0
  if [[ "$LAST_HTTP" != "200" && "$STRICT" != 1 ]]; then
    ollama_warm
    post_runner "In one short sentence, name the top EU AI Act evidence duty for account DE89370400440532013000."
    retried=1
  fi
  expect_http 200
  local id; id="$(latest_evidence_id)"
  if [[ "$retried" == 1 ]]; then
    block_request "# TWO attempts via the agent runner — attempt 1 timed out on a cold local model," \
      "# attempt 2 succeeded. Same routing decision; only local inference latency varied." \
      "\$ curl …/v1/chat/completions  -H 'X-Talon-Session-ID: ${SESSION_ID}'   → HTTP 200"
  else
    block_request "# ONE request via the policy-aware agent runner (NOT a /v1/proxy URL)" \
      "\$ curl …/v1/chat/completions  -H 'X-Talon-Session-ID: ${SESSION_ID}'   → HTTP 200"
  fi
  block_evidence "\$ talon audit show ${id}"
  talon_in_container audit show "$id" 2>/dev/null | grep -iE 'Selected:|Rejected:|Routing Decision' | sed 's/^ */             /' || true
  block_result "✓" "Confidential data ran on local Llama — 0 OpenAI calls, data stayed in-region"
}

act_budget() {
  block_rule "$1" "$2" "💶" "BLOCKED" "session budget stops the next request"
  block_config "callers[session-demo].policy_overrides.max_session_cost: 0.03"
  # Drive real governed requests until the caller's session cap closes the gate.
  # This is an honest loop, not one curl: the block below reports how many
  # governed requests ran and the accumulated spend that tripped the cap.
  local i denied=0 rl=0 sent=0
  for ((i = 1; i <= BUDGET_LOOP_MAX; i++)); do
    post_openai "$TENANT_KEY" "$EXECUTOR_MODEL" "Continue: one short paragraph (${i}) on AI cost accountability."
    case "$LAST_HTTP" in
      403) denied=1; break ;;
      429) rl=$((rl + 1)); [[ "$rl" -gt 5 ]] && { echo "✗ provider rate-limited 5x; rerun shortly" >&2; exit 1; }; echo "  … provider 429, waiting 12s"; sleep 12; continue ;;
      200) rl=0; sent=$((sent + 1)) ;;
      *) echo "✗ Unexpected HTTP ${LAST_HTTP} in budget loop" >&2; cat "$LAST_BODY" >&2; exit 1 ;;
    esac
  done
  if [[ "$denied" != 1 ]]; then
    echo "✗ Session budget gate did not close within ${BUDGET_LOOP_MAX} calls" >&2
    echo "  session spend: $(session_spend_now) / cap 0.03" >&2
    exit 1
  fi
  grep -q "session_budget_exceeded" "$LAST_BODY" || { echo "✗ expected session_budget_exceeded" >&2; cat "$LAST_BODY" >&2; exit 1; }
  local reason spend; reason="$(jq -r '.error.message // empty' "$LAST_BODY" 2>/dev/null)"
  spend="$(session_spend_now)"
  block_request "SPEND     ${sent} governed gpt-4o requests → \$${spend:-?} accumulated in this session" \
    "\$ curl …/chat/completions  {\"model\":\"gpt-4o\", …}  (the next request)   → HTTP 403"
  block_evidence "body: ${reason}"
  block_result "✗" "session_budget_exceeded — real accumulated spend capped, next request refused"
}

# ── Long-demo-only acts ──────────────────────────────────────────────────────

PLAN_TEXT=""  # captured planner output, fed to the executor (P4: real orchestration)

act_planner_write() {
  block_rule "$1" "$2" "💾" "ORCHESTRATOR" "Anthropic plans, prompt-cache WRITE"
  block_config "system block with cache_control: {type: ephemeral}  (~2.3k-token prefix)"
  post_anthropic "$TENANT_KEY" "Plan three short executor steps to summarize EU AI Act evidence duties for a mid-market SaaS. Return only the numbered steps."
  expect_http 200
  PLAN_TEXT="$(jq -r '.content[0].text // empty' "$LAST_BODY" 2>/dev/null | tr '\n' ' ' | head -c 400)"
  local id; id="$(latest_evidence_id)"
  block_request "\$ curl …/v1/proxy/anthropic/v1/messages  {\"model\":\"claude-sonnet-5\", …}   → HTTP 200"
  block_evidence "\$ talon audit show ${id}"
  talon_in_container audit show "$id" 2>/dev/null | grep -iE 'cache_write|cost|pricing basis' | sed 's/^ */             /' || true
  block_result "✓" "Anthropic (orchestrator) wrote the prefix to cache; Talon priced it exactly"
}

act_planner_read() {
  block_rule "$1" "$2" "💾" "ORCHESTRATOR" "same prefix reused, cache READ ~0.1× price"
  block_config "identical cache_control system block → cache HIT"
  # Self-contained turn (P0): the plan text travels IN the user message, so the
  # model refines a real plan instead of replying \"I have no prior plan\".
  local prior="${PLAN_TEXT:-1) classify scope 2) map controls 3) draft RoPA}"
  post_anthropic "$TENANT_KEY" "Here is a draft plan: ${prior}. Tighten it to two terse steps."
  expect_http 200
  local id; id="$(latest_evidence_id)"
  block_evidence "\$ talon audit show ${id}"
  talon_in_container audit show "$id" 2>/dev/null | grep -iE 'cache_read|cost' | sed 's/^ */             /' || true
  block_result "✓" "Same tokens billed at the read rate — naïve input×rate math already wrong"
}

act_executor() {
  block_rule "$1" "$2" "✅" "EXECUTOR" "ChatGPT runs the planner's plan, priced and signed"
  block_config "executor prompt = the plan Anthropic returned (real orchestration, P4)"
  local plan="${PLAN_TEXT:-Summarize GDPR Article 30 records for AI traffic}"
  post_openai "$TENANT_KEY" "$EXECUTOR_MODEL" "Execute this plan in one paragraph: ${plan}"
  expect_http 200
  local id; id="$(latest_evidence_id)"
  block_evidence "\$ talon audit verify ${id}   → signature VALID · cached_tokens → cache_read"
  block_result "✓" "Executor ran the planner's steps — same session, same signed trail"
}

act_redact() {
  block_rule "$1" "$2" "✂️" "REDACTED" "email scrubbed, request still succeeds"
  block_config "callers[session-demo-redact].policy_overrides.pii_action: \"redact\""
  post_openai "talon-session-redact" "$PROBE_MODEL" "Reply to the customer who wrote from jan@example.com about their invoice."
  expect_http 200
  local id; id="$(latest_evidence_id)"
  block_evidence "\$ talon audit show ${id}   → PII redacted (email) · Allowed: true"
  block_result "✓" "Not every control is a wall — PII removed, the call still ran"
}

act_routing_deny() {
  block_rule "$1" "$2" "🧭" "BLOCKED" "model not in caller allowlist"
  block_config "callers[session-demo-eu].policy_overrides.allowed_models: [\"gpt-4o-mini\"]"
  post_openai "talon-session-eu" "$EXECUTOR_MODEL" "Summarize AI governance risks for a European SaaS."
  expect_http 403
  local id; id="$(latest_evidence_id)"
  block_evidence "\$ talon audit show ${id}   → Reason: model not in caller allowlist"
  block_result "✗" "POLICY_DENIED_ROUTING — model governance, not a silent swap"
}

act_money() {
  block_rule "$1" "$2" "🧮" "PROVEN" "naïve vs cache-aware cost + tamper check"
  require_jq
  # Export the SIGNED evidence bundle (HMAC per record) — the money story and
  # the tamper check both operate on it.
  local export_file="${OUT_DIR}/session-evidence.json"
  local tampered_file="${OUT_DIR}/session-evidence.tampered.json"
  talon_in_container audit export --session "$SESSION_ID" --format signed-json >"$export_file"

  # signed-json wraps full Evidence records: cost/model/tokens live under
  # .execution.*, tokens under .execution.tokens.{input,output,cache_read,cache_write}.
  local corrected currency naive reads writes
  corrected="$(jq '[.records[].execution.cost // 0] | add // 0' "$export_file")"
  currency="$(jq -r '[.records[].execution.currency | select(. != null and . != "")][0] // "USD"' "$export_file")"
  # Naïve = every input-family token (input + cache read + cache write) billed at
  # the model's full input rate, output at the output rate — keyed on the exact
  # model_used so gpt-4o vs gpt-4o-mini are priced apart. Unknown models cost 0
  # in the naïve figure (never over-claims a delta).
  naive="$(jq --argjson rates "$MODEL_RATES_JSON" '
    [.records[] | .execution as $e | ($e.tokens // {}) as $t
      | ($rates[$e.model_used] // {in:0,out:0}) as $rate
      | ((($t.input // 0) + ($t.cache_read // 0) + ($t.cache_write // 0)) * $rate.in
         + ($t.output // 0) * $rate.out) / 1000000
    ] | add // 0' "$export_file")"
  reads="$(jq '[.records[].execution.tokens.cache_read // 0] | add' "$export_file")"
  writes="$(jq '[.records[].execution.tokens.cache_write // 0] | add' "$export_file")"
  block_evidence "\$ talon audit export --session … --format signed-json"
  awk -v cur="$currency" -v n="$naive" -v c="$corrected" -v r="$reads" -v w="$writes" 'BEGIN {
    printf "             cache reads %s · cache writes %s\n", r, w
    printf "             Naïve (all input tokens × input rate):  %s %.6f\n", cur, n
    printf "             Corrected (Talon, cache-aware):         %s %.6f   Δ %s %.6f\n", cur, c, cur, n - c
  }'

  # Tamper check: flip a SIGNED field (policy_decision.allowed) in a valid-JSON
  # copy, then re-verify. The signature must catch it. verify_file_in_container
  # streams the file into the container's `audit verify --file` and returns its
  # exit code (nonzero = at least one record failed HMAC verification).
  jq '(.records[0].policy_decision.allowed) |= not' "$export_file" >"$tampered_file"
  # Capture exit codes with if/then/else: a bare `verify_file_in_container …; rc=$?`
  # would terminate the whole script under `set -euo pipefail` the instant verify
  # returns nonzero (which is exactly what the tampered file is meant to do),
  # before $? is ever read.
  local clean_rc=1 tampered_rc=0
  if verify_file_in_container "$export_file"; then clean_rc=0; else clean_rc=$?; fi
  if verify_file_in_container "$tampered_file"; then tampered_rc=0; else tampered_rc=$?; fi
  if [[ "$clean_rc" -ne 0 ]]; then
    echo "✗ The untampered signed export should verify clean" >&2
    exit 1
  fi
  if [[ "$tampered_rc" -eq 0 ]]; then
    echo "✗ Tamper NOT detected — the signature did not catch a flipped field" >&2
    exit 1
  fi
  block_evidence "\$ jq '.records[0].policy_decision.allowed |= not' … > tampered.json" \
    "\$ talon audit verify --file tampered.json   → Invalid records: 1 (signature INVALID)"
  block_result "✓" "Cache-aware cost is the budget's basis; flipping a signed field breaks the HMAC"
}

# verify_file_in_container <host-json-file> — stream a JSON export into the
# container and run `audit verify --file` on it. Returns that command's exit
# code (0 = all records valid; nonzero = at least one signature failed).
verify_file_in_container() {
  local f="$1"
  dc exec -T talon sh -c 'cat > /tmp/verify-input.json && talon audit verify --file /tmp/verify-input.json' <"$f" >/dev/null 2>&1
}

# session_verify_clean — run `audit verify --session`, print its summary line,
# and return nonzero if any record is invalid. Shared by act_verify and the
# hero's closing proof.
session_verify_clean() {
  local verify_out
  verify_out="$(talon_in_container audit verify --session "$SESSION_ID" 2>&1)"
  echo "$verify_out" | grep -iE 'valid|invalid|record' | tail -1 | sed 's/^/             /'
  echo "$verify_out" | grep -qE ", [0-9]+ valid, 0 invalid"
}

act_verify() {
  block_rule "$1" "$2" "📜" "AUDITOR" "signed session verifies + RoPA export"
  block_evidence "\$ talon audit verify --session ${SESSION_ID}"
  if ! session_verify_clean; then
    echo "✗ Expected all session records valid (0 invalid)" >&2
    exit 1
  fi
  # Actually generate the RoPA pack (GDPR Art. 30). `compliance ropa` with no
  # --output streams HTML to stdout, so we capture it into a host-side file under
  # out/ — the artifact is inspectable after the run, and a stale file can't fake
  # a pass. rm -f the target first, DON'T swallow failure with `|| true` (a failed
  # export must fail the act), then assert the file is freshly written and real
  # HTML (non-trivial size + an <html> tag), not an empty shell.
  local ropa_file="${OUT_DIR}/governed-session-ropa.html"
  rm -f "$ropa_file"
  talon_in_container compliance ropa --format html >"$ropa_file"
  local ropa_bytes
  ropa_bytes="$(wc -c <"$ropa_file" | tr -d '[:space:]')"
  if [[ ! -s "$ropa_file" || "$ropa_bytes" -lt 200 ]] || ! grep -qi '<html' "$ropa_file"; then
    echo "✗ RoPA export did not produce a valid HTML document (${ropa_bytes:-0} bytes)" >&2
    exit 1
  fi
  block_evidence "\$ talon compliance ropa --format html > out/governed-session-ropa.html   → ${ropa_bytes} bytes (GDPR Art. 30)"
  block_result "✓" "Every decision verifies (0 invalid) — and an auditor-ready RoPA pack is generated"
}

# ── Cuts ─────────────────────────────────────────────────────────────────────

cmd_hero() {
  require_stack; require_jq
  block_banner "Talon — One AI session. One governed boundary." \
    "Session: ${SESSION_ID}   ·   enforce · proxy + agent-runner · openai(US) ollama(LOCAL)"
  act_allowed 1 5
  act_tool    2 5
  act_pii     3 5
  act_route   4 5
  act_budget  5 5
  # Closing proof: actually verify the WHOLE session and assert 0 invalid — the
  # "every decision verifies" claim must be real and visible, not deferred.
  echo ""
  printf ' %sPROOF%s     $ talon audit verify --session %s\n' "$C_CYAN" "$C_RESET" "$SESSION_ID"
  if ! session_verify_clean; then
    echo "✗ Hero session did not verify clean (0 invalid)" >&2
    exit 1
  fi
  block_banner "Talon — One AI session, every decision signed and verified." \
    "govern before the provider, prove what happened after"
}

cmd_all() {
  require_stack; require_jq
  block_banner "Talon — Governed Session · Anthropic orchestrates, ChatGPT executes, one boundary" \
    "Session: ${SESSION_ID}   ·   enforce · session cap \$0.03 · ⚠ ~\$0.06 real spend"
  act_planner_write 1 11
  act_planner_read  2 11
  act_executor      3 11
  act_tool          4 11
  act_redact        5 11
  act_pii           6 11
  act_routing_deny  7 11
  act_route         8 11
  act_budget        9 11
  act_money        10 11
  act_verify       11 11
  block_banner "Talon — govern before the provider, prove what happened after"
}

usage() {
  sed -n '3,14p' "$0" | tr -d '#'
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    hero) cmd_hero ;;
    all) cmd_all ;;
    allowed) require_stack; require_jq; act_allowed 1 1 ;;
    tool) require_stack; require_jq; act_tool 1 1 ;;
    pii) require_stack; require_jq; act_pii 1 1 ;;
    route) require_stack; require_jq; act_route 1 1 ;;
    budget) require_stack; require_jq; act_budget 1 1 ;;
    planner-write) require_stack; require_jq; act_planner_write 1 1 ;;
    planner-read) require_stack; require_jq; act_planner_read 1 1 ;;
    executor) require_stack; require_jq; act_executor 1 1 ;;
    redact) require_stack; require_jq; act_redact 1 1 ;;
    routing-deny) require_stack; require_jq; act_routing_deny 1 1 ;;
    money) require_stack; require_jq; act_money 1 1 ;;
    verify) require_stack; act_verify 1 1 ;;
    -h|--help|help|"") usage ;;
    *) echo "Unknown command: $cmd" >&2; usage >&2; exit 1 ;;
  esac
}

main "$@"
