#!/usr/bin/env bash
# Governed-session demo driver (#107 Act II) — REAL Anthropic + OpenAI traffic.
#
# Usage (from examples/governed-session, stack running on localhost:8080):
#   ./demo.sh planner-write
#   ./demo.sh planner-read
#   ./demo.sh executors
#   ./demo.sh pii-probe
#   ./demo.sh budget-gate
#   ./demo.sh money-story
#   ./demo.sh verify
#   ./demo.sh all
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GATEWAY="${GATEWAY:-http://localhost:8080}"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/out}"
SESSION_ID="${SESSION_ID:-sess-governed-$(date +%s)}"
TENANT_KEY="talon-session-demo"
PLANNER_MODEL="claude-sonnet-5"
EXECUTOR_MODEL="gpt-4o"
PROBE_MODEL="gpt-4o-mini"
BUDGET_LOOP_MAX=12
NARRATE=0
PROOF_TOTAL=7

# Rates mirrored from pricing/models.yaml (per 1M tokens, table currency) for
# the narrated naïve-vs-corrected arithmetic. The CORRECTED total is never
# computed here — it is read from Talon's signed evidence; these rates only
# reconstruct the misleading naïve figure.
SONNET_IN_RATE=3.00
SONNET_OUT_RATE=15.00
GPT4O_IN_RATE=2.50
GPT4O_OUT_RATE=10.00

readonly DEMO_SEP='─────────────────────────────────────────────────────'
readonly DEMO_WIDE_SEP='─────────────────────────────────────────────────────────'

mkdir -p "$OUT_DIR"
echo "$SESSION_ID" >"${OUT_DIR}/session-id"

# shellcheck source=../../scripts/lib/docker-compose-detect.sh
source "${SCRIPT_DIR}/../../scripts/lib/docker-compose-detect.sh"
detect_docker_compose

dc() {
  $COMPOSE "$@"
}

talon_in_container() {
  dc exec -T talon talon "$@"
}

require_stack() {
  if ! curl -sf "${GATEWAY}/health" >/dev/null 2>&1; then
    echo "✗ Talon gateway not healthy at ${GATEWAY}" >&2
    echo "  → export ANTHROPIC_API_KEY=… OPENAI_API_KEY=…; make governed-session" >&2
    exit 1
  fi
}

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "✗ jq is required for the governed-session demo" >&2
    exit 1
  fi
}

# ── Output helpers (mirrors shortlist demo / talon CLI style) ───────────────

demo_intro() {
  [[ "$NARRATE" == "1" ]] || return 0
  echo ""
  echo "🦅 Dativo Talon — Governed Session Demo (#107 Act II)"
  echo "$DEMO_WIDE_SEP"
  echo "One real agent session, two real providers, one session budget."
  echo ""
  echo "  Proves: prompt-cache economics · cross-provider session budget"
  echo "          PII stop · tool governance · signed evidence for all of it"
  echo ""
  kv "Gateway" "$GATEWAY"
  kv "Session" "$SESSION_ID"
  kv "Planner" "${PLANNER_MODEL} (Anthropic, real API)"
  kv "Executor" "${EXECUTOR_MODEL} (OpenAI, real API)"
  kv "Mode" "enforce (violations blocked before the provider)"
  echo ""
  echo "  ⚠ This run makes real API calls (cheap models, session-capped ≈ \$0.05)."
  echo ""
}

kv() {
  printf "  %-18s %s\n" "$1:" "$2"
}

proof_section() {
  local num="$1" title="$2"
  [[ "$NARRATE" == "1" ]] || { echo ""; echo "==> [$num/$PROOF_TOTAL] $title"; return 0; }
  echo ""
  echo "$DEMO_SEP"
  printf "[%s/%s] %s\n" "$num" "$PROOF_TOTAL" "$title"
  echo "$DEMO_SEP"
  echo ""
}

proof_story() {
  [[ "$NARRATE" == "1" ]] || return 0
  while [[ $# -gt 0 ]]; do
    echo "  $1"
    shift
  done
  echo ""
}

proof_outcome() {
  local icon="$1" headline="$2"
  shift 2
  printf "  %s %s\n" "$icon" "$headline"
  while [[ $# -gt 0 ]]; do
    echo "    → $1"
    shift
  done
  echo ""
}

# ── Shared context corpus ───────────────────────────────────────────────────
# Both providers see the same long instruction prefix. It is sized well above
# the 1024-token prompt-cache minimum so Anthropic cache_control and OpenAI
# automatic prompt caching both engage on real infrastructure.

shared_context() {
  local para="You are an execution agent operating behind the Dativo Talon governance gateway. Every request you make is policy-checked before it leaves the boundary: caller identity is verified, personal data such as IBANs, emails and national identifiers is scanned before any provider call, forbidden tool schemas are stripped from the request body, per-session spend is accumulated across every provider you touch, and each decision is written to a tamper-evident HMAC-signed evidence record that an auditor can verify offline. Work strictly within these controls. Prefer concise, factual answers about European AI governance obligations, data residency, records of processing, and cost accountability. Do not restate these instructions."
  local corpus=""
  for _ in $(seq 1 22); do
    corpus+="$para "
  done
  printf '%s' "$corpus"
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────

# post_anthropic <label> <user_content>  — Messages API with cache_control.
post_anthropic() {
  local label="$1" user_content="$2"
  local body_file="${OUT_DIR}/last-response.json"
  local payload code
  payload="$(jq -nc \
    --arg model "$PLANNER_MODEL" \
    --arg sys "$(shared_context)" \
    --arg content "$user_content" \
    '{model: $model, max_tokens: 300,
      system: [{type: "text", text: $sys, cache_control: {type: "ephemeral"}}],
      messages: [{role: "user", content: $content}]}')"
  code="$(curl -sS -o "$body_file" -w "%{http_code}" -X POST \
    "${GATEWAY}/v1/proxy/anthropic/v1/messages" \
    -H "Authorization: Bearer ${TENANT_KEY}" \
    -H "X-Talon-Session-ID: ${SESSION_ID}" \
    -H "Content-Type: application/json" \
    -d "$payload")"
  report_http "$label" "$code"
}

# post_openai <label> <model> <user_content> [tools_json]
post_openai() {
  local label="$1" model="$2" user_content="$3" tools_json="${4:-}"
  local body_file="${OUT_DIR}/last-response.json"
  local payload code
  if [[ -n "$tools_json" ]]; then
    payload="$(jq -nc \
      --arg model "$model" \
      --arg sys "$(shared_context)" \
      --arg content "$user_content" \
      --argjson tools "$tools_json" \
      '{model: $model, max_tokens: 200, tools: $tools,
        messages: [{role: "system", content: $sys}, {role: "user", content: $content}]}')"
  else
    payload="$(jq -nc \
      --arg model "$model" \
      --arg sys "$(shared_context)" \
      --arg content "$user_content" \
      '{model: $model, max_tokens: 200,
        messages: [{role: "system", content: $sys}, {role: "user", content: $content}]}')"
  fi
  code="$(curl -sS -o "$body_file" -w "%{http_code}" -X POST \
    "${GATEWAY}/v1/proxy/openai/v1/chat/completions" \
    -H "Authorization: Bearer ${TENANT_KEY}" \
    -H "X-Talon-Session-ID: ${SESSION_ID}" \
    -H "Content-Type: application/json" \
    -d "$payload")"
  report_http "$label" "$code"
}

LAST_HTTP=""
report_http() {
  local label="$1" code="$2"
  LAST_HTTP="$code"
  local body_file="${OUT_DIR}/last-response.json"
  if [[ "$NARRATE" == "1" ]]; then
    kv "Request" "$label"
    kv "HTTP status" "$code"
    local excerpt
    excerpt="$(jq -r '.error.message // .content[0].text // .choices[0].message.content // empty' "$body_file" 2>/dev/null | tr '\n' ' ' | head -c 110)"
    [[ -n "$excerpt" ]] && kv "Response" "${excerpt}…"
    echo ""
  else
    echo "    ${label}: HTTP ${code}"
  fi
  if [[ "${EXPECT_HTTP:-}" != "" && "$code" != "${EXPECT_HTTP}" ]]; then
    echo "✗ Expected HTTP ${EXPECT_HTTP}, got ${code}" >&2
    cat "$body_file" >&2 || true
    exit 1
  fi
}

latest_evidence_id() {
  talon_in_container audit list --limit 1 2>/dev/null | grep -oE '(gw_|req_)[a-zA-Z0-9_-]+' | head -1
}

show_evidence_lines() {
  local id="$1"
  [[ -n "$id" ]] || return 0
  talon_in_container audit show "$id" 2>/dev/null \
    | grep -E '^(Allowed:|  Reason:|Cost:|Tokens:|Pricing Basis:)|POLICY_' | sed 's/^/    /' || true
  echo ""
}

# ── Acts ─────────────────────────────────────────────────────────────────────

cmd_planner_write() {
  require_stack
  require_jq
  proof_section "1" "Planner call — Anthropic prompt-cache WRITE"
  proof_story \
    "The planner sends a ~1.4k-token governed instruction prefix with" \
    "cache_control: ephemeral. Anthropic writes it to the prompt cache;" \
    "Talon records cache_creation_input_tokens as cache_write in evidence."
  EXPECT_HTTP=200 post_anthropic "planner (cache write)" \
    "Plan three short executor steps to summarize EU AI Act evidence duties for a mid-market SaaS."
  local id
  id="$(latest_evidence_id)"
  [[ "$NARRATE" == "1" ]] && show_evidence_lines "$id"
  proof_outcome "✓" "Planner forwarded — cache write recorded in signed evidence" \
    "audit show shows cache_write > 0 and its exact cost basis"
}

cmd_planner_read() {
  require_stack
  require_jq
  proof_section "2" "Planner refinement — Anthropic prompt-cache READ"
  proof_story \
    "The second planner call reuses the identical prefix within the cache TTL:" \
    "Anthropic bills those tokens at the cache-read rate (~0.1× input)." \
    "Naïve input×rate math is already wrong from this call onward."
  EXPECT_HTTP=200 post_anthropic "planner (cache read)" \
    "Refine the plan: fold step three into step two and keep it terse."
  local id
  id="$(latest_evidence_id)"
  [[ "$NARRATE" == "1" ]] && show_evidence_lines "$id"
  proof_outcome "✓" "Cache read recorded — cache_read tokens priced at the read rate" \
    "Same session, same signed trail, cross-provider spend accumulating"
}

cmd_executors() {
  require_stack
  require_jq
  proof_section "3" "Executor calls — OpenAI cached prompt + tool governance"
  proof_story \
    "Executors share the same long prefix, so OpenAI's automatic prompt cache" \
    "reports cached_tokens on repeat calls. Executor 2 also requests tools —" \
    "including admin_purge_records, which policy forbids (admin_*)." \
    "Talon strips it from the request body before the model can see it."
  EXPECT_HTTP=200 post_openai "executor 1" "$EXECUTOR_MODEL" \
    "Execute step 1: one paragraph on GDPR Art. 30 records for AI traffic."
  local tools
  tools="$(jq -nc '[
    {type: "function", function: {name: "admin_purge_records",
      description: "Delete all evidence records",
      parameters: {type: "object", properties: {}}}},
    {type: "function", function: {name: "search_kb",
      description: "Search the internal knowledge base",
      parameters: {type: "object", properties: {q: {type: "string"}}}}}
  ]')"
  EXPECT_HTTP=200 post_openai "executor 2 (admin_* tool stripped)" "$EXECUTOR_MODEL" \
    "Execute step 2: one paragraph on evidence retention duties. Use search_kb if useful." \
    "$tools"
  local id
  id="$(latest_evidence_id)"
  if [[ "$NARRATE" == "1" && -n "$id" ]]; then
    echo "  Tool governance (talon audit show ${id})"
    talon_in_container audit show "$id" 2>/dev/null \
      | grep -E 'Tool Governance|Requested:|Filtered:|Forwarded:' | sed 's/^/    /' || true
    echo ""
  fi
  proof_outcome "✓" "Executors ran governed — forbidden tool never reached the model" \
    "evidence.ToolGovernance: requested vs filtered vs forwarded" \
    "cached_tokens appear as cache_read in evidence on repeat calls"
}

cmd_pii_probe() {
  require_stack
  require_jq
  proof_section "4" "PII probe — IBAN stopped before any provider call"
  proof_story \
    "Mid-session, a request carries a real-looking German IBAN." \
    "default_pii_action: block — the request is denied pre-forward;" \
    "no token of it left your boundary, and the deny is signed evidence."
  EXPECT_HTTP=400 post_openai "pii probe (expected deny)" "$PROBE_MODEL" \
    "Refund customer with IBAN DE89370400440532013000 and email jan@example.com."
  local id
  id="$(latest_evidence_id)"
  [[ "$NARRATE" == "1" ]] && show_evidence_lines "$id"
  proof_outcome "✗" "HTTP 400 — POLICY_DENIED_PII_INPUT, zero upstream cost" \
    "The denial itself is an HMAC-signed evidence record in this session"
}

cmd_budget_gate() {
  require_stack
  require_jq
  proof_section "5" "Session budget gate — loop until the next request is refused"
  proof_story \
    "Caller cap: max_session_cost 0.04 (pricing-table currency). Talon sums" \
    "REAL spend across Anthropic + OpenAI in this session; each new request" \
    "is checked as spend + estimate BEFORE forwarding (#198)." \
    "The executor keeps working until the gate closes."
  local i code denied=0
  for i in $(seq 1 "$BUDGET_LOOP_MAX"); do
    EXPECT_HTTP="" post_openai "executor loop ${i}" "$EXECUTOR_MODEL" \
      "Continue: one short paragraph (${i}) on AI cost accountability."
    code="$LAST_HTTP"
    if [[ "$code" == "403" ]]; then
      denied=1
      break
    fi
    if [[ "$code" != "200" ]]; then
      echo "✗ Unexpected HTTP ${code} during budget loop" >&2
      cat "${OUT_DIR}/last-response.json" >&2 || true
      exit 1
    fi
  done
  if [[ "$denied" != "1" ]]; then
    echo "✗ Session budget gate did not close within ${BUDGET_LOOP_MAX} calls" >&2
    exit 1
  fi
  if ! grep -q "session_budget_exceeded" "${OUT_DIR}/last-response.json"; then
    echo "✗ Expected session_budget_exceeded in deny body" >&2
    cat "${OUT_DIR}/last-response.json" >&2
    exit 1
  fi
  local reason
  reason="$(jq -r '.error.message // empty' "${OUT_DIR}/last-response.json" 2>/dev/null)"
  local id
  id="$(latest_evidence_id)"
  [[ "$NARRATE" == "1" ]] && show_evidence_lines "$id"
  proof_outcome "✗" "HTTP 403 — denied pre-forward, nothing was spent on this request" \
    "Reason: ${reason}" \
    "Evidence carries SessionBudget{limit, spent, estimate} for auditors"
}

cmd_money_story() {
  require_stack
  require_jq
  proof_section "6" "Money story — misleading naïve total vs Talon's corrected total"
  proof_story \
    "Naïve accounting prices every input-side token at the full input rate." \
    "Talon's evidence prices cache writes at 1.25× and cache reads at ~0.1×," \
    "exactly as the providers bill. Same session, two very different numbers."
  local export_file="${OUT_DIR}/session-evidence.json"
  talon_in_container audit export --session "$SESSION_ID" --format json >"$export_file"

  local corrected currency
  corrected="$(jq '[.records[].cost] | add // 0' "$export_file")"
  currency="$(jq -r '[.records[].currency | select(. != null and . != "")][0] // "USD"' "$export_file")"

  local naive
  naive="$(jq --argjson sin "$SONNET_IN_RATE" --argjson sout "$SONNET_OUT_RATE" \
    --argjson gin "$GPT4O_IN_RATE" --argjson gout "$GPT4O_OUT_RATE" '
    [.records[]
      | . as $r
      | (if ($r.provider == "anthropic") then {in: $sin, out: $sout}
         elif ($r.provider == "openai")   then {in: $gin, out: $gout}
         else {in: 0, out: 0} end) as $rate
      | ((($r.input_tokens // 0) + ($r.cache_read_tokens // 0) + ($r.cache_write_tokens // 0)) * $rate.in
         + ($r.output_tokens // 0) * $rate.out) / 1000000
    ] | add // 0' "$export_file")"

  local reads writes
  reads="$(jq '[.records[].cache_read_tokens // 0] | add' "$export_file")"
  writes="$(jq '[.records[].cache_write_tokens // 0] | add' "$export_file")"

  echo "  Token classes across the session (from signed evidence):"
  kv "cache writes" "${writes} tokens (billed 1.25× input rate)"
  kv "cache reads" "${reads} tokens (billed ~0.1× input rate)"
  echo ""
  awk -v cur="$currency" -v n="$naive" -v c="$corrected" 'BEGIN {
    printf "  Naïve total  (all input-side tokens × input rate):   %s %.6f\n", cur, n
    printf "  Corrected    (Talon evidence, cache-aware):          %s %.6f\n", cur, c
    printf "  Delta        (what naïve math would misreport):      %s %.6f\n", cur, n - c
  }'
  echo ""
  proof_outcome "✓" "Corrected total is what the budget gate enforced against" \
    "Recompute it yourself: rates in pricing/models.yaml × tokens in the export" \
    "Export: out/session-evidence.json (signed records)"
}

cmd_verify() {
  require_stack
  proof_section "7" "Session rollup + signature verification"
  proof_story \
    "The whole session — two providers, allowed work, both denials — is one" \
    "auditable unit. Every record's HMAC must verify."
  echo "  talon audit list --session ${SESSION_ID}"
  talon_in_container audit list --session "$SESSION_ID" | sed 's/^/  /'
  echo ""
  echo "  talon audit verify --session ${SESSION_ID}"
  local verify_out
  verify_out="$(talon_in_container audit verify --session "$SESSION_ID")"
  while IFS= read -r line; do echo "  $line"; done <<<"$verify_out"
  echo ""
  if ! echo "$verify_out" | grep -qE ", [0-9]+ valid, 0 invalid"; then
    echo "✗ Expected all session records valid (0 invalid)" >&2
    exit 1
  fi
  proof_outcome "✓" "Every decision in this session verifies — 0 invalid" \
    "Auditors can re-verify offline from the signed export"
}

demo_finale() {
  [[ "$NARRATE" == "1" ]] || return 0
  echo ""
  echo "$DEMO_WIDE_SEP"
  echo "📋 Governed session complete"
  echo "$DEMO_WIDE_SEP"
  echo ""
  echo "  ✓ Real two-provider session  — Anthropic planner + OpenAI executors"
  echo "  ✓ Prompt-cache economics     — writes and reads priced exactly"
  echo "  ✓ Session budget gate        — cross-provider spend capped pre-forward"
  echo "  ✓ PII stop                   — IBAN never left the boundary"
  echo "  ✓ Tool governance            — admin_* stripped before the model"
  echo "  ✓ Signed evidence            — every record verified, 0 invalid"
  echo ""
  echo "  Talon provides enforceable controls and supporting evidence for your"
  echo "  GDPR / EU AI Act reviews; compliance remains your determination."
  echo ""
  kv "Session" "$SESSION_ID"
  kv "Artifacts" "$OUT_DIR (session-evidence.json)"
  echo ""
}

cmd_all() {
  NARRATE=1
  demo_intro
  cmd_planner_write
  cmd_planner_read
  cmd_executors
  cmd_pii_probe
  cmd_budget_gate
  cmd_money_story
  cmd_verify
  demo_finale
}

usage() {
  sed -n '3,14p' "$0" | tr -d '#'
  echo ""
  echo "Environment: GATEWAY (default http://localhost:8080), OUT_DIR (default ./out),"
  echo "             SESSION_ID (default sess-governed-<epoch>)"
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    planner-write) cmd_planner_write ;;
    planner-read) cmd_planner_read ;;
    executors) cmd_executors ;;
    pii-probe) cmd_pii_probe ;;
    budget-gate) cmd_budget_gate ;;
    money-story) cmd_money_story ;;
    verify) cmd_verify ;;
    all) cmd_all ;;
    -h|--help|help|"") usage ;;
    *)
      echo "Unknown command: $cmd" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
