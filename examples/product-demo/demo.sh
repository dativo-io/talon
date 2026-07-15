#!/usr/bin/env bash
# Talon product demo — one operating layer for a company's AI use cases.
#
# Operates three real AI use cases through ONE Talon gateway, on REAL providers,
# and walks the four things Talon does for every use case in one operating period:
#
#   customer-support  → reliability (policy-valid failover) + shared policy (PII redaction)
#   coding-assistant  → shared capability policy (an organization tool boundary)
#   document-summary  → cost control (a projected-cost budget stop) + operational control
#   the fleet         → session understanding (talon agents + one session drill-down)
#                       and a signed record behind every decision, verified offline
#
# REAL providers, real paid calls (~$0.02-0.05/run of Talon-accounted cost on cheap
# models; denials cost $0). Requires OPENAI_API_KEY and ANTHROPIC_API_KEY, and the
# local model (Ollama, :11434) must be OFFLINE so the reliability beat sees a real
# failover.
#
#   ./demo.sh          # full evaluator walkthrough (verbose)
#   ./demo.sh hero     # directed, fixed-screen LIVE cut (the README GIF)
#
# The hero and full cuts share the SAME live execution and the SAME signed-evidence
# assertions — only the presentation density differs, so they can never disagree
# on what happened. Every headline is asserted against Talon's own signed evidence
# (jq -e) before it is presented; an unexpected outcome is ALWAYS fatal (in every
# mode) — the demo can never present a proof that did not actually happen.
#
# Security: the gateway binds to loopback only, on a random free port, with a
# random admin key and random per-use-case traffic keys. Not a hardened multi-user
# posture (keys reach `talon secrets set` as argv) — run it as yourself.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PAUSE="${DEMO_STEP_PAUSE:-0}"
COLOR="${TALON_DEMO_COLOR:-0}"
CUT="all"                                   # set by the dispatch below

OPENAI_URL="${TALON_DEMO_OPENAI_URL:-https://api.openai.com}"
ANTHROPIC_URL="${TALON_DEMO_ANTHROPIC_URL:-https://api.anthropic.com}"
LOCAL_LLAMA_URL="${TALON_DEMO_LOCAL_LLAMA_URL:-http://localhost:11434}"
PORT_OVERRIDE="${PORT:-}"

for t in go jq curl openssl; do command -v "$t" >/dev/null 2>&1 || { echo "✗ $t is required" >&2; exit 1; }; done

WORK=""; GW_PID=""
cleanup() { [[ -n "$GW_PID" ]] && kill "$GW_PID" >/dev/null 2>&1 || true; [[ -n "$WORK" ]] && rm -rf "$WORK"; }
trap cleanup EXIT
die() { echo "✗ $*" >&2; exit 1; }
trap 'echo "ERROR: demo aborted at line $LINENO (see above)." >&2' ERR

rand() { openssl rand -hex "${1:-12}"; }
fmt()  { awk -v v="$1" 'BEGIN{printf "%.4f", v}'; }        # consistent 4-dp money

# ── Semantic palette (one meaning per color) ─────────────────────────────────
#   cyan=Talon/selected/info · green=completed/enforced-ok · amber=policy/skip/budget
#   red=genuine technical failure only · grey=context.
if [[ -t 1 || "$COLOR" == 1 ]]; then
  R=$'\033[0m'; DIM=$'\033[2m'; B=$'\033[1m'; GRN=$'\033[32m'; RED=$'\033[31m'; CYN=$'\033[36m'; YEL=$'\033[33m'
else
  R=''; DIM=''; B=''; GRN=''; RED=''; CYN=''; YEL=''
fi
HRULE='────────────────────────────────────────────────────────────────────────'   # 72

# Verbose-cut renderers (used by the full `all` walkthrough).
BAR='══════════════════════════════════════════════════════════════════════'
banner() { echo; printf '%s%s%s\n' "$B" "$BAR" "$R"; while [[ $# -gt 0 ]]; do printf '%s %s%s\n' "$B" "$1" "$R"; shift; done; printf '%s%s%s\n' "$B" "$BAR" "$R"; }
beat()   { [[ "$1" != 1 ]] && [[ "$PAUSE" != 0 ]] && sleep "$PAUSE"; echo; printf '%s──[ %s/%s ]── %s  %s%s\n' "$B" "$1" "$2" "$3" "$4" "$R"; printf '%s              %s%s\n' "$DIM" "$5" "$R"; }
row()    { printf '  %s%-9s%s %s\n' "$YEL" "$1" "$R" "$2"; }
route()  { local c="$CYN"; [[ "$1" == FAILED ]]&&c="$RED"; [[ "$1" == SKIPPED ]]&&c="$YEL"; [[ "$1" == SELECTED ]]&&c="$GRN"; printf '  %s%-13s%s%-10s%s %s\n' "$B" "$2" "$c" "$1" "$R" "$3"; }
ok()     { printf '  %s✓ %s%s\n' "$GRN" "$1" "$R"; }
runcmd() { printf '\n%s$ %s%s\n' "$DIM" "$*" "$R"; eval "$*"; }
pause()  { [[ "$PAUSE" != 0 ]] && sleep "$PAUSE"; return 0; }

# Hero-cut renderers (fixed screen: clear, redraw, hold).
clear_scene() { printf '\033[2J\033[H'; }
draw_header() {
  printf '%b%s%b%*sENFORCE %b●%b\n' "${B}${CYN}" "TALON / ACME" "$R" 55 '' "$GRN" "$R"
  printf '%b3 AI USE CASES · 1 ORG POLICY · 1 OPERATING VIEW%b\n' "$DIM" "$R"
  printf '%b%s%b\n\n' "$DIM" "$HRULE" "$R"
}
scene()   { clear_scene; draw_header; }
hold()    { [[ "$PAUSE" != 0 ]] && sleep "${1:-2}"; return 0; }
running() { scene; printf '  %s%s%s\n' "$DIM" "$1" "$R"; }
title()   { printf '  %s%-24s%s%36s%s%s / 6%s\n\n' "$B" "$1" "$R" '' "$DIM" "$2" "$R"; }

# ── Assertions — ALWAYS fatal, in every mode ─────────────────────────────────
HTTP=""
require_http() { # require_http <expected> <label>
  [[ "$HTTP" == "$1" ]] && return 0
  echo "  response body:" >&2; cat "$WORK/b" >&2 2>/dev/null || true; echo >&2
  if grep -qiE "usage limit|quota|rate.?limit|invalid_api_key|authentication|permission|overloaded|billing|credit" "$WORK/b" 2>/dev/null; then
    echo "  ⚠ This looks like a PROVIDER-ACCOUNT issue (quota / auth / rate limit / outage), not a Talon" >&2
    echo "    policy decision. Check the relevant provider key/account and re-run. The demo aborts here" >&2
    echo "    on purpose — it will not fake a governed result on top of a failed upstream call." >&2
  fi
  die "$2: expected HTTP $1, got $HTTP"
}
assert_ev() { # assert_ev <file> <jq-filter> <label>
  jq -e "$2" "$1" >/dev/null 2>&1 || { echo "  (evidence in $1):" >&2; jq -c '.records[]?|{agent:.agent_id,allowed:.policy_decision.allowed,pii:.classification.pii_detected,fail:.failover.role,sb:.session_budget}' "$1" >&2 2>/dev/null | head -20; die "$3: signed evidence did not confirm the claim"; }
}
export_session() { talon audit export --format signed-json --session "$1" --output "$2" >/dev/null 2>&1 || die "export of session $1 failed"; }

# ── Setup: isolate env, mint keys, loopback bind, verify the running server ───
CS_KEY=""; CODE_KEY=""; DOC_KEY=""; GW_PORT=""; GATEWAY=""; SUPPORT_SID=""
setup() {
  WORK="$(mktemp -d)"
  local v
  for v in $(env | grep -oE '^TALON_[A-Za-z0-9_]+=' | sed 's/=$//'); do unset "$v"; done
  export TALON_DATA_DIR="$WORK/state"
  TALON_SECRETS_KEY="$(rand 32)"
  TALON_SIGNING_KEY="$(rand 32)"
  TALON_ADMIN_KEY="$(rand 24)"
  export TALON_SECRETS_KEY TALON_SIGNING_KEY TALON_ADMIN_KEY
  export TALON_LOG_LEVEL="warn"
  mkdir -p "$TALON_DATA_DIR"
  CS_KEY="$(rand 12)"; CODE_KEY="$(rand 12)"; DOC_KEY="$(rand 12)"
  SUPPORT_SID="support-$(rand 4)"

  [[ -n "${OPENAI_API_KEY:-}" ]]    || die "OPENAI_API_KEY is required (real provider, real spend ~\$0.05)."
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] || die "ANTHROPIC_API_KEY is required (document-summary runs on Anthropic)."
  if curl -sf -m 2 "${LOCAL_LLAMA_URL}/api/tags" >/dev/null 2>&1 || curl -sf -m 2 "${LOCAL_LLAMA_URL}/v1/models" >/dev/null 2>&1; then
    die "The local model at ${LOCAL_LLAMA_URL} is UP — this demo's reliability beat needs it DOWN (customer-support fails over FROM the local model). Stop Ollama and retry."
  fi

  if [[ -n "$PORT_OVERRIDE" ]]; then GW_PORT="$PORT_OVERRIDE"
  elif command -v python3 >/dev/null 2>&1; then GW_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
  else GW_PORT=$(( (RANDOM % 20000) + 20000 )); fi
  GATEWAY="http://127.0.0.1:${GW_PORT}"

  echo "==> Preparing the fleet (build, isolated config, loopback gateway)..." >&2
  mkdir -p "$WORK/bin"
  ( cd "$REPO_ROOT" && go build -o "$WORK/bin/talon" ./cmd/talon )
  export PATH="$WORK/bin:$PATH"

  sed -e "s#https://api.openai.com#${OPENAI_URL}#g" \
      -e "s#https://api.anthropic.com#${ANTHROPIC_URL}#g" \
      -e "s#http://localhost:11434#${LOCAL_LLAMA_URL}#g" \
      "$SCRIPT_DIR/talon.config.yaml" > "$WORK/talon.config.yaml"
  printf '\ndata_dir: %s\n' "$TALON_DATA_DIR" >> "$WORK/talon.config.yaml"
  cp -r "$SCRIPT_DIR/agents" "$WORK/agents"
  cd "$WORK"

  talon secrets set local-llama-demo-key  "not-a-real-key-local-demo" --tenant acme --agent customer-support >/dev/null
  talon secrets set openai-api-key    "$OPENAI_API_KEY"    --tenant acme --agent customer-support --agent coding-assistant >/dev/null
  talon secrets set anthropic-api-key "$ANTHROPIC_API_KEY" --tenant acme --agent document-summary >/dev/null
  talon secrets set customer-support-talon-key "$CS_KEY"   --tenant acme --agent customer-support >/dev/null
  talon secrets set coding-assistant-talon-key "$CODE_KEY" --tenant acme --agent coding-assistant >/dev/null
  talon secrets set document-summary-talon-key "$DOC_KEY"  --tenant acme --agent document-summary >/dev/null

  ( talon serve --host 127.0.0.1 --port "$GW_PORT" --gateway ) >"$WORK/gw.log" 2>&1 &
  GW_PID=$!
  local _ up=0
  for _ in $(seq 1 60); do curl -sf "${GATEWAY}/health" >/dev/null 2>&1 && { up=1; break; }; sleep 0.3; done
  [[ "$up" == 1 ]] || { tail -30 "$WORK/gw.log" >&2; die "gateway did not become healthy at ${GATEWAY}"; }
  kill -0 "$GW_PID" 2>/dev/null || die "gateway process exited during startup"
  local hdr; hdr="$(curl -s -D- -o /dev/null "${GATEWAY}/health")"
  grep -qi '^x-talon-service: talon' <<<"$hdr" || die "server on ${GW_PORT} is not Talon (missing X-Talon-Service marker) — port collision?"
  local n; n="$(talon agents --url "$GATEWAY" --json 2>/dev/null | jq '.agents | length')"
  [[ "$n" == 3 ]] || die "expected exactly 3 discovered agents, got ${n:-none} — wrong config or stale server"
}

# ── Live HTTP (shared by both cuts) ──────────────────────────────────────────
openai_chat() { # <bearer> <provider> <model> <content> [session]
  local -a h=(-H "Authorization: Bearer $1" -H "Content-Type: application/json"); [[ -n "${5:-}" ]] && h+=(-H "X-Talon-Session-ID: $5")
  HTTP="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X POST "${GATEWAY}/v1/proxy/$2/v1/chat/completions" "${h[@]}" \
    -d "$(jq -nc --arg m "$3" --arg c "$4" '{model:$m,messages:[{role:"user",content:$c}]}')")"
}
anthropic_msg() { # <bearer> <model> <content> <max_tokens> [session]
  local -a h=(-H "Authorization: Bearer $1" -H "Content-Type: application/json"); [[ -n "${5:-}" ]] && h+=(-H "X-Talon-Session-ID: $5")
  HTTP="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X POST "${GATEWAY}/v1/proxy/anthropic/v1/messages" "${h[@]}" \
    -d "$(jq -nc --arg m "$2" --arg c "$3" --argjson mt "$4" '{model:$m,max_tokens:$mt,messages:[{role:"user",content:$c}]}')")"
}
tools_req() { # <bearer>; coding-assistant declares no forbidden_tools — the ORG boundary fires
  HTTP="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X POST "${GATEWAY}/v1/proxy/openai/v1/chat/completions" \
    -H "Authorization: Bearer $1" -H "Content-Type: application/json" -H "X-Talon-Session-ID: coding-${SUPPORT_SID}" \
    -d '{"model":"gpt-4o","messages":[{"role":"user","content":"refactor the billing module"}],"tools":[{"type":"function","function":{"name":"read_file","description":"x","parameters":{"type":"object"}}},{"type":"function","function":{"name":"search_kb","description":"y","parameters":{"type":"object"}}},{"type":"function","function":{"name":"admin_purge_records","description":"z","parameters":{"type":"object"}}}]}')"
}
dsum_json() { talon agents show document-summary --url "$GATEWAY" --json 2>/dev/null | jq -r ".$1"; }

# ════════════════════════════════════════════════════════════════════════════
# Beats: [hero running frame] → live call → assert (shared) → extract → present.
# ════════════════════════════════════════════════════════════════════════════

# ── 1. Category + fleet ──────────────────────────────────────────────────────
present_fleet_hero() {
  scene
  printf '  %s$ talon agents%s\n\n' "$DIM" "$R"
  printf '  %s%-20s %-14s %s%s\n' "$B" "USE CASE" "HEALTH" "SPEND TODAY" "$R"
  talon agents --url "$GATEWAY" --json 2>/dev/null \
    | jq -r '.agents | sort_by(.name)[] | "\(.name)\t\(.health)\t\(.spend_day)"' \
    | while IFS=$'\t' read -r name health spend; do
        printf '  %-20s %b●%b %-12s $%s\n' "$name" "$GRN" "$R" "$health" "$(fmt "$spend")"
      done
  hold 4
}
present_fleet_full() { runcmd "talon agents --url '$GATEWAY'"; }
beat_fleet() {
  if [[ "$CUT" == hero ]]; then present_fleet_hero
  else
    banner "Talon — one operating layer for a company's AI use cases"
    printf ' %s3 production AI use cases   ·   1 organization policy   ·   1 operating view%s\n' "$DIM" "$R"
    present_fleet_full
  fi
}

# ── 2. Customer-support incident (reliability + shared policy) ────────────────
beat_support() {
  [[ "$CUT" == hero ]] && running "Routing customer request through Talon…"
  openai_chat "$CS_KEY" local-llama llama3.2:1b \
    "Refund Anna Kowalska. Email: anna.kowalska@example.com IBAN: DE89370400440532013000" "$SUPPORT_SID"
  require_http 200 "reliability"
  export_session "$SUPPORT_SID" "$WORK/support.json"
  assert_ev "$WORK/support.json" \
    'any(.records[]; .classification.input_pii_redacted==true and (.classification.pii_detected|index("email")) and (.classification.pii_detected|index("iban")) and .classification.input_tier==2)' \
    "input-path PII redaction (email+iban, tier 2)"
  assert_ev "$WORK/support.json" \
    'any(.records[]; .failover.role=="failed_attempt" and .failover.provider=="local-llama" and .failover.error_class=="connection_error")' \
    "local model failed attempt (connection_error)"
  assert_ev "$WORK/support.json" \
    'any(.records[]; .failover.role=="fallback_decision" and .failover.provider=="openai" and any(.failover.skipped_candidates[]?; .provider=="openai-batch" and .filter=="agent_provider_allowlist"))' \
    "policy-valid failover (openai-batch skipped by agent allowlist, openai selected)"
  local pii ph tier failed_prov failed_err skip_prov sel
  pii="$(jq -r '[.records[].classification.pii_detected//empty]|flatten|unique|join(", ")' "$WORK/support.json")"
  ph="$(echo "$pii" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | awk 'NF{printf (NR>1?", ":"")"["toupper($0)"]"}')"
  tier="$(jq -r '[.records[].classification.input_tier//0]|max' "$WORK/support.json")"
  failed_prov="$(jq -r 'first(.records[]|select(.failover.role=="failed_attempt").failover.provider)' "$WORK/support.json")"
  failed_err="$(jq -r 'first(.records[]|select(.failover.role=="failed_attempt").failover.error_class)' "$WORK/support.json")"
  skip_prov="$(jq -r 'first(.records[].failover.skipped_candidates[]?.provider)' "$WORK/support.json")"
  sel="$(jq -r 'first(.records[]|select(.failover.role=="fallback_decision").failover.provider)' "$WORK/support.json")"
  if [[ "$CUT" == hero ]]; then present_support_hero "$ph" "$tier" "$failed_prov" "$skip_prov" "$sel"
  else present_support_full "$pii" "$ph" "$tier" "$failed_prov" "$failed_err" "$skip_prov" "$sel"; fi
}
present_support_hero() { # ph tier failed skip sel
  scene; title "CUSTOMER-SUPPORT" 2
  printf '  %b✓ EMAIL + IBAN REDACTED%b\n' "$GRN" "$R"
  printf '  %b  classification remains confidential (tier %s)%b\n\n' "$DIM" "$2" "$R"
  printf '  %b%-14s%b %b×%b connection error\n'          "$B" "$3" "$R" "$RED" "$R"
  printf '  %b%-14s%b %b⊘%b blocked by use-case policy\n' "$B" "$4" "$R" "$YEL" "$R"
  printf '  %b%-14s%b %b✓%b selected\n\n'                 "$B" "$5" "$R" "$GRN" "$R"
  printf '  %bRESULT%b        completed\n' "$YEL" "$R"
  hold 6
}
present_support_full() { # pii ph tier failed failed_err skip sel
  beat 1 4 "🛡 " "Reliability + shared policy" "customer-support — prefers the local model; talks to customers"
  row "EVENT" "a customer refund request carrying a name, an email, and an IBAN"
  row "SHARED" "PII redacted before the provider: ${1} → ${2}   (tier ${3}, unchanged)"
  echo
  route FAILED   "$4" "${5} — the local model is down"
  route SKIPPED  "$6" "not allowed for customer-support (agent_provider_allowlist)"
  route SELECTED "$7" "first policy-valid fallback"
  echo
  ok "Answered on ${7}, masked — and only through a provider this use case may use."
}

# ── 3. Organization tool boundary (shared capability policy) ──────────────────
beat_capability() {
  [[ "$CUT" == hero ]] && running "Evaluating organization policy…"
  tools_req "$CODE_KEY"
  require_http 403 "capability"
  export_session "coding-${SUPPORT_SID}" "$WORK/coding.json"
  assert_ev "$WORK/coding.json" \
    'any(.records[]; .policy_decision.allowed==false and ((.execution.cost//0)==0) and (tostring|test("admin_purge_records")) and (.policy_decision.reasons|tostring|test("tool")))' \
    "organization tool boundary (admin_purge_records denied, \$0)"
  if [[ "$CUT" == hero ]]; then present_capability_hero; else present_capability_full; fi
}
present_capability_hero() {
  scene; title "CODING-ASSISTANT" 3
  printf '  %sRequested%s\n' "$DIM" "$R"
  printf '    read_file\n    search_kb\n    %badmin_purge_records%b\n\n' "$YEL" "$R"
  printf '  %bORGANIZATION BOUNDARY%b     admin_*\n\n' "$B" "$R"
  printf '  %b✓ BLOCKED BEFORE MODEL%b\n' "$GRN" "$R"
  printf '  %b  Provider call prevented\n    Cost                 $0.0000%b\n' "$DIM" "$R"
  hold 5
}
present_capability_full() {
  beat 2 4 "🔧" "Shared capability policy" "coding-assistant — the admin_* boundary is company-wide"
  row "REQUEST"  "tools: read_file, search_kb, admin_purge_records"
  row "BOUNDARY" "organization_policy.constraints.forbidden_tools: [admin_*]   — the agent declares none of its own"
  echo
  ok "Blocked before the provider — admin_purge_records never reached the model. Provider call prevented, \$0 spent."
}

# ── 4. Cost control (projected-cost session budget — a SOFT cap) ──────────────
beat_cost() {
  [[ "$CUT" == hero ]] && running "Checking projected session cost…"
  local sess n; sess="doc-budget-$(rand 4)"
  # One (or a few) allowed summaries, then the next is denied on PROJECTED cost.
  for n in $(seq 1 12); do
    anthropic_msg "$DOC_KEY" claude-sonnet-5 "Please write a full, multi-section summary of this quarterly compliance document." 1024 "$sess"
    [[ "$HTTP" == "403" ]] && break
    require_http 200 "cost-batch"
  done
  [[ "$HTTP" == "403" ]] || die "cost: session budget never tripped in 12 calls"
  export_session "$sess" "$WORK/doc.json"
  assert_ev "$WORK/doc.json" \
    'any(.records[]; .session_budget != null and .session_budget.limit != null and .session_budget.spent != null and .session_budget.estimate != null)' \
    "session-budget projected-cost stop (structured { limit, spent, estimate })"
  local sp es li pr
  sp="$(jq -r 'first(.records[]|select(.session_budget!=null).session_budget.spent)' "$WORK/doc.json")"
  es="$(jq -r 'first(.records[]|select(.session_budget!=null).session_budget.estimate)' "$WORK/doc.json")"
  li="$(jq -r 'first(.records[]|select(.session_budget!=null).session_budget.limit)' "$WORK/doc.json")"
  pr="$(awk -v a="$sp" -v b="$es" 'BEGIN{printf "%.4f", a+b}')"
  if [[ "$CUT" == hero ]]; then present_cost_hero "$sp" "$es" "$pr" "$li"; else present_cost_full "$sp" "$es" "$pr" "$li"; fi
}
present_cost_hero() { # spent est projected limit
  scene; title "DOCUMENT-SUMMARY" 4
  printf '  SESSION SPEND        $%s\n' "$(fmt "$1")"
  printf '  NEXT ESTIMATE        $%s\n' "$(fmt "$2")"
  printf '  %bPROJECTED TOTAL      $%s%b\n' "$B" "$(fmt "$3")" "$R"
  printf '  %bSOFT SESSION LIMIT   $%s%b\n\n' "$YEL" "$(fmt "$4")" "$R"
  printf '  %b✓ NEXT CALL PREVENTED%b\n' "$GRN" "$R"
  printf '  %b  Anthropic not called · $0.0000%b\n' "$DIM" "$R"
  hold 6
}
present_cost_full() { # spent est projected limit
  beat 3 4 "💶" "Cost control before spend" "document-summary — a batch summarizer on Anthropic"
  row "BUDGET"  "per-session cost budget (SOFT cap — an in-flight request may overshoot; daily/monthly are the hard, pre-provider caps)"
  row "RECEIPT" "$(printf 'session spend $%.4f + next estimate $%.4f = projected $%.4f  →  over the soft $%.4f limit' "$1" "$2" "$3" "$4")"
  echo
  ok "Prevented the next Anthropic call on PROJECTED cost — decided before spend, not after the bill. \$0 spent on the denied call."
}

# ── 5. Live operational control (a policy edit → fleet blocked) ───────────────
beat_policy() {
  # A couple more real summaries this operating period, then Finance lowers the
  # daily budget below today's spend (a live YAML edit, activated by safe reload).
  local sess _; sess="doc-day-$(rand 4)"
  anthropic_msg "$DOC_KEY" claude-sonnet-5 "Summarize this quarterly compliance document in detail." 1024 "$sess" || true
  anthropic_msg "$DOC_KEY" claude-sonnet-5 "Summarize this quarterly compliance document in detail." 1024 "$sess" || true
  local oldcap spend newcap
  oldcap="$(dsum_json daily_cap)"; spend="$(dsum_json spend_day)"
  [[ -n "$spend" && "$spend" != "null" && "$spend" != "0" ]] || die "could not read document-summary daily spend"
  newcap="$(awk -v s="$spend" 'BEGIN{printf "%.4f", s*0.9}')"
  [[ "$CUT" == hero ]] && running "Finance sets an emergency daily ceiling…"
  sed -i.bak -E "s/daily: [0-9.]+/daily: ${newcap}/" "$WORK/agents/document-summary/agent.talon.yaml"
  local health=""
  for _ in $(seq 1 30); do health="$(dsum_json health)"; [[ "$health" == "blocked" ]] && break; sleep 0.5; done
  [[ "$health" == "blocked" ]] || die "document-summary did not reach HEALTH=blocked after lowering the daily cap (reload/eval issue)"
  local final_spend; final_spend="$(dsum_json spend_day)"
  if [[ "$CUT" == hero ]]; then present_policy_hero "$oldcap" "$newcap" "$final_spend"; else present_policy_full "$oldcap" "$newcap" "$final_spend"; fi
}
present_policy_hero() { # oldcap newcap spend
  scene; title "DOCUMENT-SUMMARY" 5
  printf '  %bFINANCE SETS AN EMERGENCY DAILY CEILING%b\n\n' "$B" "$R"
  printf '  Daily budget       $%s → %b$%s%b\n' "$(fmt "$1")" "$YEL" "$(fmt "$2")" "$R"
  printf '  Policy reload      %b✓ activated safely%b\n' "$GRN" "$R"
  printf '  Current spend      $%s\n\n' "$(fmt "$3")"
  talon agents --url "$GATEWAY" --json 2>/dev/null \
    | jq -r '.agents | sort_by(.name)[] | "\(.name)\t\(.health)"' \
    | while IFS=$'\t' read -r name health; do
        if [[ "$health" == blocked ]]; then printf '  %-20s %b■ blocked%b\n' "$name" "$RED" "$R"
        else printf '  %s%-20s ● %s%s\n' "$DIM" "$name" "$health" "$R"; fi
      done
  hold 6
}
present_policy_full() { # oldcap newcap spend
  beat 4 4 "📊" "Operational control" "document-summary — a live budget edit flips fleet health"
  row "EVENT" "Finance imposes an emergency daily ceiling on document-summary"
  printf '  %sPOLICY UPDATE%s   daily budget  $%s → $%s   (edited on disk, activated by safe reload)\n' "$YEL" "$R" "$(fmt "$1")" "$(fmt "$2")"
  printf '  %sRESULT%s          document-summary blocked from new work (daily budget reached)\n' "$YEL" "$R"
  echo
  runcmd "talon agents --url '$GATEWAY'"
  printf '  %sDAILY SPEND $%s   DAILY CAP $%s   HEALTH blocked%s\n' "$DIM" "$(fmt "$3")" "$(fmt "$2")" "$R"
  echo
  printf ' %sDescend from the fleet to one session, and from the session to one signed decision:%s\n' "$DIM" "$R"
  runcmd "talon audit list --session '$SUPPORT_SID'"
}

# ── 6. Session understanding + signed-evidence close ─────────────────────────
beat_close() {
  talon audit export --format signed-json --output "$WORK/hero-evidence.json" >/dev/null || die "signed export failed"
  assert_ev "$WORK/hero-evidence.json" '(.records|length) >= 5' "signed export is non-empty"
  assert_ev "$WORK/hero-evidence.json" \
    '([.records[].agent_id]|unique) as $a | ($a|index("customer-support")) and ($a|index("coding-assistant")) and ($a|index("document-summary"))' \
    "export covers all three use cases"
  local corr vout total valid fv scost
  corr="$(jq -r 'first(.records[]|select(.failover.role=="fallback_decision").correlation_id)' "$WORK/support.json")"
  vout="$(talon audit verify --file "$WORK/hero-evidence.json")"
  grep -q "Invalid records: 0" <<<"$vout" || die "signed export failed verification"
  total="$(awk -F': *' '/^Total records:/{print $2}' <<<"$vout")"
  valid="$(awk -F': *' '/^Valid records:/{print $2}' <<<"$vout")"
  fv=""
  if [[ -n "$corr" && "$corr" != "null" ]]; then
    fv="$(talon audit verify --failover "$corr" 2>&1)"
    grep -qiE "valid_fallback|chains checked: 1" <<<"$fv" || die "failover-chain verification did not confirm the support incident's chain"
  fi
  scost="$(jq -r '[.records[].execution.cost // 0]|add' "$WORK/support.json" 2>/dev/null)"
  if [[ "$CUT" == hero ]]; then present_close_hero "$total" "$valid" "$fv" "$scost"
  else present_close_full "$corr" "$fv"; fi
}
present_close_hero() { # total valid fv scost
  scene; title "SESSION ${SUPPORT_SID:0:12}" 6
  printf '  %-13s completed\n' "OUTCOME"
  printf '  %-13s email + IBAN redacted\n' "PII"
  printf '  %-13s local-llama failed\n' "PRIMARY"
  printf '  %-13s openai-batch\n' "POLICY SKIP"
  printf '  %-13s openai\n' "SELECTED"
  printf '  %-13s %s\n\n' "COST" "$(awk -v c="$4" 'BEGIN{ if (c+0 < 0.0001) printf "< $0.0001"; else printf "$%.4f", c }')"
  printf '  %bSIGNED EVIDENCE%b\n' "$B" "$R"
  printf '  %s records · %s valid · 0 invalid\n' "$1" "$2"
  [[ -n "$3" ]] && printf '  Failover · valid_fallback\n'
  printf '  %b✓ VERIFIED OFFLINE%b\n' "$GRN" "$R"
  hold 4
  # Closing frame — clean, no header.
  clear_scene
  printf '\n\n\n  %b%bTALON%b\n\n' "$B" "$CYN" "$R"
  printf '  %bOperate every AI use case%b\n' "$B" "$R"
  printf '  %bthrough one shared control plane%b\n\n' "$B" "$R"
  printf '  %scost · reliability · policy · understanding%s\n' "$DIM" "$R"
  hold 4
}
present_close_full() { # corr fv
  banner "Every decision is signed and verifiable offline"
  runcmd "talon audit export --format signed-json --output hero-evidence.json >/dev/null && echo '  wrote hero-evidence.json ('\$(jq '.records|length' \"$WORK/hero-evidence.json\")' records)'"
  pause
  runcmd "talon audit verify --file '$WORK/hero-evidence.json' | grep -E '^(File|Total records|Valid records|Invalid records):'"
  if [[ -n "$2" ]]; then
    pause
    printf ' %sVerify the failover chain itself — that the recorded fallback was policy-valid:%s\n' "$DIM" "$R"
    runcmd "talon audit verify --failover '$1'"
  fi
  banner "Talon — operate every AI use case through one shared control plane" \
         "cost control · reliability · shared policy · session understanding"
}

# ── Cuts ─────────────────────────────────────────────────────────────────────
run_beats() { # run_beats <hero|all>
  CUT="$1"
  beat_fleet; beat_support; beat_capability; beat_cost; beat_policy; beat_close
  if [[ "$CUT" == hero ]]; then printf '\033]0;HERO_COMPLETE\007'; fi   # machine marker, off the visible frame
}

write_state() { # write_state <file> <cut>
  cat > "$1" <<EOF
export TALON_DATA_DIR='${TALON_DATA_DIR}' TALON_SECRETS_KEY='${TALON_SECRETS_KEY}' TALON_SIGNING_KEY='${TALON_SIGNING_KEY}' TALON_ADMIN_KEY='${TALON_ADMIN_KEY}' TALON_LOG_LEVEL='warn'
export PATH='${WORK}/bin:'"\$PATH"
WORK='${WORK}'; GW_PORT='${GW_PORT}'; GATEWAY='${GATEWAY}'; GW_PID='${GW_PID}'
CS_KEY='${CS_KEY}'; CODE_KEY='${CODE_KEY}'; DOC_KEY='${DOC_KEY}'; SUPPORT_SID='${SUPPORT_SID}'; STATE_CUT='${2}'
EOF
}

case "${1:-all}" in
  hero|all) setup; run_beats "${1:-all}" ;;
  prepare)
    STATE="${2:?usage: demo.sh prepare <statefile> [hero|all]}"
    setup; write_state "$STATE" "${3:-hero}"
    trap - EXIT
    echo "prepared: gateway ${GATEWAY}, state ${STATE} (run: demo.sh play ${STATE})" >&2 ;;
  play)
    STATE="${2:?usage: demo.sh play <statefile>}"
    # shellcheck disable=SC1090
    source "$STATE"; cd "$WORK"
    run_beats "${STATE_CUT:-hero}" ;;
  *) echo "usage: $0 [hero | all | prepare <statefile> [hero|all] | play <statefile>]" >&2; exit 2 ;;
esac
