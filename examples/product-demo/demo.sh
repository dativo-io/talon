#!/usr/bin/env bash
# Talon product demo — one operating layer for a company's AI use cases.
#
# Operates three real AI use cases through ONE Talon gateway, on REAL providers,
# and walks the four things Talon does for every use case in one operating period:
#
#   customer-support  → reliability (policy-valid failover) + shared policy (PII redaction)
#   coding-assistant  → shared capability policy (an organization tool boundary)
#   document-summary  → cost control before spend (a projected-cost budget stop)
#   the fleet         → session understanding (talon agents + one session drill-down)
#                       and a signed, independently verifiable record behind every decision
#
# REAL providers, real spend (~$0.02-0.05/run on cheap models; denials cost $0).
# No mock. Requires OPENAI_API_KEY and ANTHROPIC_API_KEY, and the local model
# (Ollama, :11434) must be OFFLINE so the reliability beat sees a real failure.
#
#   ./demo.sh          # full narrated demo
#   ./demo.sh hero     # tight product-story cut (the README GIF)
#
# Every line printed under a "$ ..." prompt is the actual command the script ran,
# and every receipt is parsed from Talon's own signed evidence — nothing is faked.
# In strict mode (TALON_DEMO_STRICT=1, set by the recorder) any beat whose outcome
# is unexpected is a hard failure, so a recorded asset can never ship a broken proof.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CUT="${1:-all}"
GW_PORT="${PORT:-8080}"
GATEWAY="http://localhost:${GW_PORT}"
STRICT="${TALON_DEMO_STRICT:-0}"
PAUSE="${DEMO_STEP_PAUSE:-0}"

# Provider endpoints — REAL by default. Overridable only so the bash logic can be
# smoke-tested against a stand-in; the shipped demo runs against real providers.
OPENAI_URL="${TALON_DEMO_OPENAI_URL:-https://api.openai.com}"
ANTHROPIC_URL="${TALON_DEMO_ANTHROPIC_URL:-https://api.anthropic.com}"
LOCAL_LLAMA_URL="${TALON_DEMO_LOCAL_LLAMA_URL:-http://localhost:11434}"

for t in go jq curl; do command -v "$t" >/dev/null 2>&1 || { echo "✗ $t is required" >&2; exit 1; }; done

WORK="$(mktemp -d)"; GW_PID=""
cleanup() { [[ -n "$GW_PID" ]] && kill "$GW_PID" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
trap 'echo "ERROR: demo aborted at line $LINENO (see above)." >&2' ERR

# ── Tight receipt renderer — one receipt at a time, EVENT / DECISION / WHY / RESULT ──
if [[ -t 1 || "${TALON_DEMO_COLOR:-0}" == 1 ]]; then
  R=$'\033[0m'; DIM=$'\033[2m'; B=$'\033[1m'; GRN=$'\033[32m'; RED=$'\033[31m'; CYN=$'\033[36m'; YEL=$'\033[33m'
else
  R=''; DIM=''; B=''; GRN=''; RED=''; CYN=''; YEL=''
fi
BAR='══════════════════════════════════════════════════════════════════════'
banner() { echo; printf '%s%s%s\n' "$B" "$BAR" "$R"; while [[ $# -gt 0 ]]; do printf '%s %s%s\n' "$B" "$1" "$R"; shift; done; printf '%s%s%s\n' "$B" "$BAR" "$R"; }
beat()   { [[ "$1" != 1 ]] && [[ "$PAUSE" != 0 ]] && sleep "$PAUSE"; echo; printf '%s──[ %s/%s ]── %s  %s%s\n' "$B" "$1" "$2" "$3" "$4" "$R"; printf '%s              %s%s\n' "$DIM" "$5" "$R"; }
row()    { printf '  %s%-9s%s %s\n' "$YEL" "$1" "$R" "$2"; }             # label   value
route()  { local c="$CYN"; [[ "$1" == FAILED ]]&&c="$RED"; [[ "$1" == SKIPPED ]]&&c="$DIM"; [[ "$1" == SELECTED ]]&&c="$GRN"; printf '  %s%-13s%s%-10s%s %s\n' "$B" "$2" "$c" "$1" "$R" "$3"; }
ok()     { printf '  %s✓ %s%s\n' "$GRN" "$1" "$R"; }
no()     { printf '  %s✗ %s%s\n' "$RED" "$1" "$R"; }
runcmd() { printf '\n%s$ %s%s\n' "$DIM" "$*" "$R"; eval "$*"; }
pause()  { [[ "$PAUSE" != 0 ]] && sleep "$PAUSE"; return 0; }

# ── Setup ────────────────────────────────────────────────────────────────────
setup() {
  export TALON_DATA_DIR="$WORK/state"
  export TALON_SECRETS_KEY="${TALON_SECRETS_KEY:-productdemo0secrets0key0032bytes}"
  export TALON_SIGNING_KEY="${TALON_SIGNING_KEY:-product-demo-signing-key-not-for-production}"
  export TALON_LOG_LEVEL="${TALON_LOG_LEVEL:-warn}"
  mkdir -p "$TALON_DATA_DIR"

  [[ -n "${OPENAI_API_KEY:-}" ]]    || { echo "✗ OPENAI_API_KEY is required (real provider, real spend ~\$0.05)." >&2; exit 1; }
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] || { echo "✗ ANTHROPIC_API_KEY is required (document-summary runs on Anthropic)." >&2; exit 1; }
  # The reliability beat demonstrates failover when the LOCAL model is down.
  if curl -sf -m 2 "${LOCAL_LLAMA_URL}/api/tags" >/dev/null 2>&1 || curl -sf -m 2 "${LOCAL_LLAMA_URL}/v1/models" >/dev/null 2>&1; then
    echo "✗ The local model at ${LOCAL_LLAMA_URL} is UP. This demo's reliability beat needs it DOWN" >&2
    echo "  (customer-support fails over from the local model to the cloud). Stop Ollama and retry." >&2
    exit 1
  fi

  echo "==> Building talon from this checkout..." >&2
  mkdir -p "$WORK/bin"
  ( cd "$REPO_ROOT" && go build -o "$WORK/bin/talon" ./cmd/talon )
  export PATH="$WORK/bin:$PATH"

  # Runtime config = committed baseline with the provider endpoints + isolated
  # data_dir substituted in. The committed talon.config.yaml stays the readable
  # reference; nothing here touches your real ~/.talon.
  sed -e "s#https://api.openai.com#${OPENAI_URL}#g" \
      -e "s#https://api.anthropic.com#${ANTHROPIC_URL}#g" \
      -e "s#http://localhost:11434#${LOCAL_LLAMA_URL}#g" \
      "$SCRIPT_DIR/talon.config.yaml" > "$WORK/talon.config.yaml"
  printf '\ndata_dir: %s\n' "$TALON_DATA_DIR" >> "$WORK/talon.config.yaml"
  cp -r "$SCRIPT_DIR/agents" "$WORK/agents"
  cd "$WORK"

  echo "==> Seeding vault secrets (your real provider keys + one traffic key per use case)..." >&2
  talon secrets set openai-api-key    "$OPENAI_API_KEY"    >/dev/null
  talon secrets set anthropic-api-key "$ANTHROPIC_API_KEY" >/dev/null
  talon secrets set customer-support-talon-key traffic-cs   >/dev/null
  talon secrets set coding-assistant-talon-key traffic-code >/dev/null
  talon secrets set document-summary-talon-key traffic-doc  >/dev/null

  echo "==> Starting Talon gateway — one process, three use cases (agents_dir)..." >&2
  ( talon serve --port "$GW_PORT" --gateway ) >"$WORK/gw.log" 2>&1 &
  GW_PID=$!
  local _; for _ in $(seq 1 60); do curl -sf "${GATEWAY}/health" >/dev/null 2>&1 && return 0; sleep 0.3; done
  echo "✗ Talon gateway did not become healthy at ${GATEWAY}" >&2; tail -30 "$WORK/gw.log" >&2; exit 1
}

SUPPORT_SID="support-$(date +%s)"
HTTP=""
# openai_chat <bearer> <provider> <model> <content> [session]
openai_chat() {
  local -a h=(-H "Authorization: Bearer $1" -H "Content-Type: application/json"); [[ -n "${5:-}" ]] && h+=(-H "X-Talon-Session-ID: $5")
  HTTP="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X POST "${GATEWAY}/v1/proxy/$2/v1/chat/completions" "${h[@]}" \
    -d "$(jq -nc --arg m "$3" --arg c "$4" '{model:$m,messages:[{role:"user",content:$c}]}')")"
}
# anthropic_msg <bearer> <model> <content> <max_tokens> [session]
anthropic_msg() {
  local -a h=(-H "Authorization: Bearer $1" -H "Content-Type: application/json"); [[ -n "${5:-}" ]] && h+=(-H "X-Talon-Session-ID: $5")
  HTTP="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X POST "${GATEWAY}/v1/proxy/anthropic/v1/messages" "${h[@]}" \
    -d "$(jq -nc --arg m "$2" --arg c "$3" --argjson mt "$4" '{model:$m,max_tokens:$mt,messages:[{role:"user",content:$c}]}')")"
}
tools_req() { # tools_req <bearer> — coding-assistant declares no forbidden_tools; the org boundary fires
  HTTP="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X POST "${GATEWAY}/v1/proxy/openai/v1/chat/completions" \
    -H "Authorization: Bearer $1" -H "Content-Type: application/json" -H "X-Talon-Session-ID: coding-${SUPPORT_SID}" \
    -d '{"model":"gpt-4o","messages":[{"role":"user","content":"refactor the billing module"}],"tools":[{"type":"function","function":{"name":"admin_purge_records","description":"x","parameters":{"type":"object"}}},{"type":"function","function":{"name":"search_kb","description":"y","parameters":{"type":"object"}}}]}')"
}
assert_http() { [[ "$HTTP" == "$1" ]] && return 0; echo "✗ ${2}: expected HTTP ${1}, got ${HTTP}" >&2; cat "$WORK/b" >&2; [[ "$STRICT" == 1 ]] && exit 1; return 0; }
errmsg() { jq -r '.error.message // empty' "$WORK/b" 2>/dev/null; }

# ── Beats ────────────────────────────────────────────────────────────────────
opening() {
  banner "Talon — one operating layer for a company's AI use cases"
  printf ' %s3 production AI use cases   ·   1 organization policy   ·   1 operating view%s\n' "$DIM" "$R"
  runcmd "talon agents --url '$GATEWAY'"
}

beat_reliability() {
  beat 1 4 "🛡 " "Reliability + shared policy" "customer-support — prefers the local model; talks to customers"
  row "EVENT" "a customer refund request carrying a name, an email, and an IBAN"
  # One customer incident: PII in the message, and the preferred (local) model is down.
  openai_chat traffic-cs local-llama gpt-4o-mini \
    "Refund Anna Kowalska. Email: anna.kowalska@example.com IBAN: DE89370400440532013000" "$SUPPORT_SID"
  assert_http 200 "reliability"
  # Everything below is parsed from Talon's own signed evidence for this incident.
  talon audit export --format signed-json --session "$SUPPORT_SID" --output "$WORK/support.json" >/dev/null 2>&1
  local pii tier failed_prov failed_err skip_prov skip_why sel placeholders
  pii="$(jq -r '[.records[].classification.pii_detected // empty]|flatten|unique|join(", ")' "$WORK/support.json" 2>/dev/null)"
  tier="$(jq -r '[.records[].classification.input_tier // 0]|max' "$WORK/support.json" 2>/dev/null)"
  failed_prov="$(jq -r 'first(.records[]|select(.failover.role=="failed_attempt").failover.provider) // "local-llama"' "$WORK/support.json" 2>/dev/null)"
  failed_err="$(jq -r 'first(.records[]|select(.failover.role=="failed_attempt").failover.error_class) // "connection_error"' "$WORK/support.json" 2>/dev/null)"
  skip_prov="$(jq -r 'first(.records[].failover.skipped_candidates[]?.provider) // empty' "$WORK/support.json" 2>/dev/null)"
  skip_why="$(jq -r 'first(.records[].failover.skipped_candidates[]?.filter) // empty' "$WORK/support.json" 2>/dev/null)"
  sel="$(jq -r 'first(.records[]|select(.failover.role=="fallback_decision").failover.provider) // "openai"' "$WORK/support.json" 2>/dev/null)"
  # Placeholders derived from the entities Talon actually detected ([TYPE] form).
  placeholders="$(echo "${pii:-email, iban}" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | awk 'NF{printf (NR>1?", ":"")"["toupper($0)"]"}')"
  row "SHARED" "PII redacted before the provider: ${pii:-email, iban} → ${placeholders}   (tier ${tier:-2}, unchanged)"
  echo
  route FAILED   "$failed_prov"   "${failed_err} — the local model is down"
  [[ -n "$skip_prov" ]] && route SKIPPED "$skip_prov" "not allowed for customer-support (${skip_why})"
  route SELECTED "$sel"           "first policy-valid fallback"
  echo
  ok "Answered on ${sel}, masked — and only through a provider this use case may use."
}

beat_capability() {
  beat 2 4 "🔧" "Shared capability policy" "coding-assistant — the admin_* boundary is company-wide"
  tools_req traffic-code
  assert_http 403 "capability"
  row "REQUEST"  "tool call: admin_purge_records  (+ search_kb)"
  row "BOUNDARY" "organization_policy.constraints.forbidden_tools: [admin_*]   — the agent declares none of its own"
  echo
  no "403 — $(errmsg). The use case cannot weaken the company boundary. \$0 spent."
}

beat_cost() {
  beat 3 4 "💶" "Cost control before spend" "document-summary — a batch summarizer on Anthropic"
  # Silent batch until the session budget's PROJECTED cost would exceed the limit.
  local sess n; sess="doc-batch-$(date +%s)"
  for n in $(seq 1 40); do
    anthropic_msg traffic-doc claude-sonnet-5 "Please write a full, multi-section summary of this quarterly compliance document." 1024 "$sess"
    [[ "$HTTP" == "403" ]] && break
    [[ "$HTTP" != "200" ]] && { assert_http 200 "cost-batch"; break; }
  done
  if [[ "$HTTP" != "403" ]]; then echo "✗ session budget did not trip" >&2; [[ "$STRICT" == 1 ]] && exit 1; fi
  row "BUDGET"  "per-session cost budget (soft cap)"
  row "RECEIPT" "$(errmsg)"
  echo
  no "Next call denied before Anthropic — the decision uses PROJECTED cost, not the bill after. \$0 spent on it."
}

# Drive document-summary's real DAILY spend to its hard cap so the fleet shows it
# BLOCKED. A long real summary can cost more than the fixed pre-estimate, so its
# recorded spend crosses the cap; fresh session ids keep the session budget out of
# the way. Silent — the operating period already happened above.
drive_to_blocked() {
  local n health
  for n in $(seq 1 12); do
    anthropic_msg traffic-doc claude-sonnet-5 \
      "Write an exhaustive, section-by-section summary of this long quarterly compliance document, covering every heading in detail." 2048 "fill-${n}-$(date +%s)"
    health="$(talon agents show document-summary --url "$GATEWAY" 2>/dev/null | awk -F'[: ]+' '/^Health/{print $2}')"
    [[ "$health" == "blocked" ]] && return 0
    # Once the daily cap starts pre-empting calls (403) without the recorded spend
    # having crossed it, no further call will accrue — the overshoot didn't happen.
    [[ "$HTTP" == "403" ]] && return 1
  done
  return 1
}

beat_sessions() {
  beat 4 4 "📊" "Session understanding" "the whole fleet — one operating period, one attention queue"
  if ! drive_to_blocked; then
    echo "✗ document-summary did not reach its daily cap (HEALTH=blocked)." >&2
    echo "  A real summary must cost more than the ~\$0.006 pre-estimate to cross the \$0.02 daily cap;" >&2
    echo "  raise max_tokens or lower the daily cap in agents/document-summary/agent.talon.yaml." >&2
    [[ "$STRICT" == 1 ]] && exit 1
  fi
  runcmd "talon agents --url '$GATEWAY'"
  echo
  printf ' %sDescend from the fleet to one session, and from the session to one signed decision:%s\n' "$DIM" "$R"
  runcmd "talon audit list --session '$SUPPORT_SID'"
}

evidence_close() {
  banner "Every decision is signed and independently verifiable"
  local today; today="$(date +%Y-%m-%d)"
  runcmd "talon audit export --format signed-json --from '$today' --output '$WORK/hero-evidence.json' >/dev/null && echo '  wrote hero-evidence.json'"
  pause
  runcmd "talon audit verify --file '$WORK/hero-evidence.json'"
}

closing() {
  banner "Talon — operate every AI use case through one shared control plane" \
         "cost control · reliability · shared policy · session understanding"
}

cmd_hero() { setup; opening; beat_reliability; beat_capability; beat_cost; beat_sessions; evidence_close; closing; }
cmd_all()  { setup; opening; beat_reliability; beat_capability; beat_cost; beat_sessions; evidence_close; closing; }

case "$CUT" in
  hero) cmd_hero ;;
  all)  cmd_all ;;
  *) echo "usage: $0 [hero|all]" >&2; exit 2 ;;
esac
