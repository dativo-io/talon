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
#   ./demo.sh hero     # anchored LIVE product cut (the README GIF)
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
# Hero presentation surface: 'gum' = the styled live operations console (the
# recorded README asset; requires gum); 'plain' = a pure Bash/ANSI fallback used
# ONLY for automated text assertions. The verbose `all` cut ignores this entirely
# and never touches gum.
UI="${TALON_DEMO_UI:-gum}"

OPENAI_URL="${TALON_DEMO_OPENAI_URL:-https://api.openai.com}"
ANTHROPIC_URL="${TALON_DEMO_ANTHROPIC_URL:-https://api.anthropic.com}"
LOCAL_LLAMA_URL="${TALON_DEMO_LOCAL_LLAMA_URL:-http://localhost:11434}"
PORT_OVERRIDE="${PORT:-}"

for t in go jq curl openssl; do command -v "$t" >/dev/null 2>&1 || { echo "✗ $t is required" >&2; exit 1; }; done

WORK=""; GW_PID=""
cleanup() { g_restore_screen 2>/dev/null || true; [[ -n "$GW_PID" ]] && kill "$GW_PID" >/dev/null 2>&1 || true; [[ -n "$WORK" ]] && rm -rf "$WORK"; }
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
  # High-contrast hero palette — bright variants render as distinct hues in agg's
  # theme, so labels, values, warnings and successes never blend into one olive wash.
  WHT=$'\033[97m'; GRY=$'\033[90m'; BCY=$'\033[96m'; BGR=$'\033[92m'; AMB=$'\033[93m'; BRD=$'\033[91m'
else
  R=''; DIM=''; B=''; GRN=''; RED=''; CYN=''; YEL=''
  WHT=''; GRY=''; BCY=''; BGR=''; AMB=''; BRD=''
fi

# Verbose-cut renderers (used by the full `all` walkthrough).
BAR='══════════════════════════════════════════════════════════════════════'
banner() { echo; printf '%s%s%s\n' "$B" "$BAR" "$R"; while [[ $# -gt 0 ]]; do printf '%s %s%s\n' "$B" "$1" "$R"; shift; done; printf '%s%s%s\n' "$B" "$BAR" "$R"; }
beat()   { [[ "$1" != 1 ]] && [[ "$PAUSE" != 0 ]] && sleep "$PAUSE"; echo; printf '%s──[ %s/%s ]── %s  %s%s\n' "$B" "$1" "$2" "$3" "$4" "$R"; printf '%s              %s%s\n' "$DIM" "$5" "$R"; }
row()    { printf '  %s%-9s%s %s\n' "$YEL" "$1" "$R" "$2"; }
route()  { local c="$CYN"; [[ "$1" == FAILED ]]&&c="$RED"; [[ "$1" == SKIPPED ]]&&c="$YEL"; [[ "$1" == SELECTED ]]&&c="$GRN"; printf '  %s%-13s%s%-10s%s %s\n' "$B" "$2" "$c" "$1" "$R" "$3"; }
ok()     { printf '  %s✓ %s%s\n' "$GRN" "$1" "$R"; }
runcmd() { printf '\n%s$ %s%s\n' "$DIM" "$*" "$R"; eval "$*"; }
pause()  { [[ "$PAUSE" != 0 ]] && sleep "$PAUSE"; return 0; }

# Hero-cut renderers — an ANCHORED LIVE NARRATIVE, not one slide per scene.
# Clear ONCE at the open and ONCE before the closing frame; every chapter and
# every verified result APPENDS beneath a divider, so request→decision→result
# accumulates on screen and the causal chain is never erased mid-story.
clear_scene() { printf '\033[2J\033[H'; }
hold()    { [[ "$PAUSE" != 0 ]] && sleep "${1:-2}"; return 0; }
dashes()  { local n="$1" s=''; while (( n-- > 0 )); do s+='─'; done; printf '%s' "$s"; }
moneylt() { awk -v c="$1" 'BEGIN{ if (c+0 < 0.0001) printf "< $0.0001"; else printf "$%.4f", c }'; }
tierlabel() { case "$1" in 0) echo public;; 1) echo internal;; 3) echo restricted;; *) echo confidential;; esac; }
chapter() { # chapter <n> <TITLE> — a symmetric high-contrast divider (grey number, bright-cyan title)
  local bar; bar="$(dashes 16)"
  printf '\n%b%s%b  %b%s / 3%b  %b%s%b  %b%s%b\n' \
    "$GRY" "$bar" "$R" "$GRY" "$1" "$R" "${B}${BCY}" "$2" "$R" "$GRY" "$bar" "$R"
}
pending() { # pending <request> <talon-status> [request-subline] — the live in-flight frame
  printf '\n  %b%-11s%b %b%s%b\n' "$B" "REQUEST" "$R" "$WHT" "$1" "$R"
  [[ -n "${3:-}" ]] && printf '  %-11s %b%s%b\n' '' "$WHT" "$3" "$R"
  printf '  %b%-11s%b %b%s%b\n' "$B" "TALON" "$R" "$GRY" "$2" "$R"
}
hroute() { # hroute <name> <status> <status-color> <desc>
  printf '  %b%-15s%b %b%-13s%b %b%s%b\n' "$WHT" "$1" "$R" "$3" "$2" "$R" "$GRY" "$4" "$R"
}

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
# Gum operations-console renderers — hero cut with TALON_DEMO_UI=gum ONLY.
# A persistent alternate-screen dashboard (header + progress rail + live main
# panel + status bar), each frame composed in memory and written home in one
# write (no clear-then-print tearing). gum is a DEMO-ONLY dependency: the verbose
# `all` cut and the plain-UI fallback never call it.
# ════════════════════════════════════════════════════════════════════════════
GUM_TEXT=$'\033[38;2;240;246;252m'; GUM_MUTED=$'\033[38;2;139;148;158m'
GUM_CYAN=$'\033[38;2;88;166;255m';  GUM_GREEN=$'\033[38;2;63;185;80m'
GUM_AMBER=$'\033[38;2;210;153;34m'; GUM_RED=$'\033[38;2;248;81;73m'
GUM_PURPLE=$'\033[38;2;188;140;255m'; GB=$'\033[1m'; GR=$'\033[0m'
GUM_BORDER='#30363D'; GUM_PANEL='#161B22'
HEADW=88; CMDW=88; RAILW=20; MAINW=64; CH=14; CMDH=6
declare -a STAGE_ST=("active" "next" "next" "next")
SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
HERO_SCREEN=0; LAST_MAIN=""; CMD=""

g_vislen() { local t; t="$(sed -E $'s/\033\\[[0-9;]*m//g' <<<"$1")"; printf '%s' "${#t}"; }
g_lr()   { local w="$1" pad; pad=$(( w - $(g_vislen "$2") - $(g_vislen "$3") )); (( pad<1 )) && pad=1; printf '%s%*s%s' "$2" "$pad" '' "$3"; }
pcell()  { local s; printf -v s '%-*s' "$1" "$2"; printf '%s%s%s' "$3" "$s" "$GR"; }   # pcell <w> <text> <color>
money()  { printf '$%s' "$(fmt "$1")"; }
g_panel() { gum style --border rounded --border-foreground "$GUM_BORDER" --background "$GUM_PANEL" \
  --width "$1" --height "$2" --padding '0 1' --margin "${5:-0}" "$(printf '%s\n%s' "$3" "$4")"; }
mainp()  { g_panel "$MAINW" "$CH" "$1" "$2"; }
g_header() {
  local l2; l2="$(g_lr 80 "${GUM_MUTED}Control plane for company AI use cases${GR}" "${GUM_MUTED}ACME · ENFORCE ${GUM_GREEN}●${GR}")"
  gum style --border rounded --border-foreground "$GUM_BORDER" --background "$GUM_PANEL" --width "$HEADW" --padding '0 1' \
    "$(printf '%s%sTALON%s   %s3 use cases · 1 policy · 1 operating view%s\n%s' "$GB" "$GUM_CYAN" "$GR" "$GUM_MUTED" "$GR" "$l2")"
}
g_rail() {
  local -a nm=(Fleet Reliability "Policy + cost" "Operations + proof") out=(); local i g l
  for i in 0 1 2 3; do
    case "${STAGE_ST[$i]}" in
      done)   g="${GUM_GREEN}✓${GR}"; l="${GUM_MUTED}${nm[$i]}${GR}";;
      active) g="${GUM_CYAN}●${GR}";  l="${GB}${GUM_CYAN}${nm[$i]}${GR}";;
      *)      g="${GUM_MUTED}○${GR}"; l="${GUM_MUTED}${nm[$i]}${GR}";;
    esac
    out+=("$g $l")
  done
  g_panel "$RAILW" "$CH" "${GB}${GUM_MUTED}LIVE RUN${GR}" "$(printf '\n%s\n\n%s\n\n%s\n\n%s' "${out[0]}" "${out[1]}" "${out[2]}" "${out[3]}")" '0 2 0 0'
}
g_receipt() { gum style --border rounded --border-foreground "$GUM_BORDER" --background "$GUM_PANEL" --width "$HEADW" --padding '0 1' "$1"; }
# ── LIVE COMMAND panel — the real command being executed + a concise, real excerpt
# of its output. Compact (≤5 rows). Secrets and temp values are redacted; $GATEWAY
# and paths are shown as safe placeholders (the panel says so).
g_cmdpanel() { # g_cmdpanel <STATE|""> <body>
  local title="LIVE COMMAND"; [[ -n "$1" ]] && title="LIVE COMMAND · $1"
  gum style --border rounded --border-foreground "$GUM_BORDER" --background "$GUM_PANEL" --width "$CMDW" --height "$CMDH" --padding '0 1' \
    "$(printf '%s%s%s\n%s' "$GB$GUM_MUTED" "$title" "$GR" "$2")"
}
hero_truncate_line() { local s="$1" w="$2"; (( ${#s} <= w )) && { printf '%s' "$s"; return; }; local k=$(( (w-2)/2 )); printf '%s…%s' "${s:0:k}" "${s: -k}"; }
# A safe curl command line for a proxied provider request (loopback → $GATEWAY).
hero_curl_cmd() { # hero_curl_cmd <provider> <payload-summary>
  printf '%s$ curl -X POST %s$GATEWAY/v1/proxy/%s/…%s\n%s  %s%s' \
    "$GUM_CYAN" "$GUM_TEXT" "$1" "$GR" "$GUM_MUTED" "$2" "$GR"
}
hero_cli_cmd() { printf '%s$ %s%s' "$GUM_CYAN" "$1" "$GR"; }   # a talon CLI command line
hero_cmd_running()  { CMD="$(g_cmdpanel RUNNING  "$(printf '%s\n\n%s%s waiting for Talon…%s' "$1" "$GUM_CYAN" "${2:-⠋}" "$GR")")"; }
hero_cmd_complete() { CMD="$(g_cmdpanel COMPLETE "$(printf '%s\n\n%s' "$1" "$2")")"; }   # <cmd-block> <output-block>
# hero_http_output <http> <detail> <subline>  — colours the real HTTP status (2xx green,
# 4xx amber = policy denial, else red) and shows a real one-line excerpt beneath.
hero_http_output() {
  local hc; case "$1" in 2*) hc="$GUM_GREEN";; 4*) hc="$GUM_AMBER";; *) hc="$GUM_RED";; esac
  local head="HTTP $1"; [[ -n "${2:-}" ]] && head="HTTP $1 · $2"
  if [[ -n "${3:-}" ]]; then printf '%s%s%s\n%s%s%s' "$hc" "$head" "$GR" "$GUM_MUTED" "$3" "$GR"
  else printf '%s%s%s' "$hc" "$head" "$GR"; fi
}
# hero_agents_output — the real `talon agents` table, first 3 rows, AGENT/STATE/HEALTH
# columns only (visual-safe trim of the real stdout); blocked health rendered amber.
hero_agents_output() {
  talon agents --url "$GATEWAY" 2>/dev/null | awk 'NR>1 && NF>=3 {print $1"\t"$2"\t"$3}' | head -3 \
    | while IFS=$'\t' read -r a s h; do
        local hc="$GUM_GREEN"; [[ "$h" == blocked ]] && hc="$GUM_AMBER"
        printf '%s %s %s\n' "$(pcell 20 "$a" "$GUM_TEXT")" "$(pcell 9 "$s" "$GUM_MUTED")" "$(pcell 10 "$h" "$hc")"
      done
}
# hero_perl_edit_cmd <oldcap> <newcap-or-empty> — the real in-place YAML edit, safe
# display (relative path; the temp dir is redacted). Matches the executed command.
hero_perl_edit_cmd() {
  local q; q="'s/daily: $1/daily: ${2:-…}/'"
  printf '%s$ perl -i.bak -pe %s%s%s\n%s  agents/document-summary/agent.talon.yaml%s' \
    "$GUM_CYAN" "$GUM_TEXT" "$q" "$GR" "$GUM_MUTED" "$GR"
}
# hero_agent_row <name> — the real `talon agents` row for one agent (STATE + HEALTH), trimmed.
hero_agent_row() {
  talon agents --url "$GATEWAY" 2>/dev/null | awk -v n="$1" '$1==n && NF>=3 {print $2"\t"$3; exit}' \
    | while IFS=$'\t' read -r s h; do
        local hc="$GUM_GREEN"; [[ "$h" == blocked ]] && hc="$GUM_AMBER"
        printf '%s %s %s' "$(pcell 20 "$1" "$GUM_TEXT")" "$(pcell 9 "$s" "$GUM_MUTED")" "$(pcell 10 "$h" "$hc")"
      done
}
g_show() { # g_show <main-panel> <receipt-line>
  LAST_MAIN="$1"
  printf '\033[H\033[J%s' "$(gum join --vertical "$(g_header)" "$CMD" "$(gum join --horizontal --align top "$(g_rail)" "$1")" "$(g_receipt "$2")")"
}
g_await() { # g_await <pid> <content-precomposed> <cmd-block> <receipt-line>  spinner lives in the LIVE COMMAND panel
  local pid="$1" content="$2" cmdblock="$3" i=0 hdr rc; hdr="$(g_header)"; rc="$(g_receipt "$4")"
  # Draw the RUNNING frame at least once (so even a fast call shows its live
  # in-flight state), then animate the command-panel spinner until the call ends.
  while :; do
    hero_cmd_running "$cmdblock" "${SPIN[$((i%10))]}"
    printf '\033[H\033[J%s' "$(gum join --vertical "$hdr" "$CMD" "$content" "$rc")"
    kill -0 "$pid" 2>/dev/null || break
    i=$((i+1)); sleep 0.3
  done
  wait "$pid" 2>/dev/null || true
}
g_hold() { [[ "$PAUSE" != 0 ]] && sleep "${1:-2}"; return 0; }   # holds pace the RECORDING (PAUSE>0); no-op for fast test runs
hero_set_stage() { local a="$1" i; for i in 0 1 2 3; do if (( i<a )); then STAGE_ST[i]="done"; elif (( i==a )); then STAGE_ST[i]="active"; else STAGE_ST[i]="next"; fi; done; }
g_transition() { # g_transition <proved> <next-title> <next-stage-idx>  — advance the rail + a brief transition status
  hero_set_stage "$3"
  g_show "$LAST_MAIN" "$(printf '%s✓ %s%s   %s→  NEXT: %s%s' "$GUM_GREEN" "$1" "$GR" "$GUM_MUTED" "$2" "$GR")"
  sleep 0.7
}
g_enter_screen()   { printf '\033[?1049h\033[?25l'; HERO_SCREEN=1; }
g_restore_screen() { [[ "${HERO_SCREEN:-0}" == 1 ]] && printf '\033[?25h\033[?1049l'; HERO_SCREEN=0; }

# ── OPENING / FLEET (live data) ──────────────────────────────────────────────
hero_opening() {
  STAGE_ST=("active" "next" "next" "next")
  hero_cmd_complete "$(hero_cli_cmd 'talon agents')" "$(hero_agents_output)"
  local rows body
  rows="$(talon agents --url "$GATEWAY" --json 2>/dev/null \
    | jq -r '.agents|sort_by(.name)[]|"\(.name)\t\(.health)\t\(.spend_day)"' \
    | while IFS=$'\t' read -r n h s; do
        printf '%s %s %s\n' "$(pcell 20 "$n" "$GUM_TEXT")" "$(pcell 13 "● $h" "$GUM_GREEN")" "$(pcell 10 "$(money "$s")" "$GUM_TEXT")"
      done)"
  body="$(printf '%s3 production AI use cases%s\n\n%s %s %s\n%s\n\n%sOne organization policy · one operating view%s' \
    "$GUM_TEXT" "$GR" \
    "$(pcell 20 "USE CASE" "$GB$GUM_MUTED")" "$(pcell 13 HEALTH "$GB$GUM_MUTED")" "$(pcell 12 "SPEND TODAY" "$GB$GUM_MUTED")" \
    "$rows" "$GUM_MUTED" "$GR")"
  g_show "$(mainp "${GB}${GUM_CYAN}FLEET${GR}" "$body")" "${GUM_MUTED}LIVE · one policy · one operating view · real requests next${GR}"
}

# ── RELIABILITY + SHARED POLICY ──────────────────────────────────────────────
support_pending_content() {
  local body; body="$(printf '%s%sCUSTOMER-SUPPORT%s\n\n%sIncoming request%s\n%sRefund request containing email + IBAN%s\n\n%sscanning input · evaluating policy-valid routes%s' \
    "$GB" "$GUM_TEXT" "$GR" "$GB$GUM_MUTED" "$GR" "$GUM_TEXT" "$GR" "$GUM_MUTED" "$GR")"
  gum join --horizontal --align top "$(g_rail)" "$(mainp "${GB}${GUM_CYAN}RELIABILITY + SHARED POLICY${GR}" "$body")"
}
hero_support_complete() { # tier failed skip sel cost
  STAGE_ST=("done" "done" "next" "next")
  local body
  body="$(printf '%s%sCUSTOMER-SUPPORT%s\n\n%sDATA%s\n%s✓ Email + IBAN redacted%s\n%s  Tier remains %s%s\n\n%sROUTE%s\n%s %s\n%s %s\n%s %s' \
    "$GB" "$GUM_TEXT" "$GR" \
    "$GB$GUM_MUTED" "$GR" "$GUM_GREEN" "$GR" "$GUM_MUTED" "$(tierlabel "$1")" "$GR" \
    "$GB$GUM_MUTED" "$GR" \
    "$(pcell 18 "× $2" "$GUM_RED")"   "${GUM_MUTED}connection error${GR}" \
    "$(pcell 18 "⊘ $3" "$GUM_AMBER")" "${GUM_MUTED}blocked by use-case policy${GR}" \
    "$(pcell 18 "✓ $4" "$GUM_CYAN")"  "${GUM_MUTED}selected fallback${GR}")"
  g_show "$(mainp "${GB}${GUM_CYAN}RELIABILITY + SHARED POLICY${GR}" "$body")" \
    "$(printf '%s✓ COMPLETED%s%s · %s · policy-valid fallback · evidence signed%s' "$GUM_GREEN" "$GR" "$GUM_MUTED" "$(moneylt "$5")" "$GR")"
}

# ── ORGANIZATION POLICY + COST (two cards, one stage) ────────────────────────
stage2_body() { # <tool:active|done> <cost:muted|active|done> [sp es pr li]
  local tool="$1" cost="$2" sp="${3:-}" es="${4:-}" pr="${5:-}" li="${6:-}" tblk cblk
  tblk="$(printf '%s%sORGANIZATION TOOL BOUNDARY%s\n%sRequested%s  %sread_file · search_kb · %sadmin_purge_records%s\n%sBoundary%s   %sadmin_*%s' \
    "$GB" "$GUM_TEXT" "$GR" "$GB$GUM_MUTED" "$GR" "$GUM_MUTED" "$GUM_AMBER" "$GR" "$GB$GUM_MUTED" "$GR" "$GUM_AMBER" "$GR")"
  [[ "$tool" == "done" ]] && tblk="$(printf '%s\n%s✓ BLOCKED BEFORE MODEL%s\n%s  provider call prevented · $0.0000%s' "$tblk" "$GUM_GREEN" "$GR" "$GUM_MUTED" "$GR")"
  if [[ "$cost" == "done" ]]; then
    cblk="$(printf '%s%sPROJECTED COST CONTROL%s\n%s %s\n%s %s\n%s %s\n%s %s\n%s✓ NEXT CALL PREVENTED%s\n%s  Anthropic not called · $0.0000%s' \
      "$GB" "$GUM_TEXT" "$GR" \
      "$(pcell 18 "Spend now" "$GUM_MUTED")" "$(pcell 8 "$(money "$sp")" "$GUM_TEXT")" \
      "$(pcell 18 "Next estimate" "$GUM_MUTED")" "$(pcell 8 "$(money "$es")" "$GUM_TEXT")" \
      "$(pcell 18 "Projected" "$GUM_MUTED")" "$(pcell 8 "$(money "$pr")" "$GUM_TEXT")" \
      "$(pcell 18 "Soft session limit" "$GUM_MUTED")" "$(pcell 8 "$(money "$li")" "$GUM_AMBER")" \
      "$GUM_GREEN" "$GR" "$GUM_MUTED" "$GR")"
  else
    local c="$GUM_MUTED"; [[ "$cost" == "active" ]] && c="$GUM_TEXT"
    cblk="$(printf '%s%sPROJECTED COST CONTROL%s\n%schecking projected session cost before the next call%s' "$GB" "$c" "$GR" "$GUM_MUTED" "$GR")"
  fi
  printf '%s\n\n%s' "$tblk" "$cblk"
}
tool_pending_content() { STAGE_ST=("done" "done" "active" "next"); gum join --horizontal --align top "$(g_rail)" "$(mainp "${GB}${GUM_CYAN}ORGANIZATION POLICY + COST${GR}" "$(stage2_body "active" "muted")")"; }
hero_tool_complete()   { g_show "$(mainp "${GB}${GUM_CYAN}ORGANIZATION POLICY + COST${GR}" "$(stage2_body "done" "muted")")" "$(printf '%s✓ BLOCKED BEFORE MODEL%s%s · provider call prevented · $0.0000%s' "$GUM_GREEN" "$GR" "$GUM_MUTED" "$GR")"; }
cost_pending_content() { gum join --horizontal --align top "$(g_rail)" "$(mainp "${GB}${GUM_CYAN}ORGANIZATION POLICY + COST${GR}" "$(stage2_body "done" "active")")"; }
hero_cost_complete()   { # sp es pr li
  STAGE_ST=("done" "done" "done" "next")
  g_show "$(mainp "${GB}${GUM_CYAN}ORGANIZATION POLICY + COST${GR}" "$(stage2_body "done" "done" "$1" "$2" "$3" "$4")")" \
    "$(printf '%s✓ NEXT CALL PREVENTED%s%s · Anthropic not called · denied-call cost $0.0000%s' "$GUM_GREEN" "$GR" "$GUM_MUTED" "$GR")"
}

# ── OPERATIONS + PROOF ───────────────────────────────────────────────────────
ops_pending_content() {
  STAGE_ST=("done" "done" "done" "active")
  local body; body="$(printf '%s%sLIVE POLICY EDIT%s\n\n%sFinance sets an emergency daily ceiling%s\n\n%sediting the budget on disk · periodic safe reload%s' \
    "$GB" "$GUM_TEXT" "$GR" "$GUM_TEXT" "$GR" "$GUM_MUTED" "$GR")"
  gum join --horizontal --align top "$(g_rail)" "$(mainp "${GB}${GUM_CYAN}OPERATIONS + PROOF${GR}" "$body")"
}
hero_ops_complete() { # oldcap newcap spend
  local edit fleet body
  edit="$(printf '%s%sLIVE POLICY EDIT%s\n%s %s → %s\n%s %s\n%s %s✓ activated safely%s' \
    "$GB" "$GUM_TEXT" "$GR" \
    "$(pcell 14 "Daily budget" "$GUM_MUTED")" "$(pcell 9 "$(money "$1")" "$GUM_TEXT")" "${GUM_AMBER}$(money "$2")${GR}" \
    "$(pcell 14 "Current spend" "$GUM_MUTED")" "$(pcell 9 "$(money "$3")" "$GUM_TEXT")" \
    "$(pcell 14 "Reload" "$GUM_MUTED")" "$GUM_GREEN" "$GR")"
  local frows; frows="$(talon agents --url "$GATEWAY" --json 2>/dev/null | jq -r '.agents|sort_by(.name)[]|"\(.name)\t\(.health)"' \
    | while IFS=$'\t' read -r n h; do
        if [[ "$h" == blocked ]]; then printf '%s %s\n' "$(pcell 20 "$n" "$GUM_TEXT")" "$(pcell 8 BLOCKED "$GUM_AMBER")"
        else printf '%s %s\n' "$(pcell 20 "$n" "$GUM_TEXT")" "$(pcell 8 "$h" "$GUM_GREEN")"; fi
      done)"
  fleet="$(printf '%s%sFLEET AFTER RELOAD%s\n%s' "$GB" "$GUM_TEXT" "$GR" "$frows")"
  body="$(printf '%s\n\n%s' "$edit" "$fleet")"
  g_show "$(mainp "${GB}${GUM_CYAN}OPERATIONS + PROOF${GR}" "$body")" "${GUM_MUTED}emergency ceiling active · document-summary blocked from new work${GR}"
}
hero_proof() { # sid failed skip sel cost total valid
  local body
  body="$(printf '%s%sSESSION%s  %s%s%s\n%scompleted · PII redacted · %s failed%s\n%s%s skipped · %s selected · cost %s%s\n\n%s%sSIGNED EVIDENCE%s\n%s%s records · %s valid · 0 invalid%s\n%sfailover · valid_fallback%s\n\n%s✓ VERIFIED OFFLINE%s' \
    "$GB" "$GUM_TEXT" "$GR" "$GUM_MUTED" "$1" "$GR" \
    "$GUM_MUTED" "$2" "$GR" \
    "$GUM_MUTED" "$3" "$4" "$(moneylt "$5")" "$GR" \
    "$GB" "$GUM_PURPLE" "$GR" \
    "$GUM_TEXT" "$6" "$7" "$GR" \
    "$GUM_MUTED" "$GR" \
    "$GUM_PURPLE" "$GR")"
  g_show "$(mainp "${GB}${GUM_PURPLE}PROOF${GR}" "$body")" "$(printf '%s✓ VERIFIED OFFLINE%s%s · every decision signed · tamper-evident%s' "$GUM_PURPLE" "$GR" "$GUM_MUTED" "$GR")"
}
hero_final() {
  STAGE_ST=("done" "done" "done" "done")
  local body; body="$(printf '\n%s%sOperate every AI use case%s\n%s%sthrough one shared control plane%s\n\n%sCost control · Reliability · Shared policy · Session understanding%s\n\n%s✓ Live decisions   ✓ Signed evidence   ✓ Verified offline%s' \
    "$GB" "$GUM_TEXT" "$GR" "$GB" "$GUM_TEXT" "$GR" "$GUM_MUTED" "$GR" "$GUM_GREEN" "$GR")"
  g_show "$(g_panel "$MAINW" "$CH" "${GB}${GUM_CYAN}TALON${GR}" "$body")" "${GUM_MUTED}one control plane · every AI use case · proven live${GR}"
}

# ════════════════════════════════════════════════════════════════════════════
# Beats: [pending frame] → live call (spinner in gum) → assert (shared) → extract → present.
# ════════════════════════════════════════════════════════════════════════════

# ── 1. Category + fleet ──────────────────────────────────────────────────────
present_fleet_hero() {   # OPENING / FLEET — the single clear of the whole hero
  clear_scene
  printf '\n  %b%bTALON%b\n' "$B" "$BCY" "$R"
  printf '  %bOne operating layer for your company'\''s AI use cases%b\n\n' "$GRY" "$R"
  printf '  %b3 AI USE CASES  ·  1 ORGANIZATION POLICY  ·  1 OPERATING VIEW%b\n\n' "$WHT" "$R"
  printf '  %b$ talon agents%b\n\n' "$GRY" "$R"
  printf '  %b%-20s %-18s %s%b\n' "$B" "USE CASE" "HEALTH" "SPEND TODAY" "$R"
  talon agents --url "$GATEWAY" --json 2>/dev/null \
    | jq -r '.agents | sort_by(.name)[] | "\(.name)\t\(.health)\t\(.spend_day)"' \
    | while IFS=$'\t' read -r name health spend; do
        printf '  %b%-20s%b %b%-18s%b %b$%s%b\n' "$WHT" "$name" "$R" "$BGR" "$health" "$R" "$WHT" "$(fmt "$spend")" "$R"
      done
  hold 3
}
present_fleet_full() { runcmd "talon agents --url '$GATEWAY'"; }
beat_fleet() {
  if [[ "$CUT" == hero && "$UI" == gum ]]; then hero_opening; g_hold 2
  elif [[ "$CUT" == hero ]]; then present_fleet_hero
  else
    banner "Talon — one operating layer for a company's AI use cases"
    printf ' %s3 production AI use cases   ·   1 organization policy   ·   1 operating view%s\n' "$DIM" "$R"
    present_fleet_full
  fi
}

# ── 2. Customer-support incident (reliability + shared policy) ────────────────
beat_support() {
  local cmdblock=""
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    hero_set_stage 1
    local content; content="$(support_pending_content)"
    cmdblock="$(hero_curl_cmd 'local-llama' 'agent=customer-support · prompt · email + IBAN')"
    ( openai_chat "$CS_KEY" local-llama llama3.2:1b \
        "Refund Anna Kowalska. Email: anna.kowalska@example.com IBAN: DE89370400440532013000" "$SUPPORT_SID" || true
      printf '%s' "${HTTP:-}" >"$WORK/.http" ) &
    g_await "$!" "$content" "$cmdblock" "${GUM_MUTED}LIVE · executing the governed request · evidence pending${GR}"
    HTTP="$(cat "$WORK/.http" 2>/dev/null || echo)"
  else
    [[ "$CUT" == hero ]] && pending "customer refund · contains email + IBAN" "scanning input and evaluating the route…"
    openai_chat "$CS_KEY" local-llama llama3.2:1b \
      "Refund Anna Kowalska. Email: anna.kowalska@example.com IBAN: DE89370400440532013000" "$SUPPORT_SID"
  fi
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
  local scost; scost="$(jq -r '[.records[].execution.cost // 0]|add' "$WORK/support.json" 2>/dev/null)"
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    local model; model="$(jq -r '.model // .model_id // empty' "$WORK/b" 2>/dev/null)"
    hero_cmd_complete "$cmdblock" "$(hero_http_output "$HTTP" "$([[ -n "$model" ]] && printf 'model=%s' "$model")" 'response received through fallback route')"
    hero_support_complete "$tier" "$failed_prov" "$skip_prov" "$sel" "$scost"; g_hold 3
    g_transition "RELIABILITY PROVED" "ORGANIZATION POLICY + COST" 2
  elif [[ "$CUT" == hero ]]; then present_support_hero "$ph" "$tier" "$failed_prov" "$skip_prov" "$sel" "$scost"
  else present_support_full "$pii" "$ph" "$tier" "$failed_prov" "$failed_err" "$skip_prov" "$sel"; fi
}
present_support_hero() { # ph tier failed skip sel cost — appended below the pending frame
  printf '\n  %b%-11s%b %b✓ email + IBAN redacted%b\n' "$B" "PII" "$R" "$BGR" "$R"
  printf '  %b%-11s%b %b%s%b %b· unchanged after redaction%b\n\n' "$B" "TIER" "$R" "$WHT" "$(tierlabel "$2")" "$R" "$GRY" "$R"
  printf '  %b%s%b\n' "$B" "ROUTE" "$R"
  hroute "$3" "FAILED"      "$BRD" "connection error"
  hroute "$4" "POLICY SKIP" "$AMB" "blocked by use-case policy"
  hroute "$5" "SELECTED"    "$BCY" "first policy-valid fallback"
  printf '\n  %b%-11s%b %b✓ completed%b\n' "$B" "RESULT" "$R" "$BGR" "$R"
  printf '  %b%-11s%b %b%s%b\n' "$B" "COST" "$R" "$WHT" "$(moneylt "$6")" "$R"
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
  local cmdblock=""
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    local content; content="$(tool_pending_content)"
    cmdblock="$(hero_curl_cmd 'openai' 'tools=read_file,search_kb,admin_purge_records')"
    ( tools_req "$CODE_KEY" || true; printf '%s' "${HTTP:-}" >"$WORK/.http" ) &
    g_await "$!" "$content" "$cmdblock" "${GUM_MUTED}LIVE · evaluating organization capability policy · evidence pending${GR}"
    HTTP="$(cat "$WORK/.http" 2>/dev/null || echo)"
  else
    [[ "$CUT" == hero ]] && pending "coding-assistant asks for:" "evaluating organization capability policy…" "read_file · search_kb · admin_purge_records"
    tools_req "$CODE_KEY"
  fi
  require_http 403 "capability"
  export_session "coding-${SUPPORT_SID}" "$WORK/coding.json"
  assert_ev "$WORK/coding.json" \
    'any(.records[]; .policy_decision.allowed==false and ((.execution.cost//0)==0) and (tostring|test("admin_purge_records")) and (.policy_decision.reasons|tostring|test("tool")))' \
    "organization tool boundary (admin_purge_records denied, \$0)"
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    hero_cmd_complete "$cmdblock" "$(hero_http_output "$HTTP" 'forbidden tool' 'admin_purge_records')"
    hero_tool_complete; g_hold 2
  elif [[ "$CUT" == hero ]]; then present_capability_hero; else present_capability_full; fi
}
present_capability_hero() {   # appended below the pending frame — Talon behaved correctly, so ✓ (not ✗)
  printf '\n  %b%-11s%b %borganization forbids%b %badmin_*%b\n\n' "$B" "BOUNDARY" "$R" "$GRY" "$R" "$AMB" "$R"
  printf '  %b✓ BLOCKED BEFORE MODEL%b\n' "${B}${BGR}" "$R"
  printf '  %b  Provider call prevented%b\n' "$GRY" "$R"
  printf '  %b  Cost $0.0000%b\n' "$GRY" "$R"
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
# The projected-cost loop: one (or a few) allowed summaries, then the next is
# denied on projected cost. Sets HTTP; no die (the caller checks HTTP + evidence).
cost_loop() { local sess="$1" n; for n in $(seq 1 12); do
    anthropic_msg "$DOC_KEY" claude-sonnet-5 "Please write a full, multi-section summary of this quarterly compliance document." 1024 "$sess"
    case "$HTTP" in 403|200) [[ "$HTTP" == 403 ]] && break;; *) break;; esac
  done; }
beat_cost() {
  local sess cmdblock=""; sess="doc-budget-$(rand 4)"
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    local content; content="$(cost_pending_content)"
    cmdblock="$(hero_curl_cmd 'anthropic' 'session=document-summary · batch summary')"
    ( cost_loop "$sess" || true; printf '%s' "${HTTP:-}" >"$WORK/.http" ) &
    g_await "$!" "$content" "$cmdblock" "${GUM_MUTED}LIVE · checking projected session cost · evidence pending${GR}"
    HTTP="$(cat "$WORK/.http" 2>/dev/null || echo)"
  else
    [[ "$CUT" == hero ]] && pending "document-summary" "checking projected session cost…"
    cost_loop "$sess"
  fi
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
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    hero_cmd_complete "$cmdblock" "$(hero_http_output "$HTTP" 'session_budget_exceeded' \
      "$(printf 'spent=$%s · estimate=$%s · limit=$%s' "$(fmt "$sp")" "$(fmt "$es")" "$(fmt "$li")")")"
    hero_cost_complete "$sp" "$es" "$pr" "$li"; g_hold 3
    g_transition "POLICY + COST PROVED" "OPERATIONS + PROOF" 3
  elif [[ "$CUT" == hero ]]; then present_cost_hero "$sp" "$es" "$pr" "$li"
  else present_cost_full "$sp" "$es" "$pr" "$li"; fi
}
present_cost_hero() { # spent est projected limit — appended below the pending frame
  printf '\n  %b%-24s%b %b$%s%b\n' "$B" "SESSION SPEND" "$R" "$WHT" "$(fmt "$1")" "$R"
  printf '  %b%-24s%b %b$%s%b\n' "$B" "NEXT ESTIMATE" "$R" "$WHT" "$(fmt "$2")" "$R"
  printf '  %b%-24s%b %b$%s%b\n' "$B" "PROJECTED TOTAL" "$R" "$WHT" "$(fmt "$3")" "$R"
  printf '  %b%-24s%b %b$%s%b\n' "$B" "SOFT SESSION LIMIT" "$R" "$AMB" "$(fmt "$4")" "$R"
  printf '  %-24s %b───────%b\n\n' '' "$GRY" "$R"
  printf '  %b✓ NEXT CALL PREVENTED%b\n' "${B}${BGR}" "$R"
  printf '  %b  Anthropic was not called%b\n' "$GRY" "$R"
  printf '  %b  Denied-call cost $0.0000%b\n' "$GRY" "$R"
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
# A couple more real summaries this operating period, then Finance lowers the
# daily budget below today's spend (a live YAML edit, activated by safe reload).
# Writes "oldcap<TAB>newcap<TAB>final_spend<TAB>health" to $WORK/.policy; no die.
policy_apply() {
  local sess oldcap spend newcap health="" _; sess="doc-day-$(rand 4)"
  anthropic_msg "$DOC_KEY" claude-sonnet-5 "Summarize this quarterly compliance document in detail." 1024 "$sess" || true
  anthropic_msg "$DOC_KEY" claude-sonnet-5 "Summarize this quarterly compliance document in detail." 1024 "$sess" || true
  oldcap="$(dsum_json daily_cap)"; spend="$(dsum_json spend_day)"
  if [[ -z "$spend" || "$spend" == "null" || "$spend" == "0" ]]; then printf 'ERR\t\t\t' >"$WORK/.policy"; return; fi
  newcap="$(awk -v s="$spend" 'BEGIN{printf "%.4f", s*0.9}')"
  # Real in-place edit (this exact command is what the hero's LIVE COMMAND panel shows).
  perl -i.bak -pe "s/daily: [0-9.]+/daily: ${newcap}/" "$WORK/agents/document-summary/agent.talon.yaml"
  for _ in $(seq 1 30); do health="$(dsum_json health)"; [[ "$health" == "blocked" ]] && break; sleep 0.5; done
  printf '%s\t%s\t%s\t%s' "$oldcap" "$newcap" "$(dsum_json spend_day)" "$health" >"$WORK/.policy"
}
beat_policy() {
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    local content oldcap_pre; content="$(ops_pending_content)"
    oldcap_pre="$(dsum_json daily_cap)"
    ( policy_apply ) &
    g_await "$!" "$content" "$(hero_perl_edit_cmd "$(fmt "$oldcap_pre")" "")" "${GUM_MUTED}LIVE · applying policy edit · periodic safe reload${GR}"
  else
    [[ "$CUT" == hero ]] && pending "document-summary · new daily ceiling" "applying policy edit and reloading…"
    policy_apply
  fi
  local oldcap newcap final_spend health
  IFS=$'\t' read -r oldcap newcap final_spend health < "$WORK/.policy" 2>/dev/null || true
  [[ "$oldcap" != "ERR" ]] || die "could not read document-summary daily spend"
  [[ "$health" == "blocked" ]] || die "document-summary did not reach HEALTH=blocked after lowering the daily cap (reload/eval issue)"
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    hero_cmd_complete "$(hero_cli_cmd 'talon agents')" "$(printf '%s\n%sdaily budget exhausted%s' "$(hero_agent_row document-summary)" "$GUM_MUTED" "$GR")"
    hero_ops_complete "$oldcap" "$newcap" "$final_spend"; g_hold 3
  elif [[ "$CUT" == hero ]]; then present_policy_hero "$oldcap" "$newcap" "$final_spend"
  else present_policy_full "$oldcap" "$newcap" "$final_spend"; fi
}
present_policy_hero() { # oldcap newcap spend — appended below the pending frame
  printf '\n  %bFINANCE SETS AN EMERGENCY DAILY CEILING%b\n\n' "$B" "$R"
  printf '  %b%-14s%b %b$%s%b → %b$%s%b\n' "$B" "Daily budget" "$R" "$WHT" "$(fmt "$1")" "$R" "$AMB" "$(fmt "$2")" "$R"
  printf '  %b%-14s%b %b$%s%b\n' "$B" "Current spend" "$R" "$WHT" "$(fmt "$3")" "$R"
  printf '  %b%-14s%b %b✓ activated safely%b\n\n' "$B" "Policy reload" "$R" "$BGR" "$R"
  printf '  %b%-20s %s%b\n' "$B" "USE CASE" "HEALTH" "$R"
  talon agents --url "$GATEWAY" --json 2>/dev/null \
    | jq -r '.agents | sort_by(.name)[] | "\(.name)\t\(.health)"' \
    | while IFS=$'\t' read -r name health; do
        if [[ "$health" == blocked ]]; then
          printf '  %b%-20s%b %b%-10s%b %bdaily budget exhausted%b\n' "$WHT" "$name" "$R" "$AMB" "BLOCKED" "$R" "$GRY" "$R"
        else
          printf '  %b%-20s%b %b%s%b\n' "$WHT" "$name" "$R" "$BGR" "$health" "$R"
        fi
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
  local c_failed c_skip c_sel
  c_failed="$(jq -r 'first(.records[]|select(.failover.role=="failed_attempt").failover.provider)' "$WORK/support.json")"
  c_skip="$(jq -r 'first(.records[].failover.skipped_candidates[]?.provider)' "$WORK/support.json")"
  c_sel="$(jq -r 'first(.records[]|select(.failover.role=="fallback_decision").failover.provider)' "$WORK/support.json")"
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    hero_cmd_complete "$(hero_cli_cmd 'talon audit verify --file signed-evidence.json')" \
      "$(printf '%sTotal records: %s%s\n%sValid records: %s%s\n%sInvalid records: 0%s' \
         "$GUM_TEXT" "$total" "$GR" "$GUM_GREEN" "$valid" "$GR" "$GUM_GREEN" "$GR")"
    hero_proof "${SUPPORT_SID:0:12}" "$c_failed" "$c_skip" "$c_sel" "$scost" "$total" "$valid"; g_hold 3
    hero_final; g_hold 3
  elif [[ "$CUT" == hero ]]; then present_close_hero "$total" "$valid" "$fv" "$scost" "$c_failed" "$c_skip" "$c_sel"
  else present_close_full "$corr" "$fv"; fi
}
present_close_hero() { # total valid fv scost failed skip sel — the compact product-level receipt
  printf '\n  %b%-13s%b %b%s%b\n'              "$B" "SESSION"     "$R" "$WHT" "${SUPPORT_SID:0:12}" "$R"
  printf '  %b%-13s%b %bcompleted%b\n'         "$B" "OUTCOME"     "$R" "$WHT" "$R"
  printf '  %b%-13s%b %bemail + IBAN redacted%b\n' "$B" "PII"     "$R" "$WHT" "$R"
  printf '  %b%-13s%b %b%s failed%b\n'         "$B" "PRIMARY"     "$R" "$WHT" "$5" "$R"
  printf '  %b%-13s%b %b%s%b\n'                "$B" "POLICY SKIP" "$R" "$WHT" "$6" "$R"
  printf '  %b%-13s%b %b%s%b\n'                "$B" "SELECTED"    "$R" "$WHT" "$7" "$R"
  printf '  %b%-13s%b %b%s%b\n\n'              "$B" "COST"        "$R" "$WHT" "$(moneylt "$4")" "$R"
  printf '  %bSIGNED EVIDENCE%b\n\n' "$B" "$R"
  printf '  %b%s records · %s valid · 0 invalid%b\n' "$WHT" "$1" "$2" "$R"
  [[ -n "$3" ]] && printf '  %bFailover chain · %bvalid_fallback%b\n' "$WHT" "$BGR" "$R"
  printf '  %b✓ VERIFIED OFFLINE%b\n' "${B}${BGR}" "$R"
  hold 4
  # ── Final frame — clear ONCE, then the closing statement (held ≥3s) ──
  clear_scene
  printf '\n\n\n  %b%bTALON%b\n\n' "$B" "$BCY" "$R"
  printf '  %bOperate every AI use case%b\n' "$B" "$R"
  printf '  %bthrough one shared control plane%b\n\n' "$B" "$R"
  printf '  %bcost control · reliability · shared policy · session understanding%b\n' "$GRY" "$R"
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
  if [[ "$CUT" == hero && "$UI" == gum ]]; then
    # Styled live operations console: enter the alternate screen once; every beat
    # recomposes the stable header + progress rail + main panel + status bar in
    # place. The progress rail (not chapter dividers) carries orientation.
    g_enter_screen
    beat_fleet; beat_support; beat_capability; beat_cost; beat_policy; beat_close
    printf '\033]0;HERO_COMPLETE\007'   # machine marker via terminal title — off the visible frame
    # Keep the final frame as the last recorded event when recording (the recorder
    # resets the real terminal afterward); restore it for a manual/interactive run.
    if [[ "${TALON_DEMO_KEEP_SCREEN:-0}" == 1 ]]; then HERO_SCREEN=0; else g_restore_screen; fi
  elif [[ "$CUT" == hero ]]; then
    # Plain-UI anchored narrative — the automated-assertion fallback (no gum).
    beat_fleet
    chapter 1 "RELIABILITY + SHARED POLICY"; beat_support
    chapter 2 "ORGANIZATION POLICY + COST";  beat_capability; beat_cost
    chapter 3 "OPERATIONAL CONTROL + PROOF"; beat_policy;     beat_close
    printf '\033]0;HERO_COMPLETE\007'
  else
    beat_fleet; beat_support; beat_capability; beat_cost; beat_policy; beat_close
  fi
}

write_state() { # write_state <file> <cut>
  cat > "$1" <<EOF
export TALON_DATA_DIR='${TALON_DATA_DIR}' TALON_SECRETS_KEY='${TALON_SECRETS_KEY}' TALON_SIGNING_KEY='${TALON_SIGNING_KEY}' TALON_ADMIN_KEY='${TALON_ADMIN_KEY}' TALON_LOG_LEVEL='warn'
export PATH='${WORK}/bin:'"\$PATH"
WORK='${WORK}'; GW_PORT='${GW_PORT}'; GATEWAY='${GATEWAY}'; GW_PID='${GW_PID}'
CS_KEY='${CS_KEY}'; CODE_KEY='${CODE_KEY}'; DOC_KEY='${DOC_KEY}'; SUPPORT_SID='${SUPPORT_SID}'; STATE_CUT='${2}'
EOF
}

# gum is required ONLY for the styled hero (TALON_DEMO_UI=gum). The full `all`
# walkthrough and the plain-UI hero fallback never need it.
require_gum() { command -v gum >/dev/null 2>&1 || die "gum is required for the styled hero (TALON_DEMO_UI=gum) — install gum v0.17.0 (https://github.com/charmbracelet/gum). The full walkthrough needs no gum:  ./demo.sh   (and the plain hero for tests:  TALON_DEMO_UI=plain ./demo.sh hero)."; }

case "${1:-all}" in
  hero|all)
    [[ "$1" == hero && "$UI" == gum ]] && require_gum
    setup; run_beats "${1:-all}" ;;
  prepare)
    STATE="${2:?usage: demo.sh prepare <statefile> [hero|all]}"
    setup; write_state "$STATE" "${3:-hero}"
    trap - EXIT
    echo "prepared: gateway ${GATEWAY}, state ${STATE} (run: demo.sh play ${STATE})" >&2 ;;
  play)
    STATE="${2:?usage: demo.sh play <statefile>}"
    # shellcheck disable=SC1090
    source "$STATE"; cd "$WORK"
    [[ "${STATE_CUT:-hero}" == hero && "$UI" == gum ]] && require_gum
    run_beats "${STATE_CUT:-hero}" ;;
  *) echo "usage: $0 [hero | all | prepare <statefile> [hero|all] | play <statefile>]" >&2; exit 2 ;;
esac
