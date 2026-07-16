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
#   ./demo.sh hero     # annotated live terminal demo (the README GIF; needs gum)
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
# Hero presentation surface: 'gum' = the styled live terminal walkthrough (the
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
cleanup() { w_cursor_restore 2>/dev/null || true; [[ -n "$GW_PID" ]] && kill "$GW_PID" >/dev/null 2>&1 || true; [[ -n "$WORK" ]] && rm -rf "$WORK"; }
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

# Verbose-cut renderers (used by the full `all` walkthrough).
BAR='══════════════════════════════════════════════════════════════════════'
banner() { echo; printf '%s%s%s\n' "$B" "$BAR" "$R"; while [[ $# -gt 0 ]]; do printf '%s %s%s\n' "$B" "$1" "$R"; shift; done; printf '%s%s%s\n' "$B" "$BAR" "$R"; }
beat()   { [[ "$1" != 1 ]] && [[ "$PAUSE" != 0 ]] && sleep "$PAUSE"; echo; printf '%s──[ %s/%s ]── %s  %s%s\n' "$B" "$1" "$2" "$3" "$4" "$R"; printf '%s              %s%s\n' "$DIM" "$5" "$R"; }
row()    { printf '  %s%-9s%s %s\n' "$YEL" "$1" "$R" "$2"; }
route()  { local c="$CYN"; [[ "$1" == FAILED ]]&&c="$RED"; [[ "$1" == SKIPPED ]]&&c="$YEL"; [[ "$1" == SELECTED ]]&&c="$GRN"; printf '  %s%-13s%s%-10s%s %s\n' "$B" "$2" "$c" "$1" "$R" "$3"; }
ok()     { printf '  %s✓ %s%s\n' "$GRN" "$1" "$R"; }
runcmd() { printf '\n%s$ %s%s\n' "$DIM" "$*" "$R"; eval "$*"; }
pause()  { [[ "$PAUSE" != 0 ]] && sleep "$PAUSE"; return 0; }

# Shared terminal helpers (used by the walkthrough hero + the `all` cut).
clear_scene() { printf '\033[2J\033[H'; }
dashes()  { local n="$1" s=''; while (( n-- > 0 )); do s+='─'; done; printf '%s' "$s"; }
moneylt() { awk -v c="$1" 'BEGIN{ if (c+0 < 0.0001) printf "< $0.0001"; else printf "$%.4f", c }'; }

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
# ── Recorder-grade resilience — DEMO-RUNNER infrastructure, NOT a Talon feature.
# Talon does not ship same-provider retries (policy-valid failover is the shipped
# reliability story); these retries exist so a transient upstream blip (e.g. a
# real Anthropic HTTP 529 "Overloaded" seen in the field) cannot kill a recording
# take. If one fires in the hero, the surfaced line is attributed to the demo
# runner — never presented as Talon behavior.
RETRY_BACKOFF="${TALON_DEMO_RETRY_BACKOFF:-3}"   # seconds; tests set 0
transient_http() { case "$1" in 429|500|502|503|529|000|"") return 0;; *) return 1;; esac; }
retry_call() { # retry_call <fn> [args...] — ≤3 retries on transient upstream status
  # or transport failure. Always returns 0: the result travels via $HTTP/$WORK/b,
  # keeping require_http the single fail-closed gate. Retries append to
  # $WORK/.retries so hero beats can surface them (attributed to the demo runner).
  local attempt rc
  for attempt in 1 2 3; do
    rc=0; "$@" || rc=$?; (( rc != 0 )) && HTTP="000"
    transient_http "$HTTP" || return 0
    printf 'HTTP %s\n' "$HTTP" >>"$WORK/.retries"
    sleep "$(( attempt * RETRY_BACKOFF ))"
  done
  rc=0; "$@" || rc=$?; (( rc != 0 )) && HTTP="000"   # final answer stands; require_http diagnoses
  return 0
}

openai_chat() { # <bearer> <provider> <model> <content> [session]
  : >"$WORK/b"   # never let require_http diagnose a stale body from a prior attempt
  local -a h=(-H "Authorization: Bearer $1" -H "Content-Type: application/json"); [[ -n "${5:-}" ]] && h+=(-H "X-Talon-Session-ID: $5")
  HTTP="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X POST "${GATEWAY}/v1/proxy/$2/v1/chat/completions" "${h[@]}" \
    -d "$(jq -nc --arg m "$3" --arg c "$4" '{model:$m,messages:[{role:"user",content:$c}]}')")"
}
anthropic_msg() { # <bearer> <model> <content> <max_tokens> [session]
  : >"$WORK/b"
  local -a h=(-H "Authorization: Bearer $1" -H "Content-Type: application/json"); [[ -n "${5:-}" ]] && h+=(-H "X-Talon-Session-ID: $5")
  HTTP="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X POST "${GATEWAY}/v1/proxy/anthropic/v1/messages" "${h[@]}" \
    -d "$(jq -nc --arg m "$2" --arg c "$3" --argjson mt "$4" '{model:$m,max_tokens:$mt,messages:[{role:"user",content:$c}]}')")"
}
tools_req() { # <bearer>; coding-assistant declares no forbidden_tools — the ORG boundary fires
  # (Deliberately NOT retry_call-wrapped: the 403 is decided by the local gateway
  # before any provider dispatch, so there is no transient upstream surface.)
  : >"$WORK/b"
  HTTP="$(curl -sS -o "$WORK/b" -w '%{http_code}' -X POST "${GATEWAY}/v1/proxy/openai/v1/chat/completions" \
    -H "Authorization: Bearer $1" -H "Content-Type: application/json" -H "X-Talon-Session-ID: coding-${SUPPORT_SID}" \
    -d '{"model":"gpt-4o","messages":[{"role":"user","content":"refactor the billing module"}],"tools":[{"type":"function","function":{"name":"read_file","description":"x","parameters":{"type":"object"}}},{"type":"function","function":{"name":"search_kb","description":"y","parameters":{"type":"object"}}},{"type":"function","function":{"name":"admin_purge_records","description":"z","parameters":{"type":"object"}}}]}')"
}
dsum_json() { talon agents show document-summary --url "$GATEWAY" --json 2>/dev/null | jq -r ".$1"; }


# ════════════════════════════════════════════════════════════════════════════
# Hero cut — an ANNOTATED LIVE TERMINAL WALKTHROUGH (TALON_DEMO_UI=gum|plain).
# A directed, scrolling shell session: chapter heading → real command → a live
# wait line → the command's REAL output → one short annotation. This is NOT a
# dashboard/TUI — no persistent header, navigation rail, panels, status/receipt
# bars, or fixed application regions; Talon ships no such interface. gum is a
# demo-only dependency used SPARINGLY (at most one bordered callout on screen:
# the closing frame), and the recording never shows the host shell prompt.
# Three visual levels: COMMAND (cyan $ + white) · REAL OUTPUT (white + Talon
# status colours) · ANNOTATION (grey → prefix; green for a proven conclusion).
# ════════════════════════════════════════════════════════════════════════════
WT_TEXT=$'\033[38;2;240;246;252m'; WT_MUTED=$'\033[38;2;139;148;158m'
WT_CYAN=$'\033[38;2;88;166;255m';  WT_GREEN=$'\033[38;2;63;185;80m'
WT_AMBER=$'\033[38;2;210;153;34m'; WT_RED=$'\033[38;2;248;81;73m'
WB=$'\033[1m'; WR=$'\033[0m'
SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
GUMUI=0; [[ "$UI" == "gum" ]] && command -v gum >/dev/null 2>&1 && GUMUI=1
pcell()  { local s; printf -v s '%-*s' "$1" "$2"; printf '%s%s%s' "$3" "$s" "$WR"; }   # pcell <w> <text> <colour>
w_hold() { [[ "$PAUSE" != 0 ]] && sleep "${1:-2}"; return 0; }

CURSOR_HIDDEN=0
w_open() {   # the ONE clear at the start; identify the recording as a live terminal demo
  printf '\033[?25l'; CURSOR_HIDDEN=1   # hidden for the whole hero; restored by cleanup + run_beats
  clear_scene
  printf '\n  %b%bTALON · LIVE TERMINAL DEMO%b\n' "$WB" "$WT_CYAN" "$WR"
  printf '  %bReal CLI/API calls · live decisions · signed evidence%b\n' "$WT_MUTED" "$WR"
}
w_cursor_restore() {
  # When recording, the restore must NOT enter the cast (the final frame would
  # show a stray cursor block) — the recorder resets the real terminal itself
  # after asciinema exits (TALON_DEMO_NO_CURSOR_RESTORE=1).
  [[ "${TALON_DEMO_NO_CURSOR_RESTORE:-0}" == 1 ]] && { CURSOR_HIDDEN=0; return 0; }
  [[ "${CURSOR_HIDDEN:-0}" == 1 ]] && printf '\033[?25h'; CURSOR_HIDDEN=0; return 0
}
w_chapter() { # <n> <title>  — a terminal comment/separator, not a navigation tab
  local mid; mid="$(printf '── %s. %s ' "$1" "$2")"; local rest=$(( 76 - ${#mid} )); (( rest < 3 )) && rest=3
  printf '\n  %b── %s.%b %b%s%b %b%s%b\n\n' "$WT_MUTED" "$1" "$WR" "${WB}${WT_CYAN}" "$2" "$WR" "$WT_MUTED" "$(dashes "$rest")" "$WR"
}
w_cmd()   { printf '  %b$%b %b%s%b\n' "$WT_CYAN" "$WR" "$WT_TEXT" "$1" "$WR"; [[ -n "${2:-}" ]] && printf '    %b%s%b\n' "$WT_MUTED" "$2" "$WR"; return 0; }
w_comment() { printf '  %b# %s%b\n' "$WT_MUTED" "$1" "$WR"; }   # a shell-comment context line (part of the directed session)
w_line()  { printf '  %s\n' "$1"; }                          # a real-output line (pre-coloured)
w_annot() { local c="$WT_MUTED"; [[ "${2:-}" == "green" ]] && c="$WT_GREEN"; printf '  %b→ %s%b\n' "$c" "$1" "$WR"; }
w_retries() { # surface any transients retry_call absorbed — attributed to the DEMO
  # RUNNER (Talon does not ship same-provider retries; never imply it does).
  [[ -s "$WORK/.retries" ]] || return 0
  local last; last="$(tail -1 "$WORK/.retries")"
  w_annot "demo runner: provider temporarily overloaded (${last}) — retried the demonstration."
  rm -f "$WORK/.retries"
}
w_reveal() { # w_reveal <delay-s> <line...> — paced reveal of REAL, pre-rendered output
  # lines (sequence, not shimmer); instant when PAUSE=0 so tests stay fast.
  local delay="$1"; shift; local l
  for l in "$@"; do printf '%s\n' "$l"; [[ "$PAUSE" != 0 ]] && sleep "$delay"; done
  return 0
}
w_reveal_stdin() { # paced pass-through for pre-rendered multi-line output (pipelines)
  local delay="$1" l
  while IFS= read -r l; do printf '%s\n' "$l"; [[ "$PAUSE" != 0 ]] && sleep "$delay"; done
  return 0
}
w_http()  { # <http> <detail>  → real HTTP status, 2xx green / 4xx amber (policy denial) / else red
  local hc; case "$1" in 2*) hc="$WT_GREEN";; 4*) hc="$WT_AMBER";; *) hc="$WT_RED";; esac
  local head="HTTP $1"; [[ -n "${2:-}" ]] && head="HTTP $1 · $2"
  printf '  %b%s%b\n' "$hc" "$head" "$WR"
}
w_run() {  # <wait-text> <pid>  — an inline spinner beside the running command (gum UI); static otherwise
  local text="$1" pid="$2" i=0
  if [[ "$GUMUI" == 1 ]]; then
    while kill -0 "$pid" 2>/dev/null; do printf '\r  %b%s %s…%b' "$WT_MUTED" "${SPIN[$((i%10))]}" "$text" "$WR"; i=$((i+1)); sleep 0.3; done
    printf '\r%*s\r' 78 ''
  else
    printf '  %b%s…%b\n' "$WT_MUTED" "$text" "$WR"
  fi
  wait "$pid" 2>/dev/null || true
}
# The REAL `talon agents` stdout, visual-safe trims only (dash-separator row
# dropped). Default: AGENT/STATE/HEALTH. "why" mode: AGENT/HEALTH/WHY — the
# attention-queue view (WHY is the CLI's own cause text, e.g. "daily budget
# exhausted ($0.0035 / $0.0032)"); blocked health is amber.
w_agents() { # [why]
  local mode="${1:-}"
  if [[ "$mode" == "why" ]]; then
    # The CLI prints fixed printf widths (%-22s %-9s %-16s %-24s %s), so slice by
    # column position — COST itself contains spaces ("$0.0035 / $0.0032").
    talon agents --url "$GATEWAY" 2>/dev/null \
      | awk 'NF>=3 && $1 !~ /^-+$/ {
          a=substr($0,1,22); h=substr($0,34,16); w=substr($0,76)
          gsub(/[[:space:]]+$/,"",a); gsub(/[[:space:]]+$/,"",h); gsub(/[[:space:]]+$/,"",w)
          print a"\t"h"\t"w}' | head -4 \
      | while IFS=$'\t' read -r a h why; do
          if [[ "$a" == "AGENT" ]]; then printf '  %b%-22s %-9s %s%b\n' "${WB}${WT_MUTED}" "$a" "$h" "$why" "$WR"
          else local hc="$WT_TEXT"; [[ "$h" == "healthy" ]] && hc="$WT_GREEN"; [[ "$h" == "blocked" ]] && hc="$WT_AMBER"
            printf '  %s %s %b%s%b\n' "$(pcell 22 "$a" "$WT_TEXT")" "$(pcell 9 "$h" "$hc")" "$WT_MUTED" "$why" "$WR"; fi
        done
  else
    talon agents --url "$GATEWAY" 2>/dev/null | awk 'NF>=3 && $1 !~ /^-+$/ {print $1"\t"$2"\t"$3}' | head -4 \
      | while IFS=$'\t' read -r a s h; do
          if [[ "$a" == "AGENT" ]]; then printf '  %b%-22s %-9s %s%b\n' "${WB}${WT_MUTED}" "$a" "$s" "$h" "$WR"
          else local hc="$WT_TEXT"; [[ "$h" == "healthy" ]] && hc="$WT_GREEN"; [[ "$h" == "blocked" ]] && hc="$WT_AMBER"
            printf '  %s %s %s\n' "$(pcell 22 "$a" "$WT_TEXT")" "$(pcell 9 "$s" "$WT_MUTED")" "$(pcell 10 "$h" "$hc")"; fi
        done
  fi
}
# Session-scoped audit, normalized from the REAL `talon audit list --session`
# summary block (no record rows — counts/providers/cost are the CLI's own values;
# the outcome line is a demo annotation asserted from signed evidence).
w_session() { # <session-id>
  talon audit list --session "$1" >"$WORK/.audit" 2>/dev/null || true
  # Real summary line: "  Requests:  3 (2 allowed, 1 denied, 0 error)"
  local rline req err prov cost
  rline="$(grep -m1 -E '^[[:space:]]*Requests:' "$WORK/.audit" || true)"
  req="$(awk '{print $2}' <<<"$rline")"
  err="$(sed -nE 's/.*, *([0-9]+) error.*/\1/p' <<<"$rline")"
  prov="$(sed -nE 's/^[[:space:]]*Providers:[[:space:]]*(.*)$/\1/p' "$WORK/.audit" | head -1)"
  # The CLI renders tiny session costs as "$< 0.0001" and larger ones at 6dp —
  # normalize both to the demo's ≤4dp money grammar.
  cost="$(sed -nE 's/^[[:space:]]*Cost:[[:space:]]*(.*)$/\1/p' "$WORK/.audit" | head -1)"
  case "$cost" in
    *"< 0.0001"*) cost="< \$0.0001" ;;
    \$*)          cost="$(moneylt "${cost#\$}")" ;;
    *)            cost="" ;;
  esac
  printf '  %b%s%b\n' "$WT_TEXT" "Session ${1}" "$WR"
  printf '  %bRequests: %s · Errors: %s%b\n' "$WT_TEXT" "${req:-?}" "${err:-0}" "$WR"
  [[ -n "$prov" ]] && printf '  %bProviders: %s%b\n' "$WT_TEXT" "$prov" "$WR"
  [[ -n "$cost" ]] && printf '  %bCost: %s%b\n' "$WT_TEXT" "$cost" "$WR"
  return 0
}
w_close() {  # clear once; the closing statement — the single bordered callout in the gum UI
  # Compose the callout BEFORE clearing (gum exec takes real time; composing first
  # keeps clear→print adjacent so no blank frame ever appears in the recording).
  local callout
  if [[ "$GUMUI" == 1 ]]; then
    # --border normal: light box-drawing corners render cleanly in agg (the
    # rounded arc glyphs were the corner-artifact source in rendered GIFs).
    callout="$(gum style --border normal --border-foreground '#30363D' --padding '1 4' --margin '0 0 0 2' --align center \
      "$(printf '%b%bTALON%b\n\n%bOperate every AI use case\nthrough one shared control plane%b\n\n%b✓ Live decisions · ✓ Signed evidence · ✓ Verified offline%b\n\n%bCost control · Reliability · Shared policy · Session understanding%b' \
         "$WB" "$WT_CYAN" "$WR" "$WT_TEXT" "$WR" "$WT_GREEN" "$WR" "$WT_MUTED" "$WR")")"
  else
    callout="$(printf '  %b%bTALON%b\n\n  %bOperate every AI use case%b\n  %bthrough one shared control plane%b\n\n  %b✓ Live decisions · ✓ Signed evidence · ✓ Verified offline%b\n\n  %bCost control · Reliability · Shared policy · Session understanding%b' \
      "$WB" "$WT_CYAN" "$WR" "$WT_TEXT" "$WR" "$WT_TEXT" "$WR" "$WT_GREEN" "$WR" "$WT_MUTED" "$WR")"
  fi
  clear_scene; printf '\n\n%s\n' "$callout"
  w_hold 4
}

# ════════════════════════════════════════════════════════════════════════════
# Beats: chapter → real command → live wait → assert (shared) → real output → note.
# ════════════════════════════════════════════════════════════════════════════

# ── 1. Category + fleet ──────────────────────────────────────────────────────
present_fleet_full() { runcmd "talon agents --url '$GATEWAY'"; }
beat_fleet() {
  if [[ "$CUT" == hero ]]; then
    w_cmd "talon agents"; echo
    w_agents | w_reveal_stdin 0.2; echo
    w_annot "Three AI use cases under one organization policy — one operating view."
    w_hold 3
  else
    banner "Talon — one operating layer for a company's AI use cases"
    printf ' %s3 production AI use cases   ·   1 organization policy   ·   1 operating view%s\n' "$DIM" "$R"
    present_fleet_full
  fi
}

# ── 2. Customer-support incident (reliability + shared policy) ────────────────
beat_support() {
  if [[ "$CUT" == hero ]]; then
    rm -f "$WORK/.retries"
    w_cmd 'curl -X POST $GATEWAY/v1/proxy/local-llama/v1/chat/completions' "customer-support · refund request · email + IBAN"
    ( retry_call openai_chat "$CS_KEY" local-llama llama3.2:1b \
        "Refund Anna Kowalska. Email: anna.kowalska@example.com IBAN: DE89370400440532013000" "$SUPPORT_SID"
      printf '%s' "${HTTP:-}" >"$WORK/.http" ) &
    w_run "Routing through Talon" "$!"
    HTTP="$(cat "$WORK/.http" 2>/dev/null || echo)"
    w_retries
  else
    retry_call openai_chat "$CS_KEY" local-llama llama3.2:1b \
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
  if [[ "$CUT" == hero ]]; then
    local model; model="$(jq -r '.model // .model_id // empty' "$WORK/b" 2>/dev/null)"
    echo; w_http "$HTTP" "${model:+model=$model}"; echo
    # Route ledger revealed in sequence (200ms) — failed → policy-skipped → selected.
    w_reveal 0.2 \
      "  $(printf '%b✓ email + IBAN redacted%b' "$WT_GREEN" "$WR")" \
      "  $(printf '%s %bconnection error%b' "$(pcell 16 "× $failed_prov" "$WT_RED")" "$WT_MUTED" "$WR")" \
      "  $(printf '%s %bblocked by use-case policy%b' "$(pcell 16 "⊘ $skip_prov" "$WT_AMBER")" "$WT_MUTED" "$WR")" \
      "  $(printf '%s %bselected fallback%b' "$(pcell 16 "✓ $sel" "$WT_CYAN")" "$WT_MUTED" "$WR")"
    w_annot "Talon replaced the detected email and IBAN before forwarding · tier unchanged."
    w_annot "Completed through the first policy-valid destination · cost $(moneylt "$scost")."
    w_hold 5
  else present_support_full "$pii" "$ph" "$tier" "$failed_prov" "$failed_err" "$skip_prov" "$sel"; fi
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
  if [[ "$CUT" == hero ]]; then
    w_cmd 'curl -X POST $GATEWAY/v1/proxy/openai/v1/chat/completions' "coding-assistant · tools=read_file,search_kb,admin_purge_records"
    ( tools_req "$CODE_KEY" || true; printf '%s' "${HTTP:-}" >"$WORK/.http" ) &
    w_run "Evaluating organization capability policy" "$!"
    HTTP="$(cat "$WORK/.http" 2>/dev/null || echo)"
  else
    tools_req "$CODE_KEY"
  fi
  require_http 403 "capability"
  export_session "coding-${SUPPORT_SID}" "$WORK/coding.json"
  assert_ev "$WORK/coding.json" \
    'any(.records[]; .policy_decision.allowed==false and ((.execution.cost//0)==0) and (tostring|test("admin_purge_records")) and (.policy_decision.reasons|tostring|test("tool")))' \
    "organization tool boundary (admin_purge_records denied, \$0)"
  if [[ "$CUT" == hero ]]; then
    local emsg; emsg="$(jq -r '.error.message // .error // empty' "$WORK/b" 2>/dev/null | head -c 60)"
    [[ -n "$emsg" ]] || emsg="Request contains forbidden tools: admin_purge_records"
    echo; w_http "$HTTP"; w_line "$(printf '%b%s%b' "$WT_TEXT" "$emsg" "$WR")"
    w_annot "Organization boundary enforced before provider access · \$0.0000 spent."
    w_hold 4
  else present_capability_full; fi
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
    # retry_call absorbs transient upstream weather (429/5xx/529); any other
    # non-200 (the expected 403, or a hard failure) ends the loop for diagnosis.
    retry_call anthropic_msg "$DOC_KEY" claude-sonnet-5 "Please write a full, multi-section summary of this quarterly compliance document." 1024 "$sess"
    [[ "$HTTP" == "200" ]] || break
  done; }
beat_cost() {
  local sess; sess="doc-budget-$(rand 4)"
  if [[ "$CUT" == hero ]]; then
    echo
    rm -f "$WORK/.retries"
    w_cmd 'curl -X POST $GATEWAY/v1/proxy/anthropic/v1/messages' "session=document-summary · batch summary"
    ( cost_loop "$sess" || true; printf '%s' "${HTTP:-}" >"$WORK/.http" ) &
    w_run "Checking projected session cost" "$!"
    HTTP="$(cat "$WORK/.http" 2>/dev/null || echo)"
    w_retries
  else
    cost_loop "$sess"
  fi
  if [[ "$HTTP" != "403" ]]; then
    # Distinguish "the budget genuinely never tripped" (all 200s) from a provider
    # error that broke the loop early — require_http prints the REAL response body
    # and the provider-account hint (quota / auth / rate limit / outage).
    [[ "$HTTP" == "200" ]] && die "cost: session budget never tripped in 12 calls (all 200s — check document-summary session_limits.max_cost)"
    require_http 403 "cost (projected session budget; document-summary runs on Anthropic)"
  fi
  export_session "$sess" "$WORK/doc.json"
  assert_ev "$WORK/doc.json" \
    'any(.records[]; .session_budget != null and .session_budget.limit != null and .session_budget.spent != null and .session_budget.estimate != null)' \
    "session-budget projected-cost stop (structured { limit, spent, estimate })"
  local sp es li pr
  sp="$(jq -r 'first(.records[]|select(.session_budget!=null).session_budget.spent)' "$WORK/doc.json")"
  es="$(jq -r 'first(.records[]|select(.session_budget!=null).session_budget.estimate)' "$WORK/doc.json")"
  li="$(jq -r 'first(.records[]|select(.session_budget!=null).session_budget.limit)' "$WORK/doc.json")"
  pr="$(awk -v a="$sp" -v b="$es" 'BEGIN{printf "%.4f", a+b}')"
  if [[ "$CUT" == hero ]]; then
    echo; w_http "$HTTP" "session_budget_exceeded"
    w_reveal 0.3 \
      "  $(printf '%bspent=$%s%b'    "$WT_TEXT" "$(fmt "$sp")" "$WR")" \
      "  $(printf '%bestimate=$%s%b' "$WT_TEXT" "$(fmt "$es")" "$WR")" \
      "  $(printf '%blimit=$%s%b'    "$WT_TEXT" "$(fmt "$li")" "$WR")"
    w_annot "Projected total \$$(fmt "$pr") over the soft session limit — the next call was prevented."
    w_hold 5
  else present_cost_full "$sp" "$es" "$pr" "$li"; fi
}
present_cost_full() { # spent est projected limit
  beat 3 4 "💶" "Cost control before spend" "document-summary — a batch summarizer on Anthropic"
  row "BUDGET"  "per-session cost budget (SOFT cap — an in-flight request may overshoot; daily/monthly are the hard, pre-provider caps)"
  row "RECEIPT" "$(printf 'session spend $%.4f + next estimate $%.4f = projected $%.4f  →  over the soft $%.4f limit' "$1" "$2" "$3" "$4")"
  echo
  ok "Prevented the next Anthropic call on PROJECTED cost — decided before spend, not after the bill. \$0 spent on the denied call."
}

# ── 5. Live operational control (a policy edit → fleet blocked) ───────────────
# Split so the hero can display the EXACT executed edit: policy_warmup runs two
# more real summaries this operating period and computes the new ceiling from
# live spend (→ $WORK/.policy-pre "oldcap<TAB>spend<TAB>newcap"; ERR sentinel);
# policy_edit applies the perl edit + waits for the safe reload to flip health
# (→ $WORK/.policy "final_spend<TAB>health"). No die inside either (subshell-run).
policy_warmup() {
  local sess oldcap spend newcap; sess="doc-day-$(rand 4)"
  retry_call anthropic_msg "$DOC_KEY" claude-sonnet-5 "Summarize this quarterly compliance document in detail." 1024 "$sess"
  retry_call anthropic_msg "$DOC_KEY" claude-sonnet-5 "Summarize this quarterly compliance document in detail." 1024 "$sess"
  oldcap="$(dsum_json daily_cap)"; spend="$(dsum_json spend_day)"
  if [[ -z "$spend" || "$spend" == "null" || "$spend" == "0" ]]; then printf 'ERR\t\t' >"$WORK/.policy-pre"; return; fi
  newcap="$(awk -v s="$spend" 'BEGIN{printf "%.4f", s*0.9}')"
  printf '%s\t%s\t%s' "$oldcap" "$spend" "$newcap" >"$WORK/.policy-pre"
}
policy_edit() { # <newcap> — the exact command the hero displays
  local health="" _
  perl -i.bak -pe "s/daily: [0-9.]+/daily: ${1}/" "$WORK/agents/document-summary/agent.talon.yaml"
  for _ in $(seq 1 30); do health="$(dsum_json health)"; [[ "$health" == "blocked" ]] && break; sleep 0.5; done
  printf '%s\t%s' "$(dsum_json spend_day)" "$health" >"$WORK/.policy"
}
# Real config diff — the PRIMARY visual of the policy beat (the capability being
# sold is safe reload from YAML, not the edit mechanics). Lines come from the
# actual files perl left behind (.bak = before, current = after).
w_config_diff() {
  local before after yaml="$WORK/agents/document-summary/agent.talon.yaml"
  # key/value only — the trailing YAML comment is noise at demo width
  before="$(grep -m1 -E '^[[:space:]]*daily:' "${yaml}.bak" 2>/dev/null | sed 's/#.*//; s/^ *//; s/ *$//')"
  after="$(grep -m1 -E '^[[:space:]]*daily:' "$yaml" 2>/dev/null | sed 's/#.*//; s/^ *//; s/ *$//')"
  printf '  %b- %s%b\n' "$WT_RED" "${before:-daily: ?}" "$WR"
  printf '  %b+ %s%b\n' "$WT_GREEN" "${after:-daily: ?}" "$WR"
}
beat_policy() {
  if [[ "$CUT" == hero ]]; then
    rm -f "$WORK/.retries"
    w_comment "Finance sets an emergency ceiling below today's spend"
    ( policy_warmup ) &
    w_run "Reading today's live document-summary spend" "$!"
    w_retries
  else
    policy_warmup
  fi
  local oldcap newcap
  IFS=$'\t' read -r oldcap _ newcap < "$WORK/.policy-pre" 2>/dev/null || true
  [[ "$oldcap" != "ERR" && -n "${newcap:-}" ]] || die "could not read document-summary daily spend"
  if [[ "$CUT" == hero ]]; then
    # The EXACT executed command (dim — deliberately not a hero moment; the
    # config diff below is the primary visual).
    printf '  %b$ %s%b\n' "$WT_MUTED" "perl -i.bak -pe 's/daily: [0-9.]+/daily: ${newcap}/' \\" "$WR"
    printf '    %bagents/document-summary/agent.talon.yaml%b\n' "$WT_MUTED" "$WR"
    ( policy_edit "$newcap" ) &
    w_run "Applying the edit · periodic safe reload" "$!"
  else
    policy_edit "$newcap"
  fi
  local final_spend health
  IFS=$'\t' read -r final_spend health < "$WORK/.policy" 2>/dev/null || true
  [[ "$health" == "blocked" ]] || die "document-summary did not reach HEALTH=blocked after lowering the daily cap (reload/eval issue)"
  if [[ "$CUT" == hero ]]; then
    echo; w_config_diff; echo
    w_cmd "talon agents"; echo
    w_agents why | w_reveal_stdin 0.2; echo
    w_annot "Ceiling → \$$(fmt "$newcap"), below today's \$$(fmt "$final_spend") spend; the safe reload blocked new work."
    w_hold 5
  else present_policy_full "$oldcap" "$newcap" "$final_spend"; fi
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

# ── 6. Session-scoped audit (drill from the fleet into one session) ───────────
# Deliberately framed as session-scoped audit — counts, providers, cost — from
# the real CLI summary; the outcome line is a demo annotation asserted from the
# signed evidence (the CLI has no native session-outcome diagnosis yet).
beat_session() {
  [[ "$CUT" == hero ]] || return 0   # the `all` cut already drills down in present_policy_full
  echo
  w_cmd "talon audit list --session ${SUPPORT_SID}"; echo
  w_session "$SUPPORT_SID" | w_reveal_stdin 0.4
  echo
  w_annot "completed through policy-valid fallback — every decision above is a signed record." green
  w_hold 4
}

# ── 7. Signed-evidence close ──────────────────────────────────────────────────
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
    grep -q "verdict=valid_fallback" <<<"$fv" || die "failover-chain verification did not confirm the support incident's chain"
  fi
  scost="$(jq -r '[.records[].execution.cost // 0]|add' "$WORK/support.json" 2>/dev/null)"
  if [[ "$CUT" == hero ]]; then
    echo; w_cmd "talon audit verify --file signed-evidence.json"; echo
    w_reveal 0.3 \
      "  $(printf '%bTotal records: %s%b'   "$WT_TEXT"  "$total" "$WR")" \
      "  $(printf '%bValid records: %s%b'   "$WT_GREEN" "$valid" "$WR")" \
      "  $(printf '%bInvalid records: 0%b'  "$WT_GREEN" "$WR")"
    if [[ -n "$fv" ]]; then
      # Low visual weight (implementation detail): real id, shortened for display,
      # executed above with the full $corr — short hold.
      echo; w_cmd "talon audit verify --failover ${corr:0:12}…"
      w_line "$(printf '%bverdict=valid_fallback%b' "$WT_GREEN" "$WR")"
      w_hold 1.5
    fi
    w_annot "Evidence verified offline — every decision signed, tamper-evident." green
    w_hold 4
    w_close
  else present_close_full "$corr" "$fv"; fi
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
  if [[ "$CUT" == hero ]]; then
    # Annotated live terminal walkthrough — a scrolling shell session. One clear at
    # the open (self-identifying the recording), terminal-comment chapter headings,
    # then each beat prints a real command → live wait → real output → a short note.
    w_open
    w_chapter 1 "Fleet";                        beat_fleet
    w_chapter 2 "Reliability + shared policy";  beat_support
    w_chapter 3 "Organization policy + cost";   beat_capability; beat_cost
    w_chapter 4 "Operations + proof";           beat_policy; beat_session; beat_close
    printf '\033]0;HERO_COMPLETE\007'   # machine marker via terminal title — off the visible frame
    w_cursor_restore
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
