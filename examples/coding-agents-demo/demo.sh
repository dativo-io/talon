#!/usr/bin/env bash
# Coding-agents demo (#203, epic #192): a skeptical platform lead watches an
# orchestrator fan out to two model providers through Talon and holds the
# signed evidence afterwards — offline, deterministic, one command.
#
#   docker compose up -d --build && ./demo.sh all
#
# Commands: session | pii | budget | audit | verify | all
set -euo pipefail

# Never die silently: any failing step names itself and points at the stack.
trap 'echo "ERROR: demo aborted at line $LINENO (see above). Stack state: docker compose ps · logs: docker compose logs talon" >&2' ERR

GATEWAY="${GATEWAY:-http://localhost:8080}"
TENANT_KEY="talon-gw-demo-coding-0001"
SESSION="sess-coding-demo"
OUT_DIR="./out"
mkdir -p "$OUT_DIR"
# Fail loudly, not silently, if ./out isn't host-writable (e.g. a stale
# root-owned dir from an older compose that bind-mounted it).
if ! : >"$OUT_DIR/.wtest" 2>/dev/null; then
  echo "ERROR: $OUT_DIR is not writable by $(id -un). Remove it (it may be root-owned from an older demo: sudo rm -rf $OUT_DIR) and re-run." >&2
  exit 1
fi
rm -f "$OUT_DIR/.wtest"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }

# The talon container seeds vault secrets before binding the port, so the
# gateway is briefly unreachable after `docker compose up -d` returns
# (started != ready). Gate every run on /health instead of racing it.
wait_ready() {
  for _ in $(seq 1 60); do
    if curl -sf -o /dev/null "$GATEWAY/health"; then return 0; fi
    sleep 1
  done
  echo "ERROR: gateway at $GATEWAY not ready after 60s — check: docker compose logs talon" >&2
  return 1
}

# CLI steps run inside the compose container by default; set TALON_BIN to a
# local binary for the no-Docker path (see README "Run it without Docker").
talon_exec() {
  if [ -n "${TALON_BIN:-}" ]; then "$TALON_BIN" "$@"; else docker compose exec -T talon talon "$@"; fi
}

# parent_header builds the optional -H array element(s) for a parent agent,
# as a proper argv array so a value never word-splits into a broken header.
parent_header() { # $1=parent (may be empty)
  if [ -n "$1" ]; then printf '%s\n' "-H" "X-Talon-Parent-Agent-ID: $1"; fi
}

anthropic_call() { # $1=agent $2=parent $3=prompt -> prints http code
  local parent=(); while IFS= read -r line; do parent+=("$line"); done < <(parent_header "$2")
  curl -s -o "$OUT_DIR/last-anthropic.json" -w '%{http_code}' \
    "$GATEWAY/v1/proxy/anthropic/v1/messages" \
    -H "Authorization: Bearer $TENANT_KEY" -H "content-type: application/json" \
    -H "X-Talon-Session-ID: $SESSION" -H "X-Talon-Agent-ID: $1" \
    ${parent[@]+"${parent[@]}"} -H "X-Talon-Client: claude-code" \
    -d "{\"model\":\"claude-sonnet-5\",\"max_tokens\":128,\"messages\":[{\"role\":\"user\",\"content\":\"$3\"}]}"
}

responses_call() { # $1=agent $2=parent $3=prompt
  local parent=(); while IFS= read -r line; do parent+=("$line"); done < <(parent_header "$2")
  curl -s -o "$OUT_DIR/last-responses.json" -w '%{http_code}' \
    "$GATEWAY/v1/proxy/openai/v1/responses" \
    -H "Authorization: Bearer $TENANT_KEY" -H "content-type: application/json" \
    -H "X-Talon-Session-ID: $SESSION" -H "X-Talon-Agent-ID: $1" \
    ${parent[@]+"${parent[@]}"} -H "X-Talon-Client: codex" \
    -d "{\"model\":\"gpt-5.3-codex\",\"input\":\"$3\",\"store\":false}"
}

cmd_session() {
  say "1. Cross-provider session: one session id, two wire families"
  note "generator → anthropic route (Claude wire), executor → openai route (Responses wire)"
  code=$(anthropic_call generator "" "write a summary of the plan")
  note "anthropic /v1/messages (agent=generator)            → HTTP $code"
  code=$(responses_call executor generator "execute the plan")
  note "openai /v1/responses (agent=executor ← generator)   → HTTP $code"
  note "Both carry X-Talon-Session-ID: $SESSION — Talon groups them as ONE session."
}

cmd_pii() {
  say "2. PII event: input scan warns, evidence records it, code keeps flowing"
  code=$(anthropic_call generator "" "email jane.doe@example.com about the reset")
  note "request with an email address in the prompt         → HTTP $code (pii_action: warn)"
}

cmd_budget() {
  say "3. Session budget: soft cap €0.02 — deny arrives provider-native"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    code=$(anthropic_call generator "" "keep going with step $i")
    if [ "$code" = "403" ]; then
      note "request $i → HTTP 403"
      note "deny body: $(jq -r '.error.message // .error.type // .' "$OUT_DIR/last-anthropic.json" 2>/dev/null | head -c 120)"
      note "(the same session is denied on the openai route too — spend is per session, not per provider)"
      code=$(responses_call executor generator "try the other provider")
      note "openai route, same session                        → HTTP $code"
      return 0
    fi
    note "request $i → HTTP $code"
  done
  echo "ERROR: session budget did not trip" >&2
  return 1
}

cmd_audit() {
  say "4. The session as a unit: summary, per-subagent rollup, cost"
  talon_exec audit list --session "$SESSION"
  say "4b. Same numbers, machine-readable (identical to the dashboard's sessions panel)"
  talon_exec costs --session "$SESSION" --json | tee "$OUT_DIR/session-costs.json"
}

cmd_verify() {
  say "5. Hold the evidence: signed export + verification"
  talon_exec audit export --session "$SESSION" --format signed-json > "$OUT_DIR/session-signed.json"
  note "exported $(jq '.records | length' "$OUT_DIR/session-signed.json") signed records → $OUT_DIR/session-signed.json"
  talon_exec audit verify --session "$SESSION"
  note "Every record carries an HMAC-SHA256 signature; flip one byte and verify fails."
}

cmd_all() {
  cmd_session
  cmd_pii
  cmd_budget
  cmd_audit
  cmd_verify
  say "Done"
  note "One session · two providers · per-subagent attribution · a budget deny"
  note "with structured {limit, spent, estimate} in signed evidence · zero real API keys."
  note "Dashboard: $GATEWAY/gateway/dashboard?talon_admin_key=demo-admin-key (Coding Sessions panel)"
}

wait_ready

case "${1:-all}" in
  session) cmd_session ;;
  pii)     cmd_pii ;;
  budget)  cmd_budget ;;
  audit)   cmd_audit ;;
  verify)  cmd_verify ;;
  all)     cmd_all ;;
  *) echo "usage: $0 [session|pii|budget|audit|verify|all]" >&2; exit 2 ;;
esac
