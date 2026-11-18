#!/usr/bin/env bash
# Live validation of examples/n8n-refund (#434): the REAL workflow, imported
# into a REAL n8n of one pinned release, against a real `talon serve` and an
# independently counting refund service. Nothing is mocked inside n8n.
#
#   N8N_BIN      path to the n8n executable of the pinned release (required)
#   TALON_BIN    talon binary (default: bin/talon, then `talon` on PATH)
#   N8N_EXPECT   expected `n8n --version` (default: the pinned release below)
#
# Scenarios (each checks the refund service's own call counter):
#   30.00 EUR                         → one dispatch
#   75.00 EUR                         → zero until a separately authenticated
#                                       reviewer approves; then one
#   900.00 EUR                        → zero
#   rejected / expired approval       → zero
#   changed amount, same ticket       → conflict, zero
#   replay of a finished ticket       → "refunded" from Talon's record, no second dispatch
#   concurrent identical requests     → one dispatch
#   Talon stopped before dispatch     → the run fails, zero
#   refund service drops the answer   → UNKNOWN, no retry
#   unauthenticated webhook caller    → refused by n8n, zero
#   malformed request                 → refused before Talon, zero
set -euo pipefail

PINNED_N8N="2.48.5"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N8N_BIN="${N8N_BIN:?set N8N_BIN to the n8n executable of release $PINNED_N8N}"
TALON_BIN="${TALON_BIN:-}"
if [ -z "$TALON_BIN" ]; then
  if [ -x "$REPO_ROOT/bin/talon" ]; then TALON_BIN="$REPO_ROOT/bin/talon"; else TALON_BIN="$(command -v talon)"; fi
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/n8n-refund-live.XXXXXX")"
REFUND_PORT="${REFUND_PORT:-19411}"; TALON_PORT="${TALON_PORT:-19412}"; N8N_PORT="${N8N_PORT:-19413}"
WEBHOOK="http://127.0.0.1:${N8N_PORT}/webhook/talon-refund"
pids=()
failures=0

cleanup() {
  code=$?
  for p in "${pids[@]:-}"; do
    if [ -n "$p" ]; then kill "$p" 2>/dev/null || true; fi
  done
  wait 2>/dev/null || true
  if [ "$code" -ne 0 ] || [ "$failures" -ne 0 ]; then
    echo "--- n8n log (tail)"; tail -n 40 "$WORK/n8n.log" 2>/dev/null || true
    echo "--- talon log (tail)"; tail -n 15 "$WORK/talon.log" 2>/dev/null || true
    echo "(kept: $WORK)"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

check() { # check <description> <got> <want>
  if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1 (got '$2', want '$3')"; failures=$((failures + 1)); fi
}
wait_http() { # wait_http <url> <seconds>
  local deadline=$(( $(date +%s) + $2 ))
  until curl -fsS -o /dev/null "$1" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || { echo "timeout waiting for $1" >&2; return 1; }
    sleep 1
  done
}

n8n_version="$("$N8N_BIN" --version 2>/dev/null | tail -n1)"
check "n8n is the pinned release" "$n8n_version" "${N8N_EXPECT:-$PINNED_N8N}"
echo "talon: $("$TALON_BIN" version | head -n1)"

# ---- the independently counting refund service ---------------------------
cat >"$WORK/refund_service.py" <<'PY'
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
state = {"calls": 0, "mode": "ok", "keys": [], "bodies": []}
lock = threading.Lock()
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == "/count":
            with lock: self._json(200, state)
        elif self.path.startswith("/mode/"):
            with lock: state["mode"] = self.path.split("/")[-1]
            self._json(200, {"mode": state["mode"]})
        else: self._json(200, {"ok": True})
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        with lock:
            state["calls"] += 1; state["keys"].append(self.headers.get("Idempotency-Key")); state["bodies"].append(body)
            mode = state["mode"]
        if mode == "lossy":   # the refund is "booked", the answer never arrives
            self.connection.close(); return
        self._json(201, {"refund_id": "rf_%d" % state["calls"]})
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/refund_service.py" "$REFUND_PORT" & pids+=($!)
wait_http "http://127.0.0.1:${REFUND_PORT}/health" 20
refunds() { curl -fsS "http://127.0.0.1:${REFUND_PORT}/count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calls"])'; }

# ---- Talon: the example use case, a reviewer, short approval lifetime -----
export TALON_DATA_DIR="$WORK/talon-data" TALON_AGENTS_DIR="$WORK/agents" TALON_GATEWAY_CONFIG="$WORK/absent.yaml"
export TALON_SECRETS_KEY="0123456789abcdef0123456789abcdef" TALON_SIGNING_KEY="n8n-live-signing-key-0123456789abcdef-0123456789" TALON_ADMIN_KEY="n8n-live-admin-key-0001"
mkdir -p "$TALON_DATA_DIR" "$TALON_AGENTS_DIR/refund-bot"
sed -e "s#https://refunds.internal/v1/refunds#http://127.0.0.1:${REFUND_PORT}/refunds#" -e 's#expires_after: 30m#expires_after: 25s#' \
  "$REPO_ROOT/examples/n8n-refund/agent.talon.yaml" >"$TALON_AGENTS_DIR/refund-bot/agent.talon.yaml"
AGENT_KEY="n8n-live-refund-bot-key-000000000001"
talon() { (cd "$WORK" && "$TALON_BIN" "$@"); }
talon secrets set refund-bot-talon-key "$AGENT_KEY" >/dev/null
talon validate >/dev/null
REVIEWER_KEY="$(talon approver add --name lead-1 --tenant acme --groups support-leads | grep -oE 'talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+' | head -n1)"
[ -n "$REVIEWER_KEY" ] || { echo "no reviewer credential" >&2; exit 1; }
start_talon() {
  (cd "$WORK" && exec "$TALON_BIN" serve --port "$TALON_PORT") >>"$WORK/talon.log" 2>&1 &
  talon_pid=$!; pids+=("$talon_pid")
  wait_http "http://127.0.0.1:${TALON_PORT}/health" 30
}
start_talon
# The reviewer is a separate identity: its own credential, Talon's reviewer
# API, never n8n and never the workflow's key.
approval_of() { # approval_of <ticket> → the pending approval id of refund-<ticket> ("" if none)
  curl -sS "http://127.0.0.1:${TALON_PORT}/v1/action-operations/refund-$1" -H "Authorization: Bearer ${AGENT_KEY}" |
    python3 -c 'import json,sys
try:
    a = (json.load(sys.stdin).get("operation") or {}).get("approval") or {}
    print(a.get("id", "") if a.get("status") == "pending" else "")
except Exception:
    print("")'
}
wait_pending() { # wait_pending <ticket>
  local deadline=$(( $(date +%s) + 30 )) id=""
  while [ -z "$id" ] && [ "$(date +%s)" -lt "$deadline" ]; do id="$(approval_of "$1")"; [ -n "$id" ] || sleep 1; done
  echo "$id"
}
decide() { # decide <approval id> approve|reject <reason>
  curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${TALON_PORT}/v1/approvals/$1/decisions" \
    -H "Authorization: Bearer ${REVIEWER_KEY}" -H 'Content-Type: application/json' -d "{\"decision\":\"$2\",\"reason\":\"$3\"}"
}

# ---- n8n: import the real credentials and the real workflow, publish, start
export N8N_USER_FOLDER="$WORK/n8n" N8N_PORT N8N_LISTEN_ADDRESS=127.0.0.1 N8N_ENCRYPTION_KEY="n8n-live-encryption-key"
export N8N_DIAGNOSTICS_ENABLED=false N8N_VERSION_NOTIFICATIONS_ENABLED=false N8N_PERSONALIZATION_ENABLED=false N8N_HIRING_BANNER_ENABLED=false
export GENERIC_TIMEZONE=UTC N8N_LOG_LEVEL=warn N8N_TEMPLATES_ENABLED=false
mkdir -p "$N8N_USER_FOLDER"
WEBHOOK_SECRET="n8n-live-webhook-caller-secret"
cat >"$WORK/credentials.json" <<JSON
[
  {"id": "talon-refund-bot-key", "name": "Talon refund-bot key", "type": "httpHeaderAuth", "data": {"name": "Authorization", "value": "Bearer ${AGENT_KEY}"}},
  {"id": "refund-webhook-caller", "name": "Refund webhook caller", "type": "httpHeaderAuth", "data": {"name": "X-Refund-Caller", "value": "${WEBHOOK_SECRET}"}}
]
JSON
python3 - "$REPO_ROOT/examples/n8n-refund/refund-approval.workflow.json" "$WORK/workflow.json" "http://127.0.0.1:${TALON_PORT}" <<'PY'
import json, sys
wf = json.load(open(sys.argv[1]))
wf["id"] = "talonrefundlive01"
for n in wf["nodes"]:
    if n["name"] == "Config":   # the one documented post-import edit: the Talon URL
        n["parameters"]["assignments"]["assignments"][0]["value"] = sys.argv[3]
json.dump([wf], open(sys.argv[2], "w"))
PY
"$N8N_BIN" import:credentials --input="$WORK/credentials.json" >"$WORK/n8n-import.log" 2>&1
"$N8N_BIN" import:workflow --input="$WORK/workflow.json" >>"$WORK/n8n-import.log" 2>&1
"$N8N_BIN" publish:workflow --id=talonrefundlive01 >>"$WORK/n8n-import.log" 2>&1
check "the workflow imports and publishes on n8n $n8n_version" "$(grep -ciE 'error|fail' "$WORK/n8n-import.log" || true)" "0"
"$N8N_BIN" start >"$WORK/n8n.log" 2>&1 & pids+=($!)
wait_http "http://127.0.0.1:${N8N_PORT}/healthz" 180
# The production webhook is registered a moment after n8n reports healthy.
deadline=$(( $(date +%s) + 120 ))
until [ "$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$WEBHOOK" -H 'Content-Type: application/json' -d '{}')" != "404" ]; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "the workflow's webhook was never registered" >&2; exit 1; }
  sleep 1
done

call() { # call <json body> [curl args...] → prints "<http status> <result field>"
  local body="$1"; shift
  local st
  st="$(curl -sS -o "$WORK/resp" -w '%{http_code}' --max-time 120 -X POST "$WEBHOOK" -H 'Content-Type: application/json' -H "X-Refund-Caller: ${WEBHOOK_SECRET}" "$@" -d "$body")"
  printf '%s %s' "$st" "$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("result",""))
except Exception: print("")' "$WORK/resp")"
}
refund() { printf '{"ticket_id":"%s","amount":"%s","currency":"EUR"}' "$1" "$2"; }

echo; echo "== ingress"
st="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$WEBHOOK" -H 'Content-Type: application/json' -d "$(refund T-1 30.00)")"
check "an unauthenticated webhook caller is refused by n8n" "$st" "403"
st="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$WEBHOOK" -H 'Content-Type: application/json' -H 'X-Refund-Caller: wrong' -d "$(refund T-1 30.00)")"
check "a wrong webhook credential is refused by n8n" "$st" "403"
check "a malformed ticket id is refused before Talon" "$(call '{"ticket_id":"T-1/../x","amount":"30.00","currency":"EUR"}')" "400 invalid_request"
check "a numeric (non-string) amount is refused before Talon" "$(call '{"ticket_id":"T-2","amount":30,"currency":"EUR"}')" "400 invalid_request"
check "no refund so far" "$(refunds)" "0"

echo; echo "== allow, deny"
check "30.00 EUR is refunded" "$(call "$(refund T-30 30.00)")" "200 refunded"
check "30.00 EUR: one dispatch" "$(refunds)" "1"
check "replaying the finished ticket answers 'refunded' from Talon's record" "$(call "$(refund T-30 30.00)")" "200 refunded"
check "replay: no second dispatch" "$(refunds)" "1"
check "900.00 EUR is denied" "$(call "$(refund T-900 900.00)")" "403 denied"
check "900.00 EUR: zero dispatch" "$(refunds)" "1"

echo; echo "== approval by a separately authenticated reviewer"
call "$(refund T-75 75.00)" >"$WORK/t75.out" &
t75=$!
approval="$(wait_pending T-75)"
check "75.00 EUR waits for a reviewer" "$([ -n "$approval" ] && echo pending)" "pending"
check "75.00 EUR: zero dispatch before the decision" "$(refunds)" "1"
check "changed amount under the same ticket is a conflict, not a refund" "$(call "$(refund T-75 450.00)" | cut -d' ' -f1)" "409"
check "the workflow's own key cannot approve" "$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${TALON_PORT}/v1/approvals/${approval}/decisions" -H "Authorization: Bearer ${AGENT_KEY}" -H 'Content-Type: application/json' -d '{"decision":"approve","reason":"self"}')" "401"
check "the reviewer approves" "$(decide "$approval" approve "customer verified")" "200"
wait "$t75"
check "75.00 EUR is refunded after the approval" "$(cat "$WORK/t75.out")" "200 refunded"
check "75.00 EUR: one dispatch" "$(refunds)" "2"

echo; echo "== rejection and expiry"
call "$(refund T-76 76.00)" >"$WORK/t76.out" &
t76=$!
approval="$(wait_pending T-76)"
check "the reviewer rejects" "$(decide "$approval" reject "duplicate")" "200"
wait "$t76"
check "a rejected approval is not refunded" "$(cat "$WORK/t76.out")" "409 not_approved"
check "the approval lifetime is 25s here; an undecided approval expires" "$(call "$(refund T-77 77.00)")" "409 not_approved"
check "rejection and expiry: zero dispatch" "$(refunds)" "2"

echo; echo "== concurrent identical requests"
for i in 1 2 3 4; do call "$(refund T-31 31.00)" >"$WORK/c$i.out" & cpid[i]=$!; done
for i in 1 2 3 4; do wait "${cpid[$i]}"; done
check "four concurrent requests for one ticket: one dispatch" "$(refunds)" "3"
# Each run answers from Talon's state: the one that claimed reports the
# refund, one that arrives after it reports the same recorded refund, one
# that raced it reports 409. None causes a second dispatch.
check "at least one of them reports the refund" "$([ "$(cat "$WORK"/c[1-4].out | grep -c '200 refunded' || true)" -ge 1 ] && echo yes)" "yes"

echo; echo "== ambiguous outcome"
curl -fsS "http://127.0.0.1:${REFUND_PORT}/mode/lossy" >/dev/null
check "the refund service drops its answer: the workflow reports UNKNOWN" "$(call "$(refund T-32 32.00)")" "202 unknown"
check "the refund service was called once" "$(refunds)" "4"
curl -fsS "http://127.0.0.1:${REFUND_PORT}/mode/ok" >/dev/null
check "a second request for the unknown ticket still reports UNKNOWN" "$(call "$(refund T-32 32.00)")" "202 unknown"
check "unknown: no blind retry" "$(refunds)" "4"

echo; echo "== Talon unavailable"
kill "$talon_pid"; wait "$talon_pid" 2>/dev/null || true
st="$(call "$(refund T-33 33.00)" | cut -d' ' -f1)"
check "with Talon stopped the run fails (no fallback path)" "$([ "$st" -ge 500 ] && echo failed || echo "$st")" "failed"
check "Talon stopped: zero dispatch" "$(refunds)" "4"
start_talon

echo; echo "== signed evidence"
for op in refund-T-30 refund-T-75 refund-T-900 refund-T-76 refund-T-32; do
  out="$(talon audit verify --operation "$op" 2>&1 || true)"
  check "lifecycle of $op verifies" "$(echo "$out" | grep -c 'INVALID' || true)" "0"
done

echo
if [ "$failures" -eq 0 ]; then echo "PASS n8n-refund-live on n8n $n8n_version"; else echo "FAIL n8n-refund-live: $failures failed"; exit 1; fi
