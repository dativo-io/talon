#!/usr/bin/env bash
# Live validation of examples/n8n-refund (#434): the REAL workflow, imported
# into a REAL n8n of one pinned release, against a real `talon serve` and an
# independently counting refund service. Nothing is mocked inside n8n.
#
#   N8N_BIN      path to the n8n executable of the pinned release (required)
#   TALON_BIN    talon binary (default: bin/talon, then `talon` on PATH)
#   N8N_EXPECT   expected `n8n --version` (default: the pinned release below)
#
# The installation is set up the way the README documents it: the company
# configuration of the example, `talon agents add refund-bot`, the example's
# fragment appended to the registered agent file, `talon approver add`, and
# decisions through `talon approvals`.
#
# Every scenario checks the refund service's own call counter:
#   ingress          unauthenticated / wrong caller; malformed ticket, amount,
#                    currency, request_id → refused before Talon, zero
#   allow            30.00 and 50.00 EUR → one dispatch each
#   approval         50.01, 75.00 and 500.00 EUR → zero until a separately
#                    authenticated reviewer approves; then one each
#   deny             500.01 and 900.00 EUR → the company's rule, zero
#   reviewer         the workflow's key and the admin key cannot decide
#   rejection/expiry → zero
#   answers          an altered, contradictory or malformed answer to
#                    "establish" → no claim, zero
#   identity         changed arguments under one operation → conflict, zero;
#                    replay → recorded answer, no second dispatch; two stable
#                    request_ids on one ticket → two operations
#   concurrency      four identical requests → one dispatch
#   failures         Talon unreachable before the operation exists → zero;
#                    connection lost DURING the claim → the run fails, the
#                    operation completed in Talon, a retry reports it and
#                    dispatches nothing more; the refund service drops its
#                    answer → UNKNOWN, never retried
#   proof            every refund-service call carries Talon's idempotency
#                    key; every lifecycle verifies; `talon agents show`
set -euo pipefail

PINNED_N8N="2.48.5"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLE="$REPO_ROOT/examples/n8n-refund"
N8N_BIN="${N8N_BIN:?set N8N_BIN to the n8n executable of release $PINNED_N8N}"
TALON_BIN="${TALON_BIN:-}"
if [ -z "$TALON_BIN" ]; then
  if [ -x "$REPO_ROOT/bin/talon" ]; then TALON_BIN="$REPO_ROOT/bin/talon"; else TALON_BIN="$(command -v talon)"; fi
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/n8n-refund-live.XXXXXX")"
REFUND_PORT="${REFUND_PORT:-19411}"; TALON_PORT="${TALON_PORT:-19412}"; N8N_PORT="${N8N_PORT:-19413}"; LINK_PORT="${LINK_PORT:-19414}"
TALON_URL="http://127.0.0.1:${TALON_PORT}"
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
echo "talon: $("$TALON_BIN" version | sed -n 1p)"

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

# ---- the network link between n8n and Talon -------------------------------
# n8n reaches Talon through this pass-through. Its modes stand for what a
# network path or a faulty intermediary can do to Talon's answers:
#   cut-claim         a claim reaches Talon, Talon answers, and the answer is
#                     dropped: a connection lost DURING a claim
#   tamper-id         the answer to "establish" names another operation
#   tamper-arguments  ... carries other arguments than were requested
#   tamper-status     ... is delivered with a conflict status
#   tamper-body       ... is not JSON
#   tamper-claim      the answer to a claim is delivered with a server-error
#                     status although its body says "succeeded"
cat >"$WORK/link.py" <<'PY'
import json, sys, threading, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
upstream, state, lock = sys.argv[2], {"mode": "ok", "cut": 0, "tampered": 0}, threading.Lock()
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _relay(self):
        if self.path.startswith("/__link/"):
            with lock:
                if self.path.startswith("/__link/mode/"): state["mode"] = self.path.rsplit("/", 1)[-1]
                body = ("%s %d %d" % (state["mode"], state["cut"], state["tampered"])).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        data = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0)) or None
        req = urllib.request.Request(upstream + self.path, data=data, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length", "connection", "accept-encoding"): req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=60) as r: code, headers, body = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e: code, headers, body = e.code, e.headers, e.read()
        except OSError:   # Talon is not reachable: neither is it through this link
            self.close_connection = True; self.connection.close(); return
        with lock: mode = state["mode"]
        if mode == "cut-claim" and self.command == "POST" and self.path.endswith("/attempts"):
            with lock: state["cut"] += 1   # Talon has answered; the caller never hears it
            self.close_connection = True; self.connection.close(); return
        if mode == "tamper-claim" and self.command == "POST" and self.path.endswith("/attempts"):
            with lock: state["tampered"] += 1
            code = 500
        if mode.startswith("tamper-") and mode != "tamper-claim" and self.command == "POST" and self.path == "/v1/action-operations":
            with lock: state["tampered"] += 1
            if mode == "tamper-status": code = 409
            elif mode == "tamper-body": body = b'{"operation": {"verdict": "ALLOW"'
            else:
                answer = json.loads(body)
                if mode == "tamper-id": answer["operation"]["operation_id"] += "-other"
                if mode == "tamper-arguments": answer["operation"]["review"]["amount"] = "1.00"
                body = json.dumps(answer).encode()
        self.send_response(code)
        self.send_header("Content-Type", headers.get("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    do_GET = do_POST = _relay
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/link.py" "$LINK_PORT" "$TALON_URL" & pids+=($!)
link() { curl -fsS "http://127.0.0.1:${LINK_PORT}/__link/$1"; }

# ---- Talon: the installation, set up as the README documents it -----------
export TALON_DATA_DIR="$WORK/talon-data" TALON_AGENTS_DIR="$WORK/agents" TALON_GATEWAY_CONFIG="$WORK/talon.config.yaml"
export TALON_SECRETS_KEY="0123456789abcdef0123456789abcdef" TALON_SIGNING_KEY="n8n-live-signing-key-0123456789abcdef-0123456789" TALON_ADMIN_KEY="n8n-live-admin-key-0001"
unset TALON_APPROVER_KEY
cp "$EXAMPLE/talon.config.yaml" "$WORK/talon.config.yaml"
talon() { (cd "$WORK" && "$TALON_BIN" "$@"); }
view() { talon agents show refund-bot 2>&1; }

# 1. Register the AI use case. Its Talon key is issued once, here.
registration="$(talon agents add refund-bot --tenant acme --owner support-operations --description "Support refunds requested from the n8n workflow" 2>&1)"
AGENT_KEY="$(printf '%s\n' "$registration" | grep -oE 'talon_uc_[0-9a-f]{48}' | head -n1)"
[ -n "$AGENT_KEY" ] || { echo "the registration issued no key" >&2; printf '%s\n' "$registration" | grep -v talon_uc_ >&2; exit 1; }
check "talon agents add registers refund-bot under the company policy" "$(printf '%s\n' "$registration" | grep -c 'Registered refund-bot (tenant acme)')" "1"
# 2. Add the action and the use case's own rule to the registered file.
sed -e "s#https://refunds.internal/v1/refunds#http://127.0.0.1:${REFUND_PORT}/refunds#" -e 's#expires_after: 30m#expires_after: 25s#' \
  "$EXAMPLE/use-case-action.append.yaml" >>"$TALON_AGENTS_DIR/refund-bot/agent.talon.yaml"
talon validate >/dev/null
# Registered is not connected: nothing runs yet.
check "before talon serve the use case is not active" "$(view | grep -c 'Status      Not active')" "1"
# 3. A reviewer: a separate identity with its own credential.
REVIEWER_KEY="$(talon approver add --name lead-1 --tenant acme --groups support-leads | grep -oE 'talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+' | head -n1)"
[ -n "$REVIEWER_KEY" ] || { echo "no reviewer credential" >&2; exit 1; }
start_talon() {
  (cd "$WORK" && exec "$TALON_BIN" serve --host 127.0.0.1 --port "$TALON_PORT" --gateway --gateway-config talon.config.yaml) >>"$WORK/talon.log" 2>&1 &
  talon_pid=$!; pids+=("$talon_pid")
  wait_http "${TALON_URL}/health" 30
}
start_talon
wait_http "http://127.0.0.1:${LINK_PORT}/health" 20
check "a running Talon has loaded the use case; no request has arrived" "$(view | grep -cE 'Status      Waiting for its first request|Runtime     loaded by the running Talon process')" "2"

# The reviewer works with `talon approvals` and its own credential: never
# n8n, never the workflow's key, never the admin key.
approvals() { (cd "$WORK" && TALON_APPROVER_KEY="$REVIEWER_KEY" "$TALON_BIN" approvals "$@" --url "$TALON_URL"); }
approval_of() { # approval_of <operation id> → the id of its approval that can be decided now ("" if none)
  # As a reviewer does it: the listing names what needs a decision, and
  # `show` says which exact operation an approval authorizes.
  local id
  for id in $(approvals list --json 2>/dev/null | python3 -c 'import json,sys
try: print(" ".join(a.get("approval_id", "") for a in json.load(sys.stdin).get("approvals", [])))
except Exception: pass'); do
    if approvals show "$id" --json 2>/dev/null | python3 -c 'import json,sys
def has(x, want):
    if isinstance(x, dict): return x.get("operation_id") == want or any(has(v, want) for v in x.values())
    if isinstance(x, list): return any(has(v, want) for v in x)
    return False
try: sys.exit(0 if has(json.load(sys.stdin), sys.argv[1]) else 1)
except Exception: sys.exit(1)' "$1"; then echo "$id"; return 0; fi
  done
  echo ""
}
wait_pending() { # wait_pending <operation id>
  local deadline=$(( $(date +%s) + 30 )) id=""
  while [ -z "$id" ] && [ "$(date +%s)" -lt "$deadline" ]; do id="$(approval_of "$1")"; [ -n "$id" ] || sleep 1; done
  echo "$id"
}
decide() { # decide <approval id> approve|reject <reason> → "ok" or "refused"
  if approvals "$2" "$1" --reason "$3" >/dev/null 2>&1; then echo ok; else echo refused; fi
}
operation() { # operation <operation id> <field path> → the field of Talon's record, read with the use case's key
  curl -sS "${TALON_URL}/v1/action-operations/$1" -H "Authorization: Bearer ${AGENT_KEY}" | python3 -c 'import json,sys
try:
    v = (json.load(sys.stdin).get("operation") or {})
    for k in sys.argv[1].split("."): v = (v or {}).get(k)
    print("" if v is None else v)
except Exception: print("")' "$2"
}

# ---- n8n: import the real credentials and the real workflow, publish, start
export N8N_USER_FOLDER="$WORK/n8n" N8N_PORT N8N_LISTEN_ADDRESS=127.0.0.1 N8N_ENCRYPTION_KEY="n8n-live-encryption-key"
export N8N_DIAGNOSTICS_ENABLED=false N8N_VERSION_NOTIFICATIONS_ENABLED=false N8N_PERSONALIZATION_ENABLED=false N8N_HIRING_BANNER_ENABLED=false
export GENERIC_TIMEZONE=UTC N8N_LOG_LEVEL=warn N8N_TEMPLATES_ENABLED=false
mkdir -p "$N8N_USER_FOLDER"
WEBHOOK_SECRET="n8n-live-webhook-caller-secret"
( umask 077; cat >"$WORK/credentials.json" <<JSON
[
  {"id": "talon-refund-bot-key", "name": "Talon refund-bot key", "type": "httpHeaderAuth", "data": {"name": "Authorization", "value": "Bearer ${AGENT_KEY}"}},
  {"id": "refund-webhook-caller", "name": "Refund webhook caller", "type": "httpHeaderAuth", "data": {"name": "X-Refund-Caller", "value": "${WEBHOOK_SECRET}"}}
]
JSON
)
python3 - "$EXAMPLE/refund-approval.workflow.json" "$WORK/workflow.json" "http://127.0.0.1:${LINK_PORT}" <<'PY'
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
approved_refund() { # approved_refund <ticket> <amount> <reason>: the request waits, a reviewer approves, it is refunded
  local before; before="$(refunds)"
  call "$(refund "$1" "$2")" >"$WORK/$1.out" &
  local run=$! approval
  approval="$(wait_pending "refund-$1")"
  check "$2 EUR waits for a reviewer" "$([ -n "$approval" ] && echo pending)" "pending"
  check "$2 EUR: zero dispatch before the decision" "$(refunds)" "$before"
  check "$2 EUR: the reviewer approves with talon approvals" "$(decide "$approval" approve "$3")" "ok"
  wait "$run"
  check "$2 EUR is refunded after the approval" "$(cat "$WORK/$1.out")" "200 refunded"
  check "$2 EUR: exactly one dispatch" "$(refunds)" "$((before + 1))"
}

echo; echo "== ingress: nothing reaches Talon"
st="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$WEBHOOK" -H 'Content-Type: application/json' -d "$(refund T-1 30.00)")"
check "an unauthenticated webhook caller is refused by n8n" "$st" "403"
st="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$WEBHOOK" -H 'Content-Type: application/json' -H 'X-Refund-Caller: wrong' -d "$(refund T-1 30.00)")"
check "a wrong webhook credential is refused by n8n" "$st" "403"
check "a malformed ticket id is refused before Talon" "$(call '{"ticket_id":"T-1/../x","amount":"30.00","currency":"EUR"}')" "400 invalid_request"
check "a missing ticket id is refused before Talon" "$(call '{"amount":"30.00","currency":"EUR"}')" "400 invalid_request"
check "a numeric (non-string) amount is refused before Talon" "$(call '{"ticket_id":"T-2","amount":30,"currency":"EUR"}')" "400 invalid_request"
check "a missing amount is refused before Talon" "$(call '{"ticket_id":"T-2","currency":"EUR"}')" "400 invalid_request"
check "an amount with three fractional digits is refused before Talon" "$(call '{"ticket_id":"T-2","amount":"30.001","currency":"EUR"}')" "400 invalid_request"
check "a negative amount is refused before Talon" "$(call '{"ticket_id":"T-2","amount":"-30.00","currency":"EUR"}')" "400 invalid_request"
check "a missing currency is refused before Talon" "$(call '{"ticket_id":"T-2","amount":"30.00"}')" "400 invalid_request"
check "a malformed currency is refused before Talon" "$(call '{"ticket_id":"T-2","amount":"30.00","currency":"euro"}')" "400 invalid_request"
check "a malformed request_id is refused before Talon" "$(call '{"ticket_id":"T-2","amount":"30.00","currency":"EUR","request_id":"invalid/path"}')" "400 invalid_request"
check "ingress: no refund" "$(refunds)" "0"
# A well-formed currency the action does not accept reaches Talon and is
# refused by the action's trusted schema: nothing is bound, nothing dispatched.
check "a currency outside the action's schema is refused by Talon, not refunded" "$(call '{"ticket_id":"T-3","amount":"30.00","currency":"USD"}')" "409 not_authorized"
check "schema refusal: no refund" "$(refunds)" "0"

echo; echo "== allow: at or below 50.00"
check "30.00 EUR is refunded" "$(call "$(refund T-30 30.00)")" "200 refunded"
check "30.00 EUR: exactly one dispatch" "$(refunds)" "1"
check "50.00 EUR (the boundary) is refunded without a reviewer" "$(call "$(refund T-50 50.00)")" "200 refunded"
check "50.00 EUR: exactly one dispatch" "$(refunds)" "2"
check "replaying a finished operation answers 'refunded' from Talon's record" "$(call "$(refund T-30 30.00)")" "200 refunded"
check "replay: no second dispatch" "$(refunds)" "2"

echo; echo "== an answer that is not Talon's verdict for this operation never leads to a claim"
# Talon allows each of these 40.00 refunds and records the operation as
# authorized. The answer the workflow receives is altered on the way. The
# workflow must not claim: the operation stays authorized, nothing is
# dispatched.
tampered() { # tampered <mode> <ticket> <what>
  local before; before="$(refunds)"
  link "mode/$1" >/dev/null
  check "$3: the workflow reports no authorization" "$(call "$(refund "$2" 40.00)")" "409 not_authorized"
  link mode/ok >/dev/null
  check "$3: Talon had authorized the operation, and it was never claimed" "$(operation "refund-$2" operation_status) $(operation "refund-$2" attempt_count)" "authorized 0"
  check "$3: zero dispatch" "$(refunds)" "$before"
}
tampered tamper-id T-41 "the answer names another operation"
tampered tamper-arguments T-42 "the answer carries other arguments"
tampered tamper-status T-43 "an ALLOW delivered with a conflict status"
tampered tamper-body T-44 "an answer that is not JSON"
check "the four answers were really altered on the way" "$(link state | cut -d' ' -f3)" "4"

echo; echo "== deny: above 500.00 (the company's rule)"
check "500.01 EUR is denied" "$(call "$(refund T-501 500.01)")" "403 denied"
check "500.01 EUR is denied by the company's rule, not the use case's" "$(operation refund-T-501 matched_rule_source)" "company"
check "900.00 EUR is denied" "$(call "$(refund T-900 900.00)")" "403 denied"
check "deny: zero dispatch" "$(refunds)" "2"
check "a denied refund cannot be obtained under another id for the same ticket" "$(call '{"ticket_id":"T-900","amount":"900.00","currency":"EUR","request_id":"again"}')" "403 denied"
check "deny under another id: zero dispatch" "$(refunds)" "2"

echo; echo "== approval: above 50.00, at or below 500.00"
call "$(refund T-75 75.00)" >"$WORK/t75.out" &
t75=$!
approval="$(wait_pending refund-T-75)"
check "75.00 EUR waits for a reviewer" "$([ -n "$approval" ] && echo pending)" "pending"
check "75.00 EUR: zero dispatch before the decision" "$(refunds)" "2"
shown="$(approvals show "$approval" 2>&1 || true)"
check "talon approvals show names the action and the exact amount" "$(printf '%s\n' "$shown" | grep -q 'create_refund_request' && printf '%s\n' "$shown" | grep -q '75\.00' && echo yes || echo no)" "yes"
check "changed arguments under the same operation are a conflict, not a refund" "$(call "$(refund T-75 450.00)")" "409 not_authorized"
check "the workflow's own key cannot decide (reviewer API)" "$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${TALON_URL}/v1/approvals/${approval}/decisions" -H "Authorization: Bearer ${AGENT_KEY}" -H 'Content-Type: application/json' -d '{"decision":"approve","reason":"self"}')" "401"
check "the workflow's own key cannot decide (talon approvals)" "$( (cd "$WORK" && TALON_APPROVER_KEY="$AGENT_KEY" "$TALON_BIN" approvals approve "$approval" --reason self --url "$TALON_URL" >/dev/null 2>&1) && echo decided || echo refused)" "refused"
check "the admin key cannot decide" "$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${TALON_URL}/v1/approvals/${approval}/decisions" -H "X-Talon-Admin-Key: ${TALON_ADMIN_KEY}" -H "Authorization: Bearer ${TALON_ADMIN_KEY}" -H 'Content-Type: application/json' -d '{"decision":"approve","reason":"admin"}')" "401"
check "refused decisions: still zero dispatch" "$(refunds)" "2"
check "the reviewer approves with talon approvals" "$(decide "$approval" approve "customer verified")" "ok"
wait "$t75"
check "75.00 EUR is refunded after the approval" "$(cat "$WORK/t75.out")" "200 refunded"
check "75.00 EUR: exactly one dispatch" "$(refunds)" "3"
approved_refund T-5001 50.01 "just above the use case's threshold"
approved_refund T-500 500.00 "the upper boundary"
check "approvals: five dispatches so far" "$(refunds)" "5"

echo; echo "== rejection and expiry"
call "$(refund T-76 76.00)" >"$WORK/t76.out" &
t76=$!
approval="$(wait_pending refund-T-76)"
check "the reviewer rejects with talon approvals" "$(decide "$approval" reject "duplicate")" "ok"
wait "$t76"
check "a rejected approval is not refunded" "$(cat "$WORK/t76.out")" "409 not_approved"
check "the approval lifetime is 25s here; an undecided approval expires" "$(call "$(refund T-77 77.00)")" "409 not_approved"
check "rejection and expiry: zero dispatch" "$(refunds)" "5"

echo; echo "== concurrent identical requests"
for i in 1 2 3 4; do call "$(refund T-31 31.00)" >"$WORK/c$i.out" & cpid[i]=$!; done
for i in 1 2 3 4; do wait "${cpid[$i]}"; done
check "four concurrent requests for one operation: one dispatch" "$(refunds)" "6"
# Each run answers from Talon's state: the one that claimed reports the
# refund, one that arrives after it reports the same recorded refund, one
# that raced it reports 409. None causes a second dispatch.
check "at least one of them reports the refund" "$([ "$(cat "$WORK"/c[1-4].out | grep -c '200 refunded' || true)" -ge 1 ] && echo yes)" "yes"

echo; echo "== distinct operations sharing one business ticket"
check "a second legitimate request on T-30 is an operation of its own" "$(call '{"ticket_id":"T-30","amount":"30.00","currency":"EUR","request_id":"second"}')" "200 refunded"
check "two requests on one ticket: two dispatches" "$(refunds)" "7"
check "a retry reuses the same request_id" "$(call '{"ticket_id":"T-30","amount":"30.00","currency":"EUR","request_id":"second"}')" "200 refunded"
check "same request_id: no duplicate dispatch" "$(refunds)" "7"

echo; echo "== the refund service accepts the request and loses its answer"
curl -fsS "http://127.0.0.1:${REFUND_PORT}/mode/lossy" >/dev/null
check "the workflow reports UNKNOWN" "$(call "$(refund T-32 32.00)")" "202 unknown"
check "the refund service was called once" "$(refunds)" "8"
curl -fsS "http://127.0.0.1:${REFUND_PORT}/mode/ok" >/dev/null
check "the same request again still reports UNKNOWN" "$(call "$(refund T-32 32.00)")" "202 unknown"
check "unknown: no blind retry" "$(refunds)" "8"

echo; echo "== the connection to Talon is lost during the claim"
link mode/cut-claim >/dev/null
st="$(call "$(refund T-34 34.00)" | cut -d' ' -f1)"
check "the claim reached Talon and its answer was dropped on the way back" "$(link state | cut -d' ' -f2)" "1"
check "the run fails: it reports neither a refund nor that none happened" "$([ "$st" -ge 500 ] && echo failed || echo "$st")" "failed"
check "Talon's record of the operation is authoritative" "$(operation refund-T-34 operation_status)" "succeeded"
link mode/ok >/dev/null
check "the same request again reports the recorded refund" "$(call "$(refund T-34 34.00)")" "200 refunded"

echo; echo "== a contradictory answer to the claim is not a refund"
# Talon claims and dispatches; its answer arrives with a server-error status
# although the body says "succeeded". The workflow must not report a refund
# from it. The same request again is a legitimate replay: Talon answers from
# its record (409 operation_already_succeeded) and that IS reported.
before_contradiction="$(refunds)"
link mode/tamper-claim >/dev/null
check "a 'succeeded' body under a server-error status is not reported as refunded" "$(call "$(refund T-35 35.00)")" "409 not_completed"
link mode/ok >/dev/null
check "Talon had dispatched that refund once" "$(refunds)" "$((before_contradiction + 1))"
check "the same request again is a legitimate replay and reports the recorded refund" "$(call "$(refund T-35 35.00)")" "200 refunded"
check "contradictory claim answer: no second dispatch" "$(refunds)" "$((before_contradiction + 1))"

echo; echo "== Talon unavailable before the operation exists"
before_outage="$(refunds)"
kill "$talon_pid"; wait "$talon_pid" 2>/dev/null || true
st="$(call "$(refund T-33 33.00)" | cut -d' ' -f1)"
check "with Talon stopped the run fails (no fallback path)" "$([ "$st" -ge 500 ] && echo failed || echo "$st")" "failed"
check "Talon stopped: zero dispatch" "$(refunds)" "$before_outage"
start_talon

echo; echo "== no bypass, and proof"
check "every call the refund service received carried Talon's idempotency key" "$(curl -fsS "http://127.0.0.1:${REFUND_PORT}/count" | python3 -c 'import json,sys
s = json.load(sys.stdin); keys = s["keys"]
print("yes" if len(keys) == s["calls"] and all(keys) else "no")')" "yes"
check "the workflow export names no refund service" "$(grep -c "127.0.0.1:${REFUND_PORT}\|refunds.internal" "$WORK/workflow.json" || true)" "0"
# Strict: the verifier must exit 0 AND print "Lifecycle: VALID". The absence
# of the word INVALID proves nothing (a missing or incomplete lifecycle does
# not print it either).
lifecycle() { # lifecycle <operation id> [data dir] → "valid", or what the verifier said instead
  local out
  if ! out="$(cd "$WORK" && TALON_DATA_DIR="${2:-$TALON_DATA_DIR}" "$TALON_BIN" audit verify --operation "$1" 2>&1)"; then echo "not valid (the verifier failed)"; return 0; fi
  case "$(printf '%s\n' "$out" | sed -n 's/^Lifecycle: //p')" in
    VALID) echo valid ;;
    "") echo "not valid (no lifecycle verdict)" ;;
    *) echo "not valid ($(printf '%s\n' "$out" | sed -n 's/^Lifecycle: //p'))" ;;
  esac
}
# Every operation that reached an end: allowed, approved, denied, rejected,
# unknown, and the two whose claim answer was lost or altered on the way.
for op in refund-T-30 refund-T-50 refund-T-75 refund-T-5001 refund-T-500 refund-T-501 refund-T-900 refund-T-76 refund-T-31 refund-T-32 refund-T-34 refund-T-35 refund-T-30-second; do
  check "lifecycle of $op: the verifier exits 0 and prints Lifecycle: VALID" "$(lifecycle "$op")" "valid"
done
# The approval that expired undecided was never claimed, and Talon records
# an expiry when the operation is next claimed. Its lifecycle is therefore
# open, and the verifier says so: it must not read VALID, and it shows that
# nothing was attempted.
check "the expired, never claimed operation has an open lifecycle, not a VALID one" "$(lifecycle refund-T-77)" "not valid (INCOMPLETE)"
check "the expired operation was never attempted" "$(operation refund-T-77 operation_status) $(operation refund-T-77 attempt_count)" "awaiting_approval 0"
# The assertion can fail: missing, altered and incomplete evidence do not
# pass it. Copies of the evidence store are altered, with Talon stopped.
kill "$talon_pid"; wait "$talon_pid" 2>/dev/null || true
check "an operation without evidence does not pass" "$(lifecycle refund-NONE-0 | cut -c1-9)" "not valid"
alter_evidence() { # alter_evidence <copy dir> <operation id> alter|drop → rows touched
  cp -R "$TALON_DATA_DIR" "$1"
  python3 - "$1" "$2" "$3" <<'PY'
import glob, sqlite3, sys
touched = 0
for path in glob.glob(sys.argv[1] + "/*.db"):
    db = sqlite3.connect(path)
    try:
        like = '%"' + sys.argv[2] + '"%'
        if sys.argv[3] == "alter":
            touched += db.execute("UPDATE evidence SET evidence_json = replace(evidence_json, 'create_refund_request', 'create_refund_requesX') WHERE evidence_json LIKE ?", (like,)).rowcount
        else:
            row = db.execute("SELECT rowid FROM evidence WHERE evidence_json LIKE ? ORDER BY rowid LIMIT 1", (like,)).fetchone()
            if row: touched += db.execute("DELETE FROM evidence WHERE rowid = ?", row).rowcount
        db.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        db.close()
print(touched)
PY
}
check "evidence of refund-T-30 was altered in a copy of the store" "$([ "$(alter_evidence "$WORK/evidence-altered" refund-T-30 alter)" -ge 1 ] && echo yes)" "yes"
check "altered evidence does not pass" "$(lifecycle refund-T-30 "$WORK/evidence-altered" | cut -c1-9)" "not valid"
check "the first record of refund-T-75 was removed in a copy of the store" "$(alter_evidence "$WORK/evidence-incomplete" refund-T-75 drop)" "1"
check "an incomplete lifecycle does not pass" "$(lifecycle refund-T-75 "$WORK/evidence-incomplete" | cut -c1-9)" "not valid"
check "the untouched store still passes" "$(lifecycle refund-T-30)" "valid"
start_talon
check "talon agents show names the use case's newest Action Gateway record, from this installation's evidence" "$(view | grep -c '· Action Gateway ·' | sed 's/^[1-9][0-9]*$/yes/')" "yes"
echo "--- talon agents show refund-bot"; view | sed -n 1,24p
echo "--- refund service: $(refunds) calls"

echo
if [ "$failures" -eq 0 ]; then echo "PASS n8n-refund-live on n8n $n8n_version"; else echo "FAIL n8n-refund-live: $failures failed"; exit 1; fi
