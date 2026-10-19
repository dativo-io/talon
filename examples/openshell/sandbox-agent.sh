#!/bin/sh
# Reference sandboxed agent for the Talon ↔ OpenShell composition (#457/#482).
#
# Runs INSIDE an OpenShell sandbox with nothing but POSIX sh, curl and sed. It
# holds NO Talon credential: OpenShell's supervisor authenticates the sandbox
# to Talon's middleware, and Talon's hop carries a request-bound workload
# assertion to its own Action Gateway. The agent:
#   1. asks the model (through OpenShell → Talon → provider);
#   2. reads an authorized external resource through a governed read action;
#   3. requests a consequential mutation (a refund);
#   4. receives REQUIRE_APPROVAL and waits for a human reviewer;
#   5. resumes after approval and claims the attempt — Talon executes the
#      action exactly once through the supported HTTP contract;
#   6. prints the evidence references so the operator can `talon audit show`.
#
# Environment (set by the operator or the harness, never secrets):
#   TALON_BASE       Talon's HTTP API as the sandbox dials it, e.g. http://host.openshell.internal:8080
#   PROVIDER_BASE    the provider as the sandbox dials it (OpenShell injects the credential), e.g. http://host.openshell.internal:9000
#   TALON_SESSION    session id sent on every request (joins model and action records in evidence)
#   OPERATION_ID     operation id for the consequential action (default: refund-<pid>)
#   TICKET_ID        ticket to read/refund (default T-1842)
#   APPROVAL_WAIT_S  how long to wait for the reviewer (default 120)
# Output: one KEY=VALUE line per step on stdout; exit 0 only when the whole
# scenario completed as governed (RESULT=succeeded). Denials and refusals
# exit non-zero with the Talon error code.
set -eu
: "${TALON_BASE:?TALON_BASE is required}"
: "${TALON_SESSION:=sess-sandbox-agent-$$}"
: "${OPERATION_ID:=refund-$$}"
: "${TICKET_ID:=T-1842}"
: "${APPROVAL_WAIT_S:=120}"
: "${PROVIDER_BASE:=}"

# json_field BODY KEY -> first string/number value of "KEY" (flat lookup, sed only)
json_field() { printf '%s' "$1" | sed -n 's/.*"'"$2"'":"\{0,1\}\([^",}]*\)"\{0,1\}.*/\1/p' | head -n1; }
# talon METHOD PATH [BODY] -> sets CODE and BODY
talon() {
  _m="$1"; _p="$2"; _b="${3:-}"
  if [ -n "$_b" ]; then
    _out="$(curl -sS --max-time 40 -w '\n__CODE__%{http_code}' -X "$_m" "$TALON_BASE$_p" -H 'content-type: application/json' -H "X-Talon-Session-ID: $TALON_SESSION" --data "$_b")"
  else
    _out="$(curl -sS --max-time 40 -w '\n__CODE__%{http_code}' -X "$_m" "$TALON_BASE$_p" -H 'content-type: application/json' -H "X-Talon-Session-ID: $TALON_SESSION")"
  fi
  CODE="${_out##*__CODE__}"; BODY="${_out%__CODE__*}"
}
fail() { echo "RESULT=failed STEP=$1 CODE=${CODE:-} ERROR=$(json_field "${BODY:-}" code)"; exit 1; }

# 1. Model request (optional when PROVIDER_BASE is unset).
if [ -n "$PROVIDER_BASE" ]; then
  _out="$(curl -sS --max-time 40 -w '\n__CODE__%{http_code}' -X POST "$PROVIDER_BASE/v1/chat/completions" -H 'content-type: application/json' -H "Authorization: Bearer ${OPENAI_API_KEY:-placeholder}" -H "X-Talon-Session-ID: $TALON_SESSION" \
    --data '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize ticket '"$TICKET_ID"' and propose a refund amount"}]}')"
  CODE="${_out##*__CODE__}"; BODY="${_out%__CODE__*}"
  [ "$CODE" = "200" ] || fail model
  echo "MODEL=ok"
fi

# 2. Governed read: establish, then claim (Talon dispatches once).
talon POST /v1/action-operations '{"operation_id":"'"$OPERATION_ID"'-read","action":"lookup_ticket","arguments":{"ticket_id":"'"$TICKET_ID"'"}}'
[ "$CODE" = "201" ] || [ "$CODE" = "200" ] || fail read_establish
talon POST "/v1/action-operations/$OPERATION_ID-read/attempts"
[ "$CODE" = "200" ] || fail read_claim
echo "READ=$(json_field "$BODY" status) READ_EVIDENCE=$(json_field "$BODY" id)"

# 3. Consequential mutation: REQUIRE_APPROVAL expected.
talon POST /v1/action-operations '{"operation_id":"'"$OPERATION_ID"'","action":"create_refund_request","arguments":{"ticket_id":"'"$TICKET_ID"'","amount":50.00,"currency":"EUR"}}'
case "$CODE" in
  202) ;;
  201|200) echo "APPROVAL=not_required"; ;;
  *) fail refund_establish ;;
esac
OPERATION_REF="$(json_field "$BODY" operation_ref)"
APPROVAL_ID="$(printf '%s' "$BODY" | sed -n 's/.*"approval":{"id":"\([^"]*\)".*/\1/p' | head -n1)"
echo "OPERATION_REF=$OPERATION_REF"
if [ -n "$APPROVAL_ID" ]; then
  echo "APPROVAL_ID=$APPROVAL_ID"
  # 4. Wait for the human reviewer. The sandbox can read its approval, never decide it.
  _i=0
  while :; do
    talon GET "/v1/approvals/$APPROVAL_ID"
    [ "$CODE" = "200" ] || fail approval_read
    _st="$(printf '%s' "$BODY" | sed -n 's/.*"approval":{[^}]*"status":"\([^"]*\)".*/\1/p' | head -n1)"
    case "$_st" in
      approved) echo "APPROVAL=approved"; break ;;
      rejected|expired|invalidated) echo "RESULT=refused APPROVAL=$_st"; exit 2 ;;
    esac
    _i=$((_i+2)); [ "$_i" -le "$APPROVAL_WAIT_S" ] || { echo "RESULT=timeout APPROVAL=pending"; exit 3; }
    sleep 2
  done
fi
# 5. Resume: claim the attempt. Talon revalidates and dispatches at most once.
talon POST "/v1/action-operations/$OPERATION_ID/attempts"
[ "$CODE" = "200" ] || fail claim
echo "ATTEMPT=$(json_field "$BODY" status)"
# 6. Replay is safe: the same claim again never produces a second effect.
talon POST "/v1/action-operations/$OPERATION_ID/attempts"
echo "REPLAY=$(json_field "$BODY" code)"
echo "RESULT=succeeded"
