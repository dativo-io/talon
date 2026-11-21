#!/usr/bin/env bash
# Governed MCP adoption walkthrough (#431), credential-free and local.
#
# A synthetic CRM runs as a real MCP server (crm-mcp-server/, it counts every
# call it executes); Talon serves the governed POST /mcp for the AI use case
# in agent.talon.yaml; a STANDARD MCP client (mcp-client/, the official Go
# SDK client, unmodified) discovers the tools, makes a read-only call,
# prepares a consequential action, has it approved by a separate reviewer,
# executes it, and every operation's signed lifecycle is verified. Each
# "zero" and "exactly one" below is the CRM's own counter.
#
#   ./examples/mcp-governed/run.sh            # from the repository root
#   TALON_BIN=/path/to/talon ./examples/mcp-governed/run.sh
#   KEEP=1 ...                                # keep the work directory
#
# Needs: go, curl, jq, openssl. Binds 127.0.0.1 only; no network, no
# provider key, no paid call. Every key is random and lives in a temp dir.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/talon-mcp-governed.XXXXXX")"
PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do
    if [[ -n "$p" ]]; then kill "$p" 2>/dev/null || true; fi
  done
  if [[ "${KEEP:-0}" == "1" ]]; then echo "work directory kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; echo "--- talon log" >&2; tail -40 "$WORK/talon.log" >&2 || true; exit 1; }
step() { STEPS=$((STEPS + 1)); echo; echo "== step $STEPS: $*"; }
STEPS=0
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_http() { for _ in $(seq 1 100); do curl -fsS --max-time 1 "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; fail "$1 did not answer"; }
calls() { curl -fsS "http://$CRM_ADDR/calls" | jq -r --arg t "$1" '.[$t]'; }
expect_calls() { local n; n="$(calls "$1")"; [[ "$n" == "$2" ]] || fail "$1: the CRM executed $n call(s), expected $2"; echo "   CRM counter $1 = $n (expected $2)"; }
field() { sed -n "s/^$1=//p" <<<"$2" | head -1; }
indent() { sed 's/^/   /'; }

echo "== build"
mkdir -p "$WORK/bin"
if [[ -n "${TALON_BIN:-}" ]]; then cp "$TALON_BIN" "$WORK/bin/talon"; else (cd "$REPO" && go build -o "$WORK/bin/talon" ./cmd/talon); fi
(cd "$REPO" && go build -o "$WORK/bin/crm-mcp-server" ./examples/mcp-governed/crm-mcp-server && go build -o "$WORK/bin/mcp-client" ./examples/mcp-governed/mcp-client)
TALON="$WORK/bin/talon"
CLIENT="$WORK/bin/mcp-client"

export TALON_DATA_DIR="$WORK/data" TALON_SECRETS_KEY TALON_SIGNING_KEY TALON_ADMIN_KEY
TALON_SECRETS_KEY="$(openssl rand -hex 32)"
TALON_SIGNING_KEY="$(openssl rand -hex 32)"
TALON_ADMIN_KEY="$(openssl rand -hex 24)"
unset TALON_GATEWAY_CONFIG TALON_AGENTS_DIR TALON_APPROVER_KEY
USE_CASE_KEY="$(openssl rand -hex 24)"
CRM_TOKEN="$(openssl rand -hex 24)"
CRM_ADDR="127.0.0.1:$(free_port)"
TALON_PORT="$(free_port)"

step "the business system: the synthetic CRM MCP server (its own token, its own counters)"
CRM_MCP_ADDR="$CRM_ADDR" CRM_MCP_TOKEN="$CRM_TOKEN" "$WORK/bin/crm-mcp-server" >"$WORK/crm.log" 2>&1 &
PIDS+=("$!")
wait_http "http://$CRM_ADDR/health"
echo "   http://$CRM_ADDR/mcp — answers only the bearer token Talon holds"

step "declare the AI use case: the CRM as its trusted MCP action source, four tools as actions"
mkdir -p "$WORK/install"
cd "$WORK/install"
"$TALON" init --scaffold --name support-assistant >/dev/null
sed "s|http://127.0.0.1:9180/mcp|http://$CRM_ADDR/mcp|" "$HERE/agent.talon.yaml" >agent.talon.yaml
"$TALON" validate

step "keys: the use case's key and the CRM token, in Talon's vault (never in a file)"
"$TALON" secrets set support-assistant-talon-key "$USE_CASE_KEY" >/dev/null
"$TALON" secrets set crm-mcp-token "$CRM_TOKEN" --tenant default --agent support-assistant >/dev/null
echo "   use case key and CRM token stored"

step "a separate reviewer: an approver principal in the group the refund rule names"
APPROVER_OUT="$("$TALON" approver add --name lead-1 --tenant default --groups support-leads)"
APPROVER_KEY="$(grep -oE 'talon_appr_cred_[0-9a-f]+\.[A-Za-z0-9_-]+' <<<"$APPROVER_OUT" | head -1)"
[[ -n "$APPROVER_KEY" ]] || fail "no approver credential printed"
echo "   reviewer credential issued (shown once)"

step "start Talon: talon serve, governed POST /mcp on 127.0.0.1:$TALON_PORT"
"$TALON" serve --host 127.0.0.1 --port "$TALON_PORT" >"$WORK/talon.log" 2>&1 &
PIDS+=("$!")
wait_http "http://127.0.0.1:$TALON_PORT/health"
export TALON_MCP_URL="http://127.0.0.1:$TALON_PORT/mcp" TALON_USE_CASE_KEY="$USE_CASE_KEY"

step "the client discovers the governed tools (standard SDK client, use case key)"
LIST="$("$CLIENT" list)"
indent <<<"$LIST"
grep -q '^TOOL=talon_execute_operation' <<<"$LIST" || fail "talon_execute_operation not listed"
if grep -q '^TOOL=delete_customer' <<<"$LIST"; then fail "the forbidden tool is listed"; fi

step "read-only: lookup_ticket executes in one call"
OUT="$("$CLIENT" call lookup_ticket '{"ticket_id":"T-100"}')"
indent <<<"$OUT"
[[ "$(field TALON_code "$OUT")" == "allowed" ]] || fail "lookup_ticket was not allowed"
OPS=("$(field TALON_operationId "$OUT")")
expect_calls ticket.lookup 1

step "consequential: issue_voucher is PREPARED — an operation id, nothing sent"
OUT="$("$CLIENT" call issue_voucher '{"ticket_id":"T-100","amount":20}')"
indent <<<"$OUT"
VOUCHER_OP="$(field TALON_operationId "$OUT")"
[[ "$(field TALON_code "$OUT")" == "operation_prepared" && -n "$VOUCHER_OP" ]] || fail "issue_voucher was not prepared"
expect_calls voucher.issue 0

step "execute the prepared operation by its Talon-generated id: exactly once"
OUT="$("$CLIENT" execute "$VOUCHER_OP")"
indent <<<"$OUT"
expect_calls voucher.issue 1
OUT="$("$CLIENT" execute "$VOUCHER_OP" || true)"
[[ "$(field TALON_code "$OUT")" == "operation_already_succeeded" ]] || fail "a repeated execute was not refused"
expect_calls voucher.issue 1
OPS+=("$VOUCHER_OP")

step "approval: create_refund over 50.00 EUR needs a reviewer"
OUT="$("$CLIENT" call create_refund '{"ticket_id":"T-100","amount":120}')"
indent <<<"$OUT"
REFUND_OP="$(field TALON_operationId "$OUT")"
APPROVAL_ID="$(field TALON_approvalId "$OUT")"
[[ "$(field TALON_code "$OUT")" == "approval_pending" && -n "$APPROVAL_ID" ]] || fail "create_refund did not wait for approval"
OUT="$("$CLIENT" execute "$REFUND_OP" || true)"
[[ "$(field TALON_code "$OUT")" == "approval_pending" ]] || fail "execute before approval was not refused"
expect_calls refund.create 0

step "the reviewer approves (talon approvals, the reviewer's own credential) — the decision sends nothing"
TALON_APPROVER_KEY="$APPROVER_KEY" "$TALON" approvals approve "$APPROVAL_ID" --reason "verified with the customer" --url "http://127.0.0.1:$TALON_PORT" | indent
expect_calls refund.create 0

step "the client resumes the SAME operation: exactly once"
OUT="$("$CLIENT" execute "$REFUND_OP")"
indent <<<"$OUT"
expect_calls refund.create 1
OPS+=("$REFUND_OP")

step "deny: the hidden delete_customer, called by name, is refused with zero calls"
OUT="$("$CLIENT" call delete_customer '{"customer_id":"c-42"}' || true)"
indent <<<"$OUT"
[[ "$(field TALON_code "$OUT")" == "policy_denied" ]] || fail "delete_customer was not denied"
expect_calls customer.delete 0
OPS+=("$(field TALON_operationId "$OUT")")

step "verify every operation's signed lifecycle (offline, from the evidence store)"
for op in "${OPS[@]}"; do
  V="$("$TALON" audit verify --operation "$op")" || fail "audit verify $op"
  grep -q 'Lifecycle: VALID' <<<"$V" || fail "lifecycle of $op is not VALID"
  echo "   $op: Lifecycle: VALID"
done

echo
echo "PASS governed MCP walkthrough: $STEPS steps; CRM executed $(curl -fsS "http://$CRM_ADDR/calls")"
