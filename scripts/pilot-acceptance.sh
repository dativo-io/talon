#!/usr/bin/env bash
# First Production Pilot acceptance against a PUBLISHED talon executable
# (#561): the binary from a release-candidate or release archive, never one
# built here, is the system under test for the customer journey.
#
#   scripts/pilot-acceptance.sh <talon-binary> [expected-version]
#
#   TALON_IMAGE                    also run the no-clone quickstart against this image
#   TALON_PREVIOUS_STABLE_BINARY   also run the in-place upgrade from that release
#   PILOT_LIVE_PROVIDER=1          also send ONE real, priced model request through
#     with OPENAI_API_KEY          the gateway (optional; reported NOT RUN otherwise)
#
# What runs, with that binary (TALON_E2E_BINARY) and no provider key:
#   - the pilot journey: company baseline policy, `talon agents add`, model
#     traffic allowed and a PII request blocked (deterministic LOCAL provider),
#     refund allow / approval by a separately authenticated reviewer / deny by
#     the company policy with an independent refund counter, signed lifecycle
#     verification, the paired Operations Console (use case listed, evidence
#     verified as the CLI does), backup, restore with the recovery hold,
#     resume, a second use case under the same policy;
#   - the action-gateway, registration, recovery and quickstart e2e suites.
# The checkout must be the release's own tag (tests and fixtures come from
# it). Needs go to compile the test harness, not Talon.
set -euo pipefail

BIN="${1:?usage: pilot-acceptance.sh <talon-binary> [expected-version]}"
EXPECT="${2:-}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "pilot-acceptance: $BIN is not an executable" >&2; exit 2; }
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

results=()
record() { results+=("$1"); echo "$1"; }
failed=0
run() { # run <label> <command...>
  local label="$1"; shift
  echo; echo "== $label"
  if "$@"; then record "PASS $label"; else record "FAIL $label"; failed=1; fi
}

echo "binary under test: $BIN"
"$BIN" version
version_line="$("$BIN" version | head -n1)"
if [ -n "$EXPECT" ] && [ "$version_line" != "Talon ${EXPECT#v}" ]; then
  echo "FAIL pilot-acceptance: expected 'Talon ${EXPECT#v}', the binary reports '$version_line'" >&2
  exit 1
fi

export TALON_E2E_BINARY="$BIN"
e2e() { go test -count=1 -tags=e2e -timeout 12m -run "$1" ./tests/e2e/; }

run "customer journey (registration, policy, model traffic, allow/approval/deny, console, evidence, backup/restore/resume, second use case)" e2e '^TestE2E_PilotJourney$'
run "exact action governance and amount limits" e2e '^TestE2E_ActionGateway'
run "use-case registration, including concurrent registrations" e2e '^TestE2E_AgentsAdd'
run "backup, restore and the recovery hold" e2e '^TestE2E_BackupRestore_SingleNode$|^TestE2E_Restore_'
run "no-key quickstart script over this binary" e2e '^TestE2E_QuickstartScript_LocalBinary$'

if [ -n "${TALON_PREVIOUS_STABLE_BINARY:-}" ]; then
  run "in-place upgrade from the previous stable release" e2e '^TestE2E_UpgradeFromPreviousStable$'
else
  record "NOT RUN in-place upgrade from the previous stable release (TALON_PREVIOUS_STABLE_BINARY is not set)"
fi

if [ -n "${TALON_IMAGE:-}" ]; then
  run "no-clone quickstart against $TALON_IMAGE" bash scripts/quickstart.sh
else
  record "NOT RUN no-clone quickstart against the published image (TALON_IMAGE is not set)"
fi

live_provider() {
  local work port
  work="$(mktemp -d "${TMPDIR:-/tmp}/pilot-live.XXXXXX")"; port=18391
  cp examples/pilot/talon.config.yaml "$work/talon.config.yaml"
  mkdir -p "$work/agents"
  (
    cd "$work"
    export TALON_DATA_DIR="$work/data" TALON_AGENTS_DIR="$work/agents" TALON_GATEWAY_CONFIG="$work/talon.config.yaml" TALON_ADMIN_KEY="pilot-live-admin"
    TALON_SECRETS_KEY="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"; export TALON_SECRETS_KEY
    key="$("$BIN" agents add live-check --tenant acme | grep -oE 'talon_uc_[0-9a-f]{48}' | head -n1)"
    [ -n "$key" ]
    printf '%s' "$OPENAI_API_KEY" | "$BIN" secrets set openai-api-key >/dev/null
    "$BIN" serve --port "$port" --gateway --gateway-config "$work/talon.config.yaml" >"$work/serve.log" 2>&1 &
    pid=$!
    trap 'kill $pid 2>/dev/null || true' EXIT
    for _ in $(seq 60); do curl -fsS -o /dev/null "http://127.0.0.1:$port/health" 2>/dev/null && break; sleep 0.5; done
    st="$(curl -sS -o "$work/body" -w '%{http_code}' -X POST "http://127.0.0.1:$port/v1/proxy/openai/v1/chat/completions" -H "Authorization: Bearer $key" -H 'Content-Type: application/json' -d '{"model":"gpt-4o-mini","max_tokens":5,"messages":[{"role":"user","content":"Reply with the single word ok."}]}')"
    [ "$st" = "200" ] && grep -q '"choices"' "$work/body"
  )
  local rc=$?
  rm -rf "$work"
  return "$rc"
}
if [ "${PILOT_LIVE_PROVIDER:-0}" = "1" ] && [ -n "${OPENAI_API_KEY:-}" ]; then
  run "one real, priced model request through the gateway (OpenAI)" live_provider
else
  record "NOT RUN real-provider model request (set PILOT_LIVE_PROVIDER=1 and OPENAI_API_KEY to run one priced request)"
fi

echo; echo "pilot-acceptance summary for $version_line:"
printf '  %s\n' "${results[@]}"
if [ "$failed" -ne 0 ]; then echo "FAIL pilot-acceptance"; exit 1; fi
echo "PASS pilot-acceptance: $version_line"
