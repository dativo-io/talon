#!/usr/bin/env bash
# First Production Pilot acceptance against a PUBLISHED talon executable
# (#561): the binary from a release-candidate or release archive, never one
# built here, is the system under test for the customer journey.
#
#   scripts/pilot-acceptance.sh <talon-binary> [expected-version]
#
#   TALON_IMAGE                    the released image: run the no-clone quickstart against it
#   TALON_PREVIOUS_STABLE_BINARY   the stable release immediately preceding this one (N-1 gate):
#                                  run the in-place upgrade from it
#   TALON_COMPAT_BINARIES          older released binaries (path list): historical upgrade compatibility
#   N8N_BIN                        the pinned n8n: run the real n8n refund workflow against this binary
#   PILOT_REQUIRE_ALL=1            release mode: a missing input above, or missing node/npm for the
#                                  application-client check, is a FAILURE, never a silent skip
#   PILOT_LIVE_PROVIDER=1          also send ONE real, priced model request through
#     with OPENAI_API_KEY          the gateway (always optional; reported NOT RUN otherwise)
#
# What runs, with that binary (TALON_E2E_BINARY) and no provider key:
#   - the pilot journey: company baseline policy, `talon agents add`, model
#     traffic allowed and a PII request blocked (deterministic LOCAL provider),
#     the same two requests through a real application client (the official
#     OpenAI Node SDK, pinned),
#     refund allow / approval by a separately authenticated reviewer / deny by
#     the company policy with an independent refund counter, signed lifecycle
#     verification, the paired Operations Console (use case listed, evidence
#     verified as the CLI does), backup, restore with the recovery hold,
#     resume, a second use case under the same policy;
#   - the action-gateway, registration, recovery and quickstart e2e suites;
#   - with TALON_PREVIOUS_STABLE_BINARY: the in-place upgrade from it and the
#     rollback safety check (that release on a restored, held store
#     dispatches nothing).
# Results are PASS, FAIL, NOT RUN or NOT APPLICABLE. A required test that
# skips is a FAILURE, never a pass.
# The checkout must be the release's own tag (tests and fixtures come from
# it). Needs go to compile the test harness, not Talon.
set -euo pipefail

BIN="${1:?usage: pilot-acceptance.sh <talon-binary> [expected-version]}"
EXPECT="${2:-}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "pilot-acceptance: $BIN is not an executable" >&2; exit 2; }
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OPENAI_SDK_VERSION="7.59.0"
results=()
record() { results+=("$1"); echo "$1"; }
failed=0
# missing <what>: an input this run does not have. NOT RUN, or a failure in
# release mode — required acceptance is never silently skipped.
missing() {
  if [ "${PILOT_REQUIRE_ALL:-0}" = "1" ]; then record "FAIL $1 — required in release mode (PILOT_REQUIRE_ALL=1)"; failed=1; else record "NOT RUN $1"; fi
}
run() { # run <label> <command...>
  local label="$1"; shift
  echo; echo "== $label"
  if "$@"; then record "PASS $label"; else record "FAIL $label"; failed=1; fi
}

echo "binary under test: $BIN"
"$BIN" version
version_line="$("$BIN" version | sed -n 1p)"
if [ -n "$EXPECT" ] && [ "$version_line" != "Talon ${EXPECT#v}" ]; then
  echo "FAIL pilot-acceptance: expected 'Talon ${EXPECT#v}', the binary reports '$version_line'" >&2
  exit 1
fi
# The tests and fixtures come from this checkout: it must be the commit the
# binary was built from.
commit_line="$("$BIN" version | sed -n 's/^Commit: *//p')"
head_commit="$(git rev-parse HEAD 2>/dev/null || true)"
if [ -n "$EXPECT" ]; then
  case "$head_commit" in
    "$commit_line"*) [ -n "$commit_line" ] || { echo "FAIL pilot-acceptance: the binary reports no commit" >&2; exit 1; } ;;
    *) echo "FAIL pilot-acceptance: the binary was built from '$commit_line', this checkout is '$head_commit'" >&2; exit 1 ;;
  esac
  record "PASS binary under test: $version_line, commit $commit_line, sha256 $(sha256sum "$BIN" | cut -d' ' -f1)"
fi

export TALON_E2E_BINARY="$BIN"
# e2e <regex>: the tests must RUN and pass; a skipped one is a failure.
e2e() {
  local log; log="$(mktemp "${TMPDIR:-/tmp}/pilot-e2e.XXXXXX")"
  go test -count=1 -tags=e2e -timeout 12m -v -run "$1" ./tests/e2e/ >"$log" 2>&1 || { grep -E '^(--- |FAIL|ok )' "$log" | tail -n 30; tail -n 40 "$log"; return 1; }
  grep -E '^--- (PASS|SKIP)' "$log"
  if grep -q '^--- SKIP' "$log"; then echo "a required test was skipped"; return 1; fi
  grep -q '^--- PASS' "$log" || { echo "no test ran"; return 1; }
}

# A real application client for the journey: the official OpenAI Node SDK.
sdk_dir=""
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  sdk_dir="$(mktemp -d "${TMPDIR:-/tmp}/pilot-sdk.XXXXXX")"
  if (cd "$sdk_dir" && npm install --no-audit --no-fund --loglevel=error "openai@${OPENAI_SDK_VERSION}" >/dev/null); then
    export TALON_PILOT_SDK_DIR="$sdk_dir"
  else
    sdk_dir=""
  fi
fi
journey() {
  local log; log="$(mktemp "${TMPDIR:-/tmp}/pilot-journey.XXXXXX")"
  go test -count=1 -tags=e2e -timeout 12m -v -run '^TestE2E_PilotJourney$' ./tests/e2e/ >"$log" 2>&1 || { tail -n 60 "$log"; return 1; }
  grep -E '^(--- |ok )|client check|PASS (permitted|request with PII)' "$log" || true
  if [ -n "$sdk_dir" ]; then
    for uc in refund-bot hr-copilot; do
      grep -q "OpenAI Node SDK client check (${uc})" "$log" || { echo "the SDK client check did not run for ${uc}"; return 1; }
    done
    record "PASS application client: OpenAI Node SDK ${OPENAI_SDK_VERSION} through Talon for both use cases (permitted request answered once, PII request refused with pii_policy_violation)"
  fi
}

run "customer journey (registration, company policy, SDK traffic, allow/approval/deny with counted dispatch, reviewer boundaries, console, evidence, restart, cold backup, restore with the hold, resume, second use case, key replacement)" journey
[ -n "$sdk_dir" ] || missing "application client check with the OpenAI Node SDK (node and npm are needed)"
run "exact action governance and argument rules" e2e '^TestE2E_ActionGateway'
# #567's onboarding acceptance with the same binary (TALON_E2E_BINARY): the
# documented secure startup, two applications through the pinned SDK, key
# replacement, disable, revocation, concurrent registrations. It fails,
# never skips, when a prerequisite is missing.
run "use-case registration and onboarding (register, connect, verify; key replacement; concurrent registrations)" bash scripts/onboarding-acceptance.sh
run "backup, restore and the recovery hold" e2e '^TestE2E_BackupRestore_SingleNode$|^TestE2E_Restore_'
run "no-key quickstart script over this binary" e2e '^TestE2E_QuickstartScript_LocalBinary$'

if [ -n "${TALON_PREVIOUS_STABLE_BINARY:-}" ]; then
  prev_line="$("$TALON_PREVIOUS_STABLE_BINARY" version | sed -n 1p)"
  run "in-place upgrade from the immediately preceding stable release ($prev_line)" e2e '^TestE2E_UpgradeFromPreviousStable$'
  run "rollback safety: $prev_line on a restored, held store dispatches nothing" e2e '^TestE2E_RollbackOnARestoredStore_ThePreviousStableDispatchesNothing$'
else
  missing "in-place upgrade from the immediately preceding stable release (TALON_PREVIOUS_STABLE_BINARY is not set)"
  missing "rollback safety with the preceding stable release (TALON_PREVIOUS_STABLE_BINARY is not set)"
fi
if [ -n "${TALON_COMPAT_BINARIES:-}" ]; then
  run "historical upgrade compatibility (not the N-1 gate)" go test -count=1 -tags=e2e -timeout 12m -run '^TestE2E_UpgradeFromHistoricalReleases$' ./tests/e2e/
else
  record "NOT RUN historical upgrade compatibility (TALON_COMPAT_BINARIES is not set; optional)"
fi

if [ -n "${TALON_IMAGE:-}" ]; then
  run "no-clone quickstart against $TALON_IMAGE" bash scripts/quickstart.sh
else
  missing "no-clone quickstart against the published image (TALON_IMAGE is not set)"
fi

pinned_n8n="$(sed -n 's/^PINNED_N8N="\(.*\)"$/\1/p' scripts/n8n-refund-live.sh)"
if [ -n "${N8N_BIN:-}" ]; then
  n8n_version="$("$N8N_BIN" --version 2>/dev/null | tail -n1)"
  if [ "$n8n_version" != "$pinned_n8n" ] && [ "${PILOT_REQUIRE_ALL:-0}" = "1" ]; then
    record "FAIL real n8n refund workflow: n8n $n8n_version is not the pinned $pinned_n8n"; failed=1
  else
    run "real n8n refund workflow against this binary (n8n $n8n_version)" env TALON_BIN="$BIN" bash scripts/n8n-refund-live.sh
  fi
else
  missing "real n8n refund workflow against this binary (N8N_BIN is not set)"
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
