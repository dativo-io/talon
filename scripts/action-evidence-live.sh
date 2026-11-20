#!/usr/bin/env bash
# Action Gateway evidence in the console over real processes (#205):
# TestE2E_ActionGateway_ArgumentRules builds talon, starts a counting refund
# service and `talon serve`, drives allow, approval (decided with a real
# approver credential) and deny for three actions through the HTTP Action
# Gateway and proves the downstream call counts. With the browser leg (this
# script) it then starts `talon ui serve` over the same installation and the
# Playwright spec tests/browser/live/action-evidence.spec.js checks, in
# Chromium, that each signed lifecycle record's Action decision block and the
# use case's Action Gateway policy say what the CLI says.
#
# Offline: no provider key. Prerequisites: go, node >= 18 with npm; a missing
# one fails with exit 2, it is never skipped. Run by the CI browser job.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
missing=()
command -v go >/dev/null 2>&1 || missing+=("go")
command -v node >/dev/null 2>&1 || missing+=("node (>= 18)")
command -v npm >/dev/null 2>&1 || missing+=("npm")
if [ "${#missing[@]}" -gt 0 ]; then
  echo "action-evidence-live: missing prerequisite(s): ${missing[*]}" >&2
  exit 2
fi

cd "$REPO_ROOT/tests/browser"
if [ ! -d node_modules/@playwright/test ]; then
  npm ci --no-audit --no-fund
fi
npx playwright install chromium

cd "$REPO_ROOT"
# TALON_E2E_BINARY (a release executable) is honoured by the e2e TestMain.
# The run must have EXECUTED the test: `go test -run` exits 0 when the
# pattern matches nothing or the test skips, so the PASS line is required.
log="$(mktemp "${TMPDIR:-/tmp}/action-evidence-live.XXXXXX")"
trap 'rm -f "$log"' EXIT
TALON_ACTION_BROWSER=1 go test -count=1 -tags=e2e -timeout 6m -v -run '^TestE2E_ActionGateway_ArgumentRules$' ./tests/e2e/ 2>&1 | tee "$log"
if ! grep -q '^--- PASS: TestE2E_ActionGateway_ArgumentRules ' "$log" || grep -q '^--- SKIP' "$log"; then
  echo "FAIL action-evidence-live: TestE2E_ActionGateway_ArgumentRules did not execute and pass" >&2
  exit 1
fi
if [ -n "${TALON_E2E_BINARY:-}" ] && ! grep -qF "e2e: binary under test is $TALON_E2E_BINARY " "$log"; then
  echo "FAIL action-evidence-live: the run did not use TALON_E2E_BINARY=$TALON_E2E_BINARY" >&2
  exit 1
fi
echo "PASS action-evidence-live: argument rules, approval through the approval API, deny, downstream counts, signed evidence"
