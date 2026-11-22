#!/usr/bin/env bash
# Operations Console acceptance against a PUBLISHED talon executable (#533):
# the binary from a release archive, never one built here. It runs the
# console's existing acceptance suites with that binary as the system under
# test:
#
#   1. the packaged console in Chromium (pairing, session expiry, the six
#      pages, read-only boundary, evidence verification, tamper detection,
#      tenant scoping, no secret in the page) — scripts/console-browser-smoke.sh
#   2. People Analytics over real processes (#545, #431): HR MCP backend with
#      its own counters as the use case's MCP action source, `talon serve`
#      (governed MCP endpoint), `talon ui serve`; allowed read-only call
#      executed once, forbidden export never reaches the backend, a backend
#      rejection after dispatch is unknown (not a Talon denial), console = CLI
#      = browser, signatures,
#      restart, negative auth — scripts/people-analytics-live.sh
#   3. the console read-contract and readiness e2e (CLI/API parity on a live
#      store, undecryptable agent key, runtime truth) — TestE2E_Console*
#   4. conditional business actions (#205): typed argument rules over the
#      HTTP Action Gateway with a counting downstream service — allowed,
#      approval required and decided through the approval API with an
#      approver credential, denied; downstream call counts; `talon audit
#      verify` of each lifecycle; the records and the action policy in
#      Chromium — scripts/action-evidence-live.sh. The script fails unless
#      the test executed and passed against this binary.
#
# Usage: scripts/published-console-acceptance.sh <talon-binary> [expected-version]
# The checkout must be the release's own tag: tests and fixtures come from it.
# Needs go (to compile the test harness, not Talon), node >= 18 and npm.
set -euo pipefail

BIN="${1:?usage: published-console-acceptance.sh <talon-binary> [expected-version]}"
EXPECT="${2:-}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "published-console-acceptance: $BIN is not an executable" >&2; exit 2; }
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

version_line="$("$BIN" version | sed -n 1p)"
echo "binary under test: $BIN — $version_line"
if [ -n "$EXPECT" ] && [ "$version_line" != "Talon ${EXPECT#v}" ]; then
  echo "FAIL published-console-acceptance: expected 'Talon ${EXPECT#v}', the binary reports '$version_line'" >&2
  exit 1
fi

export TALON_BINARY="$BIN" TALON_E2E_BINARY="$BIN"
step() { echo; echo "== $1"; }

step "1/4 packaged console in a real browser"
bash scripts/console-browser-smoke.sh

step "2/4 People Analytics over real processes (#545), with the browser leg"
bash scripts/people-analytics-live.sh

step "3/4 console read contract and readiness over real processes"
go test -count=1 -tags=e2e -timeout 8m -run '^TestE2E_Console' ./tests/e2e/

step "4/4 conditional business actions over real processes (#205), with the browser leg"
bash scripts/action-evidence-live.sh

echo
echo "PASS published-console-acceptance: $version_line"
