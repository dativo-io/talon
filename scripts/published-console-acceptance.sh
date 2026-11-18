#!/usr/bin/env bash
# Operations Console acceptance against a PUBLISHED talon executable (#533):
# the binary from a release archive, never one built here. It runs the
# console's existing acceptance suites with that binary as the system under
# test:
#
#   1. the packaged console in Chromium (pairing, session expiry, the six
#      pages, read-only boundary, evidence verification, tamper detection,
#      tenant scoping, no secret in the page) — scripts/console-browser-smoke.sh
#   2. People Analytics over real processes (#545): HR MCP backend with its
#      own counters, `talon serve --proxy-config`, `talon ui serve`; allowed
#      call dispatched, forbidden export never reaches the backend, backend
#      rejection is not a Talon denial, console = CLI = browser, signatures,
#      restart, negative auth — scripts/people-analytics-live.sh
#   3. the console read-contract and readiness e2e (CLI/API parity on a live
#      store, undecryptable agent key, runtime truth) — TestE2E_Console*
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

version_line="$("$BIN" version | head -n1)"
echo "binary under test: $BIN — $version_line"
if [ -n "$EXPECT" ] && [ "$version_line" != "Talon ${EXPECT#v}" ]; then
  echo "FAIL published-console-acceptance: expected 'Talon ${EXPECT#v}', the binary reports '$version_line'" >&2
  exit 1
fi

export TALON_BINARY="$BIN" TALON_E2E_BINARY="$BIN"
step() { echo; echo "== $1"; }

step "1/3 packaged console in a real browser"
bash scripts/console-browser-smoke.sh

step "2/3 People Analytics over real processes (#545), with the browser leg"
bash scripts/people-analytics-live.sh

step "3/3 console read contract and readiness over real processes"
go test -count=1 -tags=e2e -timeout 8m -run '^TestE2E_Console' ./tests/e2e/

echo
echo "PASS published-console-acceptance: $version_line"
