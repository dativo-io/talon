#!/usr/bin/env bash
# Onboarding acceptance over real processes (#472): an engineer registers an
# existing application with `talon agents add`, connects it with the official
# OpenAI Node SDK to a real `talon serve --gateway`, verifies activation,
# authenticated traffic and the policy it was evaluated under with
# `talon agents show --effective` and `talon audit verify`, reads the same
# facts in the console, then connects a second, unrelated application under
# the same, unchanged company policy. The provider is a deterministic
# upstream that counts what reaches it: a permitted request arrives once, a
# request the company policy blocks and a request with an unknown key arrive
# zero times. Also: actual key replacement (old rejected, new accepted),
# emergency disable, revocation, and concurrent registrations. The secure
# startup is the guide's own: the blocks of docs/guides/
# add-talon-to-existing-app.md marked "onboarding-acceptance" are executed as
# written (keys into a 0600 file, server on 127.0.0.1 with the admin key),
# and administrative routes must refuse a request with no credential and one
# with the application's key.
#
# Offline: no provider key. Prerequisites: go, node >= 18 with npm, and the
# tools the guide's commands use (bash, openssl, curl); a missing one fails
# with exit 2, it is never skipped. TALON_ONBOARDING_SDK_DIR may
# name a directory with client.mjs and the pinned SDK already installed.
# TALON_E2E_BINARY (a release executable) is honoured by the e2e TestMain.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
missing=()
command -v go >/dev/null 2>&1 || missing+=("go")
command -v node >/dev/null 2>&1 || missing+=("node (>= 18)")
for tool in openssl curl; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "onboarding-acceptance: missing prerequisite(s): ${missing[*]}" >&2
  exit 2
fi
SDK_DIR="${TALON_ONBOARDING_SDK_DIR:-$REPO_ROOT/tests/onboarding}"
if [ ! -d "$SDK_DIR/node_modules/openai" ]; then
  command -v npm >/dev/null 2>&1 || { echo "onboarding-acceptance: missing prerequisite: npm (to install the pinned OpenAI SDK)" >&2; exit 2; }
  (cd "$SDK_DIR" && npm ci --no-audit --no-fund)
fi
SDK_VERSION="$(node -e 'console.log(require(process.argv[1]).version)' "$SDK_DIR/node_modules/openai/package.json")"
echo "onboarding-acceptance: OpenAI Node SDK $SDK_VERSION ($SDK_DIR), node $(node --version)"

cd "$REPO_ROOT"
# The run must have EXECUTED every mandatory test: `go test -run` exits 0
# when a pattern matches nothing or a test skips, so each PASS line is
# required and any SKIP fails the acceptance.
log="$(mktemp "${TMPDIR:-/tmp}/onboarding-acceptance.XXXXXX")"
trap 'rm -f "$log"' EXIT
TALON_ONBOARDING_SDK_DIR="$SDK_DIR" go test -count=1 -tags=e2e -timeout 8m -v -run '^TestE2E_Onboarding_' ./tests/e2e/ 2>&1 | tee "$log"
fail=0
for t in TestE2E_Onboarding_DocumentedSecureStartup TestE2E_Onboarding_FirstAndSecondApplication TestE2E_Onboarding_CredentialLifecycle TestE2E_Onboarding_ConcurrentProcessesOneWinner; do
  if ! grep -q "^--- PASS: $t " "$log"; then
    echo "FAIL onboarding-acceptance: $t did not execute and pass" >&2
    fail=1
  fi
done
if grep -q '^--- SKIP' "$log"; then
  echo "FAIL onboarding-acceptance: a mandatory test was skipped" >&2
  fail=1
fi
if [ -n "${TALON_E2E_BINARY:-}" ] && ! grep -qF "e2e: binary under test is $TALON_E2E_BINARY " "$log"; then
  echo "FAIL onboarding-acceptance: the run did not use TALON_E2E_BINARY=$TALON_E2E_BINARY" >&2
  fail=1
fi
[ "$fail" -eq 0 ] || exit 1
echo "PASS onboarding-acceptance: the guide's secure startup executed as written (0600 key file, loopback listener, admin routes refuse no credential and the application's key), first and second application through the OpenAI Node SDK $SDK_VERSION, verified activation and policy, upstream call counts, credential replacement and revocation, concurrent registration"
