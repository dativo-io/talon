#!/usr/bin/env bash
# Console browser smoke (#537, #539-#544): the Playwright suite in
# tests/browser drives a real Chromium through the PACKAGED console served by
# `talon ui serve` from the talon binary under test, over an installation the
# fixture (tests/browser/seed) writes through the production evidence store.
#
# It covers pairing (wrong code, startup code, replay, session expiry with
# return to the same page, logout, cross-origin), every page's operator
# journey with CLI <-> browser value parity (`talon agents --json`,
# `talon costs --json`, including a foreign-currency use case), decision vs
# dispatch vs downstream in the session timeline (allowed, denied and not
# dispatched, HR-rejected, cache hit), signature verification (valid and
# tampered), deep links and 404, and delayed-response races (record, tenant,
# timeline paging, session cursors).
#
# Shared by `make test-browser-console` and smoke section 44. Offline: no
# provider key. Prerequisites: go, node >= 18 with npm (a missing one fails
# with exit 2, it is never skipped). The first run installs the pinned
# Playwright package (npm ci from the committed lockfile) and Chromium.
#
# TALON_BINARY selects the binary (default: `talon` on PATH, as the smoke
# suite and `make test-browser-console` set it up).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BROWSER_DIR="$REPO_ROOT/tests/browser"

missing=()
command -v go >/dev/null 2>&1 || missing+=("go")
command -v node >/dev/null 2>&1 || missing+=("node (>= 18)")
command -v npm >/dev/null 2>&1 || missing+=("npm")
if [ "${#missing[@]}" -gt 0 ]; then
  echo "console-browser-smoke: missing prerequisite(s): ${missing[*]}" >&2
  echo "Install Node.js 18+ (https://nodejs.org) — it is a test-time tool only; the talon binary needs no Node." >&2
  exit 2
fi
if ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 18 ? 0 : 1)'; then
  echo "console-browser-smoke: node $(node --version) is too old; Playwright needs node >= 18" >&2
  exit 2
fi

TALON_BINARY="${TALON_BINARY:-$(command -v talon || true)}"
if [ -z "$TALON_BINARY" ] || [ ! -x "$TALON_BINARY" ]; then
  echo "console-browser-smoke: no talon binary (run 'make build' and put bin/ on PATH, or set TALON_BINARY)" >&2
  exit 2
fi
export TALON_BINARY
echo "console-browser-smoke: testing $TALON_BINARY ($("$TALON_BINARY" version 2>/dev/null | sed -n '1p'))"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/console-browser-smoke.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
(cd "$REPO_ROOT" && go build -o "$WORK/talon-browser-seed" ./tests/browser/seed)
export TALON_SEED_BINARY="$WORK/talon-browser-seed"

cd "$BROWSER_DIR"
if [ ! -d node_modules/@playwright/test ]; then
  npm ci --no-audit --no-fund
fi
# Installs Chromium into the Playwright cache when absent (no-op otherwise).
npx playwright install chromium

# CONSOLE_BROWSER_REPORTER lets the smoke section add Playwright's json
# reporter (PLAYWRIGHT_JSON_OUTPUT_NAME) to count each browser test.
npx playwright test --reporter="${CONSOLE_BROWSER_REPORTER:-list}" "$@"
