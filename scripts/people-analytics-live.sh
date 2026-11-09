#!/usr/bin/env bash
# People Analytics over real processes (#545): TestE2E_PeopleAnalytics_CrossProcess
# builds talon, starts an HR MCP backend with its own call counters, the
# production `talon serve --proxy-config` and `talon ui serve`, drives an
# allowed, a forbidden and a backend-rejected tool call in one session, and
# proves the boundary by the backend's counters, then the console = CLI,
# signatures, SIGKILL/restart, tamper detection and negative auth. With the
# browser leg (this script) the Playwright spec tests/browser/live checks the
# same installation in Chromium while the data plane runs.
#
# Offline: no provider key and no LLM call. Prerequisites: go, node >= 18
# with npm; a missing one fails with exit 2, it is never skipped. Shared by
# `make test-people-analytics-live` and the CI browser job.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
missing=()
command -v go >/dev/null 2>&1 || missing+=("go")
command -v node >/dev/null 2>&1 || missing+=("node (>= 18)")
command -v npm >/dev/null 2>&1 || missing+=("npm")
if [ "${#missing[@]}" -gt 0 ]; then
  echo "people-analytics-live: missing prerequisite(s): ${missing[*]}" >&2
  exit 2
fi

cd "$REPO_ROOT/tests/browser"
if [ ! -d node_modules/@playwright/test ]; then
  npm ci --no-audit --no-fund
fi
npx playwright install chromium

cd "$REPO_ROOT"
TALON_PA_BROWSER=1 go test -count=1 -tags=e2e -timeout 5m -v -run '^TestE2E_PeopleAnalytics_CrossProcess$' ./tests/e2e/
