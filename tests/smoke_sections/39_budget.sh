#!/usr/bin/env bash
# Smoke test section: 39_budget
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 39 — Preventive budget governance (offline)
# Runs the black-box budget proof against a binary built from the checkout
# (the e2e harness builds it in TestMain): one request under the agent daily
# cap is dispatched and settled from the provider's reported usage; the next
# is denied 403 budget_exceeded BEFORE dispatch; a model missing from the
# pricing table is denied 403 pricing_unavailable under the same cap; both
# denials are signed records that verify. The provider is a counting
# fixture, so "never reached" is a counter, not a status code. Fail-closed
# behaviour on budget-store failure (503 budget_unavailable) is covered by
# the gateway unit suite, which can inject the store failure; it has no
# black-box lever. Needs no provider key or port.
# -----------------------------------------------------------------------------
test_section_39_budget() {
  echo ""
  echo "=== SECTION 39 — Preventive budget governance (offline) ==="
  cd "$REPO_ROOT" || exit 1
  assert_pass "TestE2E_Budget_PreventiveAtTheGateway: cap denies before dispatch, unpriced model denied, signed denials verify" \
    go test -count=1 -tags=e2e -timeout 5m -run 'TestE2E_Budget_' ./tests/e2e/
}
