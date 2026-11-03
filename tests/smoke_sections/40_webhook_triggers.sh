#!/usr/bin/env bash
# Smoke test section: 40_webhook_triggers
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 40 — Webhook triggers are authenticated (#479, offline)
# Runs the black-box proof against a binary built from the checkout (the e2e
# harness builds it in TestMain): a native-only serve with the admin key set
# and the webhook's secret minted in the vault answers 401 to every request
# that does not present that secret as `Authorization: Bearer` — no header,
# a wrong value, the admin key as header or bearer — and the counting
# provider, the evidence store and the trigger history all stay at zero; the
# authorized request reaches the provider exactly once and is recorded under
# invocation_type webhook:<name>. An oversized payload is refused before it
# is parsed. Startup fails closed on a webhook without secret_name, on a
# secret the vault does not hold, and on any trigger when a gateway is
# served. Needs no provider key or port.
# -----------------------------------------------------------------------------
test_section_40_webhook_triggers() {
  echo ""
  echo "=== SECTION 40 — Webhook triggers are authenticated (#479, offline) ==="
  cd "$REPO_ROOT" || exit 1
  assert_pass "TestE2E_WebhookTrigger_*: only the webhook secret dispatches; denied requests reach no provider and leave no evidence; startup fails closed" \
    go test -count=1 -tags=e2e -timeout 5m -run 'TestE2E_WebhookTrigger_' ./tests/e2e/
}
