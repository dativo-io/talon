#!/usr/bin/env bash
# Smoke test section: 43_console_contract
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 43 — Operations-console read contract (#535)
# Runs the offline, credential-free console smoke against the built binary:
# scripts/console-smoke.sh, the SAME assertions that `make test-console-smoke`
# and the PR CI step execute (shared, not duplicated). A real `talon serve
# --gateway` with a fake provider takes governed traffic in one asserted
# session; the console read model opened read-only on that live store must
# show the same counters, spend, caps, session summary and timeline as
# `talon agents/costs/session/audit --json`, keep them across a restart of
# the data plane, keep serving the store after the data plane stops, report
# the runtime as unknown without a probe, and `talon metrics` must fail
# loudly (never a silent local fallback) when the server rejects or is gone.
# One assertion: the Go smoke's exit status.
# -----------------------------------------------------------------------------
test_section_43_console_contract() {
  echo ""
  echo "=== SECTION 43 — Operations-console read contract (#535) ==="
  cd "$REPO_ROOT" || exit 1
  # Build-and-run inside the e2e harness: the Go test builds its own binary
  # (TestMain) and uses isolated temp data dirs and ports, so this section
  # needs no port, provider key or shared state from the other sections.
  assert_pass "TestE2E_Console_*: console read model == CLI JSON on a live store, restart, stopped data plane, metrics fail-loud (scripts/console-smoke.sh)" \
    bash scripts/console-smoke.sh
}
