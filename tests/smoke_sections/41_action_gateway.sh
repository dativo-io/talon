#!/usr/bin/env bash
# Smoke test section: 41_action_gateway
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 41 — Exact governed action and one company action policy (#458, #425)
# Runs the offline, credential-free Action Gateway smoke against the built
# binary: scripts/action-smoke.sh, the SAME assertion set that
# `make test-action-smoke` and the PR CI step execute (shared, not
# duplicated). It proves, with a counting mock downstream: DENY = 0 dispatch;
# REQUIRE_APPROVAL = 0 before and 0 after the reviewer decision, exactly 1
# after the controlled resume; exact replay still 1; changed payload =
# conflict; lost response = UNKNOWN with no automatic retry; restart
# survival; `talon audit verify --operation` VALID, INVALID after a database
# tamper. And the company layer (#425/#426/#428): one
# `gateway.organization_policy.constraints` policy in talon.config.yaml
# denies and requires approval across two use cases, a use case can add but
# never weaken a company rule, the reviewer matrix (wrong group, other
# tenant, revoked and rotated credentials, admin and agent keys) refuses with
# zero dispatch, a restart under a changed company rule invalidates the
# pending approval with signed evidence, and the lifecycle verifies. One
# assertion: the Go smoke's exit status. A failure is counted in the
# consolidated summary and makes the suite exit non-zero.
# -----------------------------------------------------------------------------
test_section_41_action_gateway() {
  echo ""
  echo "=== SECTION 41 — Exact governed action and one company action policy (#458, #425) ==="
  cd "$REPO_ROOT" || exit 1
  # Build-and-run inside the e2e harness: the Go test builds its own binary
  # (TestMain) and uses isolated temp data dirs and ports, so this section
  # needs no port, provider key or shared state from the other sections.
  assert_pass "TestE2E_ActionGateway_*: exact action proof + ACME company policy over two use cases (scripts/action-smoke.sh)" \
    bash scripts/action-smoke.sh
}
