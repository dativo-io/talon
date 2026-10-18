#!/usr/bin/env bash
# Smoke test section: 37_mcp_governance
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 37 — MCP governance contract (#372)
# Runs the offline, credential-free governance-contract smoke against the
# built binary: scripts/mcp-governance-smoke.sh, the SAME assertion set that
# `make test-mcp-governance-smoke` and the PR CI step execute (shared, not
# duplicated). It proves: exactly io.dativo.talon/governance v1 advertised and
# no Tasks; allowed call → result._meta decision=allow + committed evidence id,
# one effect, full record HMAC-verified, reasonCode == signed explanation;
# forbidden call → policy_denied / deny / non-retryable + committed ref +
# deprecated alias, zero dispatch; protocol errors → no governance object, no
# effect; effect + severed answer → upstream_outcome_unknown, exactly one
# effect; vendor JSON-RPC error → vendor code kept, message/data not relayed,
# record holds only the code/category token; tampered record fails verification. One assertion: the Go smoke's
# exit status. A failure is counted in the consolidated summary and makes
# the suite exit non-zero; nothing here is optional or ignored.
# -----------------------------------------------------------------------------
test_section_37_mcp_governance() {
  echo ""
  echo "=== SECTION 37 — MCP governance contract (#372) ==="
  cd "$REPO_ROOT" || exit 1
  # Build-and-run inside the e2e harness: the Go test builds its own binary
  # (TestMain) and uses an isolated temp data dir, so this section needs no
  # port, provider key or shared state from the other sections.
  assert_pass "TestE2E_MCP_GovernanceContract: extension + signed evidence + forbidden + protocol + ambiguous effect (scripts/mcp-governance-smoke.sh)" \
    bash scripts/mcp-governance-smoke.sh
}
