#!/usr/bin/env bash
# MCP governance-contract smoke (#372): one deterministic, credential-free run
# of the BUILT talon binary over real HTTP with a counting mock MCP upstream
# and a temporary evidence DB. Proves, end to end:
#   - both routes advertise exactly io.dativo.talon/governance v1, no Tasks;
#   - an allowed call carries decision=allow + a committed evidence id in
#     result._meta, one upstream effect, and the full signed record verifies
#     (`talon audit verify`) with reasonCode == the signed explanation;
#   - a forbidden call is policy_denied / deny / non-retryable with a
#     committed evidence ref and the deprecated alias, zero dispatch;
#   - protocol errors (-32020, -32022, -32602, -32700, -32601) carry no
#     governance object and cause no effect;
#   - an effect followed by a severed answer is upstream_outcome_unknown,
#     non-retryable, exactly one effect, record status unknown;
#   - a tampered record fails verification while an untouched one verifies;
#   - the smoke's own assertion set rejects a missing id, an uncommitted
#     reference, a retryable denial and a leaked signature.
# Coverage boundary: pre-dispatch evidence-commit outages and injected
# adversarial reasons are proven in-process (internal/mcp TestGovernance_*,
# TestSafety_*),
# because they cannot be injected into a running binary.
#
# Independent of make test-smoke (no provider key, no Docker); also run as
# smoke section 37 and as a named PR CI step.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go test -tags=e2e ./tests/e2e -run 'TestE2E_MCP_GovernanceContract' -count=1 -v "$@"
