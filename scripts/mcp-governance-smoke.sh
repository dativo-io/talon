#!/usr/bin/env bash
# MCP governance-contract smoke (#372, #431): one deterministic,
# credential-free run of the BUILT talon binary (or TALON_E2E_BINARY) over
# real HTTP with a real MCP server (the official Go SDK) counting every
# tools/call it receives, and a temporary evidence DB. Every governed
# tools/call is an Action Gateway operation. Proves, end to end:
#   - a forbidden tool called directly: policy_denied, zero calls;
#   - a read-only action: one call;
#   - a consequential action: prepare (zero calls), execute (one call),
#     six concurrent executes and a repeat (still one);
#   - a caller-provided operation id: changed arguments conflict, no call;
#   - approval: pending, the use-case key cannot approve, the reviewer's
#     decision dispatches nothing, the next execute dispatches once;
#   - a tool error after dispatch: upstream_outcome_unknown, never retried,
#     the vendor's text never relayed;
#   - every operation's signed lifecycle verifies (`talon audit verify
#     --operation`).
# Also: the official Go SDK client, unmodified, through the same flows plus
# two identical prepared operations, an expired approval and the recovery
# hold after a real backup restore (TestE2E_MCP_StandardSDKClient); the
# company PII baseline in a native (MCP-only) serve across a hot reload
# (TestE2E_MCP_OrganizationPIIBaseline_NativeServe); and the runnable
# adoption example examples/mcp-governed/run.sh against the same binary.
# Coverage boundary: PII redaction details and evidence-commit faults are
# proven in-process (internal/mcp TestGoverned_*, internal/action
# TestMCPAction_*).
#
# Independent of make test-smoke (no provider key, no Docker); also run as
# smoke section 37 and as a named PR CI step.
set -euo pipefail
cd "$(dirname "$0")/.."
go test -tags=e2e ./tests/e2e -run 'TestE2E_MCP_GovernanceContract|TestE2E_MCP_StandardSDKClient|TestE2E_MCP_OrganizationPIIBaseline_NativeServe' -count=1 -v "$@"
# The adoption example uses the binary under test when one is given.
TALON_BIN="${TALON_E2E_BINARY:-}" bash examples/mcp-governed/run.sh
