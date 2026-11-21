#!/usr/bin/env bash
# MCP 2026-07-28 protocol smoke (#447, #431): one deterministic, no-key run of
# the built binary (or TALON_E2E_BINARY) against a real MCP server (the
# official Go SDK) that is the use case's trusted action source. Proves
# server/discover, the projected tools/list (canonical names, the forbidden
# tool hidden), protocol rejections that reach no governance (legacy
# initialize, Mcp-Name mismatch, unknown tool, schema violation), the use
# case's key as the only identity (no key, a wrong key and the admin key are
# refused), and that /mcp/proxy no longer exists. Zero tools/call.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go test -tags=e2e ./tests/e2e -run 'TestE2E_MCP_Protocol' -count=1 -v "$@"
