#!/usr/bin/env bash
# MCP 2026-07-28 protocol smoke (#447): one deterministic, no-key run of the
# built binary with a counting mock upstream behind /mcp/proxy. Proves
# server/discover on both routes, deterministic filtered tools/list with
# cache hints, one upstream dispatch for a valid governed call (with
# outbound Mcp-* headers generated from the authorized body), zero dispatch
# for Mcp-Name / Mcp-Param mismatches, legacy initialize + session transport
# rejected, notifications answered 202 with no body.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go test -tags=e2e ./tests/e2e -run 'TestE2E_MCP_Protocol' -count=1 -v "$@"
