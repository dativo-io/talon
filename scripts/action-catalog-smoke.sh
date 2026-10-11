#!/usr/bin/env bash
# Trusted action catalog smoke (#427): one deterministic, no-key run of the
# built binary. Proves: `talon actions list/show/validate` over one shared
# projection (declared http action + MCP-discovered action); the catalog is
# compiled into the runtime generation and served by the Action Gateway; an
# mcp-sourced action is catalogued but not executable (execution_unsupported,
# zero upstream tools/call); a failed source refresh keeps last-known-good
# with a visible rejection; a changed upstream schema activates a new
# generation; the same facts reproduce the same generation id.
set -euo pipefail
cd "$(dirname "$0")/.."
exec go test -tags=e2e ./tests/e2e -run 'TestE2E_ActionCatalog' -count=1 -v "$@"
