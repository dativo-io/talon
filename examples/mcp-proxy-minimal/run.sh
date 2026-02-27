#!/usr/bin/env bash
# Run the minimal MCP proxy example.
# Requires: talon binary built (make build).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TALON="$REPO_ROOT/bin/talon"

if [ ! -f "$TALON" ]; then
  echo "Error: talon binary not found at $TALON"
  echo "Run 'make build' from the repo root first."
  exit 1
fi

echo "Starting Talon MCP proxy (minimal config)..."
echo "  Config: $SCRIPT_DIR/proxy.talon.yaml"
echo "  Mode:   shadow (audit only, no blocking)"
echo ""
echo "Point your vendor AI at:"
echo "  http://localhost:8080/mcp/proxy"
echo ""
echo "Allowed tools: ticket_search, ticket_create, ticket_update, user_lookup"
echo "Forbidden tools: user_delete, bulk_export, admin_*"
echo ""

"$TALON" serve --port 8080 --proxy-config "$SCRIPT_DIR/proxy.talon.yaml"
