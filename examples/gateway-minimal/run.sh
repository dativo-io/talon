#!/usr/bin/env bash
# Run the minimal gateway example.
# Requires: talon binary built (make build), OpenAI API key stored in vault.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TALON="$REPO_ROOT/bin/talon"

if [ ! -f "$TALON" ]; then
  echo "Error: talon binary not found at $TALON"
  echo "Run 'make build' from the repo root first."
  exit 1
fi

echo "Starting Talon gateway (minimal config)..."
echo "  Config: $SCRIPT_DIR/talon.config.yaml"
echo "  Mode:   shadow (log only, no blocking)"
echo ""
echo "Point your app at:"
echo "  OPENAI_BASE_URL=http://localhost:8080/v1/proxy/openai/v1"
echo "  OPENAI_API_KEY=talon-gw-myapp-001"
echo ""
echo "Dashboard: http://localhost:8080/dashboard"
echo ""

"$TALON" serve --port 8080 --gateway --gateway-config "$SCRIPT_DIR/talon.config.yaml"
