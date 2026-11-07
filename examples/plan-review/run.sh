#!/usr/bin/env bash
# Run the plan review example.
# Shows: agent creates plan → plan pending → approve via CLI or API → execution.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TALON="$REPO_ROOT/bin/talon"

if [ ! -f "$TALON" ]; then
  echo "Error: talon binary not found at $TALON"
  echo "Run 'make build' from the repo root first."
  exit 1
fi

echo "=== Plan Review Demo ==="
echo ""
echo "This demonstrates EU AI Act Article 14 (human oversight)."
echo "The agent will create a plan, then wait for human approval"
echo "before executing it."
echo ""
echo "Steps:"
echo "  1. Agent receives the query and creates an execution plan"
echo "  2. Plan is held in PENDING state (not executed)"
echo "  3. You approve or reject via the CLI (talon plan approve) or the API"
echo "  4. If approved, the agent executes the plan"
echo ""

echo "Starting Talon server (plan review API + auto-dispatch)..."
"$TALON" serve --port 8080 &
TALON_PID=$!
sleep 2

echo ""
echo "Running agent with plan review enabled..."
echo "  Pending plans (CLI): talon plan pending"
echo "  Pending plans (API): http://localhost:8080/v1/plans/pending"
echo ""

"$TALON" run --policy "$SCRIPT_DIR/agent.talon.yaml" \
  "Research the latest EU AI Act enforcement timeline and summarize key deadlines" || true

echo ""
echo "Review and decide on the pending plan:"
echo "  talon plan pending"
echo "  talon plan approve <plan-id>        # or: talon plan reject <plan-id>"
echo "  # API: curl -X POST -H \"X-Talon-Admin-Key: \$TALON_ADMIN_KEY\" http://localhost:8080/v1/plans/<plan-id>/approve"

kill $TALON_PID 2>/dev/null || true
