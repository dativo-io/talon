#!/usr/bin/env bash
# Start the #107 shortlist demo stack and wait until Talon is healthy.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="${REPO_ROOT}/examples/shortlist-demo"
GATEWAY="${GATEWAY:-http://localhost:8080}"
TIMEOUT="${SHORTLIST_DEMO_TIMEOUT:-120}"

# shellcheck source=lib/docker-compose-detect.sh
source "${REPO_ROOT}/scripts/lib/docker-compose-detect.sh"
detect_docker_compose

cd "$DEMO_DIR"

echo "==> Building and starting shortlist demo stack..."
$COMPOSE up --build -d

echo "==> Waiting for Talon health (timeout ${TIMEOUT}s)..."
elapsed=0
while [[ "$elapsed" -lt "$TIMEOUT" ]]; do
  if curl -sf "${GATEWAY}/health" >/dev/null 2>&1; then
    echo "    Talon healthy at ${GATEWAY} (${elapsed}s)"
    echo ""
    echo "Next: cd examples/shortlist-demo && ./demo.sh all"
    exit 0
  fi
  sleep 2
  elapsed=$((elapsed + 2))
  if [[ $((elapsed % 10)) -eq 0 ]]; then
    echo "    waiting... (${elapsed}s)"
  fi
done

echo "Error: Talon did not become healthy within ${TIMEOUT}s" >&2
$COMPOSE ps >&2 || true
$COMPOSE logs --tail 40 talon >&2 || true
exit 1
