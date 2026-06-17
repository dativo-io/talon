#!/usr/bin/env bash
# Start the #107 shortlist demo stack and wait until Talon is healthy.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="${REPO_ROOT}/examples/shortlist-demo"
GATEWAY="${GATEWAY:-http://localhost:8080}"
TIMEOUT="${SHORTLIST_DEMO_TIMEOUT:-120}"

cd "$DEMO_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker not found. The shortlist demo requires Docker Engine and the Compose plugin." >&2
  echo "See examples/shortlist-demo/README.md#prerequisites for install steps." >&2
  exit 127
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Error: docker compose plugin not found (need 'docker compose', not legacy docker-compose)." >&2
  echo "See examples/shortlist-demo/README.md#prerequisites for install steps." >&2
  exit 127
fi

echo "==> Building and starting shortlist demo stack..."
docker compose up --build -d

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
docker compose ps >&2 || true
docker compose logs --tail 40 talon >&2 || true
exit 1
