#!/usr/bin/env bash
# Start the #107 governed-session demo stack (REAL providers) and wait for health.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="${REPO_ROOT}/examples/governed-session"
GATEWAY="${GATEWAY:-http://localhost:${DEMO_GATEWAY_PORT:-8080}}"
TIMEOUT="${GOVERNED_SESSION_TIMEOUT:-120}"

if [[ -z "${ANTHROPIC_API_KEY:-}" || -z "${OPENAI_API_KEY:-}" ]]; then
  echo "✗ governed-session demo needs REAL provider keys in the environment:" >&2
  echo "    export ANTHROPIC_API_KEY=sk-ant-..." >&2
  echo "    export OPENAI_API_KEY=sk-..." >&2
  echo "  A full ./demo.sh all run costs about \$0.05 (cheap models, session-capped)." >&2
  exit 1
fi

# shellcheck source=lib/docker-compose-detect.sh
source "${REPO_ROOT}/scripts/lib/docker-compose-detect.sh"
detect_docker_compose

cd "$DEMO_DIR"

echo "==> Building and starting governed-session demo stack (real providers)..."
$COMPOSE up --build -d

echo "==> Waiting for Talon health (timeout ${TIMEOUT}s)..."
elapsed=0
while [[ "$elapsed" -lt "$TIMEOUT" ]]; do
  if curl -sf "${GATEWAY}/health" >/dev/null 2>&1; then
    echo "    Talon healthy at ${GATEWAY} (${elapsed}s)"
    echo ""
    echo "Next: cd examples/governed-session && ./demo.sh all"
    exit 0
  fi
  sleep 2
  elapsed=$((elapsed + 2))
  if [[ $((elapsed % 10)) -eq 0 ]]; then
    echo "    still waiting (${elapsed}s)..."
  fi
done

echo "✗ Talon did not become healthy within ${TIMEOUT}s" >&2
echo "  → $COMPOSE logs talon   (missing/invalid API keys exit the container early)" >&2
exit 1
