#!/usr/bin/env bash
# Verify Flow 0: end-to-end test of the docker-compose demo.
# Clones the repo to a temp directory (or uses current dir), starts the demo
# stack, sends a request, and checks that evidence appears.
#
# Usage: bash scripts/verify-flow0.sh [--in-place]
#   --in-place  Use the current directory instead of cloning to a temp dir.
#
# Exit codes: 0 = success, 1 = failure
set -euo pipefail

TIMEOUT=120
IN_PLACE=false
CLEANUP_DIR=""

for arg in "$@"; do
  case "$arg" in
    --in-place) IN_PLACE=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

cleanup() {
  echo ""
  echo "--- Cleaning up ---"
  if [ -f "examples/docker-compose/docker-compose.yml" ]; then
    cd examples/docker-compose
    docker compose down -v 2>/dev/null || true
    cd ../..
  fi
  if [ -n "$CLEANUP_DIR" ] && [ -d "$CLEANUP_DIR" ]; then
    rm -rf "$CLEANUP_DIR"
  fi
}
trap cleanup EXIT

echo "=== Flow 0 Verification ==="
echo ""

if [ "$IN_PLACE" = false ]; then
  CLEANUP_DIR=$(mktemp -d)
  echo "[1/6] Cloning to temp directory: $CLEANUP_DIR"
  git clone --depth 1 . "$CLEANUP_DIR" 2>/dev/null
  cd "$CLEANUP_DIR"
else
  echo "[1/6] Using current directory (--in-place)"
fi

echo "[2/6] Starting docker compose demo stack..."
cd examples/docker-compose
docker compose up --build -d

echo "[3/6] Waiting for services to be healthy..."
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
  TALON_HEALTHY=$(docker compose ps --format json | grep -c '"Health":"healthy"' 2>/dev/null || echo "0")
  if [ "$TALON_HEALTHY" -ge 2 ]; then
    echo "       Services healthy after ${ELAPSED}s"
    break
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
  if [ $((ELAPSED % 10)) -eq 0 ]; then
    echo "       Waiting... (${ELAPSED}s)"
  fi
done

if [ $ELAPSED -ge $TIMEOUT ]; then
  echo "FAIL: Services did not become healthy within ${TIMEOUT}s"
  docker compose ps
  docker compose logs --tail 30
  exit 1
fi

echo "[4/6] Sending request with PII through gateway..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "My email is jan@example.com and my IBAN is DE89370400440532013000. Help me reset my password."}
    ]
  }')

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" != "200" ]; then
  echo "FAIL: Expected HTTP 200, got $HTTP_CODE"
  echo "Response: $BODY"
  exit 1
fi

echo "       Got HTTP 200 response from gateway"

# Check response has expected OpenAI format
if echo "$BODY" | grep -q '"choices"'; then
  echo "       Response has valid OpenAI format"
else
  echo "FAIL: Response missing 'choices' field"
  echo "Response: $BODY"
  exit 1
fi

echo "[5/6] Checking audit trail..."
sleep 2

AUDIT=$(docker compose exec -T talon /usr/local/bin/talon audit list 2>/dev/null || echo "")
if [ -z "$AUDIT" ]; then
  echo "FAIL: talon audit list returned empty output"
  exit 1
fi

echo "       Audit trail:"
echo "$AUDIT" | head -5

echo "[6/6] Checking dashboard..."
DASHBOARD_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/dashboard 2>/dev/null || echo "000")
if [ "$DASHBOARD_CODE" = "200" ]; then
  echo "       Dashboard returns HTTP 200"
else
  echo "WARN: Dashboard returned HTTP $DASHBOARD_CODE (non-blocking)"
fi

echo ""
echo "=== Flow 0 Verification PASSED ==="
echo ""
echo "Summary:"
echo "  - docker compose up: OK"
echo "  - curl request with PII: HTTP 200, valid OpenAI format"
echo "  - talon audit list: Evidence records present"
echo "  - Dashboard: HTTP $DASHBOARD_CODE"
