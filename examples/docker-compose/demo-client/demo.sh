#!/usr/bin/env bash
# Demo client — sends requests through the Talon gateway to show evidence generation.
# Usage: bash demo.sh [gateway_url]
set -euo pipefail

GATEWAY="${1:-http://localhost:8080}"
ENDPOINT="$GATEWAY/v1/proxy/openai/v1/chat/completions"

echo "=== Talon Demo: sending requests through gateway ==="
echo "    Gateway: $GATEWAY"
echo ""

echo "[1/5] Simple request (no PII)..."
curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What are the key trends in European AI regulation?"}]}' \
  | python3 -m json.tool 2>/dev/null || true
echo ""

echo "[2/5] Request with email PII..."
curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My email is jan@example.com, help me reset my password"}]}' \
  | python3 -m json.tool 2>/dev/null || true
echo ""

echo "[3/5] Request with IBAN PII..."
curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Please process payment to IBAN DE89370400440532013000 for invoice 12345"}]}' \
  | python3 -m json.tool 2>/dev/null || true
echo ""

echo "[4/5] Request with multiple PII types..."
curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Customer Maria Garcia, email maria@company.eu, phone +49 170 1234567, wants to update her IBAN to DE89370400440532013000"}]}' \
  | python3 -m json.tool 2>/dev/null || true
echo ""

echo "[5/5] Request with a different model..."
curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4-turbo","messages":[{"role":"user","content":"Summarize GDPR Article 30 requirements for processing records"}]}' \
  | python3 -m json.tool 2>/dev/null || true
echo ""

echo "=== Done! Check the audit trail: ==="
echo "  talon audit list"
echo "  # or: docker compose exec talon /usr/local/bin/talon audit list"
echo ""
echo "  Dashboard: http://localhost:8080/dashboard"
