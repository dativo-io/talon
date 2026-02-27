#!/usr/bin/env bash
# Generate a rich evidence trail for screenshots, GIFs, and README demos.
# Requires: Talon running with the docker-compose demo stack.
#
# Usage:
#   cd examples/docker-compose && docker compose up -d
#   bash ../../scripts/demo-recorder.sh
set -euo pipefail

GATEWAY="${1:-http://localhost:8080}"
ENDPOINT="$GATEWAY/v1/proxy/openai/v1/chat/completions"

echo "==========================================="
echo "  Talon Demo Recorder"
echo "  Gateway: $GATEWAY"
echo "==========================================="
echo ""

send() {
  local label="$1"
  local model="$2"
  local content="$3"
  echo "  Sending: $label"
  curl -s -o /dev/null -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"$model\",\"messages\":[{\"role\":\"user\",\"content\":\"$content\"}]}"
  sleep 0.5
}

echo "[Phase 1] Clean requests (no PII)"
send "EU regulation summary"    "gpt-4o-mini"  "What are the key trends in European AI regulation?"
send "Code review request"      "gpt-4o-mini"  "Review this Go function for error handling best practices"
send "Meeting summary"          "gpt-4o"       "Summarize the key decisions from yesterday's architecture review"
echo ""

echo "[Phase 2] Requests with PII"
send "Email PII"                "gpt-4o-mini"  "My email is jan@example.com, help me reset my password"
send "IBAN PII"                 "gpt-4o-mini"  "Process payment to IBAN DE89370400440532013000 for invoice 12345"
send "Phone PII"                "gpt-4o"       "Call me at +49 170 1234567 to discuss the contract"
send "Multi-PII"                "gpt-4o"       "Customer Maria Garcia, email maria@company.eu, phone +49 170 1234567, IBAN DE89370400440532013000"
send "Credit card PII"          "gpt-4o-mini"  "Charge 50 EUR to card 4532015112830366 for the annual subscription"
echo ""

echo "[Phase 3] Different models"
send "GPT-4 Turbo"              "gpt-4-turbo"  "Explain the difference between GDPR and the EU AI Act"
send "GPT-4o summary"           "gpt-4o"       "Summarize NIS2 Article 21 requirements for incident reporting"
echo ""

echo "==========================================="
echo "  Done! 10 evidence records generated."
echo "==========================================="
echo ""
echo "View the evidence trail:"
echo "  docker compose exec talon /usr/local/bin/talon audit list"
echo ""
echo "Inspect a record:"
echo "  docker compose exec talon /usr/local/bin/talon audit show <id>"
echo ""
echo "Verify HMAC signature:"
echo "  docker compose exec talon /usr/local/bin/talon audit verify <id>"
echo ""
echo "Export for compliance officer:"
echo "  docker compose exec talon /usr/local/bin/talon audit export --format csv"
echo ""
echo "Dashboard:"
echo "  open $GATEWAY/dashboard"
