#!/usr/bin/env bash
# CI smoke test for examples/product-demo/demo.sh.
#
# The shipped demo is real-provider-only. This test exercises the same script's
# ORCHESTRATION and EVIDENCE ASSERTIONS deterministically against the offline
# mock provider (examples/docker-compose/mock-provider) via the demo's base-URL
# overrides — no API keys, no spend, no recording. It validates:
#   - startup, loopback bind, exactly-three-agent discovery;
#   - the policy-valid-failover, org-tool-boundary, session-budget, and
#     blocked-fleet evidence assertions all pass on a real gateway;
#   - a NEGATIVE case: when the local model is reachable (failover could not be a
#     real event), the demo's guardrails abort it non-zero — proving the demo
#     cannot render a successful-looking proof that did not actually happen.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for t in go jq curl openssl; do command -v "$t" >/dev/null 2>&1 || { echo "✗ $t is required" >&2; exit 1; }; done

MOCK_PORT="${MOCK_PORT:-9390}"
MOCK_PID=""
cleanup() { [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> Starting mock provider on :${MOCK_PORT} (stands in for OpenAI + Anthropic)..."
( cd "$REPO_ROOT/examples/docker-compose/mock-provider" && go run main.go -port "$MOCK_PORT" ) >/tmp/smoke-mock.log 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 40); do curl -sf "http://localhost:${MOCK_PORT}/health" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sf "http://localhost:${MOCK_PORT}/health" >/dev/null 2>&1 || { echo "✗ mock did not start" >&2; cat /tmp/smoke-mock.log >&2; exit 1; }

run_demo() { # run_demo <local-llama-url>
  OPENAI_API_KEY=sk-smoke ANTHROPIC_API_KEY=sk-smoke \
  TALON_DEMO_OPENAI_URL="http://localhost:${MOCK_PORT}" \
  TALON_DEMO_ANTHROPIC_URL="http://localhost:${MOCK_PORT}" \
  TALON_DEMO_LOCAL_LLAMA_URL="$1" \
  TALON_DEMO_COLOR=0 DEMO_STEP_PAUSE=0 \
  bash "$REPO_ROOT/examples/product-demo/demo.sh" all
}

echo "==> POSITIVE: full demo against the mock (local model DOWN) — expect success + all assertions pass..."
if run_demo "http://127.0.0.1:1" >/tmp/smoke-positive.out 2>/tmp/smoke-positive.err; then
  echo "    ✓ demo.sh all exited 0"
else
  echo "✗ demo.sh all FAILED against the mock — see below" >&2
  tail -30 /tmp/smoke-positive.err >&2; tail -30 /tmp/smoke-positive.out >&2
  exit 1
fi
# Confirm the headline receipts actually rendered (not just a clean exit).
for marker in "SKIPPED" "\[EMAIL\], \[IBAN\]" "session spend" "FLEET HEALTH  blocked" "Invalid records: 0" "valid_fallback"; do
  grep -qE "$marker" /tmp/smoke-positive.out || { echo "✗ expected marker missing from output: $marker" >&2; exit 1; }
done
echo "    ✓ failover-skip, redaction, session-budget receipt, blocked fleet, offline verify, chain verify all present"

echo "==> NEGATIVE: local model reachable (points at the mock) — a real failover could not happen; a guardrail must FAIL the demo..."
if run_demo "http://localhost:${MOCK_PORT}" >/tmp/smoke-negative.out 2>/tmp/smoke-negative.err; then
  echo "✗ demo.sh all UNEXPECTEDLY SUCCEEDED when failover could not occur — assertions are not load-bearing" >&2
  exit 1
else
  # It must fail for the RIGHT reason (a preflight/assertion), not a random error.
  if grep -qE "local model at .* is UP|policy-valid failover|signed evidence did not confirm" /tmp/smoke-negative.err; then
    echo "    ✓ demo correctly aborted (preflight or the policy-valid-failover assertion)"
  else
    echo "✗ demo failed, but not for the expected reason:" >&2; tail -15 /tmp/smoke-negative.err >&2; exit 1
  fi
fi

echo ""
echo "✓ product-demo smoke test passed (orchestration + evidence assertions verified; assertions are load-bearing)."
