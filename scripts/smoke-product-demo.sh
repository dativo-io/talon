#!/usr/bin/env bash
# CI smoke test for examples/product-demo/demo.sh.
#
# The shipped demo is real-provider-only. This test exercises the same script's
# LIVE orchestration and EVIDENCE ASSERTIONS deterministically against the offline
# mock provider (examples/docker-compose/mock-provider) via the demo's base-URL
# overrides — no API keys, no spend, no recording. It validates:
#   - the full `all` evaluator cut exits 0;
#   - the anchored-live `hero` cut: the opening + three chapter dividers, every
#     beat's receipt, HERO_COMPLETE in the cast, ✓ prevention markers, the SOFT
#     session-limit label, and visual discipline (no setup noise, no temp paths,
#     no full UUIDs, no over-precise money in the presented frames);
#   - two NEGATIVE cases proving the guardrails are load-bearing: the demo aborts
#     when the local model is reachable (preflight), and — evidence omission — a
#     SUCCESSFUL response whose openai-batch skipped-candidate fact is absent FAILS
#     the hero, so a receipt can never be shown without the evidence behind it.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for t in go jq curl openssl perl; do command -v "$t" >/dev/null 2>&1 || { echo "✗ $t is required" >&2; exit 1; }; done
strip_ansi() { perl -pe 's/\e\[[0-9;]*[a-zA-Z]//g; s/\e\][0-9];[^\a]*\a//g'; }

MOCK_PORT="${MOCK_PORT:-9390}"
MOCK_PID=""
NEG_DIR=""   # a copy of the product-demo, kept under examples/ so `../..` still finds the repo root
cleanup() {
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" >/dev/null 2>&1 || true
  [[ -n "$NEG_DIR" && -d "$NEG_DIR" ]] && rm -rf "$NEG_DIR"
}
trap cleanup EXIT

echo "==> Starting mock provider on :${MOCK_PORT} (stands in for OpenAI + Anthropic)..."
( cd "$REPO_ROOT/examples/docker-compose/mock-provider" && go run main.go -port "$MOCK_PORT" ) >/tmp/smoke-mock.log 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 40); do curl -sf "http://localhost:${MOCK_PORT}/health" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sf "http://localhost:${MOCK_PORT}/health" >/dev/null 2>&1 || { echo "✗ mock did not start" >&2; cat /tmp/smoke-mock.log >&2; exit 1; }

# run_pd <pd-dir> <local-llama-url> <demo.sh args...>  — a mock-backed run.
run_pd() {
  local dir="$1" llama="$2"; shift 2
  OPENAI_API_KEY=sk-smoke ANTHROPIC_API_KEY=sk-smoke \
  TALON_DEMO_OPENAI_URL="http://localhost:${MOCK_PORT}" TALON_DEMO_ANTHROPIC_URL="http://localhost:${MOCK_PORT}" \
  TALON_DEMO_LOCAL_LLAMA_URL="$llama" TALON_DEMO_COLOR=0 DEMO_STEP_PAUSE=0 \
  bash "$dir/demo.sh" "$@"
}
PD="$REPO_ROOT/examples/product-demo"

echo "==> POSITIVE — full 'all' evaluator cut exits 0..."
if run_pd "$PD" http://127.0.0.1:1 all >/tmp/smoke-all.out 2>/tmp/smoke-all.err; then
  echo "    ✓ demo.sh all exited 0"
else
  echo "✗ demo.sh all FAILED" >&2; tail -30 /tmp/smoke-all.err >&2; exit 1
fi

echo "==> POSITIVE — anchored live 'hero' cut (prepare/play; the split record-hero.sh records)..."
STATE="$(mktemp)"
run_pd "$PD" http://127.0.0.1:1 prepare "$STATE" hero >/tmp/smoke-prep.out 2>&1 || { echo "✗ prepare failed" >&2; tail -20 /tmp/smoke-prep.out >&2; rm -f "$STATE"; exit 1; }
if TALON_DEMO_COLOR=1 DEMO_STEP_PAUSE=0 bash "$PD/demo.sh" play "$STATE" >/tmp/hero.raw 2>/tmp/hero.err; then :; else
  echo "✗ demo.sh play FAILED" >&2; tail -30 /tmp/hero.err >&2; rm -f "$STATE"; exit 1
fi
rm -f "$STATE"
grep -q "HERO_COMPLETE" /tmp/hero.raw || { echo "✗ HERO_COMPLETE marker missing from the cast" >&2; exit 1; }
strip_ansi </tmp/hero.raw >/tmp/hero.plain
# The anchored narrative: opening + three chapter dividers + each beat's receipt.
for m in "1 OPERATING VIEW" \
         "1 / 3" "RELIABILITY + SHARED POLICY" "email + IBAN redacted" "POLICY SKIP" "blocked by use-case policy" "first policy-valid fallback" \
         "2 / 3" "ORGANIZATION POLICY + COST" "admin_*" "BLOCKED BEFORE MODEL" "Provider call prevented" \
         "SOFT SESSION LIMIT" "NEXT CALL PREVENTED" "Anthropic was not called" \
         "3 / 3" "OPERATIONAL CONTROL + PROOF" "FINANCE SETS AN EMERGENCY DAILY CEILING" "daily budget exhausted" \
         "SIGNED EVIDENCE" "valid_fallback" "VERIFIED OFFLINE" "Operate every AI use case"; do
  grep -qF "$m" /tmp/hero.plain || { echo "✗ hero scene marker missing: $m" >&2; exit 1; }
done
# Successful governance renders ✓, never ✗ (Talon behaved correctly).
grep -qF "✓ NEXT CALL PREVENTED"  /tmp/hero.plain || { echo "✗ cost prevention must render ✓ (not ✗)" >&2; exit 1; }
grep -qF "✓ BLOCKED BEFORE MODEL" /tmp/hero.plain || { echo "✗ tool boundary must render ✓ (not ✗)" >&2; exit 1; }
grep -qF "SOFT SESSION LIMIT"     /tmp/hero.plain || { echo "✗ the session budget must be labeled SOFT" >&2; exit 1; }
for bad in "Preparing the fleet" "go build" "secrets set" "gateway started" "/tmp/" "/var/folders/"; do
  grep -qF "$bad" /tmp/hero.plain && { echo "✗ hero frames leaked: $bad" >&2; exit 1; } || true
done
grep -qE '[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}' /tmp/hero.plain && { echo "✗ hero frames contain a full UUID" >&2; exit 1; } || true
grep -qE '\$[0-9]+\.[0-9]{5,}' /tmp/hero.plain && { echo "✗ hero frames contain over-precise money (>4dp)" >&2; exit 1; } || true
echo "    ✓ hero: opening + 3 chapters, HERO_COMPLETE, ✓ prevention, SOFT limit, no setup/paths/UUID/over-precise money"

echo "==> NEGATIVE — local model reachable → preflight aborts the demo..."
if run_pd "$PD" "http://localhost:${MOCK_PORT}" hero >/tmp/smoke-neg1.out 2>&1; then
  echo "✗ demo did NOT abort when the local model was reachable" >&2; exit 1
fi
grep -qiE "local model at .* is UP" /tmp/smoke-neg1.out || { echo "✗ aborted, but not via the local-model preflight" >&2; tail -12 /tmp/smoke-neg1.out >&2; exit 1; }
echo "    ✓ aborts when the local model is up (preflight is load-bearing)"

echo "==> NEGATIVE (evidence omission) — a SUCCESSFUL response whose skipped-candidate fact is absent must FAIL the hero..."
# Fault injection: allow openai-batch for customer-support. The request still
# succeeds, but openai-batch is now SELECTED rather than SKIPPED — so the signed
# evidence no longer carries the openai-batch skipped-candidate fact. The hero
# must NOT be able to present the policy-valid-fallback receipt without that fact:
# beat_support's third assert_ev fails and the whole cut aborts non-zero. This
# proves the receipts are backed by evidence, not just by a healthy HTTP 200.
# The demo builds talon from SCRIPT_DIR/../.., so the variant must live under
# examples/ for that to still resolve to the repo root (a copy in /tmp would have
# no go.mod above it). A hidden sibling dir keeps the build correct while the
# patched agents/ is what the gateway loads.
NEG_DIR="$REPO_ROOT/examples/.smoke-neg-$$"
cp -r "$PD" "$NEG_DIR"
perl -0pi -e 's/allowed_providers: \["local-llama", "openai"\]/allowed_providers: ["local-llama", "openai-batch", "openai"]/' "$NEG_DIR/agents/customer-support/agent.talon.yaml"
grep -q '"local-llama", "openai-batch", "openai"' "$NEG_DIR/agents/customer-support/agent.talon.yaml" || { echo "✗ could not patch the allowlist" >&2; exit 1; }
if run_pd "$NEG_DIR" http://127.0.0.1:1 hero >/tmp/smoke-neg2.out 2>&1; then
  echo "✗ hero SUCCEEDED with openai-batch allowed — the skip assertion is not load-bearing" >&2; exit 1
fi
grep -qiE "policy-valid failover|signed evidence did not confirm" /tmp/smoke-neg2.out || { echo "✗ hero failed, but not at the policy-valid-fallback assertion" >&2; tail -20 /tmp/smoke-neg2.out >&2; exit 1; }
rm -rf "$NEG_DIR"; NEG_DIR=""
echo "    ✓ the policy-valid-fallback evidence assertion is load-bearing"

echo ""
echo "✓ product-demo smoke passed (live orchestration + evidence assertions + hero visual discipline)."
