#!/usr/bin/env bash
# CI smoke test for examples/product-demo/demo.sh.
#
# The shipped hero renders a styled gum operations console; that VISUAL is
# validated from the rendered GIF (see scripts/record-hero.sh + the preview), not
# here. This test exercises the same script's LIVE orchestration + EVIDENCE
# ASSERTIONS against the offline mock provider, using the plain-UI fallback
# (TALON_DEMO_UI=plain) for deterministic text assertions — no keys, no spend. It
# also proves the gum dependency boundary. It validates:
#   - the full `all` cut exits 0 and NEVER invokes gum (a failing gum stub on PATH);
#   - the plain-UI hero: the four stages, HERO_COMPLETE in the cast, ✓ prevention,
#     the SOFT session-limit label, and visual discipline (no setup noise, no temp
#     paths, no full UUIDs, no over-precise money);
#   - guardrails are load-bearing: the demo aborts when the local model is reachable
#     (preflight); an evidence-omission fault (a successful response whose
#     openai-batch skipped-candidate fact is absent) FAILS the hero;
#   - the gum dependency boundary: `hero` errors clearly when gum is unavailable,
#     and the recorder refuses to record the plain fallback.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# gum is required on PATH for the recorder-refuses-plain check; the no-gum tests
# use curated PATHs that deliberately exclude it.
for t in go jq curl openssl perl gum; do command -v "$t" >/dev/null 2>&1 || { echo "✗ $t is required" >&2; exit 1; }; done
strip_ansi() { perl -pe 's/\e\[[0-9;?]*[a-zA-Z]//g; s/\e\][0-9];[^\a]*\a//g'; }

MOCK_PORT="${MOCK_PORT:-9390}"
MOCK_PID=""; NEG_DIR=""; GUMSTUB=""; TOOLDIR=""
cleanup() {
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" >/dev/null 2>&1 || true
  [[ -n "$NEG_DIR"  && -d "$NEG_DIR"  ]] && rm -rf "$NEG_DIR"
  [[ -n "$GUMSTUB"  && -d "$GUMSTUB"  ]] && rm -rf "$GUMSTUB"
  [[ -n "$TOOLDIR"  && -d "$TOOLDIR"  ]] && rm -rf "$TOOLDIR"
}
trap cleanup EXIT

echo "==> Starting mock provider on :${MOCK_PORT} (stands in for OpenAI + Anthropic)..."
( cd "$REPO_ROOT/examples/docker-compose/mock-provider" && go run main.go -port "$MOCK_PORT" ) >/tmp/smoke-mock.log 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 40); do curl -sf "http://localhost:${MOCK_PORT}/health" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sf "http://localhost:${MOCK_PORT}/health" >/dev/null 2>&1 || { echo "✗ mock did not start" >&2; cat /tmp/smoke-mock.log >&2; exit 1; }

# run_pd <pd-dir> <local-llama-url> <demo.sh args...> — a mock-backed run in PLAIN UI.
run_pd() {
  local dir="$1" llama="$2"; shift 2
  OPENAI_API_KEY=sk-smoke ANTHROPIC_API_KEY=sk-smoke \
  TALON_DEMO_OPENAI_URL="http://localhost:${MOCK_PORT}" TALON_DEMO_ANTHROPIC_URL="http://localhost:${MOCK_PORT}" \
  TALON_DEMO_LOCAL_LLAMA_URL="$llama" TALON_DEMO_COLOR=0 DEMO_STEP_PAUSE=0 TALON_DEMO_UI=plain \
  bash "$dir/demo.sh" "$@"
}
PD="$REPO_ROOT/examples/product-demo"

echo "==> POSITIVE — full 'all' cut exits 0 and NEVER calls gum..."
# A failing gum stub first on PATH: if the `all` cut touched gum, it would exit 97.
GUMSTUB="$(mktemp -d)"; printf '#!/bin/sh\necho "gum must not be called by the all cut" >&2; exit 97\n' >"$GUMSTUB/gum"; chmod +x "$GUMSTUB/gum"
if PATH="$GUMSTUB:$PATH" run_pd "$PD" http://127.0.0.1:1 all >/tmp/smoke-all.out 2>/tmp/smoke-all.err; then
  echo "    ✓ demo.sh all exited 0 (gum never invoked)"
else
  echo "✗ demo.sh all FAILED (or invoked gum)" >&2; tail -30 /tmp/smoke-all.err >&2; exit 1
fi

echo "==> POSITIVE — plain-UI hero (the deterministic text surface; gum renders the recorded asset)..."
STATE="$(mktemp)"
run_pd "$PD" http://127.0.0.1:1 prepare "$STATE" hero >/tmp/smoke-prep.out 2>&1 || { echo "✗ prepare failed" >&2; tail -20 /tmp/smoke-prep.out >&2; rm -f "$STATE"; exit 1; }
if TALON_DEMO_UI=plain TALON_DEMO_COLOR=1 DEMO_STEP_PAUSE=0 bash "$PD/demo.sh" play "$STATE" >/tmp/hero.raw 2>/tmp/hero.err; then :; else
  echo "✗ demo.sh play (plain) FAILED" >&2; tail -30 /tmp/hero.err >&2; rm -f "$STATE"; exit 1
fi
rm -f "$STATE"
grep -q "HERO_COMPLETE" /tmp/hero.raw || { echo "✗ HERO_COMPLETE marker missing from the cast" >&2; exit 1; }
strip_ansi </tmp/hero.raw >/tmp/hero.plain
# The four stages + each beat's receipt content.
for m in "RELIABILITY + SHARED POLICY" "email + IBAN redacted" "POLICY SKIP" "blocked by use-case policy" \
         "ORGANIZATION POLICY + COST" "admin_*" "BLOCKED BEFORE MODEL" "Provider call prevented" \
         "SOFT SESSION LIMIT" "NEXT CALL PREVENTED" \
         "OPERATIONAL CONTROL + PROOF" "FINANCE SETS AN EMERGENCY DAILY CEILING" "daily budget exhausted" \
         "SIGNED EVIDENCE" "valid_fallback" "VERIFIED OFFLINE" "Operate every AI use case"; do
  grep -qF "$m" /tmp/hero.plain || { echo "✗ hero stage/marker missing: $m" >&2; exit 1; }
done
grep -qF "✓ NEXT CALL PREVENTED"  /tmp/hero.plain || { echo "✗ cost prevention must render ✓ (not ✗)" >&2; exit 1; }
grep -qF "✓ BLOCKED BEFORE MODEL" /tmp/hero.plain || { echo "✗ tool boundary must render ✓ (not ✗)" >&2; exit 1; }
for bad in "Preparing the fleet" "go build" "secrets set" "gateway started" "/tmp/" "/var/folders/"; do
  grep -qF "$bad" /tmp/hero.plain && { echo "✗ hero frames leaked: $bad" >&2; exit 1; } || true
done
grep -qE '[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}' /tmp/hero.plain && { echo "✗ hero frames contain a full UUID" >&2; exit 1; } || true
grep -qE '\$[0-9]+\.[0-9]{5,}' /tmp/hero.plain && { echo "✗ hero frames contain over-precise money (>4dp)" >&2; exit 1; } || true
echo "    ✓ plain hero: four stages, HERO_COMPLETE, ✓ prevention, SOFT limit, no setup/paths/UUID/over-precise money"

echo "==> POSITIVE — gum LIVE COMMAND panel: real command + real output, and NO secret / host-prompt / temp-path leak..."
# The command panel is gum-only, so capture the gum UI itself. Secrets are the
# actual generated Talon keys (read from the prepared state) + the mock provider key.
STATE2="$(mktemp)"
run_pd "$PD" http://127.0.0.1:1 prepare "$STATE2" hero >/tmp/smoke-prep2.out 2>&1 || { echo "✗ prepare (gum) failed" >&2; tail -20 /tmp/smoke-prep2.out >&2; rm -f "$STATE2"; exit 1; }
sval() { sed -nE "s/.*\\b$1='([^']*)'.*/\\1/p" "$STATE2" | head -1; }
if TALON_DEMO_UI=gum TALON_DEMO_COLOR=1 DEMO_STEP_PAUSE=0 \
   OPENAI_API_KEY=sk-smoke ANTHROPIC_API_KEY=sk-smoke \
   TALON_DEMO_OPENAI_URL="http://localhost:${MOCK_PORT}" TALON_DEMO_ANTHROPIC_URL="http://localhost:${MOCK_PORT}" \
   TALON_DEMO_LOCAL_LLAMA_URL="http://127.0.0.1:1" \
   bash "$PD/demo.sh" play "$STATE2" >/tmp/gum.raw 2>&1; then :; else
  echo "✗ gum hero play FAILED" >&2; tail -25 /tmp/gum.raw >&2; rm -f "$STATE2"; exit 1
fi
strip_ansi </tmp/gum.raw >/tmp/gum.plain
# Each stage shows its REAL command + REAL output in the LIVE COMMAND panel.
for m in "LIVE COMMAND" "talon agents" "/v1/proxy/local-llama" "/v1/proxy/openai" "/v1/proxy/anthropic" \
         "talon audit verify --file signed-evidence.json" "perl -i.bak -pe" \
         "HTTP 200" "HTTP 403" "session_budget_exceeded" "Total records:" "Valid records:" "Invalid records: 0"; do
  grep -qF "$m" /tmp/gum.plain || { echo "✗ command-panel marker missing: $m" >&2; rm -f "$STATE2"; exit 1; }
done
# The recorded hero must begin inside the Talon console: no outer host shell prompt / setup output.
for bad in "Preparing the fleet" "==> " "openclaw@" "demo.sh hero" "demo.sh play" "go build" "/var/folders/" "/tmp/tmp."; do
  grep -qF "$bad" /tmp/gum.plain && { echo "✗ host/setup text leaked into the hero: $bad" >&2; rm -f "$STATE2"; exit 1; } || true
done
# SECRET-LEAK: no generated Talon key, admin/secrets/signing key, mock provider key,
# or raw temp path may appear anywhere in the rendered output or cast.
leak=0
for var in CS_KEY CODE_KEY DOC_KEY TALON_ADMIN_KEY TALON_SECRETS_KEY TALON_SIGNING_KEY WORK; do
  v="$(sval "$var")"
  if [[ -n "$v" ]] && grep -qF "$v" /tmp/gum.raw; then echo "✗ SECRET/temp leak: ${var} value appears in the rendered hero" >&2; leak=1; fi
done
grep -qF "sk-smoke" /tmp/gum.raw && { echo "✗ SECRET leak: provider key sk-smoke appears in the rendered hero" >&2; leak=1; }
rm -f "$STATE2"
[[ "$leak" == 0 ]] || exit 1
echo "    ✓ gum LIVE COMMAND: real commands + HTTP + verify counts; no secrets, temp paths, or host prompt"

echo "==> NEGATIVE — local model reachable → preflight aborts the demo..."
if run_pd "$PD" "http://localhost:${MOCK_PORT}" hero >/tmp/smoke-neg1.out 2>&1; then
  echo "✗ demo did NOT abort when the local model was reachable" >&2; exit 1
fi
grep -qiE "local model at .* is UP" /tmp/smoke-neg1.out || { echo "✗ aborted, but not via the local-model preflight" >&2; tail -12 /tmp/smoke-neg1.out >&2; exit 1; }
echo "    ✓ aborts when the local model is up (preflight is load-bearing)"

echo "==> NEGATIVE (evidence omission) — a SUCCESSFUL response missing the skipped-candidate fact must FAIL the hero..."
# Allow openai-batch: the request still succeeds, but openai-batch is now SELECTED
# rather than SKIPPED, so the signed evidence no longer carries the skipped-candidate
# fact — beat_support's third assert_ev fails and the whole cut aborts non-zero.
# Under examples/ so `../..` still resolves to the repo root (build finds go.mod).
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

echo "==> NEGATIVE — hero (TALON_DEMO_UI=gum) errors clearly when gum is unavailable..."
# A curated PATH with the required tools but NO gum. require_gum fires before setup,
# so no build/gateway is needed.
TOOLDIR="$(mktemp -d)"
for t in bash sh env go jq curl openssl sed awk grep cat head tr sort uniq mktemp rm cut printf sleep kill dirname; do
  p="$(command -v "$t" 2>/dev/null)" && ln -sf "$p" "$TOOLDIR/$t"
done
if TALON_DEMO_UI=gum PATH="$TOOLDIR" bash "$PD/demo.sh" hero >/tmp/smoke-neg3.out 2>&1; then
  echo "✗ hero did NOT error when gum was unavailable" >&2; exit 1
fi
grep -qiE "gum is required" /tmp/smoke-neg3.out || { echo "✗ errored, but not with a clear 'gum is required' message" >&2; tail -8 /tmp/smoke-neg3.out >&2; exit 1; }
echo "    ✓ hero reports a clear error when gum is unavailable (full 'all' cut needs no gum)"

echo "==> NEGATIVE — the recorder refuses to record the plain fallback..."
if TALON_DEMO_UI=plain bash "$REPO_ROOT/scripts/record-hero.sh" >/tmp/smoke-neg4.out 2>&1; then
  echo "✗ record-hero.sh did NOT refuse TALON_DEMO_UI=plain" >&2; exit 1
fi
grep -qiE "TALON_DEMO_UI=plain will not be recorded" /tmp/smoke-neg4.out || { echo "✗ recorder aborted, but not on the plain-UI refusal" >&2; tail -8 /tmp/smoke-neg4.out >&2; exit 1; }
echo "    ✓ recorder refuses the plain fallback (records only the styled console)"

echo ""
echo "✓ product-demo smoke passed (live orchestration + evidence assertions + gum dependency boundary)."
