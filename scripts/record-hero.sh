#!/usr/bin/env bash
# Record the ~15s "hero" acquisition demo as an asciinema cast (+ optional GIF).
# Run on a dev machine with REAL keys exported, a warmed-up Ollama, and the
# governed-session stack healthy (make governed-session). Not a CI step: real
# spend + timestamp churn.
#
#   ollama pull llama3.2:1b          # warm up the local model for the routing act
#   scripts/record-hero.sh
#
# Outputs (README-readable size):
#   docs/assets/talon_hero.cast   (committed source of truth)
#   docs/assets/talon_hero.gif    (README embed; only when `agg` exists)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="${REPO_ROOT}/examples/governed-session"
ASSET_DIR="${REPO_ROOT}/docs/assets"
CAST="${ASSET_DIR}/talon_hero.cast"
GIF="${ASSET_DIR}/talon_hero.gif"
GATEWAY="${GATEWAY:-http://localhost:8080}"

if ! command -v asciinema >/dev/null 2>&1; then
  echo "✗ asciinema is required: brew install asciinema  (or pipx install asciinema)" >&2
  exit 1
fi
if ! curl -sf "${GATEWAY}/health" >/dev/null 2>&1; then
  echo "✗ Stack not healthy at ${GATEWAY} — run: make governed-session" >&2
  exit 1
fi
mkdir -p "$ASSET_DIR"
cd "$DEMO_DIR"

# Warm the routing model before recording so the ROUTED act's first local
# inference doesn't cold-start into the runner's call timeout. Probe the Ollama
# that Talon actually routes to, at its HOST-visible address (OLLAMA_PROBE_URL,
# default http://localhost:11434) — works for both a host-native Ollama and a
# published sidecar port, matching demo.sh's ollama_ready. Falls back to a
# sidecar exec if the HTTP endpoint isn't reachable from the host.
OLLAMA_PROBE_URL="${OLLAMA_PROBE_URL:-http://localhost:11434}"
if curl -sf "${OLLAMA_PROBE_URL}/api/tags" 2>/dev/null | grep -q 'llama3.2:1b'; then
  echo "==> Warming llama3.2:1b at ${OLLAMA_PROBE_URL} (avoids a cold-start timeout in the recording)..."
  curl -sf "${OLLAMA_PROBE_URL}/api/generate" \
    -d '{"model":"llama3.2:1b","prompt":"ok","stream":false,"options":{"num_predict":1}}' >/dev/null 2>&1 || true
elif docker compose exec -T ollama ollama list 2>/dev/null | grep -q 'llama3.2:1b'; then
  echo "==> Warming llama3.2:1b via the ollama sidecar..."
  docker compose exec -T ollama ollama run llama3.2:1b "ok" >/dev/null 2>&1 || true
else
  echo "⚠ llama3.2:1b not reachable at ${OLLAMA_PROBE_URL} nor in a sidecar." >&2
  echo "  host-native: ollama pull llama3.2:1b  (+ run Talon with TALON_OLLAMA_BASE_URL=http://host.docker.internal:11434)" >&2
  echo "  sidecar:     docker compose --profile routing-demo up -d && docker compose exec ollama ollama pull llama3.2:1b" >&2
  echo "  STRICT mode will fail the recording in the ROUTED act if it stays unreachable." >&2
fi

# Strict mode: a missing Ollama / skipped routing act FAILS the recording, so a
# committed hero GIF can never be missing its headline sovereignty proof.
export TALON_DEMO_STRICT=1
# Pace the acts so the rendered GIF lands in the ~20-30s readable range (5 acts
# + closing proof). --idle-time-limit MUST exceed DEMO_STEP_PAUSE or agg
# collapses the pause when it rewrites the timeline; keep them in lockstep.
export DEMO_STEP_PAUSE="${DEMO_STEP_PAUSE:-3}"
echo "==> Recording ./demo.sh hero (real API calls + local Llama; the budget act"
echo "    spends toward the \$0.03 session cap, so ~\$0.03 real spend)..."
asciinema rec --overwrite --cols 100 --rows 30 --idle-time-limit 4 \
  -c "./demo.sh hero" "$CAST"
echo "    Wrote ${CAST}"

# Render the GIF via the agg binary if present, else the official agg Docker
# image (no install needed), else skip with a hint.
if command -v agg >/dev/null 2>&1; then
  echo "==> Rendering GIF (agg)..."
  agg --font-size 16 "$CAST" "$GIF"
  echo "    Wrote ${GIF}"
elif command -v docker >/dev/null 2>&1; then
  echo "==> Rendering GIF (agg via Docker)..."
  docker run --rm -v "${ASSET_DIR}:/data" ghcr.io/asciinema/agg \
    --font-size 16 "/data/$(basename "$CAST")" "/data/$(basename "$GIF")"
  echo "    Wrote ${GIF}"
else
  echo "⚠ Neither agg nor docker found — GIF not rendered. Render the cast elsewhere:" >&2
  echo "    agg --font-size 16 ${CAST} ${GIF}    (brew/cargo install agg)" >&2
fi

echo ""
echo "Review the recording, then commit docs/assets/talon_hero.{cast,gif}."
