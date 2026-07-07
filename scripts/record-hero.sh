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

# Ollama runs as a compose sidecar (reachable at ollama:11434 inside the
# network, not on the host). Warm the model before recording so the ROUTED
# act's first local inference doesn't hit the runner's call timeout.
if docker compose exec -T ollama ollama list 2>/dev/null | grep -q 'llama3.2:1b'; then
  echo "==> Warming llama3.2:1b (avoids a cold-start timeout in the recording)..."
  echo "    (if this hangs on a small host, add swap — see the demo README)"
  docker compose exec -T ollama ollama run llama3.2:1b "ok" >/dev/null 2>&1 || true
else
  echo "⚠ llama3.2:1b not found in the ollama sidecar — the ROUTED act will note it and skip the local-serve half." >&2
  echo "  For the full recording: docker compose --profile routing-demo up -d && docker compose exec ollama ollama pull llama3.2:1b" >&2
fi

# Strict mode: a missing Ollama / skipped routing act FAILS the recording, so a
# committed hero GIF can never be missing its headline sovereignty proof.
export TALON_DEMO_STRICT=1
echo "==> Recording ./demo.sh hero (real API calls + local Llama; the budget act"
echo "    spends toward the \$0.03 session cap, so ~\$0.03 real spend)..."
asciinema rec --overwrite --cols 100 --rows 30 --idle-time-limit 1 \
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
