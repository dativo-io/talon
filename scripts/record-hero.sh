#!/usr/bin/env bash
# Record the ~15s "hero" acquisition demo as an asciinema cast (+ optional GIF).
# Run on a dev machine with REAL keys exported, a warmed-up Ollama, and the
# governed-session stack healthy (make governed-session). Not a CI step: real
# spend + timestamp churn.
#
#   ollama pull llama3.2          # warm up the local model for the routing act
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
if ! curl -sf "http://localhost:11434/api/tags" >/dev/null 2>&1; then
  echo "⚠ Ollama not reachable at :11434 — the ROUTED act will note it and skip the local-serve half." >&2
  echo "  For the full recording: ollama pull llama3.2 && ollama serve" >&2
fi

mkdir -p "$ASSET_DIR"
cd "$DEMO_DIR"

echo "==> Recording ./demo.sh hero (real API calls + local Llama, ~\$0.01)..."
asciinema rec --overwrite --cols 100 --rows 30 --idle-time-limit 1 \
  -c "./demo.sh hero" "$CAST"
echo "    Wrote ${CAST}"

if command -v agg >/dev/null 2>&1; then
  echo "==> Rendering GIF..."
  agg --font-size 16 "$CAST" "$GIF"
  echo "    Wrote ${GIF}"
else
  echo "⚠ agg not found — skipping GIF render (cargo install agg / brew install agg)"
fi

echo ""
echo "Review the recording, then commit docs/assets/talon_hero.{cast,gif}."
