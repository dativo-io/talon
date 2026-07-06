#!/usr/bin/env bash
# Record the #107 governed-session demo as an asciinema cast (+ optional GIF).
# Run on a dev machine with REAL keys exported and the stack already healthy
# (make governed-session). Not a CI step: real spend + timestamp churn.
#
#   scripts/record-governed-session.sh
#
# Outputs:
#   docs/assets/governed-session.cast   (committed source of truth)
#   docs/assets/governed-session.gif    (README embed; only when `agg` exists)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="${REPO_ROOT}/examples/governed-session"
ASSET_DIR="${REPO_ROOT}/docs/assets"
CAST="${ASSET_DIR}/governed-session.cast"
GIF="${ASSET_DIR}/governed-session.gif"
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

echo "==> Recording ./demo.sh all (real API calls, ~\$0.05)..."
asciinema rec --overwrite --cols 100 --rows 32 --idle-time-limit 2 \
  -c "./demo.sh all" "$CAST"
echo "    Wrote ${CAST}"

if command -v agg >/dev/null 2>&1; then
  echo "==> Rendering GIF..."
  agg --font-size 16 "$CAST" "$GIF"
  echo "    Wrote ${GIF}"
else
  echo "⚠ agg not found — skipping GIF render (cargo install agg / brew install agg)"
fi

echo ""
echo "Review the recording, then commit the assets under docs/assets/."
