#!/usr/bin/env bash
# Record the #107 governed-session demo as an asciinema cast (+ optional GIF).
# Run on a dev machine with REAL keys exported and the stack already healthy
# (make governed-session). Not a CI step: real spend + timestamp churn.
#
#   scripts/record-governed-session.sh
#
# Outputs (the deep demo GIF the README embeds):
#   docs/assets/talon_demo.cast   (committed source of truth)
#   docs/assets/talon_demo.gif    (README embed; only when `agg` exists)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="${REPO_ROOT}/examples/governed-session"
ASSET_DIR="${REPO_ROOT}/docs/assets"
CAST="${ASSET_DIR}/talon_demo.cast"
GIF="${ASSET_DIR}/talon_demo.gif"
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

# The deep demo's story also includes the sovereignty-routing act, so warm the
# local model and record in strict mode — a skipped routing act fails the run.
# Probe the Ollama Talon routes to at its host-visible address (OLLAMA_PROBE_URL,
# default http://localhost:11434) — host-native or a published sidecar port —
# matching demo.sh's ollama_ready, with a sidecar-exec fallback.
OLLAMA_PROBE_URL="${OLLAMA_PROBE_URL:-http://localhost:11434}"
if curl -sf "${OLLAMA_PROBE_URL}/api/tags" 2>/dev/null | grep -q 'llama3.2:1b'; then
  echo "==> Warming llama3.2:1b at ${OLLAMA_PROBE_URL} (avoids a cold-start timeout in the recording)..."
  curl -sf "${OLLAMA_PROBE_URL}/api/generate" \
    -d '{"model":"llama3.2:1b","prompt":"ok","stream":false,"options":{"num_predict":1}}' >/dev/null 2>&1 || true
elif docker compose exec -T ollama ollama list 2>/dev/null | grep -q 'llama3.2:1b'; then
  echo "==> Warming llama3.2:1b via the ollama sidecar..."
  docker compose exec -T ollama ollama run llama3.2:1b "ok" >/dev/null 2>&1 || true
else
  echo "✗ llama3.2:1b not reachable at ${OLLAMA_PROBE_URL} nor in a sidecar — the deep demo's routing act needs it." >&2
  echo "  host-native: ollama pull llama3.2:1b  (+ run Talon with TALON_OLLAMA_BASE_URL=http://host.docker.internal:11434)" >&2
  echo "  sidecar:     docker compose --profile routing-demo up -d && docker compose exec ollama ollama pull llama3.2:1b" >&2
  exit 1
fi

# PREFLIGHT: verify Talon-in-container can reach its CONFIGURED Ollama — the
# exact path the routing act (act 8) uses. Catch a topology mismatch BEFORE
# recording, not captured mid-cast as a 500.
echo "==> Preflight: Talon → configured Ollama..."
if ! ./demo.sh preflight; then
  echo "✗ Preflight failed — not recording. Fix the topology above and retry." >&2
  exit 1
fi

export TALON_DEMO_STRICT=1
# Pace the 11 acts so the rendered GIF lands in the ~60-80s readable range.
# --idle-time-limit MUST exceed DEMO_STEP_PAUSE or agg collapses the pause when
# it rewrites the timeline; keep them in lockstep.
export DEMO_STEP_PAUSE="${DEMO_STEP_PAUSE:-4}"

# TRANSACTIONAL RECORDING: record to a .tmp cast and promote to the committed
# path ONLY after the run exits 0 AND the cast carries the act-11 terminal
# markers (RoPA generated + the closing banner). Prevents asciinema --overwrite
# from clobbering a good cast with a partial failed one.
CAST_TMP="${CAST}.tmp"
DEEP_MARKER_ROPA="RoPA generated"
DEEP_MARKER_END="govern before the provider, prove what happened after"
echo "==> Recording ./demo.sh all (real API calls + local Llama, ~\$0.03)..."
rec_rc=0
asciinema rec --overwrite --cols 100 --rows 32 --idle-time-limit 5 \
  -c "./demo.sh all" "$CAST_TMP" || rec_rc=$?
if [[ "$rec_rc" -ne 0 ]]; then
  echo "✗ demo.sh all exited ${rec_rc} — recording NOT promoted. The committed cast is unchanged." >&2
  rm -f "$CAST_TMP"
  exit 1
fi
if ! grep -q "$DEEP_MARKER_ROPA" "$CAST_TMP" || ! grep -q "$DEEP_MARKER_END" "$CAST_TMP"; then
  echo "✗ Recording is missing an act-11 terminal marker (RoPA export / closing banner) — NOT promoted." >&2
  echo "  The run ended before act 11; the committed cast is unchanged." >&2
  rm -f "$CAST_TMP"
  exit 1
fi
mv -f "$CAST_TMP" "$CAST"
echo "    Wrote ${CAST} (validated: exit 0 + act-11 terminal markers)"

# Render the GIF from the VALIDATED cast, to a .tmp then promote.
GIF_TMP="${GIF}.tmp"
render_ok=0
if command -v agg >/dev/null 2>&1; then
  echo "==> Rendering GIF (agg)..."
  agg --font-size 16 "$CAST" "$GIF_TMP" && render_ok=1
elif command -v docker >/dev/null 2>&1; then
  echo "==> Rendering GIF (agg via Docker)..."
  docker run --rm -v "${ASSET_DIR}:/data" ghcr.io/asciinema/agg \
    --font-size 16 "/data/$(basename "$CAST")" "/data/$(basename "$GIF_TMP")" && render_ok=1
else
  echo "⚠ Neither agg nor docker found — GIF not rendered. Render the validated cast elsewhere:" >&2
  echo "    agg --font-size 16 ${CAST} ${GIF}    (brew/cargo install agg)" >&2
fi
if [[ "$render_ok" == 1 && -s "$GIF_TMP" ]]; then
  mv -f "$GIF_TMP" "$GIF"
  echo "    Wrote ${GIF}"
else
  rm -f "$GIF_TMP"
fi

echo ""
echo "Review the recording, then commit the assets under docs/assets/."
