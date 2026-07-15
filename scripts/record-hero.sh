#!/usr/bin/env bash
# Record the product-story "hero" demo as an asciinema cast (+ GIF).
#
# The hero is the product demo (examples/product-demo): it builds talon from this
# checkout and operates three AI use cases through one gateway on REAL providers.
# It therefore needs OPENAI_API_KEY + ANTHROPIC_API_KEY (real spend ~$0.02-0.05)
# and the local model (Ollama, :11434) OFFLINE so the reliability beat sees a real
# failover. Not a CI step: real spend + timestamp churn in the cast.
#
#   export OPENAI_API_KEY=... ANTHROPIC_API_KEY=...   # stop Ollama first
#   scripts/record-hero.sh
#
# The recording is transactional: it promotes over the committed cast/GIF only
# after the run exits 0 AND the cast carries its terminal success marker, so a
# failed run can never overwrite a good asset.
#
# Outputs (README-readable size):
#   docs/assets/talon_hero.cast   (committed source of truth)
#   docs/assets/talon_hero.gif    (README embed; only when `agg` exists)
set -euo pipefail

CAST_ONLY=0
[[ "${1:-}" == "--cast-only" ]] && CAST_ONLY=1   # allow a cast without a rendered GIF

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="${REPO_ROOT}/examples/product-demo"
ASSET_DIR="${REPO_ROOT}/docs/assets"
CAST="${ASSET_DIR}/talon_hero.cast"
GIF="${ASSET_DIR}/talon_hero.gif"
LOCAL_LLAMA_URL="${TALON_DEMO_LOCAL_LLAMA_URL:-http://localhost:11434}"

if ! command -v asciinema >/dev/null 2>&1; then
  echo "✗ asciinema is required: brew install asciinema  (or pipx install asciinema)" >&2
  exit 1
fi
for tool in go jq curl openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "✗ ${tool} is required" >&2; exit 1; }
done
# Fail before asciinema starts, so a preflight problem never records a broken cast.
[[ -n "${OPENAI_API_KEY:-}" ]]    || { echo "✗ OPENAI_API_KEY is required (real providers)." >&2; exit 1; }
[[ -n "${ANTHROPIC_API_KEY:-}" ]] || { echo "✗ ANTHROPIC_API_KEY is required (document-summary runs on Anthropic)." >&2; exit 1; }
if curl -sf -m 2 "${LOCAL_LLAMA_URL}/api/tags" >/dev/null 2>&1; then
  echo "✗ The local model at ${LOCAL_LLAMA_URL} is UP — the reliability beat needs it DOWN. Stop Ollama and retry." >&2
  exit 1
fi
mkdir -p "$ASSET_DIR"
cd "$DEMO_DIR"

# The demo asserts every headline against signed evidence and aborts non-zero on
# any unexpected outcome (in every mode), so a broken run can never be promoted
# below. Colour is forced so the GIF renders in colour even when asciinema
# records headless.
export TALON_DEMO_COLOR=1
# Pace the acts so the rendered GIF lands in the readable range. --idle-time-limit
# MUST exceed DEMO_STEP_PAUSE or agg collapses the pause when it rewrites the
# timeline; keep them in lockstep.
export DEMO_STEP_PAUSE="${DEMO_STEP_PAUSE:-2}"

# PREPARE OUTSIDE THE RECORDING: setup() (build, seed the vault, start the
# gateway) runs here — NOT inside asciinema — so the recorded frames begin with
# the opening banner, not the build/seed log. `demo.sh play` then records only
# the product story and tears the gateway down when it finishes.
STATE="$(mktemp)"
prep_cleanup() {   # safety net: if the recording aborts before play tears down, kill the prepared gateway
  # shellcheck disable=SC1090
  [[ -s "$STATE" ]] && { source "$STATE" 2>/dev/null || true; [[ -n "${GW_PID:-}" ]] && kill "$GW_PID" 2>/dev/null || true; [[ -n "${WORK:-}" ]] && rm -rf "$WORK" 2>/dev/null || true; }
  rm -f "$STATE"
}
trap prep_cleanup EXIT

echo "==> Preparing the fleet OUTSIDE the recording (build + gateway; ~\$0.02-0.05 real spend follows)..."
( cd "$DEMO_DIR" && ./demo.sh prepare "$STATE" hero ) || { echo "✗ prepare failed — nothing recorded." >&2; exit 1; }

# TRANSACTIONAL RECORDING: record to a .tmp cast and promote ONLY after the run
# exits 0 AND the cast carries its terminal success marker.
CAST_TMP="${CAST}.tmp"
HERO_MARKER="one shared control plane"
echo "==> Recording only the product story (./demo.sh play)..."
rec_rc=0
asciinema rec --overwrite --window-size 100x30 --idle-time-limit 4 \
  -c "cd '$DEMO_DIR' && ./demo.sh play '$STATE'" "$CAST_TMP" || rec_rc=$?
if [[ "$rec_rc" -ne 0 ]]; then
  echo "✗ demo.sh play exited ${rec_rc} — recording NOT promoted. The committed cast is unchanged." >&2
  rm -f "$CAST_TMP"; exit 1
fi
if ! grep -q "$HERO_MARKER" "$CAST_TMP"; then
  echo "✗ Recording is missing the terminal success marker (\"${HERO_MARKER}\") — NOT promoted." >&2
  rm -f "$CAST_TMP"; exit 1
fi
mv -f "$CAST_TMP" "$CAST"
echo "    Wrote ${CAST} (validated: exit 0 + terminal marker)"

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
fi
if [[ "$render_ok" == 1 && -s "$GIF_TMP" ]]; then
  mv -f "$GIF_TMP" "$GIF"
  echo "    Wrote ${GIF}"
else
  rm -f "$GIF_TMP"
fi

# The README embeds the GIF, not the cast: fail unless BOTH assets exist, so a
# missing/failed render can never leave the old GIF beside a new cast.
[[ -s "$CAST" ]] || { echo "✗ no cast was produced." >&2; exit 1; }
if [[ "$CAST_ONLY" != 1 ]]; then
  [[ -s "$GIF" ]] || { echo "✗ No GIF was rendered (install agg: brew/cargo install agg — or have Docker running)." >&2
    echo "  The README embeds the GIF; refusing to finish with only a cast. Re-run with --cast-only to override." >&2; exit 1; }
fi

echo ""
echo "Review the recording, then commit docs/assets/talon_hero.{cast,gif}."
