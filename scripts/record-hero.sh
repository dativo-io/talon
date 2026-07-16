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

# The recorded hero MUST be the styled terminal walkthrough; refuse the plain fallback up front
# (before any tool preflight) — the plain layout exists only for text assertions.
if [[ "${TALON_DEMO_UI:-gum}" == "plain" ]]; then
  echo "✗ TALON_DEMO_UI=plain will not be recorded — the plain layout exists only for automated text assertions." >&2
  exit 1
fi

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
# gum styles the recorded terminal walkthrough (spinner + closing callout). DEMO-ONLY — the full
# `all` walkthrough and `make product-demo` do NOT need it. Pinned for recording.
GUM_VERSION="v0.17.0"
if ! command -v gum >/dev/null 2>&1; then
  echo "✗ gum ${GUM_VERSION} is required for the recorded hero (the full demo needs no gum)." >&2
  echo "  Install:  go install github.com/charmbracelet/gum@${GUM_VERSION}   (or: brew install gum)" >&2
  exit 1
fi
gv="$(gum --version 2>&1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; gv="v${gv#v}"
[[ "$gv" == "$GUM_VERSION" ]] || echo "    ⚠ gum ${gv} is installed but the hero is pinned to ${GUM_VERSION}; styled layout may differ." >&2
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
# Record the styled walkthrough (gum spinner + closing callout). The hero is a
# scrolling terminal session (no alternate screen), so nothing to restore after.
export TALON_DEMO_UI=gum
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
HERO_MARKER="HERO_COMPLETE"   # emitted via a terminal-title escape at the end of the hero cut
echo "==> Recording only the product story (./demo.sh play)..."
# asciinema v3 sets a fixed headless geometry with --window-size; asciinema v2
# has no such flag — it records the controlling terminal's size. Detect the
# installed major version and adapt so the recorder works on either. (The v2
# usage banner lists {rec,play,cat,upload,auth} and rejects --window-size.)
ASCII_MAJOR="$(asciinema --version 2>&1 | grep -oE '[0-9]+' | head -n1)"
rec_rc=0
if [[ "${ASCII_MAJOR:-0}" -ge 3 ]]; then
  asciinema rec --overwrite --window-size 88x34 --idle-time-limit 3 \
    -c "cd '$DEMO_DIR' && ./demo.sh play '$STATE'" "$CAST_TMP" || rec_rc=$?
else
  echo "    asciinema v${ASCII_MAJOR:-?}: no --window-size — requesting an 88x34 terminal and recording at terminal size."
  echo "    For a pixel-clean asset, size this terminal to 88x34 first (or install asciinema 3)."
  printf '\033[8;34;88t'   # ask the emulator to resize to 34 rows x 88 cols (honored by most; harmless where ignored)
  sleep 1
  asciinema rec --overwrite --idle-time-limit 3 \
    -c "cd '$DEMO_DIR' && ./demo.sh play '$STATE'" "$CAST_TMP" || rec_rc=$?
fi
if [[ "$rec_rc" -ne 0 ]]; then
  echo "✗ demo.sh play exited ${rec_rc} — recording NOT promoted. The committed cast is unchanged." >&2
  rm -f "$CAST_TMP"; exit 1
fi
if ! grep -q "$HERO_MARKER" "$CAST_TMP"; then
  echo "✗ Recording is missing the terminal success marker (\"${HERO_MARKER}\") — NOT promoted." >&2
  rm -f "$CAST_TMP"; exit 1
fi
# Render the GIF from the VALIDATED TEMP cast — BEFORE promoting anything — so the
# cast and GIF promote together. A failed render can then never leave a fresh cast
# beside a stale GIF: if no fresh GIF is produced, NEITHER asset is promoted (the
# committed pair is left untouched). CAST_TMP lives under ASSET_DIR, so the Docker
# mount can read it.
GIF_TMP="${GIF}.tmp"
render_ok=0
AGG_FLAGS=(--theme github-dark --font-size 20 --line-height 1.2 --last-frame-duration 3)
if command -v agg >/dev/null 2>&1; then
  echo "==> Rendering GIF (agg, github-dark)..."
  agg "${AGG_FLAGS[@]}" "$CAST_TMP" "$GIF_TMP" && render_ok=1
elif command -v docker >/dev/null 2>&1; then
  echo "==> Rendering GIF (agg via Docker)..."
  docker run --rm -v "${ASSET_DIR}:/data" ghcr.io/asciinema/agg \
    "${AGG_FLAGS[@]}" "/data/$(basename "$CAST_TMP")" "/data/$(basename "$GIF_TMP")" && render_ok=1
fi

# Promotion gate: unless --cast-only, a FRESH GIF must have rendered this run.
# Checking render_ok (not merely -s "$GIF") means a pre-existing committed GIF can
# never satisfy the gate after a failed render.
if [[ "$CAST_ONLY" != 1 && ( "$render_ok" != 1 || ! -s "$GIF_TMP" ) ]]; then
  rm -f "$GIF_TMP" "$CAST_TMP"
  echo "✗ No GIF was rendered (install agg: brew/cargo install agg — or have Docker running)." >&2
  echo "  The README embeds the GIF; refusing to promote a cast without a fresh GIF — committed assets unchanged." >&2
  echo "  Re-run with --cast-only to promote just the cast." >&2
  exit 1
fi

# Both validated (or --cast-only): promote atomically.
mv -f "$CAST_TMP" "$CAST"
CAST_GEO="$(head -n1 "$CAST" 2>/dev/null | jq -r 'if .width then "\(.width)x\(.height)" else "?" end' 2>/dev/null || echo '?')"
echo "    Wrote ${CAST} (validated: exit 0 + terminal marker; geometry ${CAST_GEO} — aim for 88x34)"
if [[ "$render_ok" == 1 && -s "$GIF_TMP" ]]; then
  mv -f "$GIF_TMP" "$GIF"
  echo "    Wrote ${GIF}"
else
  rm -f "$GIF_TMP"   # --cast-only with no fresh render: keep the committed GIF as-is
fi
[[ -s "$CAST" ]] || { echo "✗ no cast was produced." >&2; exit 1; }

echo ""
echo "Review the recording, then commit docs/assets/talon_hero.{cast,gif}."
