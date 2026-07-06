#!/usr/bin/env bash
#
# verify-newcomer-path.sh — smoke-test the documented cold-start builder path.
#
# Validates: talon on PATH, init --scaffold, run --dry-run (no LLM key).
# Run from repo root: make verify-newcomer
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

export TALON_SECRETS_KEY="${TALON_SECRETS_KEY:-$(openssl rand -hex 32)}"
export TALON_DATA_DIR="${WORK_DIR}/.talon"

if ! command -v talon >/dev/null 2>&1; then
  if [ -x "${REPO_ROOT}/bin/talon" ]; then
    export PATH="${REPO_ROOT}/bin:${PATH}"
  elif command -v go >/dev/null 2>&1; then
    echo "==> talon not on PATH; building via make install..."
    if [ "$(uname -s)" = "Darwin" ]; then
      make -C "$REPO_ROOT" install
    else
      make -C "$REPO_ROOT" install
    fi
    GOPATH_BIN="$(go env GOPATH)/bin"
    export PATH="${GOPATH_BIN}:${PATH}"
  else
    echo "Error: talon not found and go not available to build." >&2
    exit 1
  fi
fi

echo "==> talon version"
talon version | head -3

echo "==> talon init --scaffold"
cd "$WORK_DIR"
talon init --scaffold --name newcomer-smoke >/dev/null

test -f agent.talon.yaml || { echo "missing agent.talon.yaml" >&2; exit 1; }
test -f talon.config.yaml || { echo "missing talon.config.yaml" >&2; exit 1; }

echo "==> talon run --dry-run"
out=$(talon run --dry-run "hello newcomer smoke" 2>&1)
echo "$out" | tail -5
echo "$out" | grep -qi "ALLOWED" || { echo "expected dry-run ALLOWED" >&2; exit 1; }

echo ""
echo "verify-newcomer: OK (init + dry-run on clean dir)"
