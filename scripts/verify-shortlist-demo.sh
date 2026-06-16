#!/usr/bin/env bash
# CI-safe verification for examples/shortlist-demo (#107).
# Starts the stack (unless SHORTLIST_SKIP_UP=1), runs ./demo.sh all, checks outputs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_DIR="${REPO_ROOT}/examples/shortlist-demo"
OUT_DIR="${DEMO_DIR}/out"

cleanup() {
  if [[ "${SHORTLIST_SKIP_DOWN:-}" != "1" ]]; then
    (cd "$DEMO_DIR" && docker compose down -v 2>/dev/null) || true
  fi
}
trap cleanup EXIT

if [[ "${SHORTLIST_SKIP_UP:-}" != "1" ]]; then
  bash "${REPO_ROOT}/scripts/shortlist-demo-up.sh"
fi

cd "$DEMO_DIR"
chmod +x demo.sh
./demo.sh all

test -s "${OUT_DIR}/ropa.html"
test -s "${OUT_DIR}/annex-iv.html"
test -s "${OUT_DIR}/evidence.signed.json"

if command -v jq >/dev/null 2>&1; then
  ropa_warn="$(jq '(.warnings // []) | length' "${OUT_DIR}/ropa.json")"
  annex_warn="$(jq '(.warnings // []) | length' "${OUT_DIR}/annex-iv.json")"
  if [[ "$ropa_warn" -gt 0 ]]; then
    echo "Error: RoPA has ${ropa_warn} declaration warnings" >&2
    exit 1
  fi
  if [[ "$annex_warn" -gt 0 ]]; then
    echo "Error: Annex IV has ${annex_warn} declaration warnings" >&2
    exit 1
  fi
fi

echo ""
echo "=== verify-shortlist-demo PASSED ==="
