#!/usr/bin/env bash
#
# generate-auditor-pack.sh — reproducible sample auditor handoff from the docker-compose demo.
#
# Produces examples/auditor-pack/ with signed evidence export, compliance report, and manifest.
# Requires: Docker, docker compose, curl, and a running build of talon in the demo image (compose build).
#
# Usage (from repo root):
#   scripts/generate-auditor-pack.sh
#   scripts/generate-auditor-pack.sh --keep-up   # leave compose stack running
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_DIR="${REPO_ROOT}/examples/docker-compose"
OUTPUT_DIR="${REPO_ROOT}/examples/auditor-pack"
GATEWAY="http://localhost:8080"
KEEP_UP=false

for arg in "$@"; do
  case "$arg" in
    --keep-up) KEEP_UP=true ;;
    -h|--help)
      echo "Usage: scripts/generate-auditor-pack.sh [--keep-up]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

generate_offline() {
  echo "==> Docker unavailable; generating offline sample pack (auditorpackgen)..."
  mkdir -p "$OUTPUT_DIR"
  (cd "$REPO_ROOT" && go run ./scripts/auditorpackgen/main.go -out "$OUTPUT_DIR")
  echo "Auditor pack written to ${OUTPUT_DIR}/ (offline fixture)"
}

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  generate_offline
  exit 0
fi

cd "$COMPOSE_DIR"

echo "==> Building and starting docker-compose demo stack..."
if ! docker compose up -d --build; then
  cd "$REPO_ROOT"
  generate_offline
  exit 0
fi

echo "==> Waiting for Talon health..."
for i in $(seq 1 60); do
  if curl -fsS "${GATEWAY}/health" >/dev/null 2>&1; then
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "Error: Talon did not become healthy at ${GATEWAY}/health" >&2
    docker compose logs talon --tail 30 >&2 || true
    exit 1
  fi
  sleep 2
done

echo "==> Seeding evidence (demo-recorder)..."
bash "${REPO_ROOT}/scripts/demo-recorder.sh" "$GATEWAY"

mkdir -p "$OUTPUT_DIR"

echo "==> Exporting signed evidence..."
docker compose exec -T talon /usr/local/bin/talon audit export \
  --format signed-json \
  --limit 500 >"${OUTPUT_DIR}/evidence.signed.json"

echo "==> Generating compliance report (HTML)..."
docker compose exec -T talon /usr/local/bin/talon compliance report \
  --format html >"${OUTPUT_DIR}/compliance-report.html"

echo "==> Generating compliance report (JSON)..."
docker compose exec -T talon /usr/local/bin/talon compliance report \
  --format json >"${OUTPUT_DIR}/compliance-report.json"

echo "==> Generating GDPR Art. 30 RoPA (HTML + JSON)..."
docker compose exec -T talon /usr/local/bin/talon compliance ropa \
  --format html >"${OUTPUT_DIR}/ropa.html"
docker compose exec -T talon /usr/local/bin/talon compliance ropa \
  --format json >"${OUTPUT_DIR}/ropa.json"

echo "==> Generating EU AI Act Annex IV pack (HTML + JSON)..."
docker compose exec -T talon /usr/local/bin/talon compliance annex-iv \
  --format html >"${OUTPUT_DIR}/annex-iv.html"
docker compose exec -T talon /usr/local/bin/talon compliance annex-iv \
  --format json >"${OUTPUT_DIR}/annex-iv.json"

# Basic secret-leak guard (demo uses synthetic PII only).
if grep -qiE 'sk-[a-zA-Z0-9]{20,}|Bearer[[:space:]]+[a-zA-Z0-9._-]{20,}' \
  "${OUTPUT_DIR}/evidence.signed.json" "${OUTPUT_DIR}/compliance-report.html" 2>/dev/null; then
  echo "Error: export may contain API key material; aborting." >&2
  exit 1
fi

RECORD_COUNT=0
if command -v jq >/dev/null 2>&1; then
  RECORD_COUNT=$(jq '(.records // .) | if type == "array" then length else 0 end' \
    "${OUTPUT_DIR}/evidence.signed.json" 2>/dev/null || echo 0)
fi

TALON_VERSION=$(docker compose exec -T talon /usr/local/bin/talon version 2>/dev/null | head -1 | tr -d '\r' || echo "unknown")
GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")

cat >"${OUTPUT_DIR}/manifest.json" <<EOF
{
  "generated_at": "${GENERATED_AT}",
  "git_commit": "${GIT_COMMIT}",
  "talon_version": "${TALON_VERSION}",
  "source": "examples/docker-compose demo + scripts/demo-recorder.sh",
  "record_count_estimate": ${RECORD_COUNT},
  "files": {
    "evidence_signed": "evidence.signed.json",
    "compliance_report_html": "compliance-report.html",
    "compliance_report_json": "compliance-report.json",
    "ropa_html": "ropa.html",
    "ropa_json": "ropa.json",
    "annex_iv_html": "annex-iv.html",
    "annex_iv_json": "annex-iv.json"
  },
  "verify_commands": [
    "talon audit verify --file examples/auditor-pack/evidence.signed.json",
    "open examples/auditor-pack/compliance-report.html",
    "open examples/auditor-pack/ropa.html",
    "open examples/auditor-pack/annex-iv.html"
  ],
  "claim_note": "Supporting controls and evidence for auditor review — not a completed legal filing. See LIMITATIONS.md."
}
EOF

if ! $KEEP_UP; then
  echo "==> Stopping docker-compose stack..."
  docker compose down
fi

echo ""
echo "Auditor pack written to ${OUTPUT_DIR}/"
echo "  evidence.signed.json"
echo "  compliance-report.html"
echo "  compliance-report.json"
echo "  manifest.json"
echo ""
echo "Regenerate anytime: make auditor-pack"
