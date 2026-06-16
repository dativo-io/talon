#!/usr/bin/env bash
# North-star shortlist demo driver (#107).
#
# Usage (from examples/shortlist-demo, stack running on localhost:8080):
#   ./demo.sh allowed-request
#   ./demo.sh policy-deny
#   ./demo.sh pii-request
#   ./demo.sh eu-strict-routing
#   ./demo.sh audit
#   ./demo.sh verify [evidence-id]
#   ./demo.sh tamper-evidence
#   ./demo.sh exports
#   ./demo.sh all
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GATEWAY="${GATEWAY:-http://localhost:8080}"
ENDPOINT="${GATEWAY}/v1/proxy/openai/v1/chat/completions"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/out}"
COMPOSE="docker compose"

mkdir -p "$OUT_DIR"

dc() {
  $COMPOSE "$@"
}

talon_in_container() {
  dc exec -T talon talon "$@"
}

require_stack() {
  if ! curl -sf "${GATEWAY}/health" >/dev/null 2>&1; then
    echo "Error: Talon gateway not healthy at ${GATEWAY}" >&2
    echo "Start the stack: make shortlist-demo  (from repo root)" >&2
    exit 1
  fi
}

post_chat() {
  local label="$1"
  local bearer="$2"
  local model="$3"
  local content="$4"
  local body_file="${OUT_DIR}/last-response.json"
  local code

  echo ""
  echo "==> ${label}"
  local payload
  payload="$(jq -nc --arg model "$model" --arg content "$content" \
    '{model: $model, messages: [{role: "user", content: $content}]}')"
  code="$(curl -sS -o "$body_file" -w "%{http_code}" -X POST "$ENDPOINT" \
    -H "Authorization: Bearer ${bearer}" \
    -H "Content-Type: application/json" \
    -d "$payload")"

  echo "    HTTP ${code}"
  if [[ -s "$body_file" ]]; then
    if command -v jq >/dev/null 2>&1; then
      jq -c '{error: .error.message?, choices: [.choices[0].message.content? // empty]}' "$body_file" 2>/dev/null || head -c 200 "$body_file"
    else
      head -c 200 "$body_file"
    fi
  fi

  if [[ "${EXPECT_HTTP:-}" != "" && "$code" != "$EXPECT_HTTP" ]]; then
    echo "Error: expected HTTP ${EXPECT_HTTP}, got ${code}" >&2
    cat "$body_file" >&2 || true
    exit 1
  fi
  echo "$code"
}

cmd_allowed_request() {
  require_stack
  EXPECT_HTTP=200 post_chat \
    "Proof 1 — governed OpenAI-compatible request (allowed)" \
    "talon-shortlist-allow" \
    "gpt-4o-mini" \
    "Summarize key AI governance risks for a European SaaS company."
}

cmd_policy_deny() {
  require_stack
  EXPECT_HTTP=403 post_chat \
    "Proof 2a — policy deny (model not in caller allowlist)" \
    "talon-shortlist-deny" \
    "gpt-4o" \
    "Summarize key AI governance risks for a European SaaS company."
}

cmd_pii_request() {
  require_stack
  EXPECT_HTTP=400 post_chat \
    "Proof 3 — PII blocked before provider call (server default: block)" \
    "talon-shortlist-allow" \
    "gpt-4o-mini" \
    "Customer jan@example.com has IBAN DE89370400440532013000. Help draft a support reply."
}

cmd_eu_strict_routing() {
  require_stack
  EXPECT_HTTP=403 post_chat \
    "Proof 4 — EU strict egress: non-EU provider region denied with evidence" \
    "talon-shortlist-eu" \
    "gpt-4o-mini" \
    "Summarize key AI governance risks for a European SaaS company."
}

cmd_audit() {
  require_stack
  echo ""
  echo "==> Audit trail (latest 10 records)"
  talon_in_container audit list --limit 10
  echo ""
  echo "Tip: docker compose exec talon talon audit show <evidence-id>"
}

latest_evidence_id() {
  talon_in_container audit list --limit 1 2>/dev/null | grep -oE 'req_[a-zA-Z0-9]+' | head -1
}

cmd_verify() {
  require_stack
  local id="${1:-}"
  if [[ -z "$id" ]]; then
    id="$(latest_evidence_id)"
  fi
  if [[ -z "$id" ]]; then
    echo "Error: no evidence id found" >&2
    exit 1
  fi
  echo ""
  echo "==> Proof 5 — signature verification (${id})"
  talon_in_container audit verify "$id"
}

cmd_tamper_evidence() {
  require_stack
  local signed="${OUT_DIR}/evidence.signed.json"
  local tampered="${OUT_DIR}/evidence.tampered.json"

  echo ""
  echo "==> Export signed evidence for tamper demo"
  talon_in_container audit export --format signed-json --limit 20 >"$signed"
  talon_in_container audit verify --file "/home/talon/shortlist-out/evidence.signed.json"

  if ! command -v jq >/dev/null 2>&1; then
    echo "Skip tamper step: jq not installed on host" >&2
    return 0
  fi

  echo ""
  echo "==> Tamper one signed field (policy_decision.allowed)"
  jq '(.records[0].policy_decision.allowed) = false' "$signed" >"$tampered"

  echo "==> Verify tampered export (expect failure)"
  set +e
  talon_in_container audit verify --file "/home/talon/shortlist-out/evidence.tampered.json"
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "Error: tampered export should fail verification" >&2
    exit 1
  fi
  echo "    Tamper detected (exit ${rc}) — expected"
}

cmd_exports() {
  require_stack
  echo ""
  echo "==> Proof 6 — auditor-ready exports (RoPA + Annex IV)"
  talon_in_container compliance ropa --format html --output /home/talon/shortlist-out/ropa.html
  talon_in_container compliance ropa --format json --output /home/talon/shortlist-out/ropa.json
  talon_in_container compliance annex-iv --format html --output /home/talon/shortlist-out/annex-iv.html
  talon_in_container compliance annex-iv --format json --output /home/talon/shortlist-out/annex-iv.json
  echo "    Wrote ${OUT_DIR}/ropa.html and ${OUT_DIR}/annex-iv.html"
  if command -v jq >/dev/null 2>&1; then
    local warnings
    warnings="$(jq '(.warnings // []) | length' "${OUT_DIR}/ropa.json" 2>/dev/null || echo "?")"
    echo "    RoPA declaration warnings: ${warnings}"
  fi
}

cmd_all() {
  cmd_allowed_request
  cmd_policy_deny
  cmd_pii_request
  cmd_eu_strict_routing
  cmd_audit
  cmd_verify
  cmd_tamper_evidence
  cmd_exports
  echo ""
  echo "=== Shortlist demo complete ==="
  echo "Outputs: ${OUT_DIR}/"
}

usage() {
  sed -n '3,14p' "$0" | tr -d '#'
  echo ""
  echo "Environment: GATEWAY (default http://localhost:8080), OUT_DIR (default ./out)"
}

main() {
  local cmd="${1:-}"
  shift || true
  if [[ "$cmd" == "all" || "$cmd" == "allowed-request" || "$cmd" == "policy-deny" || "$cmd" == "pii-request" || "$cmd" == "eu-strict-routing" ]]; then
    if ! command -v jq >/dev/null 2>&1; then
      echo "Error: jq is required for demo.sh request payloads" >&2
      exit 1
    fi
  fi
  case "$cmd" in
    allowed-request) cmd_allowed_request ;;
    policy-deny) cmd_policy_deny ;;
    pii-request) cmd_pii_request ;;
    eu-strict-routing) cmd_eu_strict_routing ;;
    audit) cmd_audit ;;
    verify) cmd_verify "${1:-}" ;;
    tamper-evidence) cmd_tamper_evidence ;;
    exports) cmd_exports ;;
    all) cmd_all ;;
    -h|--help|help|"") usage ;;
    *)
      echo "Unknown command: $cmd" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
