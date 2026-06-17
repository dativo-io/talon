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
NARRATE=0
PROOF_TOTAL=6

mkdir -p "$OUT_DIR"

# shellcheck source=../../scripts/lib/docker-compose-detect.sh
source "${SCRIPT_DIR}/../../scripts/lib/docker-compose-detect.sh"
detect_docker_compose

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

# ── Narration helpers (enabled for ./demo.sh all) ───────────────────────────

demo_intro() {
  [[ "$NARRATE" == "1" ]] || return 0
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════════╗"
  echo "║         Talon Shortlist Demo — enforce-mode governance proof         ║"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  This walkthrough proves six capabilities auditors and security teams"
  echo "  care about: governed access, policy deny with reasons, PII blocking,"
  echo "  EU egress enforcement, signed evidence, and compliance exports."
  echo ""
  explain "Gateway" "$GATEWAY"
  explain "Provider" "mock OpenAI (no real API key)"
  explain "Mode" "enforce — Talon blocks violations before they reach the LLM"
  echo ""
  echo "  ────────────────────────────────────────────────────────────────────"
  echo ""
}

proof_section() {
  local num="$1" title="$2"
  [[ "$NARRATE" == "1" ]] || return 0
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "  Proof %s of %s — %s\n" "$num" "$PROOF_TOTAL" "$title"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
}

proof_story() {
  [[ "$NARRATE" == "1" ]] || return 0
  while [[ $# -gt 0 ]]; do
    echo "  $1"
    shift
  done
  echo ""
}

explain() {
  printf "  %-14s %s\n" "$1" "$2"
}

proof_request() {
  [[ "$NARRATE" == "1" ]] || return 0
  echo "  Request"
  explain "Caller" "$1"
  explain "Model" "$2"
  [[ -n "${3:-}" ]] && explain "Payload" "$3"
  echo ""
}

proof_outcome() {
  local icon="$1" headline="$2"
  shift 2
  if [[ "$NARRATE" == "1" ]]; then
    echo "  Outcome  ${icon}  ${headline}"
    while [[ $# -gt 0 ]]; do
      echo "           $1"
      shift
    done
    echo ""
  fi
}

proof_detail() {
  [[ "$NARRATE" == "1" ]] || return 0
  echo "  Detail"
  while [[ $# -gt 0 ]]; do
    echo "    · $1"
    shift
  done
  echo ""
}

section_plain() {
  if [[ "$NARRATE" == "1" ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
  else
    echo ""
    echo "==> $1"
  fi
}

demo_finale() {
  [[ "$NARRATE" == "1" ]] || return 0
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════════╗"
  echo "║                    Shortlist demo complete ✓                         ║"
  echo "╚══════════════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  You just demonstrated:"
  echo "    1. Governed allow     — clean request forwarded with audit record"
  echo "    2. Policy deny        — model allowlist enforced with reason"
  echo "    3. PII block          — sensitive data stopped before provider call"
  echo "    4. EU egress deny     — non-EU destination blocked with evidence"
  echo "    5. Evidence integrity — HMAC signatures verify; tampering is detected"
  echo "    6. Compliance export  — RoPA + Annex IV packs ready for auditor review"
  echo ""
  echo "  Artifacts written to: ${OUT_DIR}/"
  echo "    ropa.html · annex-iv.html · evidence.signed.json"
  echo ""
  echo "  Dig deeper:"
  echo "    $COMPOSE exec talon talon audit show <evidence-id>"
  echo "    $COMPOSE exec talon talon audit list --limit 20"
  echo ""
}

# ── HTTP proofs ─────────────────────────────────────────────────────────────

post_chat() {
  local label="$1"
  local bearer="$2"
  local model="$3"
  local content="$4"
  local body_file="${OUT_DIR}/last-response.json"
  local code

  if [[ "$NARRATE" != "1" ]]; then
    echo ""
    echo "==> ${label}"
  fi

  local payload
  payload="$(jq -nc --arg model "$model" --arg content "$content" \
    '{model: $model, messages: [{role: "user", content: $content}]}')"
  code="$(curl -sS -o "$body_file" -w "%{http_code}" -X POST "$ENDPOINT" \
    -H "Authorization: Bearer ${bearer}" \
    -H "Content-Type: application/json" \
    -d "$payload")"

  if [[ "$NARRATE" == "1" ]]; then
    explain "HTTP status" "$code"
    if [[ -s "$body_file" ]]; then
      local excerpt
      excerpt="$(jq -r '.error.message // .choices[0].message.content // empty' "$body_file" 2>/dev/null | head -c 120)"
      if [[ -n "$excerpt" ]]; then
        explain "Response" "${excerpt}…"
      fi
    fi
    echo ""
  else
    echo "    HTTP ${code}"
    if [[ -s "$body_file" ]]; then
      jq -c '{error: .error.message?, choices: [.choices[0].message.content? // empty]}' "$body_file" 2>/dev/null || head -c 200 "$body_file"
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
  proof_section "1" "Governed OpenAI-compatible request"
  proof_story \
    "A legitimate app sends a chat completion through Talon's gateway." \
    "Talon identifies the caller, evaluates policy, and forwards to the mock provider."
  proof_request "shortlist-allow" "gpt-4o-mini" "benign governance question (no PII)"
  EXPECT_HTTP=200 post_chat \
    "Proof 1 — governed OpenAI-compatible request (allowed)" \
    "talon-shortlist-allow" \
    "gpt-4o-mini" \
    "Summarize key AI governance risks for a European SaaS company."
  proof_outcome "✓" "HTTP 200 — request allowed and forwarded" \
    "Evidence recorded with POLICY_ALLOWED and HMAC signature." \
    "Cost and latency tracked even for allowed traffic."
}

cmd_policy_deny() {
  require_stack
  proof_section "2" "Policy deny with explicit reason"
  proof_story \
    "The same gateway serves multiple callers with different policy profiles." \
    "This caller may only use gpt-4o-mini — requesting gpt-4o must be denied."
  proof_request "shortlist-policy-deny" "gpt-4o" "model outside caller allowlist"
  EXPECT_HTTP=403 post_chat \
    "Proof 2a — policy deny (model not in caller allowlist)" \
    "talon-shortlist-deny" \
    "gpt-4o" \
    "Summarize key AI governance risks for a European SaaS company."
  proof_outcome "✗" "HTTP 403 — routing policy denied the request" \
    "Error explains: model not in caller allowlist." \
    "Denial is audited (POLICY_DENIED_ROUTING) — not a silent drop."
}

cmd_pii_request() {
  require_stack
  proof_section "3" "PII blocked before the provider call"
  proof_story \
    "Server default is default_pii_action: block." \
    "Email and IBAN in the user message are detected before any upstream LLM call."
  proof_request "shortlist-allow" "gpt-4o-mini" "message contains email + German IBAN"
  EXPECT_HTTP=400 post_chat \
    "Proof 3 — PII blocked before provider call (server default: block)" \
    "talon-shortlist-allow" \
    "gpt-4o-mini" \
    "Customer jan@example.com has IBAN DE89370400440532013000. Help draft a support reply."
  proof_outcome "✗" "HTTP 400 — PII blocked at the gateway" \
    "No token left your infrastructure for this request." \
    "Evidence tagged POLICY_DENIED_PII_INPUT for audit review."
}

cmd_eu_strict_routing() {
  require_stack
  proof_section "4" "EU strict egress — deny non-EU destination"
  proof_story \
    "Caller shortlist-eu-strict allows egress only to EU/LOCAL regions." \
    "The mock OpenAI provider is configured region: US — so Talon denies with evidence." \
    "This is an explicit deny, not a silent reroute to another region."
  proof_request "shortlist-eu-strict" "gpt-4o-mini" "clean prompt; egress rule is what fails"
  EXPECT_HTTP=403 post_chat \
    "Proof 4 — EU strict egress: non-EU provider region denied with evidence" \
    "talon-shortlist-eu" \
    "gpt-4o-mini" \
    "Summarize key AI governance risks for a European SaaS company."
  proof_outcome "✗" "HTTP 403 — tier 0 data may not egress to US provider" \
    "Evidence includes egress_tier / POLICY_DENIED_EGRESS for auditors." \
    "Demonstrates data-sovereignty enforcement at the gateway."
}

cmd_audit() {
  require_stack
  section_plain "Audit trail — every decision leaves a signed record"
  if [[ "$NARRATE" == "1" ]]; then
    proof_story \
      "Each request above produced an evidence row in SQLite." \
      "✓ = allowed   ✗ = denied   Brackets show the primary explanation code."
    echo ""
  fi
  talon_in_container audit list --limit 10
  if [[ "$NARRATE" == "1" ]]; then
    echo ""
    proof_detail \
      "Compare the four newest rows to proofs 1–4 from this run." \
      "Use audit show <id> to inspect policy reasons, egress tier, and PII flags."
  else
    echo ""
    echo "Tip: $COMPOSE exec talon talon audit show <evidence-id>"
  fi
}

latest_evidence_id() {
  talon_in_container audit list --limit 1 2>/dev/null | grep -oE '(gw_|req_)[a-zA-Z0-9_-]+' | head -1
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
  proof_section "5" "Signed evidence verification (HMAC integrity)"
  if [[ "$NARRATE" == "1" ]]; then
    proof_story \
      "Every evidence record is HMAC-signed at write time." \
      "Auditors can independently verify that records were not altered in storage."
    explain "Evidence ID" "$id"
    echo ""
  else
    echo ""
    echo "==> Proof 5 — signature verification (${id})"
  fi
  talon_in_container audit verify "$id"
  if [[ "$NARRATE" == "1" ]]; then
    echo ""
    proof_outcome "✓" "Signature VALID — record integrity confirmed" \
      "The signing key (TALON_SIGNING_KEY) matches the server that wrote this evidence."
  fi
}

cmd_tamper_evidence() {
  require_stack
  local signed="${OUT_DIR}/evidence.signed.json"
  local tampered="${OUT_DIR}/evidence.tampered.json"

  if [[ "$NARRATE" == "1" ]]; then
    section_plain "Tamper detection — altered exports must fail verification"
    proof_story \
      "We export signed JSON, flip one field offline, and verify again." \
      "If verification still passes after tampering, the audit chain is broken."
    echo ""
  else
    echo ""
    echo "==> Export signed evidence for tamper demo"
  fi

  talon_in_container audit export --format signed-json --limit 20 >"$signed"
  if [[ "$NARRATE" != "1" ]]; then
    echo "==> Verify exported bundle"
  fi
  talon_in_container audit verify --file "/home/talon/shortlist-out/evidence.signed.json"

  if ! command -v jq >/dev/null 2>&1; then
    echo "Skip tamper step: jq not installed on host" >&2
    return 0
  fi

  if [[ "$NARRATE" == "1" ]]; then
    proof_detail "Exported $(jq '.records | length' "$signed" 2>/dev/null || echo '?') records to evidence.signed.json"
    echo "  Simulating attacker: set records[0].policy_decision.allowed = false"
    echo ""
  else
    echo ""
    echo "==> Tamper one signed field (policy_decision.allowed)"
  fi
  jq '(.records[0].policy_decision.allowed) = false' "$signed" >"$tampered"

  if [[ "$NARRATE" != "1" ]]; then
    echo "==> Verify tampered export (expect failure)"
  fi
  set +e
  talon_in_container audit verify --file "/home/talon/shortlist-out/evidence.tampered.json"
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "Error: tampered export should fail verification" >&2
    exit 1
  fi
  if [[ "$NARRATE" == "1" ]]; then
    proof_outcome "✓" "Tamper detected — verification failed as expected" \
      "Offline modification of signed fields breaks the HMAC chain." \
      "This is what you want in a compliance-grade audit trail."
  else
    echo "    Tamper detected (exit ${rc}) — expected"
  fi
}

cmd_exports() {
  require_stack
  proof_section "6" "Auditor-ready compliance exports"
  if [[ "$NARRATE" == "1" ]]; then
    proof_story \
      "Talon merges declared facts (controller, purposes, retention) with runtime" \
      "evidence from the gateway to produce documentation packs auditors expect."
    proof_detail \
      "RoPA (HTML/JSON) — GDPR Art. 30 Record of Processing Activities" \
      "Annex IV (HTML/JSON) — EU AI Act technical documentation starter pack"
    echo ""
  else
    echo ""
    echo "==> Proof 6 — auditor-ready exports (RoPA + Annex IV)"
  fi
  talon_in_container compliance ropa --format html --output /home/talon/shortlist-out/ropa.html
  talon_in_container compliance ropa --format json --output /home/talon/shortlist-out/ropa.json
  talon_in_container compliance annex-iv --format html --output /home/talon/shortlist-out/annex-iv.html
  talon_in_container compliance annex-iv --format json --output /home/talon/shortlist-out/annex-iv.json
  if [[ "$NARRATE" == "1" ]]; then
    local warnings="?"
    if command -v jq >/dev/null 2>&1; then
      warnings="$(jq '(.warnings // []) | length' "${OUT_DIR}/ropa.json" 2>/dev/null || echo "?")"
    fi
    proof_outcome "✓" "Exports written to ${OUT_DIR}/" \
      "ropa.html · ropa.json · annex-iv.html · annex-iv.json" \
      "RoPA declaration warnings: ${warnings} (demo uses pre-filled declarations)"
    proof_detail "Open ropa.html and annex-iv.html in a browser — print-to-PDF ready"
  else
    echo "    Wrote ${OUT_DIR}/ropa.html and ${OUT_DIR}/annex-iv.html"
    if command -v jq >/dev/null 2>&1; then
      local warnings
      warnings="$(jq '(.warnings // []) | length' "${OUT_DIR}/ropa.json" 2>/dev/null || echo "?")"
      echo "    RoPA declaration warnings: ${warnings}"
    fi
  fi
}

cmd_all() {
  NARRATE=1
  demo_intro
  cmd_allowed_request
  cmd_policy_deny
  cmd_pii_request
  cmd_eu_strict_routing
  cmd_audit
  cmd_verify
  cmd_tamper_evidence
  cmd_exports
  demo_finale
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
