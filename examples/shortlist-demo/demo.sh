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

# Match Talon CLI separators (audit show, init wizard).
readonly DEMO_SEP='─────────────────────────────────────────────────────'
readonly DEMO_WIDE_SEP='─────────────────────────────────────────────────────────'

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
    echo "✗ Talon gateway not healthy at ${GATEWAY}" >&2
    echo "  → Start the stack: make shortlist-demo  (from repo root)" >&2
    exit 1
  fi
}

# switch_agent <name> — restart the gateway serving a different agent (#266).
# This demo deliberately serves one agent per gateway process (agents_dir
# discovery — #267, shipped — could serve every proof identity at once);
# proofs that exercise another identity switch by restarting the talon
# service with TALON_ACT_AGENT and waiting for health.
CURRENT_ACT_AGENT="shortlist-allow"
switch_agent() {
  local want="$1"
  [[ "$CURRENT_ACT_AGENT" == "$want" ]] && return 0
  echo "  ↻  switching gateway agent: ${CURRENT_ACT_AGENT} → ${want} (#266; one agent per process by design)"
  TALON_ACT_AGENT="$want" dc up -d talon >/dev/null 2>&1
  local _attempt
  for _attempt in $(seq 1 30); do
    curl -sf "${GATEWAY}/health" >/dev/null 2>&1 && break
    sleep 1
  done
  require_stack
  CURRENT_ACT_AGENT="$want"
}

# ── Output helpers (narrated ./demo.sh all; mirrors talon init / audit / doctor) ──

demo_intro() {
  [[ "$NARRATE" == "1" ]] || return 0
  echo ""
  echo "🦅 Dativo Talon — Shortlist Demo (#107)"
  echo "$DEMO_WIDE_SEP"
  echo "Enforce-mode governance proof — mock OpenAI provider, no real API key."
  echo ""
  echo "  Proves: allow · policy deny · PII block · EU egress · signed evidence · compliance export"
  echo ""
  kv "Gateway" "$GATEWAY"
  kv "Provider" "mock OpenAI"
  kv "Mode" "enforce (violations blocked before the LLM)"
  echo ""
}

kv() {
  printf "  %-18s %s\n" "$1:" "$2"
}

proof_section() {
  local num="$1" title="$2"
  [[ "$NARRATE" == "1" ]] || return 0
  echo ""
  echo "$DEMO_SEP"
  printf "[%s/%s] %s\n" "$num" "$PROOF_TOTAL" "$title"
  echo "$DEMO_SEP"
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

proof_request() {
  [[ "$NARRATE" == "1" ]] || return 0
  echo "  Request"
  kv "Agent" "$1"
  kv "Model" "$2"
  [[ -n "${3:-}" ]] && kv "Payload" "$3"
  echo ""
}

status_icon() {
  local code="$1"
  case "$code" in
    2*) echo "✓" ;;
    *) echo "✗" ;;
  esac
}

proof_outcome() {
  local icon="$1" headline="$2"
  shift 2
  if [[ "$NARRATE" == "1" ]]; then
    printf "  %s %s\n" "$icon" "$headline"
    while [[ $# -gt 0 ]]; do
      echo "    → $1"
      shift
    done
    echo ""
  fi
}

proof_detail() {
  [[ "$NARRATE" == "1" ]] || return 0
  while [[ $# -gt 0 ]]; do
    echo "    → $1"
    shift
  done
  echo ""
}

section_plain() {
  if [[ "$NARRATE" == "1" ]]; then
    echo ""
    echo "$DEMO_SEP"
    echo "$1"
    echo "$DEMO_SEP"
    echo ""
  else
    echo ""
    echo "==> $1"
  fi
}

# Indent Talon CLI output so it reads as nested under the demo script.
talon_pretty() {
  if [[ "$NARRATE" == "1" ]]; then
    talon_in_container "$@" | sed 's/^/  /'
  else
    talon_in_container "$@"
  fi
}

# Compact summary from `talon audit verify --file` (skip per-record spam in narrate mode).
verify_file_summary() {
  local path="$1"
  talon_in_container audit verify --file "$path" 2>&1 | grep -E '^(File:|Total records:|Valid records:|Invalid records:|Missing signature:|Hint:)' | sed 's/^/  /' || true
}

# Compliance export writes WARNING lines to stderr; suppress in narrated mode
# (warnings stay in HTML/JSON) but keep them in a host-side file so a failure
# is diagnosable from CI logs alone (#258).
compliance_export() {
  local rc=0
  local stderr_file="${OUT_DIR}/compliance.stderr"
  if [[ "$NARRATE" == "1" ]]; then
    talon_in_container compliance "$@" >/dev/null 2>"$stderr_file" || rc=$?
  else
    talon_in_container compliance "$@" 2> >(tee "$stderr_file" >&2) || rc=$?
  fi
  if [[ "$rc" -ne 0 ]]; then
    echo "✗ compliance export failed: talon compliance $*" >&2
    if [[ -s "$stderr_file" ]]; then
      echo "  stderr:" >&2
      sed 's/^/    /' "$stderr_file" >&2
    fi
    exit "$rc"
  fi
}

export_consistency_note() {
  [[ "$NARRATE" == "1" ]] || return 0
  if ! command -v jq >/dev/null 2>&1; then
    return 0
  fi
  local msg
  # `|| true` keeps an unreadable/missing export from killing the demo via
  # set -e with jq's own error hidden by 2>/dev/null (#258).
  msg="$(jq -r '.warnings[]? | select(startswith("consistency:"))' "${OUT_DIR}/ropa.json" 2>/dev/null | head -1 || true)"
  [[ -n "$msg" ]] || return 0
  echo ""
  echo "  Note (expected for this demo)"
  echo "    ⚠ RoPA reports one consistency warning — not a failure."
  echo "    → Declared data_residency: eu (agent.talon.yaml)"
  echo "    → Mock OpenAI provider region: US (needed for Proof 4 egress deny)"
  echo "    → Talon surfaces the mismatch in exports so auditors see declared vs observed flows"
  echo "    → Full text is in out/ropa.json and the warnings box in out/ropa.html"
  echo ""
}

demo_finale() {
  [[ "$NARRATE" == "1" ]] || return 0
  echo ""
  echo "$DEMO_WIDE_SEP"
  echo "📋 Shortlist demo complete"
  echo "$DEMO_WIDE_SEP"
  echo ""
  echo "  ✓ Governed allow      — clean request forwarded with audit record"
  echo "  ✓ Policy deny         — model allowlist enforced with reason"
  echo "  ✓ PII block           — sensitive data stopped before provider call"
  echo "  ✓ EU egress deny      — non-EU destination blocked with evidence"
  echo "  ✓ Evidence integrity  — HMAC verify passes; tampering is detected"
  echo "  ✓ Compliance export   — RoPA + Annex IV packs for auditor review"
  echo ""
  echo "  Artifacts:"
  kv "Directory" "$OUT_DIR"
  echo "    ropa.html · annex-iv.html · evidence.signed.json"
  echo ""
  echo "  Next steps:"
  echo "    → $COMPOSE exec talon talon audit show <evidence-id>"
  echo "    → $COMPOSE exec talon talon audit list --limit 20"
  echo "    → open ${OUT_DIR}/ropa.html and ${OUT_DIR}/annex-iv.html"
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
    kv "HTTP status" "$code $(status_icon "$code")"
    if [[ -s "$body_file" ]]; then
      local excerpt
      excerpt="$(jq -r '.error.message // .choices[0].message.content // empty' "$body_file" 2>/dev/null | head -c 120)"
      if [[ -n "$excerpt" ]]; then
        kv "Response" "${excerpt}…"
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
    echo "✗ Expected HTTP ${EXPECT_HTTP}, got ${code}" >&2
    cat "$body_file" >&2 || true
    exit 1
  fi
}

cmd_allowed_request() {
  require_stack
  switch_agent "shortlist-allow"
  proof_section "1" "Governed OpenAI-compatible request"
  proof_story \
    "A legitimate app sends a chat completion through Talon's gateway." \
    "Talon resolves the agent key, evaluates the effective policy, and forwards to the mock provider."
  proof_request "shortlist-allow" "gpt-4o-mini" "benign governance question (no PII)"
  EXPECT_HTTP=200 post_chat \
    "Proof 1 — governed OpenAI-compatible request (allowed)" \
    "talon-shortlist-allow" \
    "gpt-4o-mini" \
    "Summarize key AI governance risks for a European SaaS company."
  proof_outcome "✓" "HTTP 200 — request allowed and forwarded" \
    "Evidence recorded with POLICY_ALLOWED and HMAC signature" \
    "Cost and latency tracked even for allowed traffic"
}

cmd_policy_deny() {
  require_stack
  switch_agent "shortlist-policy-deny"
  proof_section "2" "Policy deny with explicit reason"
  proof_story \
    "Each policy profile is its own agent — the demo switches which agent the gateway serves (#266)." \
    "This agent may only use gpt-4o-mini — requesting gpt-4o must be denied."
  proof_request "shortlist-policy-deny" "gpt-4o" "model outside agent allowlist"
  EXPECT_HTTP=403 post_chat \
    "Proof 2a — policy deny (model not in agent allowlist)" \
    "talon-shortlist-deny" \
    "gpt-4o" \
    "Summarize key AI governance risks for a European SaaS company."
  proof_outcome "✗" "HTTP 403 — routing policy denied the request" \
    "Error: model not in agent allowlist" \
    "Audited as POLICY_DENIED_ROUTING — not a silent drop"
}

cmd_pii_request() {
  require_stack
  switch_agent "shortlist-allow"
  proof_section "3" "PII blocked before the provider call"
  proof_story \
    "Server default is organization_policy.defaults.pii_action: block." \
    "Email and IBAN in the user message are detected before any upstream LLM call."
  proof_request "shortlist-allow" "gpt-4o-mini" "message contains email + German IBAN"
  EXPECT_HTTP=400 post_chat \
    "Proof 3 — PII blocked before provider call (server default: block)" \
    "talon-shortlist-allow" \
    "gpt-4o-mini" \
    "Customer jan@example.com has IBAN DE89370400440532013000. Help draft a support reply."
  proof_outcome "✗" "HTTP 400 — PII blocked at the gateway" \
    "No token left your infrastructure for this request" \
    "Audited as POLICY_DENIED_PII_INPUT"
}

cmd_eu_strict_routing() {
  require_stack
  switch_agent "shortlist-eu-strict"
  proof_section "4" "EU strict egress — deny non-EU destination"
  proof_story \
    "Agent shortlist-eu-strict allows egress only to EU/LOCAL regions." \
    "Mock OpenAI provider is region: US — Talon denies with evidence." \
    "Explicit deny, not a silent reroute to another region."
  proof_request "shortlist-eu-strict" "gpt-4o-mini" "clean prompt; egress rule is what fails"
  EXPECT_HTTP=403 post_chat \
    "Proof 4 — EU strict egress: non-EU provider region denied with evidence" \
    "talon-shortlist-eu" \
    "gpt-4o-mini" \
    "Summarize key AI governance risks for a European SaaS company."
  proof_outcome "✗" "HTTP 403 — tier 0 data may not egress to US provider" \
    "Evidence includes POLICY_DENIED_EGRESS for auditors" \
    "Demonstrates data-sovereignty enforcement at the gateway"
}

cmd_audit() {
  require_stack
  switch_agent "shortlist-allow"
  section_plain "Audit trail — every decision leaves a signed record"
  if [[ "$NARRATE" == "1" ]]; then
    proof_story \
      "Each request above produced an evidence row in SQLite." \
      "✓ = allowed   ✗ = denied   [brackets] = primary explanation code"
    echo ""
  fi
  talon_pretty audit list --limit 10
  if [[ "$NARRATE" == "1" ]]; then
    echo ""
    proof_detail \
      "Compare the four newest rows to proofs 1–4 from this run" \
      "Run: $COMPOSE exec talon talon audit show <evidence-id>"
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
    echo "✗ No evidence id found" >&2
    exit 1
  fi
  proof_section "5" "Signed evidence verification (HMAC integrity)"
  if [[ "$NARRATE" == "1" ]]; then
    proof_story \
      "Every evidence record is HMAC-signed at write time." \
      "Auditors can independently verify records were not altered in storage."
    kv "Evidence ID" "$id"
    echo ""
  else
    echo ""
    echo "==> Proof 5 — signature verification (${id})"
  fi
  talon_pretty audit verify "$id"
  if [[ "$NARRATE" == "1" ]]; then
    echo ""
    proof_outcome "✓" "Signature VALID — record integrity confirmed" \
      "TALON_SIGNING_KEY matches the server that wrote this evidence"
  fi
}

cmd_tamper_evidence() {
  require_stack
  local signed="${OUT_DIR}/evidence.signed.json"
  local tampered="${OUT_DIR}/evidence.tampered.json"

  if [[ "$NARRATE" == "1" ]]; then
    section_plain "Tamper detection — altered exports must fail verification"
    proof_story \
      "Export signed JSON, flip one field offline, verify again." \
      "If verification still passes after tampering, the audit chain is broken."
    echo ""
  else
    echo ""
    echo "==> Export signed evidence for tamper demo"
  fi

  talon_in_container audit export --format signed-json --limit 20 >"$signed"
  if [[ "$NARRATE" == "1" ]]; then
    echo "  Signed export (expected: all valid)"
    verify_file_summary "/home/talon/shortlist-out/evidence.signed.json"
    talon_in_container audit verify --file "/home/talon/shortlist-out/evidence.signed.json" >/dev/null 2>&1 \
      || { echo "✗ Signed export verification failed" >&2; exit 1; }
    echo ""
  else
    echo "==> Verify exported bundle"
    talon_in_container audit verify --file "/home/talon/shortlist-out/evidence.signed.json"
  fi

  if ! command -v jq >/dev/null 2>&1; then
    echo "⚠ Skip tamper step: jq not installed on host" >&2
    return 0
  fi

  if [[ "$NARRATE" == "1" ]]; then
    proof_detail "Exported $(jq '.records | length' "$signed" 2>/dev/null || echo '?') records → evidence.signed.json"
    echo "  Simulating attacker: flip records[0].policy_decision.allowed"
    echo ""
  else
    echo ""
    echo "==> Tamper one signed field (flip policy_decision.allowed)"
  fi
  jq '(.records[0].policy_decision.allowed) |= not' "$signed" >"$tampered"

  if [[ "$NARRATE" != "1" ]]; then
    echo "==> Verify tampered export (expect failure)"
  else
    echo "  Tampered export (expected: invalid records > 0)"
  fi
  set +e
  if [[ "$NARRATE" == "1" ]]; then
    verify_file_summary "/home/talon/shortlist-out/evidence.tampered.json"
    talon_in_container audit verify --file "/home/talon/shortlist-out/evidence.tampered.json" >/dev/null 2>&1
    local rc=$?
  else
    talon_in_container audit verify --file "/home/talon/shortlist-out/evidence.tampered.json"
    local rc=$?
  fi
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "✗ Tampered export should fail verification" >&2
    exit 1
  fi
  if [[ "$NARRATE" == "1" ]]; then
    echo ""
    proof_outcome "✓" "Tamper detected — verification failed as expected" \
      "Offline modification breaks the HMAC chain" \
      "Compliance-grade audit trail behaviour"
  else
    echo "    Tamper detected (exit ${rc}) — expected"
  fi
}

cmd_exports() {
  require_stack
  proof_section "6" "Auditor-ready compliance exports"
  if [[ "$NARRATE" == "1" ]]; then
    proof_story \
      "Talon merges declared facts with runtime gateway evidence" \
      "to produce documentation packs auditors expect."
    proof_detail \
      "RoPA (HTML/JSON) — GDPR Art. 30 Record of Processing Activities" \
      "Annex IV (HTML/JSON) — EU AI Act technical documentation starter pack"
    echo ""
  else
    echo ""
    echo "==> Proof 6 — auditor-ready exports (RoPA + Annex IV)"
  fi
  if [[ "$NARRATE" == "1" ]]; then
    echo "  Generating RoPA and Annex IV (warnings captured in HTML/JSON, not echoed here)…"
    echo ""
  fi
  compliance_export ropa --format html --output /home/talon/shortlist-out/ropa.html
  compliance_export ropa --format json --output /home/talon/shortlist-out/ropa.json
  compliance_export annex-iv --format html --output /home/talon/shortlist-out/annex-iv.html
  compliance_export annex-iv --format json --output /home/talon/shortlist-out/annex-iv.json
  # The container writes these 0600 under its own uid; on Linux hosts the
  # host-side jq reads below (and verify-shortlist-demo.sh) would get EACCES
  # through the bind mount (#258). Demo artifacts are non-sensitive.
  dc exec -T talon sh -c 'chmod 644 /home/talon/shortlist-out/*.html /home/talon/shortlist-out/*.json' || true
  export_consistency_note
  if [[ "$NARRATE" == "1" ]]; then
    local warnings="?"
    local consistency="0"
    if command -v jq >/dev/null 2>&1; then
      warnings="$(jq '(.warnings // []) | length' "${OUT_DIR}/ropa.json" 2>/dev/null || echo "?")"
      consistency="$(jq '[.warnings[]? | select(startswith("consistency:"))] | length' "${OUT_DIR}/ropa.json" 2>/dev/null || echo "0")"
    fi
    proof_outcome "✓" "Exports written to ${OUT_DIR}/" \
      "ropa.html · ropa.json · annex-iv.html · annex-iv.json" \
      "RoPA warnings: ${warnings} (${consistency} expected consistency check for this demo)"
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
      echo "✗ jq is required for demo.sh request payloads" >&2
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
