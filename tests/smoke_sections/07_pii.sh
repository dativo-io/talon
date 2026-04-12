#!/usr/bin/env bash
# Smoke test section: 07_pii
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 07 — PII Detection (docs/explanation/what-talon-does-to-your-request.md, policy cookbook)
# -----------------------------------------------------------------------------
test_section_07_pii() {
  local section="07_pii"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  # Ensure input_scan and pii_action in policy (edit or use pack); then run with email
  run_talon run "Reply OK. User email: jan.kowalski@example.com" &>/dev/null; true
  local ev_id; ev_id="$(run_talon audit list --limit 1 2>/dev/null | awk '/req_/{print $2; exit}')"
  if [[ -n "$ev_id" ]]; then
    local show_out; show_out="$(run_talon audit show "$ev_id" 2>/dev/null)"; true
    assert_pass "evidence shows email in pii_detected or PII" \
      grep -qiE 'pii|email|jan\.kowalski' <<< "$show_out"
  else
    log_failure "PII evidence check (no evidence id from audit list)" "run audit list first or check TALON_DATA_DIR"
  fi

  run_talon run "Reply OK. IBAN: PL61109010140000071219812874" &>/dev/null; true
  ev_id="$(run_talon audit list --limit 1 2>/dev/null | awk '/req_/{print $2; exit}')"
  if [[ -n "$ev_id" ]]; then
    show_out="$(run_talon audit show "$ev_id" 2>/dev/null)"; true
    assert_pass "evidence shows IBAN detected" grep -qiE 'iban|pii' <<< "$show_out"
  fi
  # pii_action block: would need policy edit; skip if scaffold has no block_on_pii
  # pii_action redact: same
  cd "$REPO_ROOT" || true
}

