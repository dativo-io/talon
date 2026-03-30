#!/usr/bin/env bash
# Smoke test section: 21_doctor_report_enforce
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 21 — Doctor, Report, Enforce (health checks, compliance summary, gateway mode)
# -----------------------------------------------------------------------------
test_section_21_doctor_report_enforce() {
  local section="21_doctor_report_enforce"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  assert_pass "talon doctor exits 0" run_talon doctor
  local doc_out; doc_out="$(run_talon doctor 2>/dev/null)"; true
  assert_pass "doctor output contains pass or Result" grep -qiE 'pass|Result' <<< "$doc_out"
  assert_pass "talon doctor --format json exits 0" run_talon doctor --format json
  assert_pass "doctor JSON is valid" jq . <<< "$(run_talon doctor --format json 2>/dev/null)"
  assert_pass "talon report exits 0" run_talon report
  local rpt_out; rpt_out="$(run_talon report 2>/dev/null)"; true
  assert_pass "report output contains evidence or cost" grep -qiE 'evidence|cost' <<< "$rpt_out"
  assert_pass "talon report --tenant default exits 0" run_talon report --tenant default
  assert_pass "talon enforce status exits 0" run_talon enforce status
  local enf_out; enf_out="$(run_talon enforce status 2>/dev/null)"; true
  assert_pass "enforce status contains mode" grep -qiE 'mode|shadow|enforce' <<< "$enf_out"
  cd "$REPO_ROOT" || true
}

