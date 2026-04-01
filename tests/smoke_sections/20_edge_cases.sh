#!/usr/bin/env bash
# Smoke test section: 20_edge_cases
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 20 — Negative and Edge Cases
# -----------------------------------------------------------------------------
test_section_20_edge_cases() {
  local section="20_edge"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  smoke_tighten_limits "$dir"
  local run_no_args_err; run_no_args_err="$(run_talon run 2>&1)"; local c=$?
  if [[ $c -eq 0 ]]; then
    log_failure "talon run with no args should exit non-zero" "$run_no_args_err"
  else
    echo "  ✓  talon run with no args exits non-zero"
    record_pass
  fi
  local run_empty_err; run_empty_err="$(run_talon run "" 2>&1)"; c=$?
  if [[ $c -eq 0 ]]; then
    log_failure "talon run \"\" should exit non-zero" "$run_empty_err"
  else
    echo "  ✓  talon run \"\" exits non-zero"
    record_pass
  fi
  local secrets_err; secrets_err="$(run_talon secrets set 2>&1)"; c=$?
  if [[ $c -eq 0 ]]; then
    log_failure "talon secrets set with no args should exit non-zero" "$secrets_err"
  else
    echo "  ✓  talon secrets set with no args exits non-zero"
    record_pass
  fi
  local audit_show_err; audit_show_err="$(run_talon audit show nonexistent-id-00000 2>&1)"; c=$?
  if [[ $c -eq 0 ]]; then
    log_failure "talon audit show nonexistent-id should exit non-zero" "$audit_show_err"
  else
    echo "  ✓  talon audit show nonexistent-id exits non-zero"
    record_pass
  fi
  local serve_port_err; serve_port_err="$(run_talon serve --port 99999 2>&1)"; c=$?
  if [[ $c -eq 0 ]]; then
    log_failure "talon serve --port 99999 should exit non-zero" "$serve_port_err"
  else
    echo "  ✓  talon serve --port 99999 exits non-zero"
    record_pass
  fi
  # Long prompt no panic
  local long_prompt; long_prompt="$(printf 'a%.0s' {1..10001})"
  local err; err="$(run_talon run --dry-run "$long_prompt" 2>&1)"; true
  if echo "$err" | grep -qE 'panic|goroutine|runtime'; then
    log_failure "dry-run with long prompt must not produce Go panic" "$err"
  else
    echo "  ✓  dry-run with long prompt does not panic"
    record_pass
  fi
  # Three concurrent dry-runs
  run_talon run --dry-run "test" & run_talon run --dry-run "test" & run_talon run --dry-run "test" & wait
  echo "  ✓  three concurrent dry-runs completed"
  record_pass
  cd "$REPO_ROOT" || true
}

