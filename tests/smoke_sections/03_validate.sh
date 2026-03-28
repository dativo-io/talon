#!/usr/bin/env bash
# Smoke test section: 03_validate
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 03 — Policy Validation (docs/reference/configuration.md, policy cookbook)
# -----------------------------------------------------------------------------
test_section_03_validate() {
  local section="03_validate"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent --owner qa@dativo.io &>/dev/null; true
  assert_pass "talon validate exits 0" run_talon validate
  local val_out; val_out="$(run_talon validate 2>/dev/null)"; true
  assert_pass "talon validate stdout contains valid (case-insensitive)" grep -qi valid <<< "$val_out"
  assert_pass "talon validate --strict exits 0" run_talon validate --strict
  # Corrupt agent.talon.yaml with broken syntax (parser must fail)
  printf ':::broken yaml{{{\n' > "$dir/agent.talon.yaml"
  local val_err; val_err="$(run_talon validate 2>&1)"
  local val_code=$?
  if [[ $val_code -eq 0 ]]; then
    log_failure "talon validate with corrupt YAML should exit non-zero" "$val_err"
  else
    echo "  ✓  talon validate with corrupt YAML exits non-zero"
    record_pass
  fi
  # Restore: re-init with --force to get valid file again (docs/reference/configuration.md)
  run_talon init --scaffold --name smoke-agent --owner qa@dativo.io --force &>/dev/null; true
  assert_pass "talon validate --file agent.talon.yaml exits 0" run_talon validate --file "$dir/agent.talon.yaml"
  local nf_err; nf_err="$(run_talon validate --file /nonexistent.yaml 2>&1)"
  local nf_code=$?
  if [[ $nf_code -eq 0 ]]; then
    log_failure "talon validate --file /nonexistent.yaml should exit non-zero" "$nf_err"
  else
    echo "  ✓  talon validate --file /nonexistent.yaml exits non-zero"
    record_pass
  fi
  cd "$REPO_ROOT" || true
}

