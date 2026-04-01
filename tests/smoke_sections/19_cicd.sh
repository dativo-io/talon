#!/usr/bin/env bash
# Smoke test section: 19_cicd
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 19 — CI/CD (docs/guides/cicd-pipeline-governance.md)
# -----------------------------------------------------------------------------
test_section_19_cicd() {
  local section="19_cicd"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  assert_pass "talon init --scaffold --name ci-agent exits 0 non-interactive" \
    run_talon init --scaffold --name ci-agent
  smoke_tighten_limits "$dir"
  assert_pass "talon validate exits 0" run_talon validate
  assert_pass "talon run --dry-run exits 0" run_talon run --dry-run "Analyse this commit diff for security issues."
  export NO_COLOR=1
  local out; out="$(run_talon version 2>/dev/null)"; true
  # grep exits 0 if ANSI found; we want no ANSI so assert_fail passes when grep exits 1
  assert_fail "NO_COLOR=1 output has no ANSI escapes" env SMOKE_OUT="$out" bash -c 'echo "$SMOKE_OUT" | grep -qE "\x1b\[|\\\\e\["'
  cd "$REPO_ROOT" || true
}

