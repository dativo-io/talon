#!/usr/bin/env bash
# Smoke test section: 17_config_provider
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 17 — CLI Config and Provider (QUICKSTART, PERSONA_GUIDES)
# -----------------------------------------------------------------------------
test_section_17_config_provider() {
  local section="17_config"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  assert_pass "talon config show exits 0" run_talon config show
  local cfg_out; cfg_out="$(run_talon config show 2>/dev/null)"; true
  assert_pass "config show prints data_dir or Data directory" grep -qiE 'data_dir|Data directory' <<< "$cfg_out"
  assert_pass "talon validate --strict exits 0" run_talon validate --strict
  assert_pass "talon provider list exits 0" run_talon provider list
  local prov; prov="$(run_talon provider list 2>/dev/null)"; true
  assert_pass "talon provider list lists openai" grep -qi openai <<< "$prov"
  assert_pass "talon provider info openai exits 0" run_talon provider info openai
  local info_out; info_out="$(run_talon provider info openai 2>/dev/null)"; true
  assert_pass "provider info shows Jurisdiction" grep -qi 'Jurisdiction' <<< "$info_out"
  assert_pass "talon provider allowed exits 0" run_talon provider allowed
  assert_pass "talon provider test exits 0 when key valid" run_talon provider test 2>/dev/null || true
  cd "$REPO_ROOT" || true
}

