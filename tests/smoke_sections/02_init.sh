#!/usr/bin/env bash
# Smoke test section: 02_init
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 02 — Project Initialisation (docs/reference/configuration.md, QUICKSTART)
# -----------------------------------------------------------------------------
test_section_02_init() {
  local section="02_init"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  # talon init --scaffold --name smoke-agent --owner qa@dativo.io in clean temp dir exits 0
  assert_pass "talon init --scaffold --name smoke-agent --owner qa@dativo.io exits 0" \
    run_talon init --scaffold --name smoke-agent --owner qa@dativo.io
  assert_pass "agent.talon.yaml exists" test -f "$dir/agent.talon.yaml"
  assert_pass "talon.config.yaml exists" test -f "$dir/talon.config.yaml"
  # talon init --list-providers exits 0 and stdout contains openai
  assert_pass "talon init --list-providers exits 0" run_talon init --list-providers
  local prov_out; prov_out="$(run_talon init --list-providers 2>/dev/null)"; true
  assert_pass "talon init --list-providers contains openai" grep -qi openai <<< "$prov_out"
  assert_pass "talon init --list-packs exits 0" run_talon init --list-packs
  local packs_out; packs_out="$(run_talon init --list-packs 2>/dev/null)"; true
  assert_pass "talon init --list-packs contains crewai" grep -q crewai <<< "$packs_out"
  # CrewAI pack: init with --pack crewai produces agent + config with multi-agent callers
  local crewai_dir; crewai_dir="$(setup_section_dir "02_init_crewai")"
  cd "$crewai_dir" || exit 1
  assert_pass "talon init --pack crewai --name smoke-crew --force exits 0" run_talon init --pack crewai --name smoke-crew --force
  assert_pass "crewai init creates agent.talon.yaml" test -f "$crewai_dir/agent.talon.yaml"
  assert_pass "crewai init creates talon.config.yaml" test -f "$crewai_dir/talon.config.yaml"
  assert_pass "crewai agent.talon.yaml contains crewai-crew" grep -q crewai-crew "$crewai_dir/agent.talon.yaml"
  assert_pass "crewai talon.config.yaml contains crew callers" grep -q "talon-gw-crew-researcher" "$crewai_dir/talon.config.yaml"
  # Compliance overlay: --compliance gdpr merges into generated policy
  local gdpr_dir; gdpr_dir="$(setup_section_dir "02_init_compliance")"
  cd "$gdpr_dir" || exit 1
  assert_pass "talon init --pack langchain --compliance gdpr --name smoke-gdpr --force exits 0" \
    run_talon init --pack langchain --compliance gdpr --name smoke-gdpr --force
  assert_pass "compliance gdpr overlay: agent.talon.yaml contains gdpr or data_residency eu" \
    grep -qE 'gdpr|data_residency:.*eu' "$gdpr_dir/agent.talon.yaml"
  cd "$dir" || exit 1
  # Running talon init again in same dir exits non-zero (files already exist)
  local init_err; init_err="$(run_talon init --scaffold --name other 2>&1)"
  local init_code=$?
  if [[ $init_code -eq 0 ]]; then
    log_failure "init again in same dir should exit non-zero (files already exist)" "$init_err"
  else
    echo "  ✓  talon init again in same dir exits non-zero (files already exist)"
    record_pass
  fi
  local pack_dir; pack_dir="$(setup_section_dir "02_init_pack")"
  cd "$pack_dir" || exit 1
  assert_pass "talon init --pack openclaw exits 0" run_talon init --pack openclaw --name pack-test --force
  assert_pass "pack init creates agent.talon.yaml" test -f "$pack_dir/agent.talon.yaml"
  cd "$REPO_ROOT" || true
}

