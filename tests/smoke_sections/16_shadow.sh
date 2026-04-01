#!/usr/bin/env bash
# Smoke test section: 16_shadow
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 16 — Shadow Mode (docs/explanation/what-talon-does-to-your-request.md Step 7, evidence schema)
# -----------------------------------------------------------------------------
test_section_16_shadow() {
  local section="16_shadow"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  # Set mode: shadow in gateway or policy; then IBAN prompt passes; evidence shows shadow_violations or observation_mode_override
  # Without gateway config, we only test that run still works; shadow is gateway-level
  assert_pass "run with policy exits 0" run_talon run "Reply OK"
  cd "$REPO_ROOT" || true
}

