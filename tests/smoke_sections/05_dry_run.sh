#!/usr/bin/env bash
# Smoke test section: 05_dry_run
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 05 — Agent Run Dry Run (docs/guides/first-governed-agent.md, PERSONA_GUIDES DevOps)
# -----------------------------------------------------------------------------
test_section_05_dry_run() {
  local section="05_dry_run"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  assert_pass "talon run --dry-run exits 0" run_talon run --dry-run "What is the capital of France?"
  local out; out="$(run_talon run --dry-run "What is the capital of France?" 2>/dev/null)"; true
  assert_pass "dry-run stdout contains ALLOWED or dry (case-insensitive)" \
    grep -qiE 'ALLOWED|dry' <<< "$out"
  assert_pass "talon run --dry-run --agent smoke-agent exits 0" \
    run_talon run --dry-run "test" --agent smoke-agent
  cd "$REPO_ROOT" || true
}

