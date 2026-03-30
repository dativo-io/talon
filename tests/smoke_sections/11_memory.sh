#!/usr/bin/env bash
# Smoke test section: 11_memory
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 11 — Agent Memory (docs/MEMORY_GOVERNANCE.md, docs/guides/memory-verification.md)
# -----------------------------------------------------------------------------
test_section_11_memory() {
  local section="11_memory"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  # Enable memory in policy (scaffold may have memory.enabled; if not, skip or enable)
  if grep -q "enabled: true" "$dir/agent.talon.yaml" 2>/dev/null || grep -q "memory:" "$dir/agent.talon.yaml" 2>/dev/null; then
    assert_pass "talon run remember FALCON exits 0" run_talon run "Remember: the project codename is FALCON."
    assert_pass "talon memory list exits 0" run_talon memory list
    assert_pass "talon memory list --agent smoke-agent exits 0" run_talon memory list --agent smoke-agent
    assert_pass "talon memory search exits 0" run_talon memory search "FALCON"
    assert_pass "talon memory health exits 0" run_talon memory health
    assert_pass "talon memory audit exits 0" run_talon memory audit
  else
    echo "  -  (skip memory tests: enable memory in policy)"
  fi
  cd "$REPO_ROOT" || true
}

