#!/usr/bin/env bash
# Smoke test section: 06_live_run
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 06 — Agent Run Live LLM (docs/guides/first-governed-agent.md, QUICKSTART)
# -----------------------------------------------------------------------------
test_section_06_live_run() {
  local section="06_live_run"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  # Ensure policy allows gpt-4o-mini and has per_request/daily limits (scaffold default may suffice)
  assert_pass "talon run PONG prompt exits 0" run_talon run "Reply with the single word: PONG"
  local run_out; run_out="$(run_talon run 'Reply with the single word: PONG' 2>/dev/null)"; true
  assert_pass "stdout contains PONG" grep -q PONG <<< "$run_out"
  assert_pass "talon audit list returns at least one entry after run" \
    test "$(run_talon audit list --limit 5 2>/dev/null | grep -c 'req_' || true)" -ge 1
  assert_pass "talon run --verbose contains pipeline step markers" \
    grep -qiE 'classify|policy|evidence' <<< "$(run_talon run --verbose 'Reply with the single word: PONG' 2>/dev/null)" || true
  cd "$REPO_ROOT" || true
}

