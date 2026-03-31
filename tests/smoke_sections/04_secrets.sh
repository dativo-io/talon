#!/usr/bin/env bash
# Smoke test section: 04_secrets
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 04 — Secrets Vault (docs/reference/configuration.md, PERSONA_GUIDES SecOps)
# -----------------------------------------------------------------------------
test_section_04_secrets() {
  local section="04_secrets"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  if [[ -n "${OPENAI_API_KEY:-}" ]]; then
    assert_pass "talon secrets set openai-api-key exits 0" \
      run_talon secrets set openai-api-key "$OPENAI_API_KEY"
  else
    assert_pass "vault has openai-api-key (pre-set)" run_talon secrets list 2>/dev/null
  fi
  assert_pass "talon secrets list exits 0" run_talon secrets list
  local list_out; list_out="$(run_talon secrets list 2>/dev/null)"; true
  assert_pass "talon secrets list contains openai-api-key" grep -q openai-api-key <<< "$list_out"
  assert_fail "talon secrets list does not contain literal API key" grep -q "sk-" <<< "$list_out"
  assert_pass "talon secrets audit exits 0" run_talon secrets audit
  local audit_out; audit_out="$(run_talon secrets audit 2>/dev/null)"; true
  assert_pass "talon secrets audit contains openai-api-key" grep -q openai-api-key <<< "$audit_out"
  if [[ -n "${OPENAI_API_KEY:-}" ]]; then
    assert_pass "talon secrets rotate openai-api-key exits 0" run_talon secrets rotate openai-api-key
    local audit2; audit2="$(run_talon secrets audit 2>/dev/null)"; true
    assert_pass "after rotate, secrets audit shows second access log entry" \
      test "$(grep -c openai-api-key <<< "$audit2" || true)" -ge 2
  fi
  assert_pass "talon secrets set second-secret exits 0" run_talon secrets set second-secret "hello-world"
  list_out="$(run_talon secrets list 2>/dev/null)"; true
  assert_pass "talon secrets list shows both secrets" \
    grep -q second-secret <<< "$list_out" && grep -q openai-api-key <<< "$list_out"
  cd "$REPO_ROOT" || true
}

