#!/usr/bin/env bash
# Smoke test section: 15_multi_tenant
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 15 — Multi-Tenant Isolation (docs/guides/multi-tenant-msp.md)
# -----------------------------------------------------------------------------
test_section_15_multi_tenant() {
  local section="15_multi_tenant"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  local tenant_key_a="key-tenant-a"
  local tenant_key_b="key-tenant-b"
  export TALON_TENANT_KEY="$tenant_key_a"
  run_talon run --tenant tenant-a "Hello from A" &>/dev/null; true
  run_talon run --tenant tenant-b "Hello from B" &>/dev/null; true
  assert_pass "talon run --tenant tenant-a exits 0" run_talon run --tenant tenant-a "Hello from A"
  assert_pass "talon run --tenant tenant-b exits 0" run_talon run --tenant tenant-b "Hello from B"
  local list_a; list_a="$(run_talon audit list --tenant tenant-a 2>/dev/null)"; true
  assert_fail "audit list tenant-a has no tenant-b entries" env SMOKE_LIST_A="$list_a" bash -c 'echo "$SMOKE_LIST_A" | grep -q "tenant-b"'
  # Restore default API keys for remaining sections
  export TALON_TENANT_KEY="${TALON_TENANT_KEY:-smoke-test-key}"
  cd "$REPO_ROOT" || true
}

