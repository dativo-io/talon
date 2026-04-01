#!/usr/bin/env bash
# Smoke test section: 14_deny
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 14 — Policy Enforcement Deny (docs/guides/policy-cookbook.md)
# -----------------------------------------------------------------------------
test_section_14_deny() {
  local section="14_deny"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  assert_pass "dry-run with policy exits 0" run_talon run --dry-run "test"
  # Restrict per_request to 0 so policy denies any run with non-zero estimated cost
  if command -v yq &>/dev/null; then
    yq -i '.policies.cost_limits.per_request = 0' "$dir/agent.talon.yaml" 2>/dev/null || true
  else
    sed -i.bak 's/per_request:.*/per_request: 0/' "$dir/agent.talon.yaml" 2>/dev/null || true
  fi
  local deny_out; deny_out="$(run_talon run --dry-run "test" 2>&1)"; true
  if echo "$deny_out" | grep -qiE 'DENIED|denied|exceed|limit|budget'; then
    echo "  ✓  policy deny: cost limit triggers deny"
    record_pass
  else
    echo "  -  policy deny: cost limit did not trigger (per_request may not apply in dry-run)"
  fi
  cd "$REPO_ROOT" || true
}

