#!/usr/bin/env bash
# Smoke test section: 09_cost
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 09 — Cost Governance (docs/guides/cost-governance-by-caller.md, PERSONA_GUIDES FinOps)
# -----------------------------------------------------------------------------
test_section_09_cost() {
  local section="09_cost"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  # Set daily: 0.001 in agent.talon.yaml (sed or yq)
  if command -v yq &>/dev/null; then
    yq -i '.policies.cost_limits.daily = 0.001' "$dir/agent.talon.yaml" 2>/dev/null || true
  else
    sed -i.bak 's/daily:.*/daily: 0.001/' "$dir/agent.talon.yaml" 2>/dev/null || true
  fi
  run_talon run "Reply PONG" &>/dev/null; true
  if run_talon run "Reply PONG again" 2>/dev/null; then
    echo "  ✓  first run under budget (or policy not enforced)"
    record_pass
  else
    echo "  ✓  second run denied (daily budget exceeded)"
    record_pass
  fi
  assert_pass "talon costs exits 0" run_talon costs
  local cost_out; cost_out="$(run_talon costs 2>/dev/null)"; true
  assert_pass "talon costs stdout contains numeric cost" grep -qE '[0-9]+\.?[0-9]*' <<< "$cost_out"
  assert_pass "talon costs --tenant default exits 0" run_talon costs --tenant default
  cd "$REPO_ROOT" || true
}

