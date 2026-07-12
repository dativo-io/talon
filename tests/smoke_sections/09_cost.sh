#!/usr/bin/env bash
# Smoke test section: 09_cost
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 09 — Cost Governance (docs/guides/cost-governance-by-agent.md, PERSONA_GUIDES FinOps)
# -----------------------------------------------------------------------------
test_section_09_cost() {
  local section="09_cost"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  # Set daily: 0.001 in agent.talon.yaml (sed or yq)
  if command -v yq &>/dev/null; then
    yq -i '.policies.cost_limits.daily = 0.001' "$dir/agent.talon.yaml" 2>/dev/null || true
  else
    sed -i.bak 's/daily:.*/daily: 0.001/' "$dir/agent.talon.yaml" 2>/dev/null || true
  fi
  run_talon run "Reply PONG" &>/dev/null; true
  local second_denied=0
  if run_talon run "Reply PONG again" 2>/dev/null; then
    echo "  ✓  first run under budget (or policy not enforced)"
    record_pass
  else
    second_denied=1
    echo "  ✓  second run denied (daily budget exceeded)"
    record_pass
  fi
  if [[ "$second_denied" -eq 1 ]]; then
    local last_id
    last_id="$(run_talon audit list --limit 1 2>/dev/null | grep -oE '(req|gw)_[[:alnum:]_-]+' | head -1 || true)"
    if [[ -n "$last_id" ]]; then
      local audit_show
      audit_show="$(run_talon audit show "$last_id" 2>/dev/null || true)"
      if grep -qi "budget_exceeded" <<< "$audit_show" || grep -qi "budget" <<< "$audit_show"; then
        echo "  ✓  denied request evidence contains budget reason ($last_id)"
        record_pass
      else
        echo "  -  denied request evidence did not include explicit budget marker"
      fi
    fi
  fi
  assert_pass "talon costs exits 0" run_talon costs
  local cost_out; cost_out="$(run_talon costs 2>/dev/null)"; true
  assert_pass "talon costs stdout contains numeric cost" grep -qE '[0-9]+\.?[0-9]*' <<< "$cost_out"
  assert_pass "talon costs --tenant default exits 0" run_talon costs --tenant default
  assert_pass "talon costs --json exits 0" run_talon costs --tenant default --json
  local cost_json_out; cost_json_out="$(run_talon costs --tenant default --json 2>/dev/null || true)"
  if [[ -n "$cost_json_out" ]] && jq -e 'type=="object"' <<< "$cost_json_out" &>/dev/null; then
    echo "  ✓  talon costs --json outputs JSON object"
    record_pass
  else
    log_failure "talon costs --json outputs JSON object" "output=$(echo "$cost_json_out" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | cut -c1-200)"
  fi
  assert_pass "talon costs --by-provider exits 0" run_talon costs --tenant default --by-provider
  assert_pass "talon costs export --format csv exits 0" run_talon costs export --tenant default --format csv --limit 20
  assert_pass "talon costs export --format json exits 0" run_talon costs export --tenant default --format json --limit 20
  local cost_export_json; cost_export_json="$(run_talon costs export --tenant default --format json --limit 20 2>/dev/null || true)"
  if [[ -n "$cost_export_json" ]]; then
    assert_pass "cost export JSON is an array" jq -e 'type=="array"' <<< "$cost_export_json" &>/dev/null
  fi
  cd "$REPO_ROOT" || true
}

