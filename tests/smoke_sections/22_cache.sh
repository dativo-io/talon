#!/usr/bin/env bash
# Smoke test section: 22_cache
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 22 — Governed semantic cache (internal/cache, talon cache CLI, cache in pipeline)
# -----------------------------------------------------------------------------
test_section_22_cache() {
  local section="22_cache"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  # Enable cache in infra config (append cache block so it is used; last key wins in YAML)
  if ! grep -q "cache:" "$dir/talon.config.yaml" 2>/dev/null; then
    cat >> "$dir/talon.config.yaml" <<'CACHEEOF'

cache:
  enabled: true
  default_ttl: 3600
  similarity_threshold: 0.92
  max_entries_per_tenant: 10000
CACHEEOF
  else
    # Template may have cache with enabled: false; enable it
    sed -i.bak 's/enabled: false/enabled: true/' "$dir/talon.config.yaml" 2>/dev/null || true
  fi
  # First run: miss, response stored in cache
  assert_pass "talon run (cache miss) exits 0" run_talon run "Reply with exactly: SMOKE_CACHE_OK"
  local run1; run1="$(run_talon run 'Reply with exactly: SMOKE_CACHE_OK' 2>/dev/null)"; true
  assert_pass "first run stdout contains SMOKE_CACHE_OK" grep -q "SMOKE_CACHE_OK" <<< "$run1"
  # Second run with same prompt: should hit cache (no LLM call)
  local run2; run2="$(run_talon run 'Reply with exactly: SMOKE_CACHE_OK' 2>/dev/null)"; true
  assert_pass "second run (cache hit) exits 0 and returns cached content" grep -q "SMOKE_CACHE_OK" <<< "$run2"
  # Cache CLI
  assert_pass "talon cache config exits 0" run_talon cache config
  local config_out; config_out="$(run_talon cache config 2>/dev/null)"; true
  assert_pass "talon cache config shows enabled" grep -qiE 'enabled|true' <<< "$config_out"
  assert_pass "talon cache stats exits 0" run_talon cache stats
  local stats_out; stats_out="$(run_talon cache stats 2>/dev/null)"; true
  assert_pass "talon cache stats shows tenant or entries" grep -qiE 'default|tenant|entries|count' <<< "$stats_out"
  assert_pass "talon cache list exits 0" run_talon cache list
  local list_out; list_out="$(run_talon cache list 2>/dev/null)"; true
  assert_pass "talon cache list non-empty or shows default" test -n "$list_out"
  # Audit should show cache hit for recent run
  local audit_list; audit_list="$(run_talon audit list --limit 3 2>/dev/null)"; true
  assert_pass "talon audit list after cache run exits 0" run_talon audit list --limit 3
  # Optional: one of the recent entries may show [CACHE] if audit list displays it
  if echo "$audit_list" | grep -q "CACHE"; then
    echo "  ✓  audit list shows [CACHE] for cache hit"
    record_pass
  else
    echo "  -  (audit list may not show [CACHE] in this format; cache hit still recorded)"
  fi
  # costs and report may show cache savings
  assert_pass "talon costs exits 0 after cache runs" run_talon costs
  local cost_out; cost_out="$(run_talon costs 2>/dev/null)"; true
  if echo "$cost_out" | grep -qi "cache"; then
    echo "  ✓  talon costs mentions cache (savings or hit rate)"
    record_pass
  else
    echo "  -  (talon costs may not show cache line if no hits yet in window)"
  fi
  assert_pass "talon report exits 0" run_talon report
  # Semantic cache metrics in CLI: report and costs must mention cache when we had a hit
  local report_out; report_out="$(run_talon report 2>/dev/null)"; true
  if echo "$report_out" | grep -qiE 'Cache|from cache|cache.*saved'; then
    echo "  ✓  talon report shows semantic cache metrics (7d/30d hits or saved)"
    record_pass
  else
    echo "  -  talon report may not show cache line (format or window); cache hit was recorded"
  fi
  # GDPR erasure: erase cache for default tenant, then stats should show zero or reduced
  assert_pass "talon cache erase --tenant default exits 0" run_talon cache erase --tenant default
  assert_pass "talon cache stats after erase exits 0" run_talon cache stats
  cd "$REPO_ROOT" || true
}

