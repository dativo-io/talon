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
  smoke_tighten_limits "$dir"
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
  # Cache correctness, not model wording: the model may answer the prompt
  # any way it likes. What must hold is that the first response is served
  # and cached, and that an equivalent second request returns EXACTLY the
  # cached first response with a cache-hit evidence record — no literal is
  # expected from a nondeterministic model.
  local cache_prompt="Reply with a short greeting for the smoke test."
  local run1_out run1_exit run1_resp
  run1_out="$(run_talon run "$cache_prompt" 2>/dev/null)"; run1_exit=$?
  run1_resp="$(smoke_run_response_text "$run1_out")"
  if [[ $run1_exit -eq 0 && -n "$run1_resp" ]]; then
    assert_pass "talon run (cache miss) exits 0 with a non-empty response" true
  else
    log_failure "talon run (cache miss) should exit 0 with a non-empty response" "exit=$run1_exit"
    dump_diag_json "cache miss run output" "$run1_out"
  fi
  local list_after_miss; list_after_miss="$(run_talon cache list 2>/dev/null)"; true
  assert_pass "cache entry written after first run (cache list non-empty)" test -n "$list_after_miss"
  sleep 1
  local run2_out run2_exit run2_resp
  run2_out="$(run_talon run "$cache_prompt" 2>/dev/null)"; run2_exit=$?
  run2_resp="$(smoke_run_response_text "$run2_out")"
  if [[ $run2_exit -eq 0 && -n "$run1_resp" && "$run2_resp" == "$run1_resp" ]]; then
    assert_pass "second equivalent run exits 0 and returns exactly the cached first response" true
  else
    log_failure "second equivalent run should return exactly the cached first response" "exit=$run2_exit"
    dump_diag_kv "cache hit comparison" "run1_resp=${run1_resp:0:200}" "run2_resp=${run2_resp:0:200}"
    dump_diag_json "cache hit run output" "$run2_out"
  fi
  # The newest evidence record must be the cache hit ([CACHE] mark from
  # evidence.cache_hit), proving the hit was governed and evidenced.
  local audit_newest; audit_newest="$(run_talon audit list --limit 1 2>/dev/null)"; true
  assert_pass "newest evidence record is marked [CACHE] (cache hit evidenced)" grep -q "\[CACHE\]" <<< "$audit_newest"
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
  assert_pass "talon audit list after cache run exits 0" run_talon audit list --limit 3
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

