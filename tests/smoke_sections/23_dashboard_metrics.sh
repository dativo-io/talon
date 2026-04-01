#!/usr/bin/env bash
# Smoke test section: 23_dashboard_metrics
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 23 — Gateway Dashboard Metrics (dashboard API, CLI↔dashboard parity)
# -----------------------------------------------------------------------------
test_section_23_dashboard_metrics() {
  local section="23_dashboard_metrics"
  local dashboard_port="8080"
  local dashboard_base_url="http://127.0.0.1:${dashboard_port}"
  echo ""
  echo "=== SECTION 23 — Gateway Dashboard Metrics ==="
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  if ! wait_port_free "$dashboard_port" 180 10; then
    log_failure "dashboard metrics section could not acquire port ${dashboard_port}" "port remained busy"
    dump_diag_kv "port ${dashboard_port} in use" \
      "lsof=$(lsof -nP -iTCP:${dashboard_port} -sTCP:LISTEN 2>/dev/null | head -5 || echo '(lsof unavailable)')" \
      "TALON_SERVE_PID=${TALON_SERVE_PID:-}" \
      "TALON_GATEWAY_PID=${TALON_GATEWAY_PID:-}"
    cd "$REPO_ROOT" || true
    return 0
  fi
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  # Add gateway config with dashboard token
  if [[ -f "$dir/talon.config.yaml" ]]; then
    if ! grep -q "gateway:" "$dir/talon.config.yaml" 2>/dev/null; then
      cat >> "$dir/talon.config.yaml" <<'GWEOF'

gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "enforce"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  callers:
    - name: "metrics-caller"
      tenant_key: "talon-gw-metrics-001"
      tenant_id: "default"
      allowed_providers: ["openai"]
    - name: "pii-block-caller"
      tenant_key: "talon-gw-pii-block-001"
      tenant_id: "default"
      allowed_providers: ["openai"]
      policy_overrides:
        pii_action: "block"
    - name: "tool-filter-caller"
      tenant_key: "talon-gw-tool-filter-001"
      tenant_id: "default"
      allowed_providers: ["openai"]
      policy_overrides:
        forbidden_tools: ["exec_cmd"]
        tool_policy_action: "filter"
  default_policy:
    default_pii_action: "redact"
    forbidden_tools: ["delete_*"]
    tool_policy_action: "block"
    max_daily_cost: 100.00
    max_monthly_cost: 500.00
    require_caller_id: true
GWEOF
    fi
    # Enable semantic cache so dashboard cache_stats and CLI cache metrics can be tested.
    # Scaffold already has a cache: key; avoid duplicating it (YAML forbids duplicate keys).
    if grep -qE '^\s*cache\s*:' "$dir/talon.config.yaml" 2>/dev/null; then
      if command -v yq &>/dev/null; then
        yq -i '.cache.enabled = true | .cache.default_ttl = 3600 | .cache.similarity_threshold = 0.92 | .cache.max_entries_per_tenant = 1000' "$dir/talon.config.yaml" 2>/dev/null || true
      else
        sed -i.bak 's/enabled: false/enabled: true/' "$dir/talon.config.yaml" 2>/dev/null || true
      fi
    else
      cat >> "$dir/talon.config.yaml" <<'CACHEEOF'

cache:
  enabled: true
  default_ttl: 3600
  similarity_threshold: 0.92
  max_entries_per_tenant: 1000
CACHEEOF
    fi
  fi
  local GW_PID=""
  local gw_log_file="$dir/dashboard_gateway_serve.log"
  run_talon serve --port "$dashboard_port" --gateway --gateway-config "$dir/talon.config.yaml" >"$gw_log_file" 2>&1 &
  GW_PID=$!
  if ! smoke_wait_health "$dashboard_base_url" 45 1; then
    local gw_pid_state="running"
    if ! kill -0 "$GW_PID" 2>/dev/null; then
      wait "$GW_PID" 2>/dev/null
      local gw_exit_code=$?
      gw_pid_state="exited(${gw_exit_code})"
    fi
    log_failure "dashboard gateway server did not start on port ${dashboard_port}" \
      "url=${dashboard_base_url}/health pid=${GW_PID} state=${gw_pid_state}"
    dump_diag_file "section 23 serve log" "$gw_log_file" 120
    dump_diag_file "talon.config.yaml" "$dir/talon.config.yaml"
    dump_diag_env
    if [[ -f "$gw_log_file" ]]; then
      echo "    Last gateway log lines:"
      tail -10 "$gw_log_file" | sed 's/^/    | /'
    fi
    kill "$GW_PID" 2>/dev/null || true
    wait "$GW_PID" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi
  local admin_key="${TALON_ADMIN_KEY}"
  local gw_key="talon-gw-metrics-001"

  # --- 23.2: Metrics JSON endpoint structure (before any proxy traffic) ---
  # Take snapshot before gw_probe so pre-traffic counters are truly 0.
  local snap_before; snap_before="$(smoke_gw_get_metrics "$dashboard_base_url" "$admin_key")"
  assert_pass "GET /api/v1/metrics returns valid JSON" jq -e '.' <<< "$snap_before" &>/dev/null
  assert_pass "metrics snapshot has summary.total_requests" \
    jq -e '.summary.total_requests >= 0' <<< "$snap_before" &>/dev/null
  assert_pass "metrics snapshot has enforcement_mode" \
    jq -e '.enforcement_mode' <<< "$snap_before" &>/dev/null
  assert_pass "metrics snapshot has uptime" \
    jq -e '.uptime' <<< "$snap_before" &>/dev/null
  assert_pass "metrics snapshot has generated_at" \
    jq -e '.generated_at' <<< "$snap_before" &>/dev/null
  # Summary sub-fields (all documented in docs/reference/gateway-dashboard.md)
  assert_pass "summary has blocked_requests" \
    jq -e '.summary | has("blocked_requests")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has pii_detections" \
    jq -e '.summary | has("pii_detections")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has pii_redactions" \
    jq -e '.summary | has("pii_redactions")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has tools_filtered" \
    jq -e '.summary | has("tools_filtered")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has total_cost_eur" \
    jq -e '.summary | has("total_cost_eur")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has avg_latency_ms" \
    jq -e '.summary | has("avg_latency_ms")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has p99_latency_ms" \
    jq -e '.summary | has("p99_latency_ms")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has error_rate" \
    jq -e '.summary | has("error_rate")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has active_runs" \
    jq -e '.summary | has("active_runs")' <<< "$snap_before" &>/dev/null
  # Prompt 16 enhanced summary fields
  assert_pass "summary has total_successful" \
    jq -e '.summary | has("total_successful")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has total_failed" \
    jq -e '.summary | has("total_failed")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has total_timed_out" \
    jq -e '.summary | has("total_timed_out")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has total_denied" \
    jq -e '.summary | has("total_denied")' <<< "$snap_before" &>/dev/null
  assert_pass "summary has success_rate" \
    jq -e '.summary | has("success_rate")' <<< "$snap_before" &>/dev/null
  # Record pre-traffic baselines. BackfillFromStore replays recent evidence so
  # counters may already be >0 from earlier sections sharing the same data dir.
  local before_count; before_count="$(jq '.summary.total_requests' <<< "$snap_before")"
  local before_successful; before_successful="$(jq '.summary.total_successful' <<< "$snap_before")"
  local before_failed; before_failed="$(jq '.summary.total_failed' <<< "$snap_before")"
  local before_timed_out; before_timed_out="$(jq '.summary.total_timed_out' <<< "$snap_before")"
  local before_denied; before_denied="$(jq '.summary.total_denied' <<< "$snap_before")"
  local before_success_rate; before_success_rate="$(jq '.summary.success_rate' <<< "$snap_before")"
  dump_diag_kv "section 23 pre-traffic baselines" \
    "total_requests=$before_count" \
    "total_successful=$before_successful" \
    "total_failed=$before_failed" \
    "total_timed_out=$before_timed_out" \
    "total_denied=$before_denied" \
    "success_rate=$before_success_rate" \
    "note=backfill from evidence.db means these may be >0"
  assert_pass "pre-traffic total_successful is a number" \
    jq -e '.summary.total_successful | type == "number"' <<< "$snap_before" &>/dev/null
  assert_pass "pre-traffic total_failed is a number" \
    jq -e '.summary.total_failed | type == "number"' <<< "$snap_before" &>/dev/null
  assert_pass "pre-traffic total_timed_out is a number" \
    jq -e '.summary.total_timed_out | type == "number"' <<< "$snap_before" &>/dev/null
  assert_pass "pre-traffic total_denied is a number" \
    jq -e '.summary.total_denied | type == "number"' <<< "$snap_before" &>/dev/null
  assert_pass "pre-traffic success_rate is a number" \
    jq -e '.summary.success_rate | type == "number"' <<< "$snap_before" &>/dev/null

  # Verify the gateway routes are actually registered (not just health)
  local gw_probe; gw_probe="$(smoke_gw_post_chat "$dashboard_base_url" "Bearer talon-gw-metrics-001" "$SMOKE_BODY_EMPTY")"
  if [[ "$gw_probe" == "404" ]]; then
    log_failure "gateway routes not registered for dashboard metrics section" "proxy=${dashboard_base_url}${SMOKE_PATH_GW_PROXY} got=404"
    kill "$GW_PID" 2>/dev/null || true
    wait "$GW_PID" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi

  # --- 23.1: Dashboard HTML served ---
  assert_pass "GET /gateway/dashboard 200 (with admin key)" \
    test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: $admin_key" "${dashboard_base_url}${SMOKE_PATH_GATEWAY_DASHBOARD}")" = "200"
  local dash_html; dash_html="$(smoke_gw_get_dashboard "$dashboard_base_url" "$admin_key")"
  assert_pass "dashboard HTML contains Talon" grep -qi "talon" <<< "$dash_html"
  assert_pass "dashboard HTML contains Mission Control marker" grep -q "Talon <span>Mission Control</span>" <<< "$dash_html"
  assert_pass "dashboard HTML contains Session Timeline marker" grep -q "Session Timeline (Lifecycle)" <<< "$dash_html"
  assert_pass "dashboard HTML contains Compliance Report Preview marker" grep -q "Compliance Report Preview" <<< "$dash_html"
  assert_pass "dashboard HTML contains <script>" grep -qi "<script" <<< "$dash_html"
  assert_pass "dashboard HTML contains Success Rate KPI" grep -qi "Success Rate" <<< "$dash_html"
  assert_pass "dashboard HTML contains Timeouts KPI" grep -qi "Timeouts" <<< "$dash_html"
  assert_pass "dashboard HTML contains Violation Trend (7d) panel" grep -qi "Violation Trend (7d)" <<< "$dash_html"
  assert_pass "dashboard caller table contains EUR/Success column" grep -qi "EUR/Success" <<< "$dash_html"
  assert_pass "dashboard caller table contains Trend(7d) column" grep -qi "Trend(7d)" <<< "$dash_html"
  assert_pass "dashboard caller table contains Success column header" grep -q ">Success<" <<< "$dash_html"
  assert_pass "dashboard caller table contains Failed column header" grep -q ">Failed<" <<< "$dash_html"
  assert_pass "dashboard caller table contains Timeout column header" grep -q ">Timeout<" <<< "$dash_html"
  assert_pass "dashboard caller table contains Denied column header" grep -q ">Denied<" <<< "$dash_html"
  assert_pass "dashboard caller table contains Rate column header" grep -q ">Rate<" <<< "$dash_html"

  # --- 23.2b: PII and tool governance config behaviour (different callers / default_policy) ---
  # (1) PII block: caller with pii_action: "block" must get 400 on PII body
  local pii_block_code; pii_block_code="$(smoke_gw_post_chat "$dashboard_base_url" "Bearer talon-gw-pii-block-001" "$SMOKE_BODY_PII")"
  if [[ "$pii_block_code" == "400" ]]; then
    echo "  ✓  PII block config: request with pii-block-caller returns 400"
    record_pass
  else
    log_failure "PII block config: expected 400 for pii-block-caller + PII body" "got HTTP $pii_block_code"
  fi
  # (2) Tool block: default_policy forbidden_tools delete_* + tool_policy_action block → 403
  local tool_block_code; tool_block_code="$(smoke_gw_post_chat "$dashboard_base_url" "Bearer $gw_key" "$SMOKE_BODY_TOOL_BLOCK")"
  if [[ "$tool_block_code" == "403" ]]; then
    echo "  ✓  Tool block config: request with forbidden tool delete_all returns 403"
    record_pass
  else
    log_failure "Tool block config: expected 403 for request with forbidden tool delete_all" "got HTTP $tool_block_code"
  fi
  # (3) Tool filter: caller with forbidden_tools exec_cmd + tool_policy_action filter → 200, tools stripped
  local tool_filter_code; tool_filter_code="$(smoke_gw_post_chat "$dashboard_base_url" "Bearer talon-gw-tool-filter-001" "$SMOKE_BODY_TOOL_FILTER")"
  if [[ "$tool_filter_code" == "200" ]]; then
    echo "  ✓  Tool filter config: request with allowed+forbidden tools returns 200 (forbidden stripped)"
    record_pass
  elif [[ "$tool_filter_code" == "400" ]]; then
    echo "  -  Tool filter config: got 400 (gateway may reject invalid tool payload or filter path returns 400)"
  else
    log_failure "Tool filter config: expected 200 for tool-filter-caller with read_file+exec_cmd" "got HTTP $tool_filter_code"
  fi

  # --- 23.3: Make 20 gateway requests so metrics accumulate (cross-checks need volume) ---
  # Requests 1–2: cache (identical body); 3–12: normal (varied); 13–20: PII (canonical body)
  local req_num
  for req_num in $(seq 1 20); do
    if [[ "$req_num" -eq 1 ]] || [[ "$req_num" -eq 2 ]]; then
      smoke_gw_post_chat "$dashboard_base_url" "Bearer $gw_key" "$SMOKE_BODY_CACHE" >/dev/null || true
    elif [[ "$req_num" -le 12 ]]; then
      smoke_gw_post_chat "$dashboard_base_url" "Bearer $gw_key" "$(smoke_body_normal "$req_num")" >/dev/null || true
    else
      smoke_gw_post_chat "$dashboard_base_url" "Bearer $gw_key" "$SMOKE_BODY_PII" >/dev/null || true
    fi
  done
  sleep 3

  # --- 23.4: Metrics reflect the gateway requests ---
  local snap_after; snap_after="$(smoke_gw_get_metrics "$dashboard_base_url" "$admin_key")"
  assert_pass "metrics snapshot after requests is valid JSON" jq -e '.' <<< "$snap_after" &>/dev/null
  local after_count; after_count="$(jq '.summary.total_requests' <<< "$snap_after")"
  local after_successful; after_successful="$(jq '.summary.total_successful' <<< "$snap_after")"
  local after_failed; after_failed="$(jq '.summary.total_failed' <<< "$snap_after")"
  local after_denied; after_denied="$(jq '.summary.total_denied' <<< "$snap_after")"
  local after_success_rate; after_success_rate="$(jq '.summary.success_rate' <<< "$snap_after")"
  dump_diag_kv "section 23 post-traffic snapshot" \
    "total_requests: $before_count → $after_count" \
    "total_successful: $before_successful → $after_successful" \
    "total_failed: $before_failed → $after_failed" \
    "total_denied: $before_denied → $after_denied" \
    "success_rate: $before_success_rate → $after_success_rate"
  if [[ -n "$after_count" ]] && [[ -n "$before_count" ]] && [[ "$after_count" -gt "$before_count" ]]; then
    echo "  ✓  metrics total_requests incremented ($before_count → $after_count)"
    record_pass
  else
    log_failure "metrics total_requests should increment after gateway request" "before=$before_count after=$after_count"
    dump_diag_json "snap_after full" "$snap_after"
  fi
  # Cost should be > 0 (we made real LLM requests)
  local cost; cost="$(jq '.summary.total_cost_eur' <<< "$snap_after")"
  if [[ "$(echo "${cost:-0} > 0" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
    echo "  ✓  metrics total_cost_eur > 0 ($cost)"
    record_pass
  else
    echo "  -  metrics total_cost_eur = $cost (may be zero if cached or free tier)"
  fi
  # Latency should be > 0 after real requests
  local avg_lat; avg_lat="$(jq '.summary.avg_latency_ms' <<< "$snap_after")"
  if [[ -n "$avg_lat" ]] && [[ "$avg_lat" != "null" ]] && [[ "$avg_lat" -gt 0 ]] 2>/dev/null; then
    echo "  ✓  metrics avg_latency_ms > 0 ($avg_lat)"
    record_pass
  else
    echo "  -  metrics avg_latency_ms = $avg_lat (may be zero if no completed requests)"
  fi
  # PII should have been detected (email + IBAN in request 2)
  local pii_count; pii_count="$(jq '.summary.pii_detections' <<< "$snap_after")"
  if [[ -n "$pii_count" ]] && [[ "$pii_count" != "null" ]] && [[ "$pii_count" -gt 0 ]] 2>/dev/null; then
    echo "  ✓  metrics pii_detections > 0 ($pii_count)"
    record_pass
  else
    echo "  -  metrics pii_detections = $pii_count (PII scanning may not be active in gateway)"
  fi

  # --- 23.4a: PII and tool governance metrics (from config-driven block/filter requests) ---
  local blocked_count; blocked_count="$(jq '.summary.blocked_requests' <<< "$snap_after")"
  if [[ -n "$blocked_count" ]] && [[ "$blocked_count" != "null" ]] && [[ "$blocked_count" -ge 2 ]]; then
    echo "  ✓  blocked_requests >= 2 from PII block + tool block ($blocked_count)"
    record_pass
  else
    echo "  -  blocked_requests = ${blocked_count:-null} (expected >= 2 after PII block and tool block)"
  fi
  local tools_filt; tools_filt="$(jq '.summary.tools_filtered' <<< "$snap_after")"
  if [[ -n "$tools_filt" ]] && [[ "$tools_filt" != "null" ]] && [[ "$tools_filt" -ge 1 ]]; then
    echo "  ✓  tools_filtered >= 1 from tool filter request ($tools_filt)"
    record_pass
  else
    log_failure "tool filter config: expected tools_filtered >= 1" "got $tools_filt"
  fi
  local pii_blocker_blocked; pii_blocker_blocked="$(jq -r '[.caller_stats[] | select(.caller == "pii-block-caller") | .blocked] | add // 0' <<< "$snap_after")"
  if [[ -n "$pii_blocker_blocked" ]] && [[ "$pii_blocker_blocked" != "null" ]] && [[ "$pii_blocker_blocked" -ge 1 ]]; then
    echo "  ✓  caller pii-block-caller has blocked >= 1 ($pii_blocker_blocked)"
    record_pass
  else
    echo "  -  pii-block-caller blocked = ${pii_blocker_blocked:-null}"
  fi

  # Prompt 16: enhanced caller fields + ranges + trend shape
  assert_pass "caller_stats entries include successful" \
    jq -e 'all(.caller_stats[]; has("successful"))' <<< "$snap_after" &>/dev/null
  assert_pass "caller_stats entries include failed" \
    jq -e 'all(.caller_stats[]; has("failed"))' <<< "$snap_after" &>/dev/null
  assert_pass "caller_stats entries include timed_out" \
    jq -e 'all(.caller_stats[]; has("timed_out"))' <<< "$snap_after" &>/dev/null
  assert_pass "caller_stats entries include denied" \
    jq -e 'all(.caller_stats[]; has("denied"))' <<< "$snap_after" &>/dev/null
  assert_pass "caller_stats entries include success_rate" \
    jq -e 'all(.caller_stats[]; has("success_rate"))' <<< "$snap_after" &>/dev/null
  assert_pass "caller_stats entries include cost_per_success" \
    jq -e 'all(.caller_stats[]; has("cost_per_success"))' <<< "$snap_after" &>/dev/null
  assert_pass "caller_stats entries include violation_trend" \
    jq -e 'all(.caller_stats[]; has("violation_trend"))' <<< "$snap_after" &>/dev/null
  assert_pass "success_rate values are in [0,1]" \
    jq -e 'all(.caller_stats[]; (.success_rate >= 0 and .success_rate <= 1))' <<< "$snap_after" &>/dev/null
  assert_pass "violation_trend has 7 points per caller" \
    jq -e 'all(.caller_stats[]; (.violation_trend | type=="array" and length==7))' <<< "$snap_after" &>/dev/null
  local tg_filtered; tg_filtered="$(jq '.tool_governance.total_filtered' <<< "$snap_after")"
  if [[ -n "$tg_filtered" ]] && [[ "$tg_filtered" != "null" ]] && [[ "$tg_filtered" -ge 1 ]]; then
    echo "  ✓  tool_governance.total_filtered >= 1 ($tg_filtered)"
    record_pass
  else
    echo "  -  tool_governance.total_filtered = ${tg_filtered:-null}"
  fi

  # --- 23.4b: Cross-checks between metrics (same invariants as unit/integration tests) ---
  local total_req; total_req="$(jq '.summary.total_requests' <<< "$snap_after")"
  if [[ -n "$total_req" ]] && [[ "$total_req" != "null" ]] && [[ "$total_req" -ge 15 ]] 2>/dev/null; then
    echo "  ✓  total_requests >= 15 ($total_req) after 20 gateway requests"
    record_pass
  else
    echo "  -  total_requests = $total_req (expected >= 15)"
  fi
  # total_requests == sum(caller_stats[].requests)
  local caller_sum; caller_sum="$(jq '[.caller_stats[].requests] | add // 0' <<< "$snap_after")"
  if [[ -n "$total_req" ]] && [[ -n "$caller_sum" ]] && [[ "$caller_sum" != "null" ]]; then
    if [[ "$total_req" -eq "$caller_sum" ]]; then
      echo "  ✓  cross-check: total_requests ($total_req) == sum(caller_stats[].requests) ($caller_sum)"
      record_pass
    else
      log_failure "metrics cross-check: total_requests ($total_req) != sum(caller_stats[].requests) ($caller_sum)" "invariant violation"
    fi
  fi
  # blocked_requests == sum(caller_stats[].blocked)
  local blocked_req; blocked_req="$(jq '.summary.blocked_requests' <<< "$snap_after")"
  local caller_blocked_sum; caller_blocked_sum="$(jq '[.caller_stats[].blocked] | add // 0' <<< "$snap_after")"
  if [[ -n "$blocked_req" ]] && [[ "$blocked_req" != "null" ]] && [[ -n "$caller_blocked_sum" ]] && [[ "$caller_blocked_sum" != "null" ]]; then
    if [[ "$blocked_req" -eq "$caller_blocked_sum" ]]; then
      echo "  ✓  cross-check: blocked_requests ($blocked_req) == sum(caller_stats[].blocked) ($caller_blocked_sum)"
      record_pass
    else
      log_failure "metrics cross-check: blocked_requests ($blocked_req) != sum(caller_stats[].blocked) ($caller_blocked_sum)" "invariant violation"
    fi
  fi
  # pii_detections == sum(pii_breakdown[].count)
  local pii_breakdown_sum; pii_breakdown_sum="$(jq '[.pii_breakdown[].count] | add // 0' <<< "$snap_after")"
  if [[ -n "$pii_count" ]] && [[ "$pii_count" != "null" ]] && [[ -n "$pii_breakdown_sum" ]] && [[ "$pii_breakdown_sum" != "null" ]]; then
    if [[ "$pii_count" -eq "$pii_breakdown_sum" ]]; then
      echo "  ✓  cross-check: pii_detections ($pii_count) == sum(pii_breakdown[].count) ($pii_breakdown_sum)"
      record_pass
    else
      log_failure "metrics cross-check: pii_detections ($pii_count) != sum(pii_breakdown[].count) ($pii_breakdown_sum)" "invariant violation"
    fi
  fi
  # total_cost_eur ≈ sum(model_breakdown[].cost_eur) when model_breakdown present
  local cost_sum; cost_sum="$(jq '[.model_breakdown[].cost_eur] | add // 0' <<< "$snap_after")"
  if [[ -n "$cost" ]] && [[ "$cost" != "null" ]] && [[ -n "$cost_sum" ]] && [[ "$cost_sum" != "null" ]]; then
    local cost_diff; cost_diff="$(echo "scale=8; d=$cost - $cost_sum; if (d < 0) -d else d" | bc -l 2>/dev/null || echo 999)"
    if [[ "$(echo "$cost_diff < 0.02" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
      echo "  ✓  cross-check: total_cost_eur ($cost) ≈ sum(model_breakdown[].cost_eur) ($cost_sum)"
      record_pass
    else
      echo "  -  cross-check: total_cost_eur ($cost) vs model_breakdown sum ($cost_sum), diff=$cost_diff (dashboard may use store)"
    fi
  fi
  # error_rate in [0, 1]
  local err_rate; err_rate="$(jq '.summary.error_rate' <<< "$snap_after")"
  if [[ -n "$err_rate" ]] && [[ "$err_rate" != "null" ]]; then
    if [[ "$(echo "$err_rate >= 0 && $err_rate <= 1" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
      echo "  ✓  cross-check: error_rate in [0,1] ($err_rate)"
      record_pass
    else
      log_failure "metrics cross-check: error_rate out of range" "error_rate=$err_rate"
    fi
  fi
  # p99_latency_ms >= 0 when we have requests
  local p99_lat; p99_lat="$(jq '.summary.p99_latency_ms' <<< "$snap_after")"
  if [[ -n "$total_req" ]] && [[ "$total_req" -gt 0 ]] && [[ -n "$p99_lat" ]] && [[ "$p99_lat" != "null" ]]; then
    if [[ "$p99_lat" -ge 0 ]]; then
      echo "  ✓  cross-check: p99_latency_ms >= 0 ($p99_lat)"
      record_pass
    fi
  fi

  # --- 23.5: Full snapshot fields present (all documented arrays/objects) ---
  assert_pass "snapshot has requests_timeline array" \
    jq -e '.requests_timeline | type == "array"' <<< "$snap_after" &>/dev/null
  assert_pass "snapshot has pii_timeline array" \
    jq -e '.pii_timeline | type == "array"' <<< "$snap_after" &>/dev/null
  assert_pass "snapshot has cost_timeline array" \
    jq -e '.cost_timeline | type == "array"' <<< "$snap_after" &>/dev/null
  assert_pass "snapshot has caller_stats array" \
    jq -e '.caller_stats | type == "array"' <<< "$snap_after" &>/dev/null
  assert_pass "snapshot has pii_breakdown array" \
    jq -e '.pii_breakdown | type == "array"' <<< "$snap_after" &>/dev/null
  assert_pass "snapshot has tool_governance object" \
    jq -e '.tool_governance | type == "object"' <<< "$snap_after" &>/dev/null
  assert_pass "snapshot has model_breakdown array" \
    jq -e '.model_breakdown | type == "array"' <<< "$snap_after" &>/dev/null

  # --- 23.5b: Budget status fields (omitempty — present when budget limits configured) ---
  local has_budget; has_budget="$(jq 'has("budget_status") and (.budget_status != null)' <<< "$snap_after")"
  if [[ "$has_budget" == "true" ]]; then
    assert_pass "snapshot has budget_status object" \
      jq -e '.budget_status | type == "object"' <<< "$snap_after" &>/dev/null
    assert_pass "budget_status has daily_used" \
      jq -e '.budget_status | has("daily_used")' <<< "$snap_after" &>/dev/null
    assert_pass "budget_status has daily_limit" \
      jq -e '.budget_status | has("daily_limit")' <<< "$snap_after" &>/dev/null
    assert_pass "budget_status has daily_percent" \
      jq -e '.budget_status | has("daily_percent")' <<< "$snap_after" &>/dev/null
    assert_pass "budget_status has monthly_used" \
      jq -e '.budget_status | has("monthly_used")' <<< "$snap_after" &>/dev/null
    assert_pass "budget_status has monthly_limit" \
      jq -e '.budget_status | has("monthly_limit")' <<< "$snap_after" &>/dev/null
    assert_pass "budget_status has monthly_percent" \
      jq -e '.budget_status | has("monthly_percent")' <<< "$snap_after" &>/dev/null
  else
    echo "  -  budget_status not present (budget limits may not be configured)"
  fi

  # --- 23.5c: Semantic cache stats (dashboard + CLI parity) ---
  local has_cache; has_cache="$(jq 'has("cache_stats") and (.cache_stats != null)' <<< "$snap_after")"
  if [[ "$has_cache" == "true" ]]; then
    assert_pass "snapshot has cache_stats object" \
      jq -e '.cache_stats | type == "object"' <<< "$snap_after" &>/dev/null
    assert_pass "cache_stats has hits" \
      jq -e '.cache_stats | has("hits")' <<< "$snap_after" &>/dev/null
    assert_pass "cache_stats has hit_rate" \
      jq -e '.cache_stats | has("hit_rate")' <<< "$snap_after" &>/dev/null
    assert_pass "cache_stats has cost_saved" \
      jq -e '.cache_stats | has("cost_saved")' <<< "$snap_after" &>/dev/null
    local cache_hits; cache_hits="$(jq '.cache_stats.hits' <<< "$snap_after")"
    local cache_saved; cache_saved="$(jq '.cache_stats.cost_saved' <<< "$snap_after")"
    if [[ -n "$cache_hits" ]] && [[ "$cache_hits" != "null" ]] && [[ "$cache_hits" -ge 1 ]]; then
      echo "  ✓  semantic cache metrics: cache_stats.hits >= 1 ($cache_hits)"
      record_pass
    else
      echo "  -  semantic cache: cache_stats.hits = ${cache_hits:-null} (expected >= 1 after identical requests)"
    fi
    if [[ -n "$cache_saved" ]] && [[ "$cache_saved" != "null" ]]; then
      if [[ "$(echo "${cache_saved:-0} >= 0" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
        echo "  ✓  semantic cache metrics: cache_stats.cost_saved >= 0 (€$cache_saved)"
        record_pass
      fi
    fi
    # CLI parity: talon cache stats and talon costs cache line vs dashboard cache_stats
    assert_pass "talon cache stats exits 0 (semantic cache CLI)" run_talon cache stats
    local costs_cache_line; costs_cache_line="$(run_talon costs 2>/dev/null | grep -i "Cache (7d)" || true)"
    if [[ -n "$costs_cache_line" ]] && [[ -n "$cache_saved" ]] && [[ "$cache_saved" != "null" ]]; then
      local costs_saved; costs_saved="$(echo "$costs_cache_line" | grep -oE '€[0-9]+\.[0-9]+' | head -1 | tr -d '€')"
      if [[ -n "$costs_saved" ]]; then
        local saved_diff; saved_diff="$(echo "scale=8; d=$cache_saved - $costs_saved; if (d < 0) -d else d" | bc -l 2>/dev/null || echo 999)"
        if [[ "$(echo "$saved_diff < 0.02" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
          echo "  ✓  semantic cache CLI↔dashboard parity: cache_stats.cost_saved (€$cache_saved) ≈ talon costs (€$costs_saved)"
          record_pass
        else
          echo "  -  cache cost_saved: dashboard €$cache_saved vs CLI €$costs_saved (diff=$saved_diff)"
        fi
      fi
    fi
  else
    echo "  -  cache_stats not present (semantic cache may not be enabled or no hits yet)"
  fi

  # --- 23.5d: Tool governance sub-fields ---
  assert_pass "tool_governance has total_requested" \
    jq -e '.tool_governance | has("total_requested")' <<< "$snap_after" &>/dev/null
  assert_pass "tool_governance has total_filtered" \
    jq -e '.tool_governance | has("total_filtered")' <<< "$snap_after" &>/dev/null

  # --- 23.5e: Model breakdown should contain gpt-4o-mini after requests ---
  local model_count; model_count="$(jq '.model_breakdown | length' <<< "$snap_after")"
  if [[ -n "$model_count" ]] && [[ "$model_count" -gt 0 ]] 2>/dev/null; then
    echo "  ✓  model_breakdown has $model_count model(s)"
    record_pass
  else
    echo "  -  model_breakdown is empty (may need more requests)"
  fi

  # --- 23.5f: PII breakdown should list types after PII request ---
  if [[ -n "$pii_count" ]] && [[ "$pii_count" -gt 0 ]] 2>/dev/null; then
    local pii_types; pii_types="$(jq '.pii_breakdown | length' <<< "$snap_after")"
    if [[ -n "$pii_types" ]] && [[ "$pii_types" -gt 0 ]] 2>/dev/null; then
      echo "  ✓  pii_breakdown has $pii_types type(s)"
      record_pass
    else
      echo "  -  pii_breakdown is empty despite pii_detections > 0"
    fi
  fi

  # --- 23.6: Caller stats include our gateway caller ---
  local callers; callers="$(jq -r '.caller_stats[].caller' <<< "$snap_after" 2>/dev/null)"
  if echo "$callers" | grep -q "metrics-caller"; then
    echo "  ✓  caller_stats includes metrics-caller"
    record_pass
    # Verify caller_stats sub-fields
    assert_pass "caller_stats entry has requests field" \
      jq -e '.caller_stats[] | select(.caller == "metrics-caller") | has("requests")' <<< "$snap_after" &>/dev/null
    assert_pass "caller_stats entry has cost_eur field" \
      jq -e '.caller_stats[] | select(.caller == "metrics-caller") | has("cost_eur")' <<< "$snap_after" &>/dev/null
    assert_pass "caller_stats entry has avg_latency_ms field" \
      jq -e '.caller_stats[] | select(.caller == "metrics-caller") | has("avg_latency_ms")' <<< "$snap_after" &>/dev/null
    assert_pass "caller_stats entry has pii_detected field" \
      jq -e '.caller_stats[] | select(.caller == "metrics-caller") | has("pii_detected")' <<< "$snap_after" &>/dev/null
    assert_pass "caller_stats entry has blocked field" \
      jq -e '.caller_stats[] | select(.caller == "metrics-caller") | has("blocked")' <<< "$snap_after" &>/dev/null
  else
    echo "  -  caller_stats does not include metrics-caller (may use different name)"
  fi

  # --- 23.7: CLI costs ↔ dashboard cost parity ---
  local cli_cost_out; cli_cost_out="$(run_talon costs --tenant default 2>/dev/null)"; true
  assert_pass "talon costs --tenant default exits 0" run_talon costs --tenant default
  # Extract the "Total" daily cost from CLI (€<value> in the Today column of the Total row)
  local cli_daily_cost; cli_daily_cost="$(echo "$cli_cost_out" | grep -E '^Total' | grep -oE '€[0-9]+\.[0-9]+' | head -1 | tr -d '€')"
  if [[ -z "$cli_daily_cost" ]]; then
    cli_daily_cost="$(echo "$cli_cost_out" | grep -i 'today' | grep -oE '[0-9]+\.[0-9]+' | head -1)"
  fi
  echo "[SMOKE] CONSISTENCY|cli_daily_cost|${cli_daily_cost:-none}"

  # Compare CLI daily cost with dashboard budget_status.daily_used (both use MetricsQuerier.CostTotal)
  if [[ "$has_budget" == "true" ]]; then
    local dash_daily_used; dash_daily_used="$(jq -r '.budget_status.daily_used' <<< "$snap_after")"
    echo "[SMOKE] CONSISTENCY|dashboard_daily_used|${dash_daily_used:-none}"
    if [[ -n "$cli_daily_cost" ]] && [[ -n "$dash_daily_used" ]] && [[ "$dash_daily_used" != "null" ]]; then
      # Both query CostTotal(dayStart, dayEnd) from the same SQLite evidence store
      local cost_diff; cost_diff="$(echo "scale=8; d=$dash_daily_used - $cli_daily_cost; if (d < 0) -d else d" | bc -l 2>/dev/null || echo 999)"
      if [[ "$(echo "$cost_diff < 0.01" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
        echo "  ✓  CLI daily cost (€$cli_daily_cost) ≈ dashboard budget_status.daily_used (€$dash_daily_used)"
        record_pass
      else
        log_failure "CLI daily cost (€$cli_daily_cost) != dashboard daily_used (€$dash_daily_used), diff=$cost_diff" \
          "cli=$cli_daily_cost dash=$dash_daily_used"
      fi
    else
      echo "  -  cost parity: could not parse CLI daily cost or dashboard daily_used"
    fi
    # Also verify budget percentages are consistent: daily_percent ≈ daily_used/daily_limit * 100
    local dash_daily_pct; dash_daily_pct="$(jq -r '.budget_status.daily_percent' <<< "$snap_after")"
    local dash_daily_lim; dash_daily_lim="$(jq -r '.budget_status.daily_limit' <<< "$snap_after")"
    if [[ -n "$dash_daily_used" ]] && [[ "$dash_daily_lim" != "null" ]] && [[ "$dash_daily_lim" != "0" ]]; then
      local expected_pct; expected_pct="$(echo "scale=4; $dash_daily_used / $dash_daily_lim * 100" | bc -l 2>/dev/null || echo 0)"
      local pct_diff; pct_diff="$(echo "scale=4; d=$dash_daily_pct - $expected_pct; if (d < 0) -d else d" | bc -l 2>/dev/null || echo 999)"
      if [[ "$(echo "$pct_diff < 1.0" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
        echo "  ✓  budget daily_percent ($dash_daily_pct%) is consistent with daily_used/daily_limit"
        record_pass
      else
        echo "  -  budget daily_percent ($dash_daily_pct%) vs computed ($expected_pct%), diff=$pct_diff"
      fi
    fi
  else
    echo "  -  budget_status absent — skipping CLI↔dashboard cost parity"
  fi

  # CLI costs --by-model: compare model names with dashboard model_breakdown
  local cli_bymodel; cli_bymodel="$(run_talon costs --by-model --tenant default 2>/dev/null)"; true
  assert_pass "talon costs --by-model exits 0" run_talon costs --by-model --tenant default
  # Extract model names from CLI output (lines between header/footer dashes that start with a non-dash word and have €)
  local cli_models; cli_models="$(echo "$cli_bymodel" | grep '€' | grep -v '^Total' | awk '{print $1}' | sort)"
  local dash_models; dash_models="$(jq -r '.model_breakdown[].model // empty' <<< "$snap_after" 2>/dev/null | sort)"
  echo "[SMOKE] CONSISTENCY|cli_models|$(echo "$cli_models" | tr '\n' ',')"
  echo "[SMOKE] CONSISTENCY|dash_models|$(echo "$dash_models" | tr '\n' ',')"
  if [[ -n "$cli_models" ]] && [[ -n "$dash_models" ]]; then
    if [[ "$cli_models" == "$dash_models" ]]; then
      echo "  ✓  CLI costs --by-model models match dashboard model_breakdown"
      record_pass
    else
      echo "  -  model mismatch: CLI=[$cli_models] dash=[$dash_models] (timing or scope difference)"
    fi
  else
    echo "  -  model parity: could not extract models from CLI or dashboard"
  fi

  # --- 23.7b: CLI report ↔ dashboard evidence count + PII parity ---
  # --- 23.7a: CLI metrics command (Prompt 16) ---
  assert_pass "talon metrics exits 0" run_talon metrics --url "$dashboard_base_url"
  local cli_metrics_out; cli_metrics_out="$(run_talon metrics --url "$dashboard_base_url" 2>/dev/null)"; true
  assert_pass "talon metrics output contains AGENT column" grep -q "AGENT" <<< "$cli_metrics_out"
  assert_pass "talon metrics output contains SUCCESS column" grep -q "SUCCESS" <<< "$cli_metrics_out"
  assert_pass "talon metrics output contains FAILED column" grep -q "FAILED" <<< "$cli_metrics_out"
  assert_pass "talon metrics output contains TIMEOUT column" grep -q "TIMEOUT" <<< "$cli_metrics_out"
  assert_pass "talon metrics output contains DENIED column" grep -q "DENIED" <<< "$cli_metrics_out"
  assert_pass "talon metrics output contains VIOLATIONS(7d) column" grep -q "VIOLATIONS(7d)" <<< "$cli_metrics_out"
  local cli_metrics_json; cli_metrics_json="$(run_talon metrics --json --url "$dashboard_base_url" 2>/dev/null)"; true
  assert_pass "talon metrics --json outputs valid JSON array" jq -e 'type=="array"' <<< "$cli_metrics_json" &>/dev/null
  assert_pass "talon metrics --json includes success_rate field" jq -e 'all(.[]; has("success_rate"))' <<< "$cli_metrics_json" &>/dev/null
  assert_pass "talon metrics --json includes cost_per_success field" jq -e 'all(.[]; has("cost_per_success"))' <<< "$cli_metrics_json" &>/dev/null
  assert_pass "talon metrics --json includes timed_out field" jq -e 'all(.[]; has("timed_out"))' <<< "$cli_metrics_json" &>/dev/null
  assert_pass "talon metrics --json includes violation_trend field" jq -e 'all(.[]; has("violation_trend"))' <<< "$cli_metrics_json" &>/dev/null
  local cli_metrics_agent; cli_metrics_agent="$(run_talon metrics --agent metrics-caller --url "$dashboard_base_url" 2>/dev/null)"; true
  assert_pass "talon metrics --agent shows single-agent heading" grep -q "Agent Metrics: metrics-caller" <<< "$cli_metrics_agent"
  assert_pass "talon metrics --agent includes Violation trend (7d)" grep -q "Violation trend (7d)" <<< "$cli_metrics_agent"

  # --- 23.7b: CLI report ↔ dashboard evidence count + PII parity ---
  local cli_report; cli_report="$(run_talon report --tenant default 2>/dev/null)"; true
  assert_pass "talon report --tenant default exits 0" run_talon report --tenant default
  assert_pass "CLI report contains evidence count" grep -q "Evidence records today" <<< "$cli_report"
  assert_pass "CLI report contains cost" grep -q "Cost today" <<< "$cli_report"

  # Extract evidence count from report "Evidence records today: N"
  local report_count; report_count="$(echo "$cli_report" | grep 'Evidence records today' | grep -oE '[0-9]+' | head -1)"
  local dash_total; dash_total="$(jq '.summary.total_requests' <<< "$snap_after")"
  echo "[SMOKE] CONSISTENCY|report_evidence_today|${report_count:-none}"
  echo "[SMOKE] CONSISTENCY|dashboard_total_requests|${dash_total:-none}"
  if [[ -n "$report_count" ]] && [[ -n "$dash_total" ]] && [[ "$dash_total" != "null" ]]; then
    if [[ "$report_count" -eq "$dash_total" ]]; then
      echo "  ✓  CLI report evidence count ($report_count) == dashboard total_requests ($dash_total)"
      record_pass
    else
      # Dashboard total_requests is event-based and can exceed persisted evidence count.
      # Allow a bounded one-sided drift (dashboard >= report) while still failing on larger mismatches.
      local dash_minus_report=$(( dash_total - report_count ))
      if [[ $dash_minus_report -ge 0 ]] && [[ $dash_minus_report -le 5 ]]; then
        echo "  ✓  CLI report evidence ($report_count) <= dashboard total_requests ($dash_total) within allowed drift ($dash_minus_report)"
        record_pass
      else
        local count_diff=$dash_minus_report
        [[ $count_diff -lt 0 ]] && count_diff=$(( -count_diff ))
        log_failure "evidence count mismatch: report=$report_count dashboard=$dash_total" "diff=$count_diff"
      fi
    fi
  else
    echo "  -  evidence count parity: could not parse report ($report_count) or dashboard ($dash_total)"
  fi

  # Extract daily cost from report "Cost today (EUR): <value>" and compare with CLI costs total
  local report_cost; report_cost="$(echo "$cli_report" | grep 'Cost today' | grep -oE '[0-9]+\.[0-9]+' | head -1)"
  echo "[SMOKE] CONSISTENCY|report_cost_today|${report_cost:-none}"
  if [[ -n "$report_cost" ]] && [[ -n "$cli_daily_cost" ]]; then
    local rc_diff; rc_diff="$(echo "scale=8; d=$report_cost - $cli_daily_cost; if (d < 0) -d else d" | bc -l 2>/dev/null || echo 999)"
    if [[ "$(echo "$rc_diff < 0.01" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
      echo "  ✓  report cost today (€$report_cost) ≈ CLI costs today (€$cli_daily_cost)"
      record_pass
    else
      echo "  -  report vs CLI cost drift: report=$report_cost cli=$cli_daily_cost diff=$rc_diff"
    fi
  fi

  # PII type parity: compare PII types from report vs dashboard pii_breakdown
  local report_pii_types; report_pii_types="$(echo "$cli_report" | grep -E '^\s+- [a-z]+:' | awk '{gsub(/:/, "", $2); print $2}' | sort)"
  local dash_pii_types; dash_pii_types="$(jq -r '.pii_breakdown[].type // empty' <<< "$snap_after" 2>/dev/null | sort)"
  echo "[SMOKE] CONSISTENCY|report_pii_types|$(echo "$report_pii_types" | tr '\n' ',')"
  echo "[SMOKE] CONSISTENCY|dash_pii_types|$(echo "$dash_pii_types" | tr '\n' ',')"
  if [[ -n "$report_pii_types" ]] && [[ -n "$dash_pii_types" ]]; then
    # Report shows 7d window PII; dashboard shows since process start. Types should overlap.
    local shared_types=0
    while IFS= read -r ptype; do
      if echo "$dash_pii_types" | grep -qx "$ptype"; then
        (( shared_types++ ))
      fi
    done <<< "$report_pii_types"
    if [[ $shared_types -gt 0 ]]; then
      echo "  ✓  PII types overlap: $shared_types type(s) shared between report and dashboard"
      record_pass
    else
      echo "  -  PII types mismatch: report=[$report_pii_types] dash=[$dash_pii_types]"
    fi
  else
    echo "  -  PII type parity: no PII types to compare"
  fi

  # --- 23.7c: audit export ↔ dashboard record count ---
  local export_json; export_json="$(run_talon audit export --format json --tenant default --from 2020-01-01 --to 2099-12-31 2>/dev/null)"; true
  if echo "$export_json" | jq -e '.records' &>/dev/null; then
    local export_count; export_count="$(echo "$export_json" | jq '.records | length')"
    echo "[SMOKE] CONSISTENCY|audit_export_count|${export_count:-none}"
    if [[ -n "$export_count" ]] && [[ "$export_count" != "null" ]] && [[ -n "$dash_total" ]] && [[ "$dash_total" != "null" ]]; then
      if [[ "$export_count" -ge "$dash_total" ]]; then
        echo "  ✓  audit export records ($export_count) >= dashboard total_requests ($dash_total)"
        record_pass
      else
        echo "  -  audit export ($export_count) < dashboard total ($dash_total) — possible timing issue"
      fi
    fi
    # Verify export records have required compliance fields
    if [[ "$export_count" -gt 0 ]]; then
      assert_pass "export records have id field" \
        jq -e '.records[0].id' <<< "$export_json" &>/dev/null
      assert_pass "export records have tenant_id" \
        jq -e '.records[0].tenant_id' <<< "$export_json" &>/dev/null
      assert_pass "export records have cost field" \
        jq -e '.records[0] | has("cost")' <<< "$export_json" &>/dev/null
      assert_pass "export records have model_used field" \
        jq -e '.records[0] | has("model_used")' <<< "$export_json" &>/dev/null
    fi
  else
    echo "  -  audit export JSON parse failed — skipping export↔dashboard parity"
  fi

  # --- 23.8: Dashboard admin-key auth works ---
  assert_pass "dashboard HTML without admin key → 401" \
    test "$(smoke_get_code "$dashboard_base_url" "$SMOKE_PATH_GATEWAY_DASHBOARD")" = "401"
  assert_pass "dashboard metrics without admin key → 401" \
    test "$(smoke_get_code "$dashboard_base_url" "$SMOKE_PATH_METRICS")" = "401"
  assert_pass "dashboard metrics with wrong admin key → 401" \
    test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: wrong" "${dashboard_base_url}${SMOKE_PATH_METRICS}")" = "401"
  assert_pass "SSE stream without admin key → 401" \
    test "$(smoke_get_code "$dashboard_base_url" "$SMOKE_PATH_METRICS_STREAM")" = "401"
  assert_pass "dashboard metrics with admin key → 200" \
    test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: $admin_key" "${dashboard_base_url}${SMOKE_PATH_METRICS}")" = "200"

  # --- 23.9: SSE stream works ---
  local sse_out; sse_out="$(timeout 8 curl -s -H "X-Talon-Admin-Key: $admin_key" "${dashboard_base_url}${SMOKE_PATH_METRICS_STREAM}" 2>/dev/null)" || true
  if echo "$sse_out" | grep -q "data:"; then
    echo "  ✓  SSE stream returns data events"
    record_pass
    # Verify SSE data is valid JSON
    local sse_json; sse_json="$(echo "$sse_out" | grep '^data:' | head -1 | sed 's/^data: //')"
    if echo "$sse_json" | jq -e '.' &>/dev/null; then
      echo "  ✓  SSE data payload is valid JSON"
      record_pass
    else
      echo "  -  SSE data payload is not valid JSON"
    fi
  else
    echo "  -  SSE stream did not return data (timeout or not supported)"
  fi

  # --- 23.10: Snapshot consistency after multiple requests ---
  # error_rate should be a float in [0, 1]
  local err_rate; err_rate="$(jq '.summary.error_rate' <<< "$snap_after")"
  if [[ -n "$err_rate" ]] && [[ "$err_rate" != "null" ]]; then
    local in_range; in_range="$(echo "${err_rate} >= 0 && ${err_rate} <= 1" | bc -l 2>/dev/null || echo 1)"
    if [[ "$in_range" == "1" ]]; then
      echo "  ✓  error_rate is in [0,1] range ($err_rate)"
      record_pass
    else
      echo "  -  error_rate out of range: $err_rate"
    fi
  fi

  # --- 23.11: Prompt 16 enhanced-metrics consistency (outcome accounting, cost efficiency, CLI↔dashboard parity) ---
  echo ""
  echo "  -- 23.11: Enhanced metrics consistency checks (Prompt 16) --"

  # 23.11a: Per-caller outcome accounting: successful + failed + denied == requests
  local caller_outcome_ok=true
  for cname in $(jq -r '.caller_stats[].caller' <<< "$snap_after" 2>/dev/null); do
    local cs; cs="$(jq --arg c "$cname" '.caller_stats[] | select(.caller == $c)' <<< "$snap_after")"
    local c_req c_succ c_fail c_deny c_tout
    c_req="$(jq '.requests' <<< "$cs")"
    c_succ="$(jq '.successful' <<< "$cs")"
    c_fail="$(jq '.failed' <<< "$cs")"
    c_deny="$(jq '.denied' <<< "$cs")"
    c_tout="$(jq '.timed_out' <<< "$cs")"
    local c_sum=$(( c_succ + c_fail + c_deny ))
    if [[ "$c_sum" -eq "$c_req" ]]; then
      echo "  ✓  outcome accounting: $cname successful($c_succ)+failed($c_fail)+denied($c_deny)=$c_sum == requests($c_req)"
      record_pass
    else
      log_failure "outcome accounting: $cname successful+failed+denied=$c_sum != requests=$c_req" \
        "succ=$c_succ fail=$c_fail deny=$c_deny tout=$c_tout req=$c_req"
      caller_outcome_ok=false
    fi
    # timed_out must be <= failed (timeouts are a subset of failures)
    if [[ "$c_tout" -le "$c_fail" ]]; then
      echo "  ✓  timeout subset: $cname timed_out($c_tout) <= failed($c_fail)"
      record_pass
    else
      log_failure "timeout subset: $cname timed_out($c_tout) > failed($c_fail)" "invariant violation"
      caller_outcome_ok=false
    fi
  done
  echo "[SMOKE] CONSISTENCY|caller_outcome_accounting|${caller_outcome_ok}"

  # 23.11b: Summary outcome accounting: total_successful + total_failed + total_denied == total_requests
  local s_succ s_fail s_deny s_tout s_total
  s_succ="$(jq '.summary.total_successful' <<< "$snap_after")"
  s_fail="$(jq '.summary.total_failed' <<< "$snap_after")"
  s_deny="$(jq '.summary.total_denied' <<< "$snap_after")"
  s_tout="$(jq '.summary.total_timed_out' <<< "$snap_after")"
  s_total="$(jq '.summary.total_requests' <<< "$snap_after")"
  if [[ -n "$s_succ" ]] && [[ "$s_succ" != "null" ]]; then
    local s_sum=$(( s_succ + s_fail + s_deny ))
    if [[ "$s_sum" -eq "$s_total" ]]; then
      echo "  ✓  summary outcome: total_successful($s_succ)+total_failed($s_fail)+total_denied($s_deny)=$s_sum == total_requests($s_total)"
      record_pass
    else
      log_failure "summary outcome: $s_sum != total_requests $s_total" "succ=$s_succ fail=$s_fail deny=$s_deny"
    fi
    # summary.success_rate ≈ total_successful / total_requests
    local s_rate; s_rate="$(jq '.summary.success_rate' <<< "$snap_after")"
    if [[ -n "$s_total" ]] && [[ "$s_total" -gt 0 ]]; then
      local expected_rate; expected_rate="$(echo "scale=6; $s_succ / $s_total" | bc -l 2>/dev/null || echo -1)"
      if [[ "$expected_rate" != "-1" ]]; then
        local rate_diff; rate_diff="$(echo "scale=6; d=$s_rate - $expected_rate; if (d < 0) -d else d" | bc -l 2>/dev/null || echo 999)"
        if [[ "$(echo "$rate_diff < 0.01" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
          echo "  ✓  summary success_rate ($s_rate) ≈ total_successful/total_requests ($expected_rate)"
          record_pass
        else
          log_failure "summary success_rate ($s_rate) != expected ($expected_rate), diff=$rate_diff" "invariant"
        fi
      fi
    fi
    # summary total_timed_out <= total_failed
    if [[ "$s_tout" -le "$s_fail" ]]; then
      echo "  ✓  summary total_timed_out($s_tout) <= total_failed($s_fail)"
      record_pass
    else
      log_failure "summary total_timed_out($s_tout) > total_failed($s_fail)" "invariant"
    fi
    # summary totals == sum of per-caller fields
    local cs_succ_sum cs_fail_sum cs_deny_sum cs_tout_sum
    cs_succ_sum="$(jq '[.caller_stats[].successful] | add // 0' <<< "$snap_after")"
    cs_fail_sum="$(jq '[.caller_stats[].failed] | add // 0' <<< "$snap_after")"
    cs_deny_sum="$(jq '[.caller_stats[].denied] | add // 0' <<< "$snap_after")"
    cs_tout_sum="$(jq '[.caller_stats[].timed_out] | add // 0' <<< "$snap_after")"
    if [[ "$s_succ" -eq "$cs_succ_sum" ]] && [[ "$s_fail" -eq "$cs_fail_sum" ]] && [[ "$s_deny" -eq "$cs_deny_sum" ]] && [[ "$s_tout" -eq "$cs_tout_sum" ]]; then
      echo "  ✓  summary totals == sum(caller_stats): succ=$s_succ fail=$s_fail deny=$s_deny tout=$s_tout"
      record_pass
    else
      log_failure "summary vs caller_stats sum mismatch" \
        "summary: succ=$s_succ fail=$s_fail deny=$s_deny tout=$s_tout | callers: succ=$cs_succ_sum fail=$cs_fail_sum deny=$cs_deny_sum tout=$cs_tout_sum"
    fi
  fi
  echo "[SMOKE] CONSISTENCY|summary_outcome_accounting|succ=$s_succ fail=$s_fail deny=$s_deny tout=$s_tout total=$s_total"

  # 23.11c: Cost-per-success consistency per caller: cost_per_success * successful ≈ cost attributed to successes
  for cname in $(jq -r '.caller_stats[] | select(.successful > 0) | .caller' <<< "$snap_after" 2>/dev/null); do
    local cs; cs="$(jq --arg c "$cname" '.caller_stats[] | select(.caller == $c)' <<< "$snap_after")"
    local cps c_succ c_cost
    cps="$(jq '.cost_per_success' <<< "$cs")"
    c_succ="$(jq '.successful' <<< "$cs")"
    c_cost="$(jq '.cost_eur' <<< "$cs")"
    # cost_per_success > 0 when there are successes and cost > 0
    if [[ "$(echo "${c_cost:-0} > 0" | bc -l 2>/dev/null || echo 0)" == "1" ]] && [[ "$c_succ" -gt 0 ]]; then
      if [[ "$(echo "${cps:-0} > 0" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
        echo "  ✓  $cname cost_per_success ($cps) > 0 with $c_succ successes"
        record_pass
      else
        echo "  -  $cname cost_per_success ($cps) is 0 despite $c_succ successes and cost $c_cost"
      fi
      # cost_per_success * successful <= total caller cost (successes can't cost more than total)
      local success_cost; success_cost="$(echo "scale=8; $cps * $c_succ" | bc -l 2>/dev/null || echo 0)"
      if [[ "$(echo "$success_cost <= $c_cost + 0.0001" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
        echo "  ✓  $cname cost_per_success*successful (€$success_cost) <= total cost (€$c_cost)"
        record_pass
      else
        log_failure "$cname cost_per_success*successful (€$success_cost) > total cost (€$c_cost)" "cps=$cps succ=$c_succ"
      fi
    fi
  done

  # 23.11d: Violation trend: today's date must appear in at least one caller's trend
  local today_key; today_key="$(date -u +%Y-%m-%d)"
  local trend_has_today; trend_has_today="$(jq --arg d "$today_key" '[.caller_stats[].violation_trend[] | select(.date == $d)] | length' <<< "$snap_after")"
  if [[ -n "$trend_has_today" ]] && [[ "$trend_has_today" -gt 0 ]]; then
    echo "  ✓  violation_trend contains today's date ($today_key) across callers"
    record_pass
  else
    echo "  -  violation_trend does not contain today's date ($today_key) — may be UTC vs local"
  fi
  # All trend dates must be valid YYYY-MM-DD and ordered oldest→newest
  assert_pass "violation_trend dates are valid and ordered" \
    jq -e '
      all(.caller_stats[];
        (.violation_trend | length == 7)
        and all(.violation_trend[]; .date | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
        and (
          [.violation_trend[].date] |
          . == (. | sort)
        )
      )' <<< "$snap_after" &>/dev/null

  # 23.11e: CLI metrics --json ↔ dashboard parity (both hit /api/v1/metrics on the same running server)
  echo ""
  echo "  -- 23.11e: CLI metrics --json ↔ dashboard parity --"
  local cli_snap; cli_snap="$(run_talon metrics --json --url "$dashboard_base_url" 2>/dev/null)"; true
  local dash_snap; dash_snap="$(smoke_gw_get_metrics "$dashboard_base_url" "$admin_key")"
  if jq -e 'type=="array"' <<< "$cli_snap" &>/dev/null && jq -e '.' <<< "$dash_snap" &>/dev/null; then
    # CLI metrics --json returns caller_stats; compare counts for each caller
    for cname in $(jq -r '.[].caller' <<< "$cli_snap" 2>/dev/null); do
      local cli_req dash_req cli_sr dash_sr cli_cps dash_cps cli_tout dash_tout
      cli_req="$(jq --arg c "$cname" '.[] | select(.caller == $c) | .requests' <<< "$cli_snap")"
      dash_req="$(jq --arg c "$cname" '.caller_stats[] | select(.caller == $c) | .requests' <<< "$dash_snap")"
      cli_sr="$(jq --arg c "$cname" '.[] | select(.caller == $c) | .success_rate' <<< "$cli_snap")"
      dash_sr="$(jq --arg c "$cname" '.caller_stats[] | select(.caller == $c) | .success_rate' <<< "$dash_snap")"
      cli_cps="$(jq --arg c "$cname" '.[] | select(.caller == $c) | .cost_per_success' <<< "$cli_snap")"
      dash_cps="$(jq --arg c "$cname" '.caller_stats[] | select(.caller == $c) | .cost_per_success' <<< "$dash_snap")"
      cli_tout="$(jq --arg c "$cname" '.[] | select(.caller == $c) | .timed_out' <<< "$cli_snap")"
      dash_tout="$(jq --arg c "$cname" '.caller_stats[] | select(.caller == $c) | .timed_out' <<< "$dash_snap")"
      # Requests: CLI may lag by 1-2 if a request lands between the two fetches
      if [[ -n "$cli_req" ]] && [[ -n "$dash_req" ]] && [[ "$cli_req" != "null" ]] && [[ "$dash_req" != "null" ]]; then
        local req_diff=$(( dash_req - cli_req ))
        [[ $req_diff -lt 0 ]] && req_diff=$(( -req_diff ))
        if [[ $req_diff -le 2 ]]; then
          echo "  ✓  CLI↔dash parity: $cname requests cli=$cli_req dash=$dash_req (diff=$req_diff)"
          record_pass
        else
          log_failure "CLI↔dash parity: $cname requests cli=$cli_req dash=$dash_req (diff=$req_diff)" "tolerance=2"
        fi
      fi
      # Success rate: within 0.05 tolerance (tiny request-count drift)
      if [[ -n "$cli_sr" ]] && [[ -n "$dash_sr" ]] && [[ "$cli_sr" != "null" ]] && [[ "$dash_sr" != "null" ]]; then
        local sr_diff; sr_diff="$(echo "scale=6; d=$cli_sr - $dash_sr; if (d < 0) -d else d" | bc -l 2>/dev/null || echo 999)"
        if [[ "$(echo "$sr_diff < 0.05" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
          echo "  ✓  CLI↔dash parity: $cname success_rate cli=$cli_sr dash=$dash_sr"
          record_pass
        else
          echo "  -  CLI↔dash drift: $cname success_rate cli=$cli_sr dash=$dash_sr diff=$sr_diff"
        fi
      fi
      # Cost per success: within 20% tolerance (float drift from concurrent updates)
      if [[ -n "$cli_cps" ]] && [[ -n "$dash_cps" ]] && [[ "$cli_cps" != "null" ]] && [[ "$dash_cps" != "null" ]]; then
        local cps_diff; cps_diff="$(echo "scale=8; d=$cli_cps - $dash_cps; if (d < 0) -d else d" | bc -l 2>/dev/null || echo 999)"
        local cps_tol; cps_tol="$(echo "scale=8; t=$dash_cps * 0.2; if (t < 0.0001) 0.0001 else t" | bc -l 2>/dev/null || echo 0.0001)"
        if [[ "$(echo "$cps_diff < $cps_tol" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
          echo "  ✓  CLI↔dash parity: $cname cost_per_success cli=$cli_cps dash=$dash_cps"
          record_pass
        else
          echo "  -  CLI↔dash drift: $cname cost_per_success cli=$cli_cps dash=$dash_cps diff=$cps_diff"
        fi
      fi
      # Timed out: exact match expected (no timeouts in normal smoke)
      if [[ -n "$cli_tout" ]] && [[ -n "$dash_tout" ]] && [[ "$cli_tout" != "null" ]] && [[ "$dash_tout" != "null" ]]; then
        if [[ "$cli_tout" -eq "$dash_tout" ]]; then
          echo "  ✓  CLI↔dash parity: $cname timed_out=$cli_tout"
          record_pass
        else
          echo "  -  CLI↔dash drift: $cname timed_out cli=$cli_tout dash=$dash_tout"
        fi
      fi
    done
    echo "[SMOKE] CONSISTENCY|cli_dash_metrics_parity|checked"
  else
    echo "  -  CLI↔dashboard parity: could not parse CLI or dashboard JSON"
  fi

  # 23.11f: Live-traffic monotonicity — fire 5 more requests, take a new snapshot, verify counters only grow
  echo ""
  echo "  -- 23.11f: Live-traffic monotonicity (fire 5 requests, verify counters grow) --"
  local snap_before_live; snap_before_live="$(smoke_gw_get_metrics "$dashboard_base_url" "$admin_key")"
  for i in 1 2 3 4 5; do
    smoke_gw_post_chat "$dashboard_base_url" "Bearer $gw_key" "$(smoke_body_normal "live_$i")" >/dev/null || true
  done
  sleep 2
  local snap_after_live; snap_after_live="$(smoke_gw_get_metrics "$dashboard_base_url" "$admin_key")"
  local live_before_total live_after_total live_before_succ live_after_succ live_before_cost live_after_cost
  live_before_total="$(jq '.summary.total_requests' <<< "$snap_before_live")"
  live_after_total="$(jq '.summary.total_requests' <<< "$snap_after_live")"
  live_before_succ="$(jq '.summary.total_successful' <<< "$snap_before_live")"
  live_after_succ="$(jq '.summary.total_successful' <<< "$snap_after_live")"
  live_before_cost="$(jq '.summary.total_cost_eur' <<< "$snap_before_live")"
  live_after_cost="$(jq '.summary.total_cost_eur' <<< "$snap_after_live")"
  if [[ -n "$live_after_total" ]] && [[ "$live_after_total" != "null" ]] && [[ "$live_after_total" -ge "$live_before_total" ]]; then
    echo "  ✓  monotonicity: total_requests $live_before_total → $live_after_total"
    record_pass
  else
    log_failure "monotonicity: total_requests decreased $live_before_total → $live_after_total" "invariant"
  fi
  if [[ -n "$live_after_succ" ]] && [[ "$live_after_succ" != "null" ]] && [[ "$live_after_succ" -ge "$live_before_succ" ]]; then
    echo "  ✓  monotonicity: total_successful $live_before_succ → $live_after_succ"
    record_pass
  else
    log_failure "monotonicity: total_successful decreased $live_before_succ → $live_after_succ" "invariant"
  fi
  if [[ "$(echo "${live_after_cost:-0} >= ${live_before_cost:-0}" | bc -l 2>/dev/null || echo 1)" == "1" ]]; then
    echo "  ✓  monotonicity: total_cost_eur $live_before_cost → $live_after_cost"
    record_pass
  else
    echo "  -  monotonicity: total_cost_eur decreased $live_before_cost → $live_after_cost (cache hit?)"
  fi
  # success_rate must still be in [0,1] after live traffic
  local live_sr; live_sr="$(jq '.summary.success_rate' <<< "$snap_after_live")"
  if [[ -n "$live_sr" ]] && [[ "$live_sr" != "null" ]]; then
    if [[ "$(echo "$live_sr >= 0 && $live_sr <= 1" | bc -l 2>/dev/null || echo 0)" == "1" ]]; then
      echo "  ✓  live-traffic success_rate still in [0,1] ($live_sr)"
      record_pass
    else
      log_failure "live-traffic success_rate out of range: $live_sr" "invariant"
    fi
  fi
  # violation_trend still 7 entries per caller after live traffic
  assert_pass "violation_trend still 7 entries after live traffic" \
    jq -e 'all(.caller_stats[]; (.violation_trend | length == 7))' <<< "$snap_after_live" &>/dev/null
  # outcome accounting still holds after live traffic
  local live_s_succ live_s_fail live_s_deny live_s_total
  live_s_succ="$(jq '.summary.total_successful' <<< "$snap_after_live")"
  live_s_fail="$(jq '.summary.total_failed' <<< "$snap_after_live")"
  live_s_deny="$(jq '.summary.total_denied' <<< "$snap_after_live")"
  live_s_total="$(jq '.summary.total_requests' <<< "$snap_after_live")"
  local live_sum=$(( live_s_succ + live_s_fail + live_s_deny ))
  if [[ "$live_sum" -eq "$live_s_total" ]]; then
    echo "  ✓  live-traffic outcome accounting: $live_sum == $live_s_total"
    record_pass
  else
    log_failure "live-traffic outcome accounting: $live_sum != $live_s_total" "succ=$live_s_succ fail=$live_s_fail deny=$live_s_deny"
  fi
  echo "[SMOKE] CONSISTENCY|live_monotonicity|before_total=$live_before_total after_total=$live_after_total"

  kill "$GW_PID" 2>/dev/null || true
  wait "$GW_PID" 2>/dev/null || true
  sleep 2
  cd "$REPO_ROOT" || true
}

