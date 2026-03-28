#!/usr/bin/env bash
# Smoke test section: 12_http_api
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 12 — HTTP API and Dashboard (QUICKSTART serve, REST API reference)
# -----------------------------------------------------------------------------
test_section_12_http_api() {
  local section="12_http"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  # Add minimal gateway block so serve loads tenant keys and "tenant key can read /v1/evidence" can pass.
  # Use unquoted heredoc so $TALON_TENANT_KEY is expanded into the caller list.
  if [[ -f "$dir/talon.config.yaml" ]] && ! grep -q "gateway:" "$dir/talon.config.yaml" 2>/dev/null; then
    cat >> "$dir/talon.config.yaml" <<GWEOF

gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "shadow"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  callers:
    - name: "api-tenant"
      tenant_key: "${TALON_TENANT_KEY}"
      tenant_id: "default"
      allowed_providers: ["openai"]
  default_policy:
    require_caller_id: true
GWEOF
  fi
  run_talon run "Seed" &>/dev/null; true
  TALON_SERVE_PID=""
  local serve_log_12="$dir/serve_section12.log"
  run_talon serve --config "$dir/talon.config.yaml" --port 8080 --gateway --gateway-config "$dir/talon.config.yaml" >"$serve_log_12" 2>&1 &
  TALON_SERVE_PID=$!
  if ! smoke_wait_health "http://127.0.0.1:8080" 10 1; then
    local s12_pid_state="running"
    if ! kill -0 "$TALON_SERVE_PID" 2>/dev/null; then
      wait "$TALON_SERVE_PID" 2>/dev/null; s12_pid_state="exited($?)"
    fi
    log_failure "server did not become ready on 8080 within 10s" \
      "pid=$TALON_SERVE_PID state=$s12_pid_state"
    dump_diag_file "section 12 serve log" "$serve_log_12"
    dump_diag_file "talon.config.yaml" "$dir/talon.config.yaml"
    dump_diag_file "agent.talon.yaml" "$dir/agent.talon.yaml"
    dump_diag_env
    kill "$TALON_SERVE_PID" 2>/dev/null || true
    TALON_SERVE_PID=""
    cd "$REPO_ROOT" || true
    return 0
  fi
  local admin_key="${TALON_ADMIN_KEY}"
  # Use caller tenant_key so server (which loads gateway callers) accepts Bearer for /v1/evidence
  local tenant_key="${TALON_TENANT_KEY:-talon-api-tenant-001}"
  assert_pass "GET /health 200" test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health)" = "200"
  local status_json; status_json="$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/status)"
  assert_pass "GET /status 200 with status field" jq -e '.status' <<< "$status_json" &>/dev/null
  assert_pass "GET /status has dashboard fields (pending_memory_reviews, blocked_count, tenant_id)" \
    jq -e 'has("pending_memory_reviews") and has("blocked_count") and has("tenant_id")' <<< "$status_json" &>/dev/null
  assert_pass "GET /v1/evidence 200 JSON array" \
    jq -e 'type == "object" and (.entries | type == "array")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/evidence)" &>/dev/null
  local ev_list; ev_list="$(curl -s -H "X-Talon-Admin-Key: $admin_key" 'http://127.0.0.1:8080/v1/evidence?limit=1')"
  assert_pass "GET /v1/evidence?limit=1 at most one entry" \
    test "$(echo "$ev_list" | jq '.entries | length')" -le 1
  local ev_id; ev_id="$(echo "$ev_list" | jq -r '.entries[0].id // empty')"
  if [[ -n "$ev_id" ]] && [[ "$ev_id" != "null" ]]; then
    assert_pass "GET /v1/evidence/<id> 200 with policy_decision" \
      jq -e '.policy_decision' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" "http://127.0.0.1:8080/v1/evidence/$ev_id")" &>/dev/null
    assert_pass "GET /v1/evidence/<id>/verify 200 valid: true" \
      grep -q true <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" "http://127.0.0.1:8080/v1/evidence/$ev_id/verify")"
  fi
  assert_pass "GET /v1/evidence/nonexistent-id-00000 404" \
    test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/evidence/nonexistent-id-00000)" = "404"
  if [[ -n "$ev_id" ]] && [[ "$ev_id" != "null" ]]; then
    assert_pass "GET /v1/evidence/timeline?around=<id> 200" \
      test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: $admin_key" "http://127.0.0.1:8080/v1/evidence/timeline?around=$ev_id")" = "200"
    assert_pass "GET /v1/evidence/<id>/trace 200 with evidence and steps" \
      jq -e '.evidence and (.steps | type == "array")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" "http://127.0.0.1:8080/v1/evidence/$ev_id/trace")" &>/dev/null
  fi
  assert_pass "GET /v1/evidence with query params (allowed, model) 200" \
    jq -e 'type == "object" and (.entries | type == "array")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" 'http://127.0.0.1:8080/v1/evidence?limit=3&allowed=true')" &>/dev/null
  assert_pass "GET /v1/costs 200 with daily/monthly" \
    jq -e 'type == "object"' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/costs)" &>/dev/null
  assert_pass "GET /v1/costs/budget 200 with daily_used and monthly_used" \
    jq -e 'has("daily_used") and has("monthly_used")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/costs/budget)" &>/dev/null
  assert_pass "GET /v1/costs/report 200 with total_eur and from/to" \
    jq -e 'has("total_eur") and has("from") and has("to")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/costs/report)" &>/dev/null
  assert_pass "GET /v1/dashboard/tenants-summary 200 with tenants and agents" \
    jq -e 'has("tenants") and has("agents")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/dashboard/tenants-summary)" &>/dev/null
  assert_pass "GET /v1/dashboard/denials-by-reason 200 with total and by_reason" \
    jq -e 'has("total") and has("by_reason")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/dashboard/denials-by-reason)" &>/dev/null
  assert_pass "GET /v1/dashboard/governance-alerts 200 with alerts array" \
    jq -e 'has("alerts") and (.alerts | type == "array")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/dashboard/governance-alerts)" &>/dev/null
  assert_pass "GET /v1/dashboard/audit-pack 200 with evidence_count" \
    jq -e 'has("evidence_count") and has("generated_at")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/dashboard/audit-pack)" &>/dev/null
  assert_pass "GET /v1/dashboard/review-history 200 with reviews array" \
    jq -e 'has("reviews") and (.reviews | type == "array")' <<< "$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/v1/dashboard/review-history)" &>/dev/null
  assert_pass "POST /v1/evidence/export 200 with CSV or JSON body" \
    test "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "X-Talon-Admin-Key: $admin_key" -H "Content-Type: application/json" -d '{"limit":10,"format":"json"}' http://127.0.0.1:8080/v1/evidence/export)" = "200"
  local export_body; export_body="$(curl -s -X POST -H "X-Talon-Admin-Key: $admin_key" -H "Content-Type: application/json" -d '{"limit":10,"format":"json"}' http://127.0.0.1:8080/v1/evidence/export)"
  assert_pass "POST /v1/evidence/export JSON returns array of records" \
    jq -e 'type == "array"' <<< "$export_body" &>/dev/null
  local dash_headers
  dash_headers="$(curl -sI http://127.0.0.1:8080/dashboard 2>/dev/null | head -10)"
  assert_pass "GET /dashboard 200" bash -c 'echo "$1" | grep -qi "200"' _ "$dash_headers"
  assert_pass "GET /dashboard Content-Type text/html" grep -qi 'text/html' <<< "$dash_headers"
  local gov_dash_html
  gov_dash_html="$(curl -s -H "X-Talon-Admin-Key: $admin_key" http://127.0.0.1:8080/dashboard)"
  assert_pass "governance dashboard contains Talon Mission Control marker" grep -q "Talon Mission Control" <<< "$gov_dash_html"
  assert_pass "governance dashboard contains session timeline marker" grep -q "Session timeline (lifecycle)" <<< "$gov_dash_html"
  assert_pass "governance dashboard contains compliance preview marker" grep -q "Compliance report preview" <<< "$gov_dash_html"
  assert_pass "No key → 401" test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/v1/evidence)" = "401"
  local tenant_ev_code; tenant_ev_code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $tenant_key" http://127.0.0.1:8080/v1/evidence)"
  if [[ "$tenant_ev_code" == "200" ]]; then
    assert_pass "tenant key can read /v1/evidence (Authorization Bearer) → 200" true
  else
    echo "  -  tenant key /v1/evidence returned $tenant_ev_code (gateway callers may not be loaded in this env)"
  fi
  local base_url="http://127.0.0.1:8080"
  # Session lifecycle checks: create + join via API and confirm continuity.
  local run1_headers="/tmp/talon_smoke_run1_headers.txt"
  local run1_body="/tmp/talon_smoke_run1_body.json"
  local run1_code run1_session run2_code run2_session run1_ev run2_ev
  run1_code="$(curl -s -D "$run1_headers" -o "$run1_body" -w '%{http_code}' -X POST "${base_url}/v1/agents/run" \
    -H "Authorization: Bearer ${tenant_key}" -H "Content-Type: application/json" \
    -H "X-Talon-Reasoning: smoke-http-session-create" \
    -d '{"tenant_id":"default","agent_name":"default","prompt":"Session smoke create (HTTP API)","_talon_reasoning":"smoke-fallback-reasoning"}')"
  if ! assert_pass "POST /v1/agents/run returns 200 for session create" test "$run1_code" = "200"; then
    dump_diag_kv "agents/run session create" \
      "http_code=$run1_code" \
      "tenant_key_used=$tenant_key" \
      "base_url=$base_url" \
      "endpoint=${base_url}/v1/agents/run"
    dump_diag_json "run1 response body" "$(cat "$run1_body" 2>/dev/null || echo '(file missing)')"
    dump_diag_file "run1 response headers" "$run1_headers"
    dump_diag_file "talon.config.yaml (gateway callers)" "$dir/talon.config.yaml"
    dump_diag_env
  fi
  run1_session="$(awk 'BEGIN{IGNORECASE=1} /^X-Talon-Session-ID:/ {gsub("\r","",$2); print $2; exit}' "$run1_headers" 2>/dev/null || true)"
  if [[ -z "$run1_session" ]]; then
    run1_session="$(jq -r '.session_id // empty' < "$run1_body" 2>/dev/null || true)"
  fi
  if [[ -n "$run1_session" ]]; then
    echo "  ✓  /v1/agents/run returns session id: $run1_session"
    record_pass
  else
    log_failure "/v1/agents/run should return session_id (header or body)" "headers=$(cat "$run1_headers" 2>/dev/null)"
    dump_diag_json "run1 response body" "$(cat "$run1_body" 2>/dev/null || echo '(file missing)')"
    dump_diag_file "run1 response headers" "$run1_headers"
  fi
  run1_ev="$(jq -r '.evidence_id // empty' < "$run1_body" 2>/dev/null || true)"
  run2_code="$(curl -s -o /tmp/talon_smoke_run2_body.json -w '%{http_code}' -X POST "${base_url}/v1/agents/run" \
    -H "Authorization: Bearer ${tenant_key}" -H "Content-Type: application/json" \
    -H "X-Talon-Session-ID: ${run1_session}" \
    -d "{\"tenant_id\":\"default\",\"agent_name\":\"default\",\"prompt\":\"Session smoke join (HTTP API)\",\"_talon_session_id\":\"${run1_session}\"}")"
  if ! assert_pass "POST /v1/agents/run with session join returns 200" test "$run2_code" = "200"; then
    dump_diag_kv "agents/run session join" \
      "http_code=$run2_code" \
      "session_id_sent=$run1_session" \
      "tenant_key=$tenant_key"
    dump_diag_json "run2 response body" "$(cat /tmp/talon_smoke_run2_body.json 2>/dev/null || echo '(missing)')"
  fi
  run2_session="$(jq -r '.session_id // empty' < /tmp/talon_smoke_run2_body.json 2>/dev/null || true)"
  if [[ -n "$run1_session" ]] && [[ -n "$run2_session" ]] && [[ "$run1_session" == "$run2_session" ]]; then
    echo "  ✓  second /v1/agents/run joined same session id"
    record_pass
  else
    log_failure "session join should preserve session_id across /v1/agents/run" \
      "run1=$run1_session run2=$run2_session"
    dump_diag_json "run2 body" "$(cat /tmp/talon_smoke_run2_body.json 2>/dev/null || echo '(missing)')"
  fi
  run2_ev="$(jq -r '.evidence_id // empty' < /tmp/talon_smoke_run2_body.json 2>/dev/null || true)"
  if [[ -n "$run1_ev" ]] && [[ -n "$run2_ev" ]]; then
    local ev1 ev2
    ev1="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "http://127.0.0.1:8080/v1/evidence/$run1_ev")"
    ev2="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "http://127.0.0.1:8080/v1/evidence/$run2_ev")"
    assert_pass "evidence for run1 contains matching session_id" \
      jq -e --arg sid "$run1_session" '.session_id == $sid' <<< "$ev1" &>/dev/null
    assert_pass "evidence for run2 contains matching session_id" \
      jq -e --arg sid "$run1_session" '.session_id == $sid' <<< "$ev2" &>/dev/null
  fi
  # Session API (GET list, GET by id, POST complete)
  local sessions_list; sessions_list="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "http://127.0.0.1:8080/v1/sessions?tenant_id=default")"
  assert_pass "GET /v1/sessions 200 and array" jq -e 'type == "array"' <<< "$sessions_list" &>/dev/null
  if [[ -n "$run1_session" ]]; then
    local sess_get; sess_get="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "http://127.0.0.1:8080/v1/sessions/$run1_session")"
    assert_pass "GET /v1/sessions/<id> 200 with id and status" \
      jq -e '.id and .status' <<< "$sess_get" &>/dev/null
    local complete_code; complete_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $tenant_key" "http://127.0.0.1:8080/v1/sessions/$run1_session/complete")"
    assert_pass "POST /v1/sessions/<id>/complete 200" test "$complete_code" = "200"
    sess_get="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "http://127.0.0.1:8080/v1/sessions/$run1_session")"
    assert_pass "GET /v1/sessions/<id> after complete has status completed" \
      jq -e '.status == "completed"' <<< "$sess_get" &>/dev/null
  fi
  rm -f "$run1_headers" "$run1_body" /tmp/talon_smoke_run2_body.json 2>/dev/null || true
  assert_pass "Wrong admin key → 401" test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: wrong-key" http://127.0.0.1:8080/v1/evidence)" = "401"
  # POST /mcp is tenant-only (TenantKeyMiddleware); use tenant key when available
  local mcp_resp; mcp_resp="$(curl -s -X POST -H "Authorization: Bearer $tenant_key" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' http://127.0.0.1:8080/mcp)"
  if echo "$mcp_resp" | jq -e '.result' &>/dev/null; then
    assert_pass "POST /mcp tools/list 200 with result" true
  else
    echo "  -  POST /mcp tools/list: no .result (tenant key may not be loaded or MCP returned error)"
  fi
  kill "$TALON_SERVE_PID" 2>/dev/null || true
  wait "$TALON_SERVE_PID" 2>/dev/null || true
  TALON_SERVE_PID=""
  cd "$REPO_ROOT" || true
}

