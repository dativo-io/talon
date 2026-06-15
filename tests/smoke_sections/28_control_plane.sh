#!/usr/bin/env bash
# Smoke test section: 28_control_plane
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# Section 28: Operational Control Plane admin API
# Proves: runs list, kill, pause/resume, overrides lockdown, tool disable,
# tool approval list/get/decide endpoint behavior, remediation decision fail-closed,
# 28p-native HTTP E2E when safe tools exist (skip otherwise), and 28p-bridge go test.
# Black-box: uses only curl against the admin API. No internal Go wiring tested here.
# -----------------------------------------------------------------------------
test_section_28_control_plane() {
  local section="28_control_plane"
  local cp_port="8080"
  local cp_base="http://127.0.0.1:${cp_port}"
  echo ""
  echo "=== SECTION 28 — Operational Control Plane Admin API ==="
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1

  if ! wait_port_free "$cp_port" 180 10; then
    log_failure "control plane section could not acquire port ${cp_port}" "port remained busy"
    cd "$REPO_ROOT" || true
    return 0
  fi

  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"

  local CP_PID=""
  local cp_log="$dir/cp_serve.log"
  run_talon serve --port "$cp_port" >"$cp_log" 2>&1 &
  CP_PID=$!
  if ! smoke_wait_health "$cp_base" 45 1; then
    log_failure "control plane server did not start on port ${cp_port}"
    dump_diag_file "section 28 serve log" "$cp_log" 120
    kill "$CP_PID" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi

  local admin_hdr="X-Talon-Admin-Key: ${TALON_ADMIN_KEY}"

  # --- 28a: GET /v1/runs returns 200 with empty runs list ---
  local runs_code runs_body
  runs_body="$(mktemp)"
  runs_code="$(curl -s -o "$runs_body" -w '%{http_code}' -H "$admin_hdr" "${cp_base}/v1/runs" 2>/dev/null)"
  if [[ "$runs_code" == "200" ]]; then
    local count
    count="$(jq -r '.count // 0' "$runs_body" 2>/dev/null)"
    if [[ "$count" =~ ^[0-9]+$ ]]; then
      echo "  ✓  control_plane_runs_list (HTTP 200, count=$count)"
      record_pass
    else
      log_failure "control_plane_runs_list response missing count field"
    fi
  else
    log_failure "control_plane_runs_list expected HTTP 200, got $runs_code"
  fi
  rm -f "$runs_body"

  # --- 28b: GET /v1/runs without admin key returns 401 ---
  local noauth_code
  noauth_code="$(curl -s -o /dev/null -w '%{http_code}' "${cp_base}/v1/runs" 2>/dev/null)"
  if [[ "$noauth_code" == "401" ]]; then
    echo "  ✓  control_plane_runs_auth_required (HTTP 401 without key)"
    record_pass
  else
    log_failure "control_plane_runs_auth_required expected HTTP 401, got $noauth_code"
  fi

  # --- 28c: GET /v1/overrides returns 200 ---
  local ovr_code
  ovr_code="$(curl -s -o /dev/null -w '%{http_code}' -H "$admin_hdr" "${cp_base}/v1/overrides" 2>/dev/null)"
  if [[ "$ovr_code" == "200" ]]; then
    echo "  ✓  control_plane_overrides_list (HTTP 200)"
    record_pass
  else
    log_failure "control_plane_overrides_list expected HTTP 200, got $ovr_code"
  fi

  # --- 28d: POST lockdown + verify + DELETE unlock ---
  local lock_code lock_body
  lock_body="$(mktemp)"
  lock_code="$(curl -s -o "$lock_body" -w '%{http_code}' -X POST -H "$admin_hdr" "${cp_base}/v1/overrides/smoke-tenant/lockdown" 2>/dev/null)"
  if [[ "$lock_code" == "200" ]]; then
    local locked
    locked="$(jq -r '.lockdown' "$lock_body" 2>/dev/null)"
    if [[ "$locked" == "true" ]]; then
      echo "  ✓  control_plane_lockdown_activate (HTTP 200, lockdown=true)"
      record_pass
    else
      log_failure "control_plane_lockdown_activate lockdown not true in response"
    fi
  else
    log_failure "control_plane_lockdown_activate expected HTTP 200, got $lock_code"
  fi
  rm -f "$lock_body"

  local get_ovr_body
  get_ovr_body="$(mktemp)"
  curl -s -o "$get_ovr_body" -H "$admin_hdr" "${cp_base}/v1/overrides/smoke-tenant" 2>/dev/null
  local is_locked
  is_locked="$(jq -r '.lockdown' "$get_ovr_body" 2>/dev/null)"
  if [[ "$is_locked" == "true" ]]; then
    echo "  ✓  control_plane_lockdown_verify (GET confirms lockdown=true)"
    record_pass
  else
    log_failure "control_plane_lockdown_verify expected lockdown=true, got $is_locked"
  fi
  rm -f "$get_ovr_body"

  local unlock_code
  unlock_code="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "$admin_hdr" "${cp_base}/v1/overrides/smoke-tenant/lockdown" 2>/dev/null)"
  if [[ "$unlock_code" == "200" ]]; then
    echo "  ✓  control_plane_lockdown_lift (HTTP 200)"
    record_pass
  else
    log_failure "control_plane_lockdown_lift expected HTTP 200, got $unlock_code"
  fi

  # --- 28e: POST tools/disable + verify + POST tools/enable ---
  local disable_code disable_body
  disable_body="$(mktemp)"
  disable_code="$(curl -s -o "$disable_body" -w '%{http_code}' -X POST \
    -H "$admin_hdr" -H "Content-Type: application/json" \
    -d '{"tools":["dangerous_tool"],"reason":"INC-SMOKE-001"}' \
    "${cp_base}/v1/overrides/smoke-tenant/tools/disable" 2>/dev/null)"
  if [[ "$disable_code" == "200" ]]; then
    local disabled_tools
    disabled_tools="$(jq -r '.disabled_tools[]?' "$disable_body" 2>/dev/null)"
    if echo "$disabled_tools" | grep -q "dangerous_tool"; then
      echo "  ✓  control_plane_tools_disable (HTTP 200, tool in list)"
      record_pass
    else
      log_failure "control_plane_tools_disable tool not found in response disabled_tools"
    fi
  else
    log_failure "control_plane_tools_disable expected HTTP 200, got $disable_code"
  fi
  rm -f "$disable_body"

  local enable_code
  enable_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "$admin_hdr" -H "Content-Type: application/json" \
    -d '{"tools":["dangerous_tool"]}' \
    "${cp_base}/v1/overrides/smoke-tenant/tools/enable" 2>/dev/null)"
  if [[ "$enable_code" == "200" ]]; then
    echo "  ✓  control_plane_tools_enable (HTTP 200)"
    record_pass
  else
    log_failure "control_plane_tools_enable expected HTTP 200, got $enable_code"
  fi

  # --- 28f: POST policy override ---
  local pol_code pol_body
  pol_body="$(mktemp)"
  pol_code="$(curl -s -o "$pol_body" -w '%{http_code}' -X POST \
    -H "$admin_hdr" -H "Content-Type: application/json" \
    -d '{"max_cost_per_run":0.01,"max_tool_calls":3}' \
    "${cp_base}/v1/overrides/smoke-tenant/policy" 2>/dev/null)"
  if [[ "$pol_code" == "200" ]]; then
    local max_cost
    max_cost="$(jq -r '.max_cost_per_run // empty' "$pol_body" 2>/dev/null)"
    if [[ -n "$max_cost" ]]; then
      echo "  ✓  control_plane_policy_override (HTTP 200, max_cost_per_run set)"
      record_pass
    else
      log_failure "control_plane_policy_override max_cost_per_run not in response"
    fi
  else
    log_failure "control_plane_policy_override expected HTTP 200, got $pol_code"
  fi
  rm -f "$pol_body"

  # --- 28g: DELETE clear all overrides ---
  local clear_code
  clear_code="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "$admin_hdr" "${cp_base}/v1/overrides/smoke-tenant" 2>/dev/null)"
  if [[ "$clear_code" == "200" ]]; then
    echo "  ✓  control_plane_overrides_clear (HTTP 200)"
    record_pass
  else
    log_failure "control_plane_overrides_clear expected HTTP 200, got $clear_code"
  fi

  # --- 28h: GET /v1/tool-approvals returns 200 (empty) ---
  local ta_code ta_body
  ta_body="$(mktemp)"
  ta_code="$(curl -s -o "$ta_body" -w '%{http_code}' -H "$admin_hdr" "${cp_base}/v1/tool-approvals" 2>/dev/null)"
  if [[ "$ta_code" == "200" ]]; then
    local ta_count
    ta_count="$(jq -r '.count // 0' "$ta_body" 2>/dev/null)"
    if [[ "$ta_count" =~ ^[0-9]+$ ]]; then
      echo "  ✓  control_plane_tool_approvals_list (HTTP 200, count=$ta_count)"
      record_pass
    else
      log_failure "control_plane_tool_approvals_list missing count field"
    fi
  else
    log_failure "control_plane_tool_approvals_list expected HTTP 200, got $ta_code"
  fi
  rm -f "$ta_body"

  # --- 28i: GET /v1/tool-approvals/{id} returns 404 for nonexistent id ---
  local ta_get_code
  ta_get_code="$(curl -s -o /dev/null -w '%{http_code}' -H "$admin_hdr" "${cp_base}/v1/tool-approvals/nonexistent" 2>/dev/null)"
  if [[ "$ta_get_code" == "404" ]]; then
    echo "  ✓  control_plane_tool_approval_get_not_found (HTTP 404 for nonexistent request)"
    record_pass
  else
    log_failure "control_plane_tool_approval_get_not_found expected HTTP 404, got $ta_get_code"
  fi

  # --- 28j: POST /v1/tool-approvals/{id}/decide invalid body returns 400 ---
  local ta_decide_invalid_code
  ta_decide_invalid_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "$admin_hdr" -H "Content-Type: application/json" \
    -d '{' \
    "${cp_base}/v1/tool-approvals/nonexistent/decide" 2>/dev/null)"
  if [[ "$ta_decide_invalid_code" == "400" ]]; then
    echo "  ✓  control_plane_tool_approval_decide_invalid_body (HTTP 400)"
    record_pass
  else
    log_failure "control_plane_tool_approval_decide_invalid_body expected HTTP 400, got $ta_decide_invalid_code"
  fi

  # --- 28k: POST /v1/tool-approvals/{id}/decide approve returns 404 for nonexistent id ---
  local ta_decide_missing_code
  ta_decide_missing_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "$admin_hdr" -H "Content-Type: application/json" \
    -d '{"decision":"approve","reason":"smoke approve"}' \
    "${cp_base}/v1/tool-approvals/nonexistent/decide" 2>/dev/null)"
  if [[ "$ta_decide_missing_code" == "404" ]]; then
    echo "  ✓  control_plane_tool_approval_decide_not_found (HTTP 404)"
    record_pass
  else
    log_failure "control_plane_tool_approval_decide_not_found expected HTTP 404, got $ta_decide_missing_code"
  fi

  # --- 28l: remediation payload on nonexistent approval stays fail-closed (404, no bypass) ---
  local ta_remediate_missing_code
  ta_remediate_missing_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "$admin_hdr" -H "Content-Type: application/json" \
    -d '{"decision":"approve","reason":"apply remediation","remediation":{"mode":"re_redact_rescan"}}' \
    "${cp_base}/v1/tool-approvals/nonexistent/decide" 2>/dev/null)"
  if [[ "$ta_remediate_missing_code" == "404" ]]; then
    echo "  ✓  control_plane_tool_approval_remediation_not_found_fail_closed (HTTP 404)"
    record_pass
  else
    log_failure "control_plane_tool_approval_remediation_not_found_fail_closed expected HTTP 404, got $ta_remediate_missing_code"
  fi

  # --- 28m: POST /v1/runs/{id}/kill returns 404 for nonexistent run ---
  local kill_code
  kill_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$admin_hdr" "${cp_base}/v1/runs/nonexistent-run/kill" 2>/dev/null)"
  if [[ "$kill_code" == "404" ]]; then
    echo "  ✓  control_plane_kill_not_found (HTTP 404 for nonexistent run)"
    record_pass
  else
    log_failure "control_plane_kill_not_found expected HTTP 404, got $kill_code"
  fi

  # --- 28n: POST /v1/runs/kill-all without tenant_id returns 400 ---
  local killall_code
  killall_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$admin_hdr" "${cp_base}/v1/runs/kill-all" 2>/dev/null)"
  if [[ "$killall_code" == "400" ]]; then
    echo "  ✓  control_plane_killall_requires_tenant (HTTP 400 without tenant_id)"
    record_pass
  else
    log_failure "control_plane_killall_requires_tenant expected HTTP 400, got $killall_code"
  fi

  # --- 28o: POST tools/disable with empty body returns 400 ---
  local empty_disable_code
  empty_disable_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "$admin_hdr" -H "Content-Type: application/json" \
    -d '{"tools":[]}' \
    "${cp_base}/v1/overrides/smoke-tenant/tools/disable" 2>/dev/null)"
  if [[ "$empty_disable_code" == "400" ]]; then
    echo "  ✓  control_plane_tools_disable_validation (HTTP 400 for empty tools)"
    record_pass
  else
    log_failure "control_plane_tools_disable_validation expected HTTP 400, got $empty_disable_code"
  fi

  # --- 28p: tool approval with remediation (native HTTP E2E + go test bridge) ---
  echo ""
  echo "  -- 28p: tool_approval_remediation --"
  echo "  -- 28p-native: end_to_end_tool_approval_with_remediation --"

  local mcp_list_resp safe_tool="" mcp_tool_name mcp_tool_count=0
  mcp_list_resp="$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' \
    "${cp_base}/mcp" 2>/dev/null || true)"
  mcp_tool_count="$(jq -r '(.result.tools // []) | length' <<< "$mcp_list_resp" 2>/dev/null || echo 0)"
  for mcp_tool_name in smoke_safe_ls ls read_file file_read; do
    if jq -e --arg t "$mcp_tool_name" '.result.tools[]? | select(.name == $t)' <<< "$mcp_list_resp" &>/dev/null; then
      safe_tool="$mcp_tool_name"
      break
    fi
  done
  if [[ -z "$safe_tool" ]]; then
    echo "  -  28p-native skipped: no registered safe tool in MCP tools/list"
    echo "[SMOKE] SECTION|28p-native|SKIP|no_registered_safe_tool"
    dump_diag_kv "28p-native skip" \
      "mcp_tool_count=$mcp_tool_count" \
      "openai_key_set=$([[ -n "${OPENAI_API_KEY:-}" ]] && echo yes || echo no)" \
      "serve_pid=$CP_PID"
    dump_diag_json "mcp tools/list response" "$mcp_list_resp"
    dump_diag_file "section 28 serve log (tools/list)" "$cp_log" 80
  elif [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "  -  28p-native skipped: OPENAI_API_KEY required for agentic tool-call flow"
    echo "[SMOKE] SECTION|28p-native|SKIP|openai_api_key_required"
    dump_diag_env
  else
  echo "  ✓  discovered safe registered tool for E2E: $safe_tool"
  record_pass

  kill "$CP_PID" 2>/dev/null || true
  wait "$CP_PID" 2>/dev/null || true
  sleep 2

  local agent_yaml="$dir/agent.talon.yaml"
  if command -v yq >/dev/null 2>&1; then
    yq -i \
      --arg tool "$safe_tool" \
      '.capabilities.allowed_tools = [$tool] |
       .policies.resource_limits.max_iterations = 3 |
       .policies.resource_limits.require_approval = [$tool] |
       .policies.rate_limits.requests_per_minute = 300' \
      "$agent_yaml" 2>/dev/null || true
  else
    cat > "$agent_yaml" <<POLICYEOF
agent:
  name: smoke-agent
  version: "1.0"
capabilities:
  allowed_tools:
    - ${safe_tool}
policies:
  cost_limits:
    per_request: 0.50
    daily: 5.0
    monthly: 50.0
  resource_limits:
    max_iterations: 3
    require_approval:
      - ${safe_tool}
    timeout:
      operation: "30s"
      tool_execution: "2m"
      agent_total: "5m"
  rate_limits:
    requests_per_minute: 300
    concurrent_executions: 1
POLICYEOF
  fi
  dump_diag_file "agent.talon.yaml for E2E tool approval" "$agent_yaml"

  run_talon serve --port "$cp_port" >"$cp_log" 2>&1 &
  CP_PID=$!
  if ! smoke_wait_health "$cp_base" 45 1; then
    log_failure "control_plane_e2e_serve_restart_failed"
    dump_diag_file "section 28 E2E serve log" "$cp_log" 120
    kill "$CP_PID" 2>/dev/null || true
  else
  local run_body="$dir/ta_e2e_run_body.json"
  local run_code_file="$dir/ta_e2e_run_http_code"
  local run_stderr="$dir/ta_e2e_run_stderr.log"
  local run_curl_pid="" approval_id="" run_code=""
  local e2e_prompt
  e2e_prompt="You MUST call the ${safe_tool} tool exactly once. Include email jan.kowalski@example.com in the tool arguments or payload. After the tool returns, reply with exactly: SMOKE_TOOL_OK"

  curl -s -o "$run_body" -w '%{http_code}' \
    -X POST "${cp_base}/v1/agents/run" \
    -H "Content-Type: application/json" \
    -d "$(jq -nc --arg p "$e2e_prompt" --arg tool "$safe_tool" \
      '{tenant_id:"default",agent_name:"smoke-agent",prompt:$p}')" \
    >"$run_code_file" 2>"$run_stderr" &
  run_curl_pid=$!

  local attempt=0 attempts=45
  while [[ $attempt -lt $attempts ]]; do
    local ta_poll
    ta_poll="$(curl -s -H "$admin_hdr" "${cp_base}/v1/tool-approvals" 2>/dev/null || true)"
    approval_id="$(jq -r --arg t "$safe_tool" '.pending[]? | select(.tool_name == $t) | .id' <<< "$ta_poll" | head -1)"
    if [[ -n "$approval_id" ]]; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  if [[ -z "$approval_id" ]]; then
    log_failure "control_plane_e2e_pending_approval_not_found" "tool=$safe_tool attempts=$attempts"
    dump_diag_file "E2E agents/run stderr" "$run_stderr"
    dump_diag_file "E2E agents/run body (partial)" "$run_body" 40
    dump_diag_file "section 28 E2E serve log" "$cp_log" 80
    kill "$run_curl_pid" 2>/dev/null || true
    wait "$run_curl_pid" 2>/dev/null || true
  else
  echo "  ✓  found pending tool approval: $approval_id (tool=$safe_tool)"
  record_pass

  local ta_get_resp
  ta_get_resp="$(curl -s -H "$admin_hdr" "${cp_base}/v1/tool-approvals/${approval_id}" 2>/dev/null || true)"
  if jq -e --arg t "$safe_tool" '.tool_name == $t and .status == "pending"' <<< "$ta_get_resp" &>/dev/null; then
    echo "  ✓  GET tool approval confirms pending request for $safe_tool"
    record_pass
  else
    log_failure "control_plane_e2e_approval_get_mismatch" "approval_id=$approval_id"
    dump_diag_json "tool approval GET response" "$ta_get_resp"
  fi

  local decide_body decide_code
  decide_body="$(mktemp)"
  decide_code="$(curl -s -o "$decide_body" -w '%{http_code}' -X POST \
    -H "$admin_hdr" -H "Content-Type: application/json" \
    -d '{"decision":"approve","reason":"smoke remediation","remediation":{"mode":"re_redact_rescan"}}' \
    "${cp_base}/v1/tool-approvals/${approval_id}/decide" 2>/dev/null)"
  if [[ "$decide_code" == "200" ]]; then
    local decide_status remed_mode remed_status
    decide_status="$(jq -r '.status // empty' "$decide_body" 2>/dev/null)"
    remed_mode="$(jq -r '.remediation_mode // empty' "$decide_body" 2>/dev/null)"
    remed_status="$(jq -r '.remediation_status // empty' "$decide_body" 2>/dev/null)"
    if [[ "$decide_status" == "approved" && "$remed_mode" == "re_redact_rescan" && "$remed_status" == "applied" ]]; then
      echo "  ✓  tool approval remediated and approved: $approval_id"
      record_pass
    else
      log_failure "control_plane_e2e_remediation_decide_fields" \
        "status=$decide_status mode=$remed_mode remed_status=$remed_status"
      dump_diag_json "decide response" "$(cat "$decide_body" 2>/dev/null || true)"
    fi
  else
    log_failure "control_plane_e2e_remediation_decide_http" "expected HTTP 200, got $decide_code"
    dump_diag_json "decide response" "$(cat "$decide_body" 2>/dev/null || true)"
  fi
  rm -f "$decide_body"

  wait "$run_curl_pid" 2>/dev/null || true
  run_curl_pid=""
  run_code="$(cat "$run_code_file" 2>/dev/null || echo "")"
  if [[ "$run_code" == "200" ]]; then
    echo "  ✓  POST /v1/agents/run completed after approval (HTTP 200)"
    record_pass
  else
    log_failure "control_plane_e2e_agents_run_http" "expected HTTP 200, got $run_code"
    dump_diag_file "E2E agents/run stderr" "$run_stderr"
    dump_diag_json "E2E agents/run body" "$(cat "$run_body" 2>/dev/null || true)"
    dump_diag_file "section 28 E2E serve log" "$cp_log" 80
  fi

  if jq -e --arg t "$safe_tool" '(.tools_called // []) | index($t) != null' < "$run_body" 2>/dev/null; then
    echo "  ✓  agents/run tools_called includes $safe_tool"
    record_pass
  else
    log_failure "control_plane_e2e_tools_called_missing" "tool=$safe_tool"
    dump_diag_json "E2E agents/run body" "$(cat "$run_body" 2>/dev/null || true)"
  fi

  local ta_after
  ta_after="$(curl -s -H "$admin_hdr" "${cp_base}/v1/tool-approvals" 2>/dev/null || true)"
  if jq -e --arg id "$approval_id" '[.pending[]?.id] | index($id) | not' <<< "$ta_after" &>/dev/null; then
    echo "  ✓  approved tool approval removed from pending list"
    record_pass
  else
    log_failure "control_plane_e2e_approval_still_pending" "approval_id=$approval_id"
    dump_diag_json "tool approvals after decide" "$ta_after"
  fi

  local events_json remediation_found=0 ev_attempt=0 ev_attempts=10
  while [[ $ev_attempt -lt $ev_attempts ]]; do
    events_json="$(curl -s -H "$admin_hdr" "${cp_base}/api/v1/events/recent?limit=30" 2>/dev/null || true)"
    if jq -e '[.events[]? | select(.reason_code == "PII_REMEDIATED_APPROVED")] | length > 0' <<< "$events_json" &>/dev/null; then
      remediation_found=1
      break
    fi
    ev_attempt=$((ev_attempt + 1))
    sleep 1
  done
  if [[ "$remediation_found" -eq 1 ]]; then
    echo "  ✓  recent events include PII_REMEDIATED_APPROVED"
    record_pass
  else
    log_failure "control_plane_e2e_remediation_event_missing"
    dump_diag_json "recent events" "$events_json"
  fi

  rm -f "$run_body" "$run_code_file" "$run_stderr" 2>/dev/null || true
  fi
  fi
  fi

  # --- 28p-bridge: remediation approval contract via Go integration test ---
  echo ""
  echo "  -- 28p-bridge: remediation_approval_contract --"
  local bridge_out bridge_err bridge_code
  bridge_out="$(mktemp)"
  bridge_err="$(mktemp)"
  (cd "$REPO_ROOT" && go test -count=1 ./internal/server -run 'TestHandleToolApprovalDecide_ApproveWithRemediation$') \
    >"$bridge_out" 2>"$bridge_err"
  bridge_code=$?
  if [[ "$bridge_code" -eq 0 ]]; then
    echo "  ✓  28p-bridge remediation approval contract (go test)"
    record_pass
  else
    log_failure "control_plane_e2e_bridge_remediation_approval" "go test exit=$bridge_code"
    dump_diag_file "28p-bridge stdout" "$bridge_out" 60
    dump_diag_file "28p-bridge stderr" "$bridge_err" 60
  fi
  rm -f "$bridge_out" "$bridge_err" 2>/dev/null || true

  echo "[SMOKE] SECTION|28_control_plane"
  kill "$CP_PID" 2>/dev/null || true
  wait "$CP_PID" 2>/dev/null || true
  sleep 2
  cd "$REPO_ROOT" || true
}

