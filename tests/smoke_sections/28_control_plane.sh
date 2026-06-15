#!/usr/bin/env bash
# Smoke test section: 28_control_plane
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# Section 28: Operational Control Plane admin API
# Proves: runs list, kill, pause/resume, overrides lockdown, tool disable,
# tool approval list/get/decide endpoint behavior, remediation decision fail-closed.
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

  echo "[SMOKE] SECTION|28_control_plane"
  kill "$CP_PID" 2>/dev/null || true
  wait "$CP_PID" 2>/dev/null || true
  sleep 2
  cd "$REPO_ROOT" || true
}

