#!/usr/bin/env bash
# Smoke test section: 24_plan_dispatch
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 24 — Plan review dispatch (non-serve CLI execute + serve auto-dispatch)
# -----------------------------------------------------------------------------
test_section_24_plan_dispatch() {
  local section="24_plan_dispatch"
  local dir; dir="$(setup_section_dir "$section")"
  local serve_port="8080"
  local base_url="http://127.0.0.1:${serve_port}"
  local plan_id=""
  local serve_plan_id=""
  local tenant_key="${TALON_TENANT_KEY}"
  local admin_key="${TALON_ADMIN_KEY}"
  local S_PID=""
  echo ""
  echo "=== SECTION 24 — Plan Review Dispatch ==="
  cd "$dir" || exit 1
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true

  # Ensure plan review gate is enabled for this section.
  # The scaffold already has a compliance: block, so we must insert into it
  # rather than appending a duplicate key (which produces invalid YAML).
  if command -v yq >/dev/null 2>&1; then
    yq -i '.compliance.human_oversight = "always"' "$dir/agent.talon.yaml" 2>/dev/null || true
  elif grep -q "human_oversight:" "$dir/agent.talon.yaml" 2>/dev/null; then
    sed -i.bak 's/human_oversight:.*/human_oversight: "always"/' "$dir/agent.talon.yaml" 2>/dev/null || true
  elif grep -q "^compliance:" "$dir/agent.talon.yaml" 2>/dev/null; then
    sed -i.bak '/^compliance:/a\  human_oversight: "always"' "$dir/agent.talon.yaml" 2>/dev/null || true
  else
    cat >> "$dir/agent.talon.yaml" <<'PREVIEWEOF'

compliance:
  human_oversight: "always"
PREVIEWEOF
  fi

  # Relax rate_limits: all sections share one TALON_DATA_DIR/evidence.db, so by
  # section 24 the evidence count from prior sections easily exceeds the scaffold
  # default of 30 requests_per_minute, causing an OPA rate-limit deny.
  if command -v yq >/dev/null 2>&1; then
    yq -i '.policies.rate_limits.requests_per_minute = 300' "$dir/agent.talon.yaml" 2>/dev/null || true
  elif grep -q "requests_per_minute:" "$dir/agent.talon.yaml" 2>/dev/null; then
    sed -i.bak 's/requests_per_minute:.*/requests_per_minute: 300/' "$dir/agent.talon.yaml" 2>/dev/null || true
  fi

  # Dump the final agent.talon.yaml so we can see whether human_oversight was set.
  dump_diag_file "agent.talon.yaml after compliance modification" "$dir/agent.talon.yaml"

  # Verify human_oversight was actually written (fail-fast with context)
  if ! grep -q 'human_oversight.*always' "$dir/agent.talon.yaml" 2>/dev/null; then
    log_failure "agent.talon.yaml does not contain human_oversight: always after modification" \
      "grep did not match; YAML may be malformed"
    dump_diag_file "agent.talon.yaml (full)" "$dir/agent.talon.yaml"
  fi

  # --- 24.1: Non-serve CLI workflow (run -> pending -> approve -> execute) ---
  local run_out run_err run_exit
  run_err="$(mktemp)"
  run_out="$(run_talon run "Summarize EU AI Act milestones for compliance teams" 2>"$run_err")"; run_exit=$?; true
  plan_id="$(echo "$run_out" | grep -oE 'plan_[A-Za-z0-9_-]+' | head -1 || true)"
  if [[ -n "$plan_id" ]]; then
    echo "  ✓  talon run produced pending plan id: $plan_id"
    record_pass
  else
    log_failure "talon run should produce PlanPending when human_oversight is always" \
      "exit=$run_exit stdout=$(echo "$run_out" | head -20)"
    dump_diag_kv "talon run diagnostics" \
      "exit_code=$run_exit" \
      "stdout_length=${#run_out}" \
      "stdout_first_200=${run_out:0:200}"
    dump_diag_file "talon run stderr" "$run_err"
    dump_diag_file "agent.talon.yaml" "$dir/agent.talon.yaml"
    dump_diag_env
  fi
  rm -f "$run_err" 2>/dev/null || true
  local pending_out; pending_out="$(run_talon plan pending --tenant default 2>/dev/null)"; true
  if [[ -n "$plan_id" ]]; then
    assert_pass "talon plan pending contains created plan id" grep -q "$plan_id" <<< "$pending_out"
    assert_pass "talon plan approve exits 0" run_talon plan approve "$plan_id" --tenant default --reviewed-by smoke-test
    local pending_after_approve; pending_after_approve="$(run_talon plan pending --tenant default 2>/dev/null)"; true
    if echo "$pending_after_approve" | grep -q "$plan_id"; then
      log_failure "approved plan should not remain in pending list" "plan_id=$plan_id"
    else
      echo "  ✓  approved plan removed from pending list"
      record_pass
    fi
    local exec_err_file; exec_err_file="$(mktemp)"
    local exec_out; exec_out="$(run_talon plan execute "$plan_id" --tenant default 2>"$exec_err_file")"; local exec_code=$?
    if [[ $exec_code -eq 0 ]]; then
      echo "  ✓  talon plan execute exits 0 for approved plan"
      record_pass
    else
      log_failure "talon plan execute should exit 0 for approved plan" "plan_id=$plan_id exit=$exec_code"
      dump_diag_kv "plan execute diagnostics" \
        "exit_code=$exec_code" \
        "stdout_length=${#exec_out}" \
        "stdout_first_200=${exec_out:0:200}"
      dump_diag_file "plan execute stderr" "$exec_err_file"
      dump_diag_file "agent.talon.yaml" "$dir/agent.talon.yaml"
    fi
    rm -f "$exec_err_file" 2>/dev/null || true
    if echo "$exec_out" | grep -qi "Evidence stored"; then
      echo "  ✓  manual plan execute produced evidence output"
      record_pass
    else
      echo "  -  manual plan execute output did not include evidence line (already dispatched or provider response formatting)"
    fi
  fi

  # --- 24.2: Serve auto-dispatch workflow (approve -> background execute) ---
  if ! wait_port_free "$serve_port" 90 5; then
    log_failure "plan dispatch section could not acquire port ${serve_port}" "port remained busy"
    dump_diag_kv "port ${serve_port} in use" \
      "lsof=$(lsof -nP -iTCP:${serve_port} -sTCP:LISTEN 2>/dev/null | head -5 || echo '(lsof unavailable)')" \
      "TALON_SERVE_PID=${TALON_SERVE_PID:-}" \
      "TALON_GATEWAY_PID=${TALON_GATEWAY_PID:-}"
    cd "$REPO_ROOT" || true
    return 0
  fi
  run_talon serve --port "$serve_port" >"$dir/plan_dispatch_serve.log" 2>&1 &
  S_PID=$!
  if ! smoke_wait_health "$base_url" 45 1; then
    local s_pid_state="running"
    if ! kill -0 "$S_PID" 2>/dev/null; then
      wait "$S_PID" 2>/dev/null
      local s_exit=$?
      s_pid_state="exited($s_exit)"
    fi
    log_failure "serve did not become healthy for plan dispatch section" \
      "url=${base_url}/health pid=$S_PID state=$s_pid_state"
    dump_diag_file "plan_dispatch serve log" "$dir/plan_dispatch_serve.log"
    dump_diag_file "agent.talon.yaml" "$dir/agent.talon.yaml"
    dump_diag_file "talon.config.yaml" "$dir/talon.config.yaml" 120
    dump_diag_env
    kill "$S_PID" 2>/dev/null || true
    wait "$S_PID" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi

  local run_json
  local run_code
  local serve_session_id=""
  local plan_run_resp_file="$dir/plan_run_resp.json"
  run_code="$(curl -s -o "$plan_run_resp_file" -w '%{http_code}' -X POST "${base_url}/v1/agents/run" \
    -H "Authorization: Bearer ${tenant_key}" -H "Content-Type: application/json" \
    -d '{"tenant_id":"default","agent_name":"default","prompt":"Create a concise compliance rollout plan for Q3"}')"
  run_json="$(cat "$plan_run_resp_file" 2>/dev/null || true)"
  # With human_oversight: "always", the server returns 202 Accepted (plan_pending).
  if [[ "$run_code" == "200" ]] || [[ "$run_code" == "202" ]]; then
    echo "  ✓  POST /v1/agents/run returns $run_code"
    record_pass
  else
    log_failure "POST /v1/agents/run should return 200 or 202 (got $run_code)"
    dump_diag_kv "section 24 agents/run" \
      "http_code=$run_code" \
      "tenant_key=$tenant_key" \
      "base_url=$base_url" \
      "endpoint=${base_url}/v1/agents/run" \
      "resp_file=$plan_run_resp_file" \
      "resp_file_size=$(wc -c < "$plan_run_resp_file" 2>/dev/null || echo 'missing')"
    dump_diag_json "agents/run response" "$run_json"
    dump_diag_file "plan_dispatch serve log" "$dir/plan_dispatch_serve.log" 50
  fi
  # Prefer reading from file (avoids variable truncation); fall back to $run_json.
  serve_plan_id="$(jq -r '.plan_pending // empty' < "$plan_run_resp_file" 2>/dev/null || true)"
  if [[ -z "$serve_plan_id" ]] && [[ -n "$run_json" ]]; then
    serve_plan_id="$(echo "$run_json" | jq -r '.plan_pending // empty' 2>/dev/null || true)"
  fi
  if [[ -n "$serve_plan_id" ]]; then
    echo "  ✓  API run returned plan_pending: $serve_plan_id"
    record_pass
  else
    log_failure "API run should return plan_pending under human oversight" \
      "http_code=$run_code json_length=${#run_json}"
    dump_diag_json "agents/run response (no plan_pending)" "$run_json"
    dump_diag_file "plan_run_resp.json (raw)" "$plan_run_resp_file"
    dump_diag_file "plan_dispatch serve log (recent)" "$dir/plan_dispatch_serve.log" 50
  fi
  serve_session_id="$(jq -r '.session_id // empty' < "$plan_run_resp_file" 2>/dev/null || true)"
  if [[ -z "$serve_session_id" ]] && [[ -n "$run_json" ]]; then
    serve_session_id="$(echo "$run_json" | jq -r '.session_id // empty' 2>/dev/null || true)"
  fi
  if [[ -n "$serve_session_id" ]]; then
    echo "  ✓  API run returned session_id for plan-gated flow: $serve_session_id"
    record_pass
  else
    log_failure "API run should return session_id for plan-gated flow" \
      "http_code=$run_code json_length=${#run_json}"
    dump_diag_file "plan_run_resp.json (raw)" "$plan_run_resp_file"
  fi
  rm -f "$plan_run_resp_file" 2>/dev/null || true
  if [[ -n "$serve_plan_id" ]]; then
    local tenant_approve_code
    tenant_approve_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${base_url}/v1/plans/${serve_plan_id}/approve" -H "Authorization: Bearer ${tenant_key}" -H "Content-Type: application/json" -d '{"reviewed_by":"smoke-test"}')"
    if [[ "$tenant_approve_code" == "401" ]] || [[ "$tenant_approve_code" == "403" ]]; then
      echo "  ✓  tenant key cannot approve pending plan via API (HTTP ${tenant_approve_code})"
      record_pass
    else
      log_failure "tenant key must not approve pending plan via API" "expected 401 or 403, got ${tenant_approve_code}"
    fi
    assert_pass "approve pending plan via API exits 200" \
      test "$(curl -s -o /dev/null -w '%{http_code}' -X POST "${base_url}/v1/plans/${serve_plan_id}/approve" -H "X-Talon-Admin-Key: ${admin_key}" -H "Content-Type: application/json" -d '{"reviewed_by":"smoke-test"}')" = "200"
    sleep 4
    local pending_json
    pending_json="$(curl -s -H "X-Talon-Admin-Key: ${admin_key}" "${base_url}/v1/plans/pending")"
    if echo "$pending_json" | jq -e --arg pid "$serve_plan_id" '.plans[]? | select(.id == $pid)' &>/dev/null; then
      log_failure "serve auto-dispatch should remove approved plan from pending list" "plan_id=$serve_plan_id"
    else
      echo "  ✓  serve auto-dispatch removed approved plan from pending list"
      record_pass
    fi
    # Section 24 runs without --gateway, so no tenant keys are loaded.
    # Use the admin key to verify evidence read access.
    assert_pass "admin key can read /v1/evidence → 200" \
      test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: ${admin_key}" "${base_url}/v1/evidence?limit=10")" = "200"
    # Filter by invocation_type so the newest plan_dispatch is first; a mixed top-N
    # list can omit the fresh dispatch or surface an older plan_dispatch first.
    assert_pass "evidence index contains plan_dispatch invocation after approval" \
      bash -c "curl -s -H 'X-Talon-Admin-Key: ${admin_key}' '${base_url}/v1/evidence?limit=10&invocation_type=plan_dispatch' | jq -e '(.entries // []) | length > 0' >/dev/null"
    if [[ -n "$serve_session_id" ]]; then
      local dispatch_evidence_id="" dispatch_ev_json="" dispatch_sid="" dispatch_index_json=""
      local attempts=10
      local attempt=0
      # Evidence indexing can lag briefly after approval/dispatch; poll for the entry
      # that matches the current serve session_id instead of assuming entries[0].
      while [[ "$attempt" -lt "$attempts" ]]; do
        dispatch_index_json="$(curl -s -H "X-Talon-Admin-Key: ${admin_key}" "${base_url}/v1/evidence?limit=20&invocation_type=plan_dispatch")"
        dispatch_evidence_id="$(echo "$dispatch_index_json" | jq -r --arg sid "$serve_session_id" '.entries[]? | select((.session_id // "") == $sid) | .id' | head -1)"
        if [[ -n "$dispatch_evidence_id" ]]; then
          dispatch_ev_json="$(curl -s -H "X-Talon-Admin-Key: ${admin_key}" "${base_url}/v1/evidence/${dispatch_evidence_id}")"
          dispatch_sid="$(echo "$dispatch_ev_json" | jq -r '.session_id // empty' 2>/dev/null || true)"
          break
        fi
        attempt=$((attempt + 1))
        sleep 1
      done

      if [[ -n "$dispatch_evidence_id" ]] && [[ "$dispatch_sid" == "$serve_session_id" ]]; then
        echo "  ✓  plan_dispatch evidence reuses session_id from plan-gated run"
        record_pass
      else
        log_failure "plan_dispatch evidence reuses session_id from plan-gated run" \
          "expected=$serve_session_id actual=${dispatch_sid:-missing} evidence_id=${dispatch_evidence_id:-missing} attempts=$attempts"
        dump_diag_kv "session_id mismatch" \
          "expected_sid=$serve_session_id" \
          "actual_sid=${dispatch_sid:-missing}" \
          "dispatch_evidence_id=${dispatch_evidence_id:-missing}" \
          "attempts=$attempts"
        dump_diag_json "plan_dispatch evidence index (latest)" "$dispatch_index_json"
        dump_diag_json "dispatch evidence" "$dispatch_ev_json"
        dump_diag_file "plan_dispatch serve log (tail)" "$dir/plan_dispatch_serve.log" 80
      fi
    fi
  fi

  kill "$S_PID" 2>/dev/null || true
  wait "$S_PID" 2>/dev/null || true
  cd "$REPO_ROOT" || true
}

