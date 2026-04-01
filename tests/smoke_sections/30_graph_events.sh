#!/usr/bin/env bash
# Smoke test section: 30_graph_events
# Sourced by smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 30 — Graph Runtime Events (LangGraph Integration)
# Proves the /v1/graph/events endpoint works end-to-end:
#   30a — run_start event returns allow decision
#   30b — step_start event (within limits) returns allow
#   30c — tool_call event with google_search (allowed tool) returns allow
#   30d — tool_call event with forbidden tool returns deny
#   30e — step_end event returns allow with evidence recorded
#   30f — retry event (within limits) returns allow
#   30g — run_end event returns allow and evidence is queryable
#   30h — step_start exceeding max_iterations is denied
#   30i — step_start exceeding max_cost_per_run is denied
#   30j — retry exceeding max_retries_per_node is denied
#   30k — invalid JSON returns 400
#   30l — missing graph_run_id returns 400
#   30m — GET method returns 405
#   30n — full lifecycle: 3-node google_search agent run
# Each sub-test asserts HTTP status and decision fields from the JSON response.
# Uses google_search as the only tool for the happy-path lifecycle.
# -----------------------------------------------------------------------------
test_section_30_graph_events() {
  local section="30_graph_events"
  local ge_port="8080"
  local ge_base="http://127.0.0.1:${ge_port}"
  echo ""
  echo "=== SECTION 30 — Graph Runtime Events (LangGraph Integration) ==="
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1

  if ! wait_port_free "$ge_port" 180 10; then
    log_failure "graph events section could not acquire port ${ge_port}" "port remained busy"
    cd "$REPO_ROOT" || true
    return 0
  fi

  run_talon init --scaffold --name smoke-graph-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true

  # Policy with resource limits for graph governance testing
  cat > "$dir/.talon.yaml" <<'POLICYEOF'
agent:
  name: "smoke-graph-agent"
  version: "1.0.0"
  model_tier: 1
capabilities:
  allowed_tools:
    - google_search
    - web_search
    - read_file
  forbidden_patterns:
    - "*.env"
policies:
  cost_limits:
    per_request: 10.0
    daily: 100.0
    monthly: 1000.0
  resource_limits:
    max_iterations: 5
    max_cost_per_run: 2.0
    max_tool_calls_per_run: 10
POLICYEOF

  # Gateway config with tenant key so Bearer auth is exercised (matches section 12 pattern).
  if [[ -f "$dir/talon.config.yaml" ]] && ! grep -q "gateway:" "$dir/talon.config.yaml" 2>/dev/null; then
    cat >> "$dir/talon.config.yaml" <<GWEOF

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
    - name: "graph-events-caller"
      tenant_key: "${TALON_TENANT_KEY}"
      tenant_id: "default"
      allowed_providers: ["openai"]
  default_policy:
    default_pii_action: "warn"
    require_caller_id: true
GWEOF
  fi

  local GE_PID=""
  local ge_log="$dir/ge_serve.log"
  run_talon serve --config "$dir/talon.config.yaml" --port "$ge_port" --gateway --gateway-config "$dir/talon.config.yaml" >"$ge_log" 2>&1 &
  GE_PID=$!
  if ! smoke_wait_health "$ge_base" 45 1; then
    log_failure "graph events server did not start on port ${ge_port}"
    dump_diag_file "section 30 serve log" "$ge_log" 120
    kill "$GE_PID" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi

  local tenant_hdr="Authorization: Bearer ${TALON_TENANT_KEY}"
  local admin_hdr="X-Talon-Admin-Key: ${TALON_ADMIN_KEY}"
  local graph_url="${ge_base}/v1/graph/events"
  local graph_run_id="gr_smoke_$(date +%s)"

  # Helper: POST a graph event and capture HTTP code + body
  post_graph_event() {
    local body="$1" out_file="$2"
    curl -s -o "$out_file" -w '%{http_code}' -X POST "$graph_url" \
      -H "$tenant_hdr" -H "Content-Type: application/json" -d "$body" 2>/dev/null
  }

  # --- 30a: run_start returns allow ---
  local body_30a resp_30a code_30a
  resp_30a="$(mktemp)"
  body_30a="{\"type\":\"run_start\",\"graph_run_id\":\"${graph_run_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"run_meta\":{\"framework\":\"langgraph\",\"node_count\":3,\"model\":\"gpt-4o\"}}"
  code_30a="$(post_graph_event "$body_30a" "$resp_30a")"
  if [[ "$code_30a" == "200" ]]; then
    local allowed_30a
    allowed_30a="$(jq -r '.allowed' "$resp_30a" 2>/dev/null)"
    if [[ "$allowed_30a" == "true" ]]; then
      echo "  ✓  graph_events_run_start (HTTP 200, allowed=true)"
      record_pass
    else
      log_failure "graph_events_run_start expected allowed=true, got $allowed_30a"
    fi
  else
    log_failure "graph_events_run_start expected HTTP 200, got $code_30a"
  fi
  rm -f "$resp_30a"

  # --- 30b: step_start within limits returns allow ---
  local body_30b resp_30b code_30b
  resp_30b="$(mktemp)"
  body_30b="{\"type\":\"step_start\",\"graph_run_id\":\"${graph_run_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":1,\"node_id\":\"plan_node\",\"node_meta\":{\"name\":\"plan\",\"type\":\"llm\",\"model\":\"gpt-4o\"}}"
  code_30b="$(post_graph_event "$body_30b" "$resp_30b")"
  if [[ "$code_30b" == "200" ]]; then
    local allowed_30b
    allowed_30b="$(jq -r '.allowed' "$resp_30b" 2>/dev/null)"
    if [[ "$allowed_30b" == "true" ]]; then
      echo "  ✓  graph_events_step_start_allowed (HTTP 200, allowed=true)"
      record_pass
    else
      log_failure "graph_events_step_start_allowed expected allowed=true, got $allowed_30b"
    fi
  else
    log_failure "graph_events_step_start_allowed expected HTTP 200, got $code_30b"
  fi
  rm -f "$resp_30b"

  # --- 30c: tool_call with google_search returns allow ---
  local body_30c resp_30c code_30c
  resp_30c="$(mktemp)"
  body_30c="{\"type\":\"tool_call\",\"graph_run_id\":\"${graph_run_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":2,\"tool_meta\":{\"name\":\"google_search\",\"arguments\":{\"query\":\"EU AI Act compliance for SMBs\"}}}"
  code_30c="$(post_graph_event "$body_30c" "$resp_30c")"
  if [[ "$code_30c" == "200" ]]; then
    local allowed_30c action_30c
    allowed_30c="$(jq -r '.allowed' "$resp_30c" 2>/dev/null)"
    action_30c="$(jq -r '.action' "$resp_30c" 2>/dev/null)"
    if [[ "$allowed_30c" == "true" ]] && [[ "$action_30c" == "allow" ]]; then
      echo "  ✓  graph_events_tool_call_google_search (HTTP 200, allowed=true, action=allow)"
      record_pass
    else
      log_failure "graph_events_tool_call_google_search expected allowed=true action=allow, got allowed=$allowed_30c action=$action_30c"
    fi
  else
    log_failure "graph_events_tool_call_google_search expected HTTP 200, got $code_30c"
  fi
  rm -f "$resp_30c"

  # --- 30d: tool_call with forbidden tool returns deny ---
  local body_30d resp_30d code_30d
  resp_30d="$(mktemp)"
  body_30d="{\"type\":\"tool_call\",\"graph_run_id\":\"${graph_run_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":2,\"tool_meta\":{\"name\":\"delete_database\",\"arguments\":{}}}"
  code_30d="$(post_graph_event "$body_30d" "$resp_30d")"
  if [[ "$code_30d" == "200" ]]; then
    local allowed_30d action_30d
    allowed_30d="$(jq -r '.allowed' "$resp_30d" 2>/dev/null)"
    action_30d="$(jq -r '.action' "$resp_30d" 2>/dev/null)"
    if [[ "$allowed_30d" == "false" ]] && [[ "$action_30d" == "deny" ]]; then
      echo "  ✓  graph_events_tool_call_forbidden (HTTP 200, allowed=false, action=deny)"
      record_pass
    else
      log_failure "graph_events_tool_call_forbidden expected allowed=false action=deny, got allowed=$allowed_30d action=$action_30d"
    fi
  else
    log_failure "graph_events_tool_call_forbidden expected HTTP 200, got $code_30d"
  fi
  rm -f "$resp_30d"

  # --- 30e: step_end returns allow ---
  local body_30e resp_30e code_30e
  resp_30e="$(mktemp)"
  body_30e="{\"type\":\"step_end\",\"graph_run_id\":\"${graph_run_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":1,\"result\":{\"status\":\"completed\",\"duration_ms\":800,\"cost\":0.002}}"
  code_30e="$(post_graph_event "$body_30e" "$resp_30e")"
  if [[ "$code_30e" == "200" ]]; then
    local allowed_30e
    allowed_30e="$(jq -r '.allowed' "$resp_30e" 2>/dev/null)"
    if [[ "$allowed_30e" == "true" ]]; then
      echo "  ✓  graph_events_step_end (HTTP 200, allowed=true)"
      record_pass
    else
      log_failure "graph_events_step_end expected allowed=true, got $allowed_30e"
    fi
  else
    log_failure "graph_events_step_end expected HTTP 200, got $code_30e"
  fi
  rm -f "$resp_30e"

  # --- 30f: retry within limits returns allow ---
  local body_30f resp_30f code_30f
  resp_30f="$(mktemp)"
  body_30f="{\"type\":\"retry\",\"graph_run_id\":\"${graph_run_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"node_id\":\"search_node\",\"error\":{\"message\":\"rate limit\",\"retryable\":true,\"retry_count\":1}}"
  code_30f="$(post_graph_event "$body_30f" "$resp_30f")"
  if [[ "$code_30f" == "200" ]]; then
    local allowed_30f
    allowed_30f="$(jq -r '.allowed' "$resp_30f" 2>/dev/null)"
    if [[ "$allowed_30f" == "true" ]]; then
      echo "  ✓  graph_events_retry_allowed (HTTP 200, allowed=true)"
      record_pass
    else
      log_failure "graph_events_retry_allowed expected allowed=true, got $allowed_30f"
    fi
  else
    log_failure "graph_events_retry_allowed expected HTTP 200, got $code_30f"
  fi
  rm -f "$resp_30f"

  # --- 30g: run_end returns allow ---
  local body_30g resp_30g code_30g
  resp_30g="$(mktemp)"
  body_30g="{\"type\":\"run_end\",\"graph_run_id\":\"${graph_run_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"cost\":0.005,\"result\":{\"status\":\"completed\",\"duration_ms\":2900,\"cost\":0.005}}"
  code_30g="$(post_graph_event "$body_30g" "$resp_30g")"
  if [[ "$code_30g" == "200" ]]; then
    local allowed_30g
    allowed_30g="$(jq -r '.allowed' "$resp_30g" 2>/dev/null)"
    if [[ "$allowed_30g" == "true" ]]; then
      echo "  ✓  graph_events_run_end (HTTP 200, allowed=true)"
      record_pass
    else
      log_failure "graph_events_run_end expected allowed=true, got $allowed_30g"
    fi
  else
    log_failure "graph_events_run_end expected HTTP 200, got $code_30g"
  fi
  rm -f "$resp_30g"

  # --- 30h: step_start exceeding max_iterations is denied ---
  local body_30h resp_30h code_30h
  resp_30h="$(mktemp)"
  body_30h="{\"type\":\"step_start\",\"graph_run_id\":\"gr_smoke_deny_iter\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":6,\"node_id\":\"node_overflow\"}"
  code_30h="$(post_graph_event "$body_30h" "$resp_30h")"
  if [[ "$code_30h" == "200" ]]; then
    local allowed_30h action_30h
    allowed_30h="$(jq -r '.allowed' "$resp_30h" 2>/dev/null)"
    action_30h="$(jq -r '.action' "$resp_30h" 2>/dev/null)"
    if [[ "$allowed_30h" == "false" ]] && [[ "$action_30h" == "deny" ]]; then
      echo "  ✓  graph_events_max_iterations_deny (HTTP 200, allowed=false, action=deny)"
      record_pass
    else
      log_failure "graph_events_max_iterations_deny expected allowed=false action=deny, got allowed=$allowed_30h action=$action_30h"
    fi
  else
    log_failure "graph_events_max_iterations_deny expected HTTP 200, got $code_30h"
  fi
  rm -f "$resp_30h"

  # --- 30i: step_start exceeding max_cost_per_run is denied ---
  local body_30i resp_30i code_30i
  resp_30i="$(mktemp)"
  body_30i="{\"type\":\"step_start\",\"graph_run_id\":\"gr_smoke_deny_cost\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":2,\"node_id\":\"expensive_node\",\"cost\":2.50}"
  code_30i="$(post_graph_event "$body_30i" "$resp_30i")"
  if [[ "$code_30i" == "200" ]]; then
    local allowed_30i action_30i
    allowed_30i="$(jq -r '.allowed' "$resp_30i" 2>/dev/null)"
    action_30i="$(jq -r '.action' "$resp_30i" 2>/dev/null)"
    if [[ "$allowed_30i" == "false" ]] && [[ "$action_30i" == "deny" ]]; then
      echo "  ✓  graph_events_max_cost_deny (HTTP 200, allowed=false, action=deny)"
      record_pass
    else
      log_failure "graph_events_max_cost_deny expected allowed=false action=deny, got allowed=$allowed_30i action=$action_30i"
    fi
  else
    log_failure "graph_events_max_cost_deny expected HTTP 200, got $code_30i"
  fi
  rm -f "$resp_30i"

  # --- 30j: retry exceeding max_retries_per_node is denied ---
  local body_30j resp_30j code_30j
  resp_30j="$(mktemp)"
  body_30j="{\"type\":\"retry\",\"graph_run_id\":\"gr_smoke_deny_retry\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"node_id\":\"flaky_node\",\"error\":{\"message\":\"timeout\",\"retryable\":true,\"retry_count\":5}}"
  code_30j="$(post_graph_event "$body_30j" "$resp_30j")"
  if [[ "$code_30j" == "200" ]]; then
    local allowed_30j action_30j
    allowed_30j="$(jq -r '.allowed' "$resp_30j" 2>/dev/null)"
    action_30j="$(jq -r '.action' "$resp_30j" 2>/dev/null)"
    if [[ "$allowed_30j" == "false" ]] && [[ "$action_30j" == "deny" ]]; then
      echo "  ✓  graph_events_max_retries_deny (HTTP 200, allowed=false, action=deny)"
      record_pass
    else
      log_failure "graph_events_max_retries_deny expected allowed=false action=deny, got allowed=$allowed_30j action=$action_30j"
    fi
  else
    log_failure "graph_events_max_retries_deny expected HTTP 200, got $code_30j"
  fi
  rm -f "$resp_30j"

  # --- 30k: invalid JSON returns 400 ---
  local code_30k
  code_30k="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$graph_url" \
    -H "$tenant_hdr" -H "Content-Type: application/json" -d "not-json" 2>/dev/null)"
  if [[ "$code_30k" == "400" ]]; then
    echo "  ✓  graph_events_invalid_json (HTTP 400)"
    record_pass
  else
    log_failure "graph_events_invalid_json expected HTTP 400, got $code_30k"
  fi

  # --- 30l: missing graph_run_id returns 400 ---
  local code_30l
  code_30l="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$graph_url" \
    -H "$tenant_hdr" -H "Content-Type: application/json" \
    -d '{"type":"run_start","tenant_id":"default"}' 2>/dev/null)"
  if [[ "$code_30l" == "400" ]]; then
    echo "  ✓  graph_events_missing_graph_run_id (HTTP 400)"
    record_pass
  else
    log_failure "graph_events_missing_graph_run_id expected HTTP 400, got $code_30l"
  fi

  # --- 30m: GET method returns 405 ---
  local code_30m
  code_30m="$(curl -s -o /dev/null -w '%{http_code}' -X GET "$graph_url" \
    -H "$tenant_hdr" 2>/dev/null)"
  if [[ "$code_30m" == "405" ]]; then
    echo "  ✓  graph_events_get_not_allowed (HTTP 405)"
    record_pass
  else
    log_failure "graph_events_get_not_allowed expected HTTP 405, got $code_30m"
  fi

  # --- 30n: full lifecycle — 3-node google_search agent run ---
  local lifecycle_id="gr_smoke_lifecycle_$(date +%s)"
  local all_ok=true

  local events=(
    "{\"type\":\"run_start\",\"graph_run_id\":\"${lifecycle_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"run_meta\":{\"framework\":\"langgraph\",\"node_count\":3,\"model\":\"gpt-4o\"}}"
    "{\"type\":\"step_start\",\"graph_run_id\":\"${lifecycle_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":1,\"node_id\":\"plan_node\",\"node_meta\":{\"name\":\"plan\",\"type\":\"llm\",\"model\":\"gpt-4o\"}}"
    "{\"type\":\"step_end\",\"graph_run_id\":\"${lifecycle_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":1,\"result\":{\"status\":\"completed\",\"duration_ms\":800,\"cost\":0.002}}"
    "{\"type\":\"step_start\",\"graph_run_id\":\"${lifecycle_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":2,\"node_id\":\"search_node\",\"cost\":0.002,\"node_meta\":{\"name\":\"search\",\"type\":\"tool\"}}"
    "{\"type\":\"tool_call\",\"graph_run_id\":\"${lifecycle_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":2,\"tool_meta\":{\"name\":\"google_search\",\"arguments\":{\"query\":\"Talon EU compliance\"}}}"
    "{\"type\":\"step_end\",\"graph_run_id\":\"${lifecycle_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":2,\"tool_meta\":{\"name\":\"google_search\"},\"result\":{\"status\":\"completed\",\"duration_ms\":1200,\"cost\":0.0}}"
    "{\"type\":\"step_start\",\"graph_run_id\":\"${lifecycle_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":3,\"node_id\":\"synthesize_node\",\"cost\":0.002,\"node_meta\":{\"name\":\"synthesize\",\"type\":\"llm\",\"model\":\"gpt-4o\"}}"
    "{\"type\":\"step_end\",\"graph_run_id\":\"${lifecycle_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"step_index\":3,\"result\":{\"status\":\"completed\",\"duration_ms\":900,\"cost\":0.003}}"
    "{\"type\":\"run_end\",\"graph_run_id\":\"${lifecycle_id}\",\"tenant_id\":\"default\",\"agent_id\":\"smoke-graph-agent\",\"cost\":0.005,\"result\":{\"status\":\"completed\",\"duration_ms\":2900,\"cost\":0.005}}"
  )

  local step_num=0
  for ev_body in "${events[@]}"; do
    ((step_num++)) || true
    local lc_resp lc_code
    lc_resp="$(mktemp)"
    lc_code="$(post_graph_event "$ev_body" "$lc_resp")"
    if [[ "$lc_code" != "200" ]]; then
      log_failure "graph_events_lifecycle step $step_num expected HTTP 200, got $lc_code"
      all_ok=false
    else
      local lc_allowed
      lc_allowed="$(jq -r '.allowed' "$lc_resp" 2>/dev/null)"
      if [[ "$lc_allowed" != "true" ]]; then
        log_failure "graph_events_lifecycle step $step_num expected allowed=true, got $lc_allowed"
        all_ok=false
      fi
    fi
    rm -f "$lc_resp"
  done

  if [[ "$all_ok" == "true" ]]; then
    echo "  ✓  graph_events_full_lifecycle (9 events, all allowed, google_search tool)"
    record_pass
  fi

  # Verify evidence via admin API
  sleep 1
  local ev_body ev_code
  ev_body="$(mktemp)"
  ev_code="$(curl -s -o "$ev_body" -w '%{http_code}' -H "$admin_hdr" \
    "${ge_base}/v1/evidence?limit=20" 2>/dev/null)"
  if [[ "$ev_code" == "200" ]]; then
    local has_graph_run
    has_graph_run="$(jq -r "[.entries[]? | select(.correlation_id == \"${lifecycle_id}\")] | length" "$ev_body" 2>/dev/null)"
    if [[ "$has_graph_run" =~ ^[1-9] ]]; then
      echo "  ✓  graph_events_evidence_recorded (found evidence for lifecycle run)"
      record_pass
    else
      log_failure "graph_events_evidence_recorded no evidence found for graph_run_id=${lifecycle_id}"
    fi
  else
    log_failure "graph_events_evidence_recorded evidence API returned HTTP $ev_code"
  fi
  rm -f "$ev_body"

  # Cleanup
  kill "$GE_PID" 2>/dev/null || true
  wait "$GE_PID" 2>/dev/null || true
  cd "$REPO_ROOT" || true
}
