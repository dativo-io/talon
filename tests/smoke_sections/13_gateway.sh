#!/usr/bin/env bash
# Smoke test section: 13_gateway
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 13 — LLM API Gateway OpenAI Proxy (docs/guides/openclaw-integration.md, docker-openclaw-talon-primer)
# -----------------------------------------------------------------------------
test_section_13_gateway() {
  local section="13_gateway"
  local gateway_port="8080"
  local gateway_base_url="http://127.0.0.1:${gateway_port}"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  if ! wait_port_free "$gateway_port" 180 10; then
    log_failure "gateway section could not acquire port ${gateway_port}" "port remained busy"
    dump_diag_kv "port ${gateway_port} in use" \
      "lsof=$(lsof -nP -iTCP:${gateway_port} -sTCP:LISTEN 2>/dev/null | head -5 || echo '(lsof unavailable)')" \
      "TALON_SERVE_PID=${TALON_SERVE_PID:-}" \
      "TALON_GATEWAY_PID=${TALON_GATEWAY_PID:-}"
    cd "$REPO_ROOT" || true
    return 0
  fi
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  # Gateway config: inject minimal gateway block if scaffold did not provide one
  if [[ ! -f "$dir/talon.config.yaml" ]]; then
    echo "  -  (skip gateway: no config)"
    cd "$REPO_ROOT" || true
    return 0
  fi
  if ! grep -q "gateway:" "$dir/talon.config.yaml" 2>/dev/null; then
    cat >> "$dir/talon.config.yaml" <<'GWEOF'

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
    - name: "smoke-caller"
      tenant_key: "talon-gw-smoke-001"
      tenant_id: "default"
      allowed_providers: ["openai"]
  default_policy:
    default_pii_action: "warn"
    max_daily_cost: 100.00
    require_caller_id: true
GWEOF
  fi
  TALON_GATEWAY_PID=""
  local gw_log_13="$dir/gateway_serve.log"
  run_talon serve --port "$gateway_port" --gateway --gateway-config "$dir/talon.config.yaml" >"$gw_log_13" 2>&1 &
  TALON_GATEWAY_PID=$!
  if ! smoke_wait_health "$gateway_base_url" 10 1; then
    local gw_pid_state_13="running"
    if ! kill -0 "$TALON_GATEWAY_PID" 2>/dev/null; then
      wait "$TALON_GATEWAY_PID" 2>/dev/null; gw_pid_state_13="exited($?)"
    fi
    log_failure "gateway server did not start on port ${gateway_port}" \
      "url=${gateway_base_url}/health pid=$TALON_GATEWAY_PID state=$gw_pid_state_13"
    dump_diag_file "section 13 serve log" "$gw_log_13"
    dump_diag_file "talon.config.yaml" "$dir/talon.config.yaml"
    dump_diag_env
    kill "$TALON_GATEWAY_PID" 2>/dev/null || true
    TALON_GATEWAY_PID=""
    cd "$REPO_ROOT" || true
    return 0
  fi
  local gw_key="talon-gw-smoke-001"
  grep -q "talon-gw-smoke-001" "$dir/talon.config.yaml" 2>/dev/null || gw_key="$(grep -oE 'tenant_key:\s*[^[:space:]]+' "$dir/talon.config.yaml" | head -1 | sed 's/tenant_key:\s*//')"
  local gw_headers="/tmp/talon_gw_headers.txt"
  local gw_body="/tmp/talon_gw_resp.json"
  local code; code="$(smoke_gw_post_chat_capture "$gateway_base_url" "Bearer $gw_key" "$SMOKE_BODY_SIMPLE" "$gw_headers" "$gw_body")"
  if ! assert_pass "POST gateway chat/completions 200" test "$code" = "200"; then
    dump_diag_kv "section 13 proxy POST" \
      "http_code=$code" \
      "gw_key=$gw_key" \
      "base_url=$gateway_base_url" \
      "endpoint=${gateway_base_url}${SMOKE_PATH_GW_PROXY}"
    dump_diag_json "proxy response body" "$(cat "$gw_body" 2>/dev/null || echo '(missing)')"
    dump_diag_file "proxy response headers" "$gw_headers"
    dump_diag_file "section 13 serve log" "$gw_log_13" 50
  fi
  assert_fail "response must not contain sk- (no API key leak)" grep -q "sk-" "$gw_body" 2>/dev/null
  local gw_sid
  gw_sid="$(awk 'BEGIN{IGNORECASE=1} /^X-Talon-Session-ID:/ {gsub("\r","",$2); print $2; exit}' "$gw_headers" 2>/dev/null || true)"
  if [[ -n "$gw_sid" ]]; then
    echo "  ✓  gateway response includes X-Talon-Session-ID"
    record_pass
  else
    log_failure "gateway should return X-Talon-Session-ID header" "headers=$(cat "$gw_headers" 2>/dev/null)"
  fi
  local code_join
  code_join="$(curl -s -o /tmp/talon_gw_resp_join.json -w '%{http_code}' -X POST "${gateway_base_url}${SMOKE_PATH_GW_PROXY}" \
    -H "Authorization: Bearer $gw_key" -H "Content-Type: application/json" -H "X-Talon-Session-ID: ${gw_sid}" -d "$SMOKE_BODY_SIMPLE" 2>/dev/null)"
  assert_pass "POST gateway chat/completions with provided session id returns 200" test "$code_join" = "200"
  local gw_ev_index gw_ev_id gw_sid_match=0
  gw_ev_index="$(curl -s -H "X-Talon-Admin-Key: ${TALON_ADMIN_KEY}" "http://127.0.0.1:${gateway_port}/v1/evidence?limit=20")"
  gw_ev_id="$(echo "$gw_ev_index" | jq -r '.entries[]? | select(.invocation_type=="gateway") | .id' | head -1)"
  if [[ -n "$gw_sid" ]]; then
    local evid
    while read -r evid; do
      [[ -z "$evid" ]] && continue
      if curl -s -H "X-Talon-Admin-Key: ${TALON_ADMIN_KEY}" "http://127.0.0.1:${gateway_port}/v1/evidence/${evid}" | jq -e --arg sid "$gw_sid" '.session_id == $sid' >/dev/null 2>&1; then
        gw_sid_match=1
        break
      fi
    done < <(echo "$gw_ev_index" | jq -r '.entries[]? | .id')
    if [[ "$gw_sid_match" -eq 1 ]]; then
      echo "  ✓  gateway evidence carries provided session id"
      record_pass
    else
      log_failure "gateway evidence should carry provided session id" "session_id=$gw_sid"
    fi
  fi
  assert_pass "Wrong gateway key → 401" test "$(smoke_gw_post_chat "$gateway_base_url" "Bearer wrong-key" "$SMOKE_BODY_EMPTY")" = "401"
  rm -f "$gw_headers" "$gw_body" /tmp/talon_gw_resp_join.json 2>/dev/null || true
  kill "$TALON_GATEWAY_PID" 2>/dev/null || true
  wait "$TALON_GATEWAY_PID" 2>/dev/null || true
  TALON_GATEWAY_PID=""
  cd "$REPO_ROOT" || true
}

