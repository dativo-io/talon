#!/usr/bin/env bash
# Smoke test section: 35_failover
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 35 — Provider fallback chains (issue #138)
# Error-driven, sovereignty-respecting failover through the gateway:
#   A) dead primary provider -> transparent failover to an OpenAI-compatible
#      backup (real OpenAI endpoint), evidenced as failed attempt + fallback
#      decision, verified by `talon audit verify --failover`.
#   B) eu_strict with a US-only backup -> request fails closed (no dispatch to
#      the US provider), recorded as a successful governance outcome.
# -----------------------------------------------------------------------------
# Backgrounding serve through the run_talon wrapper leaves $! pointing at a
# wrapper subshell; killing it orphans the talon child, which keeps the port
# and starves scenario B (and later sections). Stop by PID first, then kill
# any talon serve still listening on the port.
smoke_stop_gateway_35() {
  local pid="$1" port="$2" waited=0
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  while is_port_in_use "$port" && [[ $waited -lt 15 ]]; do
    pkill -f "talon serve --port ${port}" 2>/dev/null || true
    sleep 1
    ((waited += 1))
  done
}

test_section_35_failover() {
  local section="35_failover"
  local gateway_port="8080"
  local gateway_base_url="http://127.0.0.1:${gateway_port}"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  if ! wait_port_free "$gateway_port" 180 10; then
    log_failure "failover section could not acquire port ${gateway_port}" "port remained busy"
    cd "$REPO_ROOT" || true
    return 0
  fi
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  if [[ ! -f "$dir/talon.config.yaml" ]]; then
    echo "  -  (skip failover: no config)"
    cd "$REPO_ROOT" || true
    return 0
  fi
  # Scenario A fails over to the real OpenAI endpoint: skip the whole section
  # when no credential is available rather than asserting a doomed 200.
  if ! run_talon secrets list 2>/dev/null | grep -q openai-api-key; then
    echo "  -  (skip failover: no openai-api-key credential in vault)"
    cd "$REPO_ROOT" || true
    return 0
  fi

  local fo_key="talon-gw-failover-001"
  # Dead primary (nothing listens on this port) + real OpenAI as fallback target.
  local gw_cfg_a="$dir/talon.gateway.failover.yaml"
  cat > "$gw_cfg_a" <<'GWEOF'
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "enforce"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "http://127.0.0.1:59973"
      region: "EU"
      fallback:
        - provider: "backup"
    backup:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
      region: "EU"
  callers:
    - name: "smoke-failover"
      tenant_key: "talon-gw-failover-001"
      tenant_id: "default"
  default_policy:
    default_pii_action: "warn"
    max_daily_cost: 100.00
    require_caller_id: true
GWEOF

  # --- Scenario A: transparent failover to the backup provider ---
  local gw_log_a="$dir/gateway_failover_a.log"
  env TALON_DATA_DIR="$TALON_DATA_DIR" talon serve --port "$gateway_port" --gateway --gateway-config "$gw_cfg_a" >"$gw_log_a" 2>&1 &
  local fo_pid_a=$!
  if ! smoke_wait_health "$gateway_base_url" 10 1; then
    log_failure "failover gateway (A) did not start on port ${gateway_port}" "pid=$fo_pid_a"
    dump_diag_file "section 35 serve log (A)" "$gw_log_a"
    smoke_stop_gateway_35 "$fo_pid_a" "$gateway_port"
    cd "$REPO_ROOT" || true
    return 0
  fi

  local fo_headers="/tmp/talon_fo_headers.txt"
  local fo_body="/tmp/talon_fo_resp.json"
  local code
  code="$(smoke_gw_post_chat_capture "$gateway_base_url" "Bearer $fo_key" "$SMOKE_BODY_SIMPLE" "$fo_headers" "$fo_body")"
  if ! assert_pass "dead primary fails over transparently (POST returns 200)" test "$code" = "200"; then
    dump_diag_kv "section 35 failover POST" "http_code=$code"
    dump_diag_json "failover response body" "$(cat "$fo_body" 2>/dev/null || echo '(missing)')"
    dump_diag_file "section 35 serve log (A)" "$gw_log_a" 50
  fi
  # Correlation ID is recoverable from the session header (sess_<correlation-id>).
  local fo_corr
  fo_corr="$(grep -i '^X-Talon-Session-ID:' "$fo_headers" 2>/dev/null | head -1 | tr -d '\r' | awk '{print $2}' | sed 's/^sess_//')"

  smoke_stop_gateway_35 "$fo_pid_a" "$gateway_port"

  local export_out
  export_out="$(run_talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)"; true
  assert_pass "failed provider attempt is evidenced (gateway_failover_attempt record)" \
    grep -q "gateway_failover_attempt" <<< "$export_out"

  if [[ -n "$fo_corr" ]]; then
    local verify_out
    verify_out="$(run_talon audit verify --failover "$fo_corr" 2>&1)"
    if [[ $? -eq 0 ]] && grep -q "valid_fallback" <<< "$verify_out"; then
      echo "  ✓  audit verify --failover confirms valid fallback chain"
      record_pass
    else
      log_failure "audit verify --failover should report valid_fallback" "$verify_out"
    fi
  else
    log_failure "failover response should carry X-Talon-Session-ID for correlation" "headers=$(cat "$fo_headers" 2>/dev/null)"
  fi

  # --- Scenario B: eu_strict with a US-only backup fails closed ---
  if ! grep -q "^sovereignty:" "$dir/talon.config.yaml" 2>/dev/null; then
    cat >> "$dir/talon.config.yaml" <<'SOVEOF'

sovereignty:
  mode: eu_strict
SOVEOF
  fi
  # Backup is US in scenario B: the only region change is the backup provider's.
  local gw_cfg_b="$dir/talon.gateway.failclosed.yaml"
  awk '
    /backup:/ { in_backup=1 }
    in_backup && /region: "EU"/ { sub(/region: "EU"/, "region: \"US\""); in_backup=0 }
    { print }
  ' "$gw_cfg_a" > "$gw_cfg_b"

  if ! wait_port_free "$gateway_port" 60 5; then
    log_failure "failover section (B) could not re-acquire port ${gateway_port}" "port remained busy"
    cd "$REPO_ROOT" || true
    return 0
  fi
  local gw_log_b="$dir/gateway_failover_b.log"
  env TALON_DATA_DIR="$TALON_DATA_DIR" talon serve --port "$gateway_port" --gateway --gateway-config "$gw_cfg_b" >"$gw_log_b" 2>&1 &
  local fo_pid_b=$!
  if ! smoke_wait_health "$gateway_base_url" 10 1; then
    log_failure "failover gateway (B) did not start on port ${gateway_port}" "pid=$fo_pid_b"
    dump_diag_file "section 35 serve log (B)" "$gw_log_b"
    smoke_stop_gateway_35 "$fo_pid_b" "$gateway_port"
    cd "$REPO_ROOT" || true
    return 0
  fi

  local fo_headers_b="/tmp/talon_fo_headers_b.txt"
  local fo_body_b="/tmp/talon_fo_resp_b.json"
  local code_b
  code_b="$(smoke_gw_post_chat_capture "$gateway_base_url" "Bearer $fo_key" "$SMOKE_BODY_SIMPLE" "$fo_headers_b" "$fo_body_b")"
  if ! assert_pass "eu_strict with US-only backup fails closed (non-200)" test "$code_b" != "200"; then
    dump_diag_kv "section 35 fail-closed POST" "http_code=$code_b"
    dump_diag_json "fail-closed response body" "$(cat "$fo_body_b" 2>/dev/null || echo '(missing)')"
    dump_diag_file "section 35 serve log (B)" "$gw_log_b" 50
  fi
  local fo_corr_b
  fo_corr_b="$(grep -i '^X-Talon-Session-ID:' "$fo_headers_b" 2>/dev/null | head -1 | tr -d '\r' | awk '{print $2}' | sed 's/^sess_//')"

  smoke_stop_gateway_35 "$fo_pid_b" "$gateway_port"

  if [[ -n "$fo_corr_b" ]]; then
    local verify_out_b
    verify_out_b="$(run_talon audit verify --failover "$fo_corr_b" 2>&1)"
    if [[ $? -eq 0 ]] && grep -q "valid_fail_closed" <<< "$verify_out_b"; then
      echo "  ✓  audit verify --failover confirms fail-closed governance outcome"
      record_pass
    else
      log_failure "audit verify --failover should report valid_fail_closed" "$verify_out_b"
    fi
  else
    log_failure "fail-closed response should carry X-Talon-Session-ID for correlation" "headers=$(cat "$fo_headers_b" 2>/dev/null)"
  fi

  # Full sweep: every failover chain in the store must verify.
  assert_pass "audit verify --failover (all chains) exits 0" run_talon audit verify --failover

  rm -f "$fo_headers" "$fo_body" "$fo_headers_b" "$fo_body_b" 2>/dev/null || true
  cd "$REPO_ROOT" || true
}
