#!/usr/bin/env bash
# Smoke test section: 32_egress
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 32 — Gateway Egress Allow/Deny by Data Classification
# (docs/reference/configuration.md, docs/explanation/explanation-catalog.md)
#
# Egress denial fires before any upstream call, so this section needs no real
# OPENAI_API_KEY: a tier_2 payload (IBAN) to a US-region provider must be
# blocked with egress_tier_destination_disallowed and produce signed evidence
# carrying the egress_decision facts.
# -----------------------------------------------------------------------------

# Writes a gateway config with an EU-only tier_2 egress policy.
# Usage: smoke_write_egress_config <path> <mode>
smoke_write_egress_config() {
  local path="$1" mode="$2"
  cat > "$path" <<EGEOF
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "${mode}"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
      region: "US"
  organization_policy:
    defaults:
      pii_action: "warn"
      daily_cost: 100.00
    constraints:
      egress:
        default_action: allow
        rules:
          - tier: public          # named alias for 0
            allowed_providers: ["*"]
          - tier: confidential    # named alias for 2
            allowed_regions: ["EU", "LOCAL"]
EGEOF
}

test_section_32_egress() {
  local section="32_egress"
  local gateway_port="8080"
  local gateway_base_url="http://127.0.0.1:${gateway_port}"
  local gw_key="talon-gw-egress-001"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  if ! wait_port_free "$gateway_port" 180 10; then
    log_failure "egress section could not acquire port ${gateway_port}" "port remained busy"
    cd "$REPO_ROOT" || true
    return 0
  fi
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  smoke_bind_agent_key "$dir" "talon-gw-egress-001"
  smoke_tighten_limits "$dir"

  # --- Invalid egress config must fail fast at load (validation) ---
  smoke_write_egress_config "$dir/talon.egress.bad.yaml" "enforce"
  sed -i.bak 's/default_action: allow/default_action: maybe/' "$dir/talon.egress.bad.yaml" 2>/dev/null || true
  local bad_log="$dir/gateway_egress_bad.log"
  run_talon serve --port "$gateway_port" --gateway --gateway-config "$dir/talon.egress.bad.yaml" >"$bad_log" 2>&1 &
  local bad_pid=$!
  sleep 3
  if kill -0 "$bad_pid" 2>/dev/null; then
    log_failure "serve with invalid egress default_action should exit" "$(tail -20 "$bad_log" 2>/dev/null)"
    kill "$bad_pid" 2>/dev/null || true
    wait "$bad_pid" 2>/dev/null || true
  else
    if grep -q "default_action must be allow or deny" "$bad_log" 2>/dev/null; then
      echo "  ✓  invalid egress default_action rejected at config load"
      record_pass
    else
      log_failure "invalid egress config exit should mention default_action validation" "$(tail -20 "$bad_log" 2>/dev/null)"
    fi
  fi
  if ! wait_port_free "$gateway_port" 30 5; then
    log_failure "port ${gateway_port} busy after invalid-config check" "cannot continue section"
    cd "$REPO_ROOT" || true
    return 0
  fi

  # --- Enforce mode: tier_2 to US-region provider is blocked ---
  smoke_write_egress_config "$dir/talon.egress.yaml" "enforce"
  TALON_GATEWAY_PID=""
  local gw_log="$dir/gateway_egress_serve.log"
  run_talon serve --port "$gateway_port" --gateway --gateway-config "$dir/talon.egress.yaml" >"$gw_log" 2>&1 &
  TALON_GATEWAY_PID=$!
  if ! smoke_wait_health "$gateway_base_url" 10 1; then
    log_failure "egress gateway server did not start on port ${gateway_port}" "pid=$TALON_GATEWAY_PID"
    dump_diag_file "section 32 serve log" "$gw_log"
    kill "$TALON_GATEWAY_PID" 2>/dev/null || true
    TALON_GATEWAY_PID=""
    cd "$REPO_ROOT" || true
    return 0
  fi

  local deny_body="/tmp/talon_egress_deny.json"
  local code
  code="$(smoke_gw_post_chat_to_file "$gateway_base_url" "Bearer $gw_key" "$SMOKE_BODY_PII" "$deny_body")"
  if assert_pass "tier_2 payload to US-region provider returns 403" test "$code" = "403"; then
    :
  else
    dump_diag_json "egress deny response body" "$(cat "$deny_body" 2>/dev/null || echo '(missing)')"
    dump_diag_file "section 32 serve log" "$gw_log" 50
  fi
  assert_pass "egress denial carries egress_tier_destination_disallowed code" \
    grep -q "egress_tier_destination_disallowed" "$deny_body"

  # Clean tier_0 payload must not be egress-denied (wildcard rule). Without a
  # real provider key the request may still fail upstream/secret (5xx) — the
  # assertion is only that egress does not block it.
  local clean_body="/tmp/talon_egress_clean.json"
  code="$(smoke_gw_post_chat_to_file "$gateway_base_url" "Bearer $gw_key" "$SMOKE_BODY_SIMPLE" "$clean_body")"
  if [[ "$code" != "403" ]] && ! grep -q "egress_" "$clean_body" 2>/dev/null; then
    echo "  ✓  tier_0 payload is not egress-denied (http_code=$code)"
    record_pass
  else
    log_failure "tier_0 payload should not be egress-denied" "http_code=$code body=$(cat "$clean_body" 2>/dev/null)"
  fi

  # Evidence: the denied request must produce a signed record with egress facts.
  local ev_index ev_match=0 evid ev_json
  ev_index="$(curl -s -H "X-Talon-Admin-Key: ${TALON_ADMIN_KEY}" "${gateway_base_url}${SMOKE_PATH_EVIDENCE}?limit=20")"
  while read -r evid; do
    [[ -z "$evid" ]] && continue
    ev_json="$(curl -s -H "X-Talon-Admin-Key: ${TALON_ADMIN_KEY}" "${gateway_base_url}${SMOKE_PATH_EVIDENCE}/${evid}")"
    if echo "$ev_json" | jq -e '
        .policy_decision.allowed == false
        and .egress_decision.decision == "deny"
        and .egress_decision.tier == 2
        and .egress_decision.provider == "openai"
        and .egress_decision.reason == "egress_tier_destination_disallowed"' >/dev/null 2>&1; then
      ev_match=1
      break
    fi
  done < <(echo "$ev_index" | jq -r '.entries[]? | .id' 2>/dev/null)
  if [[ "$ev_match" -eq 1 ]]; then
    echo "  ✓  denied egress produced evidence with egress_decision facts"
    record_pass
  else
    log_failure "evidence should contain an egress_decision deny record" \
      "index=$(echo "$ev_index" | jq -c '.entries[]? | .id' 2>/dev/null | head -5)"
  fi
  kill "$TALON_GATEWAY_PID" 2>/dev/null || true
  wait "$TALON_GATEWAY_PID" 2>/dev/null || true
  TALON_GATEWAY_PID=""
  if ! wait_port_free "$gateway_port" 30 5; then
    log_failure "port ${gateway_port} busy after enforce-mode checks" "skipping shadow-mode check"
    cd "$REPO_ROOT" || true
    return 0
  fi

  # --- Shadow mode: egress violation is recorded but not enforced ---
  smoke_write_egress_config "$dir/talon.egress.shadow.yaml" "shadow"
  local gw_shadow_log="$dir/gateway_egress_shadow.log"
  run_talon serve --port "$gateway_port" --gateway --gateway-config "$dir/talon.egress.shadow.yaml" >"$gw_shadow_log" 2>&1 &
  TALON_GATEWAY_PID=$!
  if ! smoke_wait_health "$gateway_base_url" 10 1; then
    log_failure "shadow egress gateway did not start" "pid=$TALON_GATEWAY_PID"
    dump_diag_file "section 32 shadow serve log" "$gw_shadow_log"
    kill "$TALON_GATEWAY_PID" 2>/dev/null || true
    TALON_GATEWAY_PID=""
    cd "$REPO_ROOT" || true
    return 0
  fi
  local shadow_body="/tmp/talon_egress_shadow.json"
  code="$(smoke_gw_post_chat_to_file "$gateway_base_url" "Bearer $gw_key" "$SMOKE_BODY_PII" "$shadow_body")"
  if [[ "$code" != "403" ]]; then
    echo "  ✓  shadow mode does not block egress violation (http_code=$code)"
    record_pass
  else
    log_failure "shadow mode should not return 403 for egress violation" "body=$(cat "$shadow_body" 2>/dev/null)"
  fi
  local sv_match=0
  ev_index="$(curl -s -H "X-Talon-Admin-Key: ${TALON_ADMIN_KEY}" "${gateway_base_url}${SMOKE_PATH_EVIDENCE}?limit=20")"
  while read -r evid; do
    [[ -z "$evid" ]] && continue
    ev_json="$(curl -s -H "X-Talon-Admin-Key: ${TALON_ADMIN_KEY}" "${gateway_base_url}${SMOKE_PATH_EVIDENCE}/${evid}")"
    if echo "$ev_json" | jq -e '
        .observation_mode_override == true
        and ([.shadow_violations[]? | select(.detail | startswith("egress_"))] | length) > 0' >/dev/null 2>&1; then
      sv_match=1
      break
    fi
  done < <(echo "$ev_index" | jq -r '.entries[]? | .id' 2>/dev/null)
  if [[ "$sv_match" -eq 1 ]]; then
    echo "  ✓  shadow mode records egress violation in evidence"
    record_pass
  else
    log_failure "shadow evidence should carry an egress shadow violation" \
      "index=$(echo "$ev_index" | jq -c '.entries[]? | .id' 2>/dev/null | head -5)"
  fi

  rm -f "$deny_body" "$clean_body" "$shadow_body" 2>/dev/null || true
  kill "$TALON_GATEWAY_PID" 2>/dev/null || true
  wait "$TALON_GATEWAY_PID" 2>/dev/null || true
  TALON_GATEWAY_PID=""
  cd "$REPO_ROOT" || true
}
