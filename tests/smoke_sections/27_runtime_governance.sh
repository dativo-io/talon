#!/usr/bin/env bash
# Smoke test section: 27_runtime_governance
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 27 — Runtime Governance Decision Matrix
# Proves per-request runtime governance across all four TOM decisions:
#   ALLOW  — benign request allowed, evidence confirms policy_decision.allowed=true
#   BLOCK  — PII request denied at gateway, evidence confirms action=deny + reason
#   REDACT — PII request redacted (not blocked), metrics delta + evidence PII fields
#   ROUTE  — provider-restricted caller denied, evidence confirms routing reason
# Each sub-test asserts both the HTTP outcome AND the evidence record content.
# -----------------------------------------------------------------------------
test_section_27_runtime_governance() {
  local section="27_runtime_governance"
  local gov_port="8080"
  local gov_base="http://127.0.0.1:${gov_port}"
  echo ""
  echo "=== SECTION 27 — Runtime Governance Decision Matrix ==="
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1

  if ! wait_port_free "$gov_port" 180 10; then
    log_failure "runtime governance section could not acquire port ${gov_port}" "port remained busy"
    dump_diag_kv "port ${gov_port} in use" \
      "lsof=$(lsof -nP -iTCP:${gov_port} -sTCP:LISTEN 2>/dev/null | head -5 || echo '(lsof unavailable)')"
    cd "$REPO_ROOT" || true
    return 0
  fi

  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"

  # Gateway config with 4 purpose-built callers — one per governance dimension.
  if [[ -f "$dir/talon.config.yaml" ]] && ! grep -q "gateway:" "$dir/talon.config.yaml" 2>/dev/null; then
    cat >> "$dir/talon.config.yaml" <<'GOVEOF'

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
    - name: "gov-allow-caller"
      tenant_key: "talon-gw-gov-allow-001"
      tenant_id: "default"
      allowed_providers: ["openai"]
    - name: "gov-block-caller"
      tenant_key: "talon-gw-gov-block-001"
      tenant_id: "default"
      allowed_providers: ["openai"]
      policy_overrides:
        pii_action: "block"
    - name: "gov-redact-caller"
      tenant_key: "talon-gw-gov-redact-001"
      tenant_id: "default"
      allowed_providers: ["openai"]
      policy_overrides:
        pii_action: "redact"
    - name: "gov-route-deny-caller"
      tenant_key: "talon-gw-gov-route-001"
      tenant_id: "default"
      allowed_providers: ["anthropic"]
  default_policy:
    default_pii_action: "warn"
    max_daily_cost: 100.00
    require_caller_id: true
GOVEOF
  fi

  local GOV_PID=""
  local gov_log="$dir/gov_gateway_serve.log"
  run_talon serve --port "$gov_port" --gateway --gateway-config "$dir/talon.config.yaml" >"$gov_log" 2>&1 &
  GOV_PID=$!
  if ! smoke_wait_health "$gov_base" 45 1; then
    local gw_state="running"
    if ! kill -0 "$GOV_PID" 2>/dev/null; then
      wait "$GOV_PID" 2>/dev/null; gw_state="exited($?)"
    fi
    log_failure "runtime governance gateway did not start on port ${gov_port}" \
      "url=${gov_base}/health pid=$GOV_PID state=$gw_state"
    dump_diag_file "section 27 serve log" "$gov_log" 120
    dump_diag_file "talon.config.yaml" "$dir/talon.config.yaml"
    dump_diag_env
    kill "$GOV_PID" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi

  local admin_key="${TALON_ADMIN_KEY}"
  local gov_allow_ok=true gov_block_ok=true gov_redact_ok=true gov_route_ok=true
  local allow_ev_json="" # saved for ROUTE cross-reference

  # =========================================================================
  # 27.1  ALLOW — benign request through unrestricted caller
  # =========================================================================
  echo ""
  echo "  -- 27.1: runtime_governance_allow --"
  local allow_code
  allow_code="$(smoke_gw_post_chat "$gov_base" "Bearer talon-gw-gov-allow-001" "$SMOKE_BODY_SIMPLE")"
  if [[ "$allow_code" == "200" ]]; then
    echo "  ✓  ALLOW: benign request returns 200"
    record_pass
  else
    log_failure "ALLOW: expected 200 for benign request via gov-allow-caller" "got HTTP $allow_code"
    gov_allow_ok=false
  fi
  sleep 1
  allow_ev_json="$(smoke_get_latest_evidence "$gov_base" "$admin_key" 2>/dev/null)" || true
  if [[ -n "$allow_ev_json" ]] && echo "$allow_ev_json" | jq -e '.' &>/dev/null; then
    local allow_pd_allowed allow_pd_action
    allow_pd_allowed="$(jq -r '.policy_decision.allowed' <<< "$allow_ev_json")"
    allow_pd_action="$(jq -r '.policy_decision.action' <<< "$allow_ev_json")"
    if [[ "$allow_pd_allowed" == "true" ]]; then
      echo "  ✓  ALLOW evidence: policy_decision.allowed=true"
      record_pass
    else
      log_failure "ALLOW evidence: expected policy_decision.allowed=true" "got=$allow_pd_allowed"
      dump_diag_json "allow evidence" "$allow_ev_json"
      gov_allow_ok=false
    fi
    if [[ "$allow_pd_action" == "allow" ]]; then
      echo "  ✓  ALLOW evidence: policy_decision.action=allow"
      record_pass
    else
      log_failure "ALLOW evidence: expected policy_decision.action=allow" "got=$allow_pd_action"
      gov_allow_ok=false
    fi
  else
    log_failure "ALLOW evidence: could not fetch latest evidence record" "json=${allow_ev_json:0:200}"
    dump_diag_file "section 27 serve log" "$gov_log" 30
    gov_allow_ok=false
  fi
  if $gov_allow_ok; then
    echo "[SMOKE] CONSISTENCY|runtime_governance_allow|PASS|http=$allow_code"
  else
    echo "[SMOKE] CONSISTENCY|runtime_governance_allow|FAIL|http=$allow_code"
  fi

  # =========================================================================
  # 27.2  BLOCK — PII request through block-caller
  # =========================================================================
  echo ""
  echo "  -- 27.2: runtime_governance_block --"
  local block_code
  block_code="$(smoke_gw_post_chat "$gov_base" "Bearer talon-gw-gov-block-001" "$SMOKE_BODY_PII")"
  if [[ "$block_code" == "400" ]]; then
    echo "  ✓  BLOCK: PII request via gov-block-caller returns 400"
    record_pass
  else
    log_failure "BLOCK: expected 400 for PII request via gov-block-caller" "got HTTP $block_code"
    gov_block_ok=false
  fi
  sleep 1
  local block_ev_json
  block_ev_json="$(smoke_get_latest_evidence "$gov_base" "$admin_key" 2>/dev/null)" || true
  if [[ -n "$block_ev_json" ]] && echo "$block_ev_json" | jq -e '.' &>/dev/null; then
    local block_pd_allowed block_pd_action block_pd_reasons
    block_pd_allowed="$(jq -r '.policy_decision.allowed' <<< "$block_ev_json")"
    block_pd_action="$(jq -r '.policy_decision.action' <<< "$block_ev_json")"
    block_pd_reasons="$(jq -r '.policy_decision.reasons // [] | join(",")' <<< "$block_ev_json")"
    if [[ "$block_pd_allowed" == "false" ]]; then
      echo "  ✓  BLOCK evidence: policy_decision.allowed=false"
      record_pass
    else
      log_failure "BLOCK evidence: expected policy_decision.allowed=false" "got=$block_pd_allowed"
      dump_diag_json "block evidence" "$block_ev_json"
      gov_block_ok=false
    fi
    if [[ "$block_pd_action" == "deny" ]]; then
      echo "  ✓  BLOCK evidence: policy_decision.action=deny"
      record_pass
    else
      log_failure "BLOCK evidence: expected policy_decision.action=deny" "got=$block_pd_action"
      gov_block_ok=false
    fi
    if echo "$block_pd_reasons" | grep -qi "pii"; then
      echo "  ✓  BLOCK evidence: policy reasons mention PII ($block_pd_reasons)"
      record_pass
    else
      log_failure "BLOCK evidence: expected reasons to mention PII" "reasons=$block_pd_reasons"
      gov_block_ok=false
    fi
  else
    log_failure "BLOCK evidence: could not fetch latest evidence record" "json=${block_ev_json:0:200}"
    gov_block_ok=false
  fi
  if $gov_block_ok; then
    echo "[SMOKE] CONSISTENCY|runtime_governance_block|PASS|http=$block_code"
  else
    echo "[SMOKE] CONSISTENCY|runtime_governance_block|FAIL|http=$block_code"
  fi

  # =========================================================================
  # 27.3  REDACT — PII request through redact-caller (not blocked, PII redacted)
  # =========================================================================
  echo ""
  echo "  -- 27.3: runtime_governance_redact --"
  # Snapshot metrics pii_redactions BEFORE
  local redact_snap_before redact_pii_before
  redact_snap_before="$(smoke_gw_get_metrics "$gov_base" "$admin_key")"
  redact_pii_before="$(jq '.summary.pii_redactions // 0' <<< "$redact_snap_before")"

  local redact_code
  redact_code="$(smoke_gw_post_chat "$gov_base" "Bearer talon-gw-gov-redact-001" "$SMOKE_BODY_PII")"
  if [[ "$redact_code" == "200" ]]; then
    echo "  ✓  REDACT: PII request via gov-redact-caller returns 200 (not blocked)"
    record_pass
  else
    log_failure "REDACT: expected 200 for PII request via gov-redact-caller" "got HTTP $redact_code"
    gov_redact_ok=false
  fi

  sleep 2
  # Snapshot metrics pii_redactions AFTER
  local redact_snap_after redact_pii_after redact_pii_delta
  redact_snap_after="$(smoke_gw_get_metrics "$gov_base" "$admin_key")"
  redact_pii_after="$(jq '.summary.pii_redactions // 0' <<< "$redact_snap_after")"
  redact_pii_delta=$(( redact_pii_after - redact_pii_before ))
  if [[ "$redact_pii_delta" -gt 0 ]]; then
    echo "  ✓  REDACT metrics: pii_redactions delta=$redact_pii_delta (before=$redact_pii_before after=$redact_pii_after)"
    record_pass
  else
    log_failure "REDACT metrics: expected pii_redactions to increment" \
      "before=$redact_pii_before after=$redact_pii_after delta=$redact_pii_delta"
    gov_redact_ok=false
  fi

  local redact_ev_json
  redact_ev_json="$(smoke_get_latest_evidence "$gov_base" "$admin_key" 2>/dev/null)" || true
  if [[ -n "$redact_ev_json" ]] && echo "$redact_ev_json" | jq -e '.' &>/dev/null; then
    local redact_pii_detected redact_pd_allowed
    redact_pii_detected="$(jq -r '.classification.pii_detected // [] | length' <<< "$redact_ev_json")"
    redact_pd_allowed="$(jq -r '.policy_decision.allowed' <<< "$redact_ev_json")"
    if [[ "$redact_pd_allowed" == "true" ]]; then
      echo "  ✓  REDACT evidence: policy_decision.allowed=true (request not denied)"
      record_pass
    else
      log_failure "REDACT evidence: expected policy_decision.allowed=true" "got=$redact_pd_allowed"
      dump_diag_json "redact evidence" "$redact_ev_json"
      gov_redact_ok=false
    fi
    if [[ "$redact_pii_detected" -gt 0 ]]; then
      echo "  ✓  REDACT evidence: classification.pii_detected has $redact_pii_detected type(s)"
      record_pass
    else
      log_failure "REDACT evidence: expected classification.pii_detected to be non-empty" "length=$redact_pii_detected"
      gov_redact_ok=false
    fi
  else
    log_failure "REDACT evidence: could not fetch latest evidence record" "json=${redact_ev_json:0:200}"
    gov_redact_ok=false
  fi
  dump_diag_kv "section 27 REDACT summary" \
    "http=$redact_code" \
    "pii_before=$redact_pii_before" \
    "pii_after=$redact_pii_after" \
    "delta=$redact_pii_delta"
  if $gov_redact_ok; then
    echo "[SMOKE] CONSISTENCY|runtime_governance_redact|PASS|http=$redact_code pii_delta=$redact_pii_delta"
  else
    echo "[SMOKE] CONSISTENCY|runtime_governance_redact|FAIL|http=$redact_code pii_delta=$redact_pii_delta"
  fi

  # =========================================================================
  # 27.4  ROUTE — provider-restricted caller denied for wrong provider
  # =========================================================================
  echo ""
  echo "  -- 27.4: runtime_governance_route --"
  # Negative: gov-route-deny-caller only allows "anthropic", but the model
  # routes to "openai" -> gateway must deny with 403.
  local route_code
  route_code="$(smoke_gw_post_chat "$gov_base" "Bearer talon-gw-gov-route-001" "$SMOKE_BODY_SIMPLE")"
  if [[ "$route_code" == "403" ]]; then
    echo "  ✓  ROUTE deny: openai model via anthropic-only caller returns 403"
    record_pass
  else
    log_failure "ROUTE deny: expected 403 for openai model via gov-route-deny-caller" "got HTTP $route_code"
    gov_route_ok=false
  fi
  sleep 1
  local route_ev_json
  route_ev_json="$(smoke_get_latest_evidence "$gov_base" "$admin_key" 2>/dev/null)" || true
  if [[ -n "$route_ev_json" ]] && echo "$route_ev_json" | jq -e '.' &>/dev/null; then
    local route_pd_allowed route_pd_reasons
    route_pd_allowed="$(jq -r '.policy_decision.allowed' <<< "$route_ev_json")"
    route_pd_reasons="$(jq -r '.policy_decision.reasons // [] | join(",")' <<< "$route_ev_json")"
    if [[ "$route_pd_allowed" == "false" ]]; then
      echo "  ✓  ROUTE evidence: policy_decision.allowed=false"
      record_pass
    else
      log_failure "ROUTE evidence: expected policy_decision.allowed=false" "got=$route_pd_allowed"
      dump_diag_json "route evidence" "$route_ev_json"
      gov_route_ok=false
    fi
    if echo "$route_pd_reasons" | grep -qi "provider not allowed"; then
      echo "  ✓  ROUTE evidence: reasons contain 'provider not allowed' ($route_pd_reasons)"
      record_pass
    else
      log_failure "ROUTE evidence: expected reasons to contain 'provider not allowed'" "reasons=$route_pd_reasons"
      gov_route_ok=false
    fi
  else
    log_failure "ROUTE evidence: could not fetch latest evidence record" "json=${route_ev_json:0:200}"
    gov_route_ok=false
  fi

  # Positive contrast: the ALLOW test (27.1) used the same model through an
  # openai-allowed caller and succeeded — verify execution.model_used confirms
  # the openai provider was actually used, proving routing is policy-driven.
  if [[ -n "$allow_ev_json" ]] && echo "$allow_ev_json" | jq -e '.' &>/dev/null; then
    local allow_model_used
    allow_model_used="$(jq -r '.execution.model_used // empty' <<< "$allow_ev_json")"
    if [[ -n "$allow_model_used" ]] && echo "$allow_model_used" | grep -qi "gpt"; then
      echo "  ✓  ROUTE contrast: ALLOW evidence execution.model_used=$allow_model_used (openai, policy-driven)"
      record_pass
    else
      echo "  -  ROUTE contrast: ALLOW execution.model_used=$allow_model_used (could not confirm openai model)"
    fi
  fi

  if $gov_route_ok; then
    echo "[SMOKE] CONSISTENCY|runtime_governance_route|PASS|http=$route_code"
  else
    echo "[SMOKE] CONSISTENCY|runtime_governance_route|FAIL|http=$route_code"
  fi

  # =========================================================================
  # Summary
  # =========================================================================
  echo ""
  local gov_all_ok=true
  $gov_allow_ok  || gov_all_ok=false
  $gov_block_ok  || gov_all_ok=false
  $gov_redact_ok || gov_all_ok=false
  $gov_route_ok  || gov_all_ok=false
  if $gov_all_ok; then
    echo "  ✓  Runtime governance decision matrix: all 4 decisions verified"
  else
    echo "  ✗  Runtime governance decision matrix: one or more decisions failed"
  fi
  echo "[SMOKE] CONSISTENCY|runtime_governance_matrix|allow=$gov_allow_ok block=$gov_block_ok redact=$gov_redact_ok route=$gov_route_ok"

  kill "$GOV_PID" 2>/dev/null || true
  wait "$GOV_PID" 2>/dev/null || true
  sleep 2
  echo "[SMOKE] SECTION|27_runtime_governance"
  cd "$REPO_ROOT" || true
}

