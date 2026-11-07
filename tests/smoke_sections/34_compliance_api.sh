#!/usr/bin/env bash
# Smoke test section: 34_compliance_api
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 34 — Compliance API (#129): /v1/compliance/* HTTP API. A DPO must be
# able to read framework coverage and export a RoPA / Annex IV artifact over
# admin-authenticated HTTP without the CLI.
# -----------------------------------------------------------------------------
test_section_34_compliance_api() {
  local section="34_compliance_api"
  local port="8080"
  local base_url="http://127.0.0.1:${port}"
  echo ""
  echo "=== SECTION 34 — Compliance API ==="
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  if ! wait_port_free "$port" 180 10; then
    log_failure "compliance API section could not acquire port ${port}" "port remained busy"
    cd "$REPO_ROOT" || true
    return 0
  fi
  run_talon init --scaffold --name smoke-compliance-agent &>/dev/null; true
  smoke_bind_agent_key "$dir" "talon-gw-compliance-001"
  [[ -n "${OPENAI_API_KEY:-}" ]] && run_talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null; true
  smoke_tighten_limits "$dir"
  run_talon run "One" &>/dev/null; true

  # Org-level controller declaration so the RoPA carries a controller identity.
  cat >> "$dir/talon.config.yaml" <<'EOF'

compliance:
  controller:
    name: "Smoke Compliance GmbH"
    contact: "privacy@smoke.test"
EOF

  # Gateway config so agent keys exist (to verify agent keys are rejected
  # on admin-only compliance endpoints).
  if ! grep -q "gateway:" "$dir/talon.config.yaml" 2>/dev/null; then
    cat >> "$dir/talon.config.yaml" <<'GWEOF'

gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  organization_policy:
    defaults:
      pii_action: "redact"
      daily_cost: 100.00
GWEOF
  fi

  local SRV_PID=""
  local srv_log="$dir/compliance_api_serve.log"
  if ! start_owned_talon_server "compliance API server" "$srv_log" "$port" \
      serve --port "$port" --gateway --gateway-config "$dir/talon.config.yaml"; then
    cd "$REPO_ROOT" || true
    return 0
  fi
  SRV_PID="$SMOKE_SERVER_PID"
  local admin_key="${TALON_ADMIN_KEY}"
  local agent_key="talon-gw-compliance-001"

  # --- 34.2: Coverage endpoint (admin) ---
  local coverage; coverage="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "${base_url}/v1/compliance/coverage" 2>/dev/null)"
  assert_pass "coverage returns valid JSON" jq -e '.' <<< "$coverage" &>/dev/null
  assert_pass "coverage lists frameworks" \
    jq -e '.frameworks | type == "array" and length >= 5' <<< "$coverage" &>/dev/null
  assert_pass "coverage includes gdpr controls" \
    jq -e '[.frameworks[] | select(.framework == "gdpr") | .controls | length > 0] | any' <<< "$coverage" &>/dev/null
  assert_pass "coverage has declaration warnings object" \
    jq -e '.declaration_warnings | has("ropa") and has("annex_iv")' <<< "$coverage" &>/dev/null
  assert_pass "coverage claim note disclaims determination" \
    jq -e '.claim_note | test("not a completed legal filing")' <<< "$coverage" &>/dev/null

  # --- 34.3: One-click RoPA / Annex IV / report exports (admin) ---
  local ropa_json; ropa_json="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "${base_url}/v1/compliance/ropa?format=json" 2>/dev/null)"
  assert_pass "ropa export is valid JSON" jq -e '.' <<< "$ropa_json" &>/dev/null
  assert_pass "ropa export has expected title" \
    jq -e '.title == "Record of Processing Activities"' <<< "$ropa_json" &>/dev/null
  assert_pass "ropa export carries claim note" \
    jq -e '.claim_note | test("not a completed legal filing")' <<< "$ropa_json" &>/dev/null
  local ropa_html; ropa_html="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "${base_url}/v1/compliance/ropa" 2>/dev/null)"
  assert_pass "ropa HTML lists declared controller" grep -q "Smoke Compliance GmbH" <<< "$ropa_html"
  local annex_json; annex_json="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "${base_url}/v1/compliance/annex-iv?format=json" 2>/dev/null)"
  assert_pass "annex-iv export is valid JSON" jq -e '.' <<< "$annex_json" &>/dev/null
  assert_pass "annex-iv export has Annex IV title" \
    jq -e '.title | test("Annex IV")' <<< "$annex_json" &>/dev/null
  local report_json; report_json="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "${base_url}/v1/compliance/report?format=json&framework=gdpr" 2>/dev/null)"
  assert_pass "report export is valid JSON" jq -e '.' <<< "$report_json" &>/dev/null
  assert_pass "report export is gdpr-filtered" \
    jq -e '.framework == "gdpr"' <<< "$report_json" &>/dev/null

  # --- 34.4: Exports record signed control-plane evidence ---
  local cp_evidence; cp_evidence="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "${base_url}/v1/evidence?invocation_type=control_plane&limit=50" 2>/dev/null)"
  assert_pass "compliance exports recorded control-plane evidence" \
    jq -e '[.entries[] | select(.id != null)] | length > 0' <<< "$cp_evidence" &>/dev/null

  # --- 34.5: Auth — admin-only; agent key and anonymous rejected ---
  assert_pass "coverage without key → 401" \
    test "$(smoke_get_code "$base_url" "/v1/compliance/coverage")" = "401"
  assert_pass "coverage with agent key → 401" \
    test "$(smoke_get_code "$base_url" "/v1/compliance/coverage" "Bearer $agent_key")" = "401"
  assert_pass "ropa with agent key → 401" \
    test "$(smoke_get_code "$base_url" "/v1/compliance/ropa" "Bearer $agent_key")" = "401"
  assert_pass "annex-iv without key → 401" \
    test "$(smoke_get_code "$base_url" "/v1/compliance/annex-iv")" = "401"
  assert_pass "report with wrong admin key → 401" \
    test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: wrong" "${base_url}/v1/compliance/report")" = "401"

  # --- 34.6: Invalid params are rejected ---
  assert_pass "ropa with format=pdf → 400" \
    test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: $admin_key" "${base_url}/v1/compliance/ropa?format=pdf")" = "400"
  assert_pass "coverage with bad from date → 400" \
    test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Talon-Admin-Key: $admin_key" "${base_url}/v1/compliance/coverage?from=12-31-2026")" = "400"

  stop_owned_talon_server "$SRV_PID" "$port" || true
  sleep 2
  cd "$REPO_ROOT" || true
}
