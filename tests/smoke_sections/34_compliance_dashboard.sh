#!/usr/bin/env bash
# Smoke test section: 34_compliance_dashboard
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 34 — Compliance dashboard mode (#129): /v1/compliance/* HTTP API +
# dashboard compliance tab. A DPO must be able to see framework coverage and
# export a RoPA / Annex IV artifact without the CLI.
# -----------------------------------------------------------------------------
test_section_34_compliance_dashboard() {
  local section="34_compliance_dashboard"
  local port="8080"
  local base_url="http://127.0.0.1:${port}"
  echo ""
  echo "=== SECTION 34 — Compliance Dashboard Mode ==="
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  if ! wait_port_free "$port" 180 10; then
    log_failure "compliance dashboard section could not acquire port ${port}" "port remained busy"
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
    name: "Smoke Dashboard GmbH"
    contact: "privacy@smoke.test"
EOF

  # Gateway config so tenant keys exist (to verify tenant keys are rejected
  # on admin-only compliance endpoints).
  if ! grep -q "gateway:" "$dir/talon.config.yaml" 2>/dev/null; then
    cat >> "$dir/talon.config.yaml" <<'GWEOF'

gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "enforce"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  organization_policy:
    default_pii_action: "redact"
    max_daily_cost: 100.00
GWEOF
  fi

  local SRV_PID=""
  local srv_log="$dir/compliance_dashboard_serve.log"
  run_talon serve --port "$port" --gateway --gateway-config "$dir/talon.config.yaml" >"$srv_log" 2>&1 &
  SRV_PID=$!
  if ! smoke_wait_health "$base_url" 45 1; then
    log_failure "compliance dashboard server did not start on port ${port}" "url=${base_url}/health pid=${SRV_PID}"
    dump_diag_file "section 34 serve log" "$srv_log" 120
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi
  local admin_key="${TALON_ADMIN_KEY}"
  local agent_key="talon-gw-compliance-001"

  # --- 34.1: Dashboard HTML serves the compliance tab and export hooks ---
  assert_pass "GET /dashboard 200" \
    test "$(smoke_get_code "$base_url" "/dashboard")" = "200"
  local dash_html; dash_html="$(curl -s "${base_url}/dashboard" 2>/dev/null)"
  assert_pass "dashboard HTML has compliance tab" grep -q 'data-tab="compliance"' <<< "$dash_html"
  assert_pass "dashboard HTML has compliance panel" grep -q 'panel-compliance' <<< "$dash_html"
  assert_pass "dashboard HTML has RoPA export hook" grep -q '/v1/compliance/ropa' <<< "$dash_html"
  assert_pass "dashboard HTML has Annex IV export hook" grep -q '/v1/compliance/annex-iv' <<< "$dash_html"
  assert_pass "dashboard HTML has coverage hook" grep -q '/v1/compliance/coverage' <<< "$dash_html"

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
  assert_pass "ropa HTML lists declared controller" grep -q "Smoke Dashboard GmbH" <<< "$ropa_html"
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

  # --- 34.5: Auth — admin-only; tenant key and anonymous rejected ---
  assert_pass "coverage without key → 401" \
    test "$(smoke_get_code "$base_url" "/v1/compliance/coverage")" = "401"
  assert_pass "coverage with tenant key → 401" \
    test "$(smoke_get_code "$base_url" "/v1/compliance/coverage" "Bearer $agent_key")" = "401"
  assert_pass "ropa with tenant key → 401" \
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

  kill "$SRV_PID" 2>/dev/null || true
  wait "$SRV_PID" 2>/dev/null || true
  sleep 2
  cd "$REPO_ROOT" || true
}
