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
  smoke_bind_agent_key "$dir" "talon-gw-smoke-001"
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
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  organization_policy:
    defaults:
      pii_action: "warn"
      daily_cost: 100.00
GWEOF
  fi
  TALON_GATEWAY_PID=""
  local gw_log_13="$dir/gateway_serve.log"
  run_talon_bg serve --port "$gateway_port" --gateway --gateway-config "$dir/talon.config.yaml" >"$gw_log_13" 2>&1
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
  local gw_ev_index gw_sid_match=0
  gw_ev_index="$(curl -s -H "X-Talon-Admin-Key: ${TALON_ADMIN_KEY}" "http://127.0.0.1:${gateway_port}/v1/evidence?limit=20")"
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
  # A model the pricing table does not know cannot be priced; the agent's
  # daily cap (smoke_tighten_limits: 5.0) binds, so the request is denied
  # before the provider is reached — live, against the real gateway config.
  local gw_unpriced_body="/tmp/talon_gw_unpriced.json"
  local code_unpriced
  code_unpriced="$(smoke_gw_post_chat_to_file "$gateway_base_url" "Bearer $gw_key" \
    '{"model":"gpt-unpriced-smoke-model","messages":[{"role":"user","content":"hello"}]}' "$gw_unpriced_body")"
  assert_pass "Unpriced model under a spending cap → 403" test "$code_unpriced" = "403"
  assert_pass "Unpriced-model denial carries pricing_unavailable" \
    jq -e '.error.type == "pricing_unavailable"' "$gw_unpriced_body"
  rm -f "$gw_unpriced_body" 2>/dev/null || true
  rm -f "$gw_headers" "$gw_body" /tmp/talon_gw_resp_join.json 2>/dev/null || true
  kill "$TALON_GATEWAY_PID" 2>/dev/null || true
  wait "$TALON_GATEWAY_PID" 2>/dev/null || true
  TALON_GATEWAY_PID=""
  cd "$REPO_ROOT" || true
  smoke_13_onboarding_two_use_cases
}

# smoke_13_secs prints b - a, two `date +%s.%N` stamps, in seconds.
smoke_13_secs() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", b - a }'; }

# The documented onboarding against the real provider (#575): two AI use
# cases registered with `talon agents add` under one company policy, the
# second while the server runs, each sending one real request. A counting
# pass-through between Talon and the provider proves that the denied requests
# never reached it, and separates the provider's latency from Talon's. Two
# small paid requests per run (gpt-4o-mini); PII requests are denied for free.
smoke_13_onboarding_two_use_cases() {
  local dir; dir="$(setup_section_dir "13_onboarding")"
  local data="$dir/data" port pt_port pt_pid serve_pid
  local pt_log="$dir/passthrough.jsonl" serve_log="$dir/serve.log"
  local upstream="${TALON_SMOKE_PASSTHROUGH_UPSTREAM:-https://api.openai.com}"
  local pii='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My email is jan@example.com and my IBAN is DE89370400440532013000."}]}'
  port="$(smoke_free_port)"; pt_port="$(smoke_free_port)"
  cd "$dir" || return 0
  : > "$pt_log"
  python3 "$REPO_ROOT/tests/smoke_counting_passthrough.py" "$pt_port" "$pt_log" "$upstream" &
  pt_pid=$!
  cat > talon.config.yaml <<OBEOF
agents_dir: ./agents
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "http://127.0.0.1:${pt_port}"
  organization_policy:
    defaults:
      pii_action: block
      daily_cost: 1
      monthly_cost: 5
OBEOF
  ob() { env TALON_DATA_DIR="$data" talon "$@"; }
  ob_key() { awk '/Application key/{getline; gsub(/^ +| +$/,""); print; exit}' "$1"; }
  forwarded() { wc -l < "$pt_log" | tr -d ' '; }
  printf '%s' "$OPENAI_API_KEY" | ob secrets set openai-api-key >/dev/null
  local t0 t1 t_reg1 t_reg2 t_start t_act t_ver key1 key2
  t0="$(date +%s.%N)"; ob agents add smoke-support --owner smoke-ops >"$dir/register-1.txt" 2>&1; t1="$(date +%s.%N)"
  t_reg1="$(smoke_13_secs "$t0" "$t1")"; key1="$(ob_key "$dir/register-1.txt")"
  t0="$(date +%s.%N)"
  env TALON_DATA_DIR="$data" talon serve --host 127.0.0.1 --port "$port" --gateway --gateway-config talon.config.yaml >"$serve_log" 2>&1 &
  serve_pid=$!
  [[ -n "$SMOKE_BG_PIDS_FILE" ]] && echo "$serve_pid" >> "$SMOKE_BG_PIDS_FILE"
  if [[ -z "$key1" ]] || ! smoke_wait_health "http://127.0.0.1:${port}" 15 1; then
    log_failure "onboarding: the first use case's registration or the server's start failed" "key_printed=$([[ -n "$key1" ]] && echo yes || echo no)"
    dump_diag_file "13_onboarding serve log" "$serve_log" 40
    kill "$pt_pid" 2>/dev/null || true; stop_talon_pid "$serve_pid" "$port" || true
    cd "$REPO_ROOT" || true
    return 0
  fi
  t_start="$(smoke_13_secs "$t0" "$(date +%s.%N)")"
  local base="http://127.0.0.1:${port}${SMOKE_PATH_GW_PROXY}" r1 r2
  r1="$(curl -s -o "$dir/answer-1.json" -w '%{http_code} %{time_total}' -X POST "$base" -H "Authorization: Bearer $key1" -H "Content-Type: application/json" -d "$SMOKE_BODY_SIMPLE")"
  assert_pass "onboarding: the first use case's request is answered by the provider through Talon" test "${r1%% *}" = "200"
  assert_pass "onboarding: that request reached the provider once (counted at the pass-through)" test "$(forwarded)" = "1"
  # The next use case, registered while the server runs: the server loads it
  # at its next re-scan (product default interval). Refused attempts (401)
  # never reach the provider; the first accepted one is its real request.
  t0="$(date +%s.%N)"; ob agents add smoke-hr --owner smoke-people >"$dir/register-2.txt" 2>&1; t1="$(date +%s.%N)"
  t_reg2="$(smoke_13_secs "$t0" "$t1")"; key2="$(ob_key "$dir/register-2.txt")"
  r2="401"
  t0="$(date +%s.%N)"
  while [[ -n "$key2" && "${r2%% *}" = "401" ]] && [[ "$(smoke_13_secs "$t0" "$(date +%s.%N)" | cut -d. -f1)" -lt 75 ]]; do
    r2="$(curl -s -o "$dir/answer-2.json" -w '%{http_code} %{time_total}' -X POST "$base" -H "Authorization: Bearer $key2" -H "Content-Type: application/json" -d "$SMOKE_BODY_SIMPLE")"
    [[ "${r2%% *}" = "401" ]] && sleep 0.25
  done
  t_act="$(smoke_13_secs "$t0" "$(date +%s.%N)")"
  assert_pass "onboarding: the second use case, registered while serving, is answered through Talon" test "${r2%% *}" = "200"
  assert_pass "onboarding: two paid requests in total reached the provider" test "$(forwarded)" = "2"
  local d1 d2
  d1="$(curl -s -o "$dir/denied-1.json" -w '%{http_code}' -X POST "$base" -H "Authorization: Bearer $key1" -H "Content-Type: application/json" -d "$pii")"
  d2="$(curl -s -o "$dir/denied-2.json" -w '%{http_code}' -X POST "$base" -H "Authorization: Bearer $key2" -H "Content-Type: application/json" -d "$pii")"
  assert_pass "onboarding: the shared company PII rule denies both use cases (400 pii_policy_violation)" \
    bash -c "[ '$d1' = 400 ] && [ '$d2' = 400 ] && jq -e '.error.code == \"pii_policy_violation\"' '$dir/denied-1.json' >/dev/null && jq -e '.error.code == \"pii_policy_violation\"' '$dir/denied-2.json' >/dev/null"
  if ! assert_pass "onboarding: the denied requests never reached the provider (still 2 at the pass-through)" test "$(forwarded)" = "2"; then
    dump_diag_file "13_onboarding pass-through log (path, status, latency only)" "$pt_log"
    dump_diag_file "13_onboarding serve log" "$serve_log" 40
  fi
  t0="$(date +%s.%N)"
  local show1 show2 ev
  show1="$(ob agents show smoke-support 2>&1)"; show2="$(ob agents show smoke-hr 2>&1)"
  assert_pass "onboarding: both use cases read Working, newest records signature-valid" \
    bash -c "grep -q 'Status      Working' <<<\"\$1\" && grep -q 'Status      Working' <<<\"\$2\" && grep -q '(signature valid)' <<<\"\$1\" && grep -q '(signature valid)' <<<\"\$2\"" _ "$show1" "$show2"
  while read -r ev; do
    [[ -n "$ev" ]] && assert_pass "onboarding: talon audit verify $ev" ob audit verify "$ev"
  done < <(grep -ohE 'evidence gw_[0-9a-f-]+' <<<"$show1"$'\n'"$show2" | cut -d' ' -f2)
  t_ver="$(smoke_13_secs "$t0" "$(date +%s.%N)")"
  local c1 c2
  c1="$(ob costs --agent smoke-support --json 2>/dev/null | jq -r '[.. | numbers] | max // 0' 2>/dev/null || echo 0)"
  c2="$(ob costs --agent smoke-hr --json 2>/dev/null | jq -r '[.. | numbers] | max // 0' 2>/dev/null || echo 0)"
  assert_pass "onboarding: each use case is charged for its own request (costs by use case > 0)" \
    awk -v a="$c1" -v b="$c2" 'BEGIN { exit !(a > 0 && b > 0) }'
  local up1 up2 tot1 tot2
  up1="$(sed -n 1p "$pt_log" | jq -r '.upstream_ms')"; up2="$(sed -n 2p "$pt_log" | jq -r '.upstream_ms')"
  tot1="$(awk -v t="${r1##* }" 'BEGIN { printf "%.0f", t * 1000 }')"; tot2="$(awk -v t="${r2##* }" 'BEGIN { printf "%.0f", t * 1000 }')"
  echo "  ONBOARDING SMOKE (real provider through a counting pass-through: ${upstream})"
  echo "    registration, first / second use case     ${t_reg1}s / ${t_reg2}s"
  echo "    server start                              ${t_start}s"
  echo "    second use case activation                ${t_act}s (product default agents_reload_interval)"
  echo "    request total, first / second             ${tot1}ms / ${tot2}ms"
  echo "    provider latency, first / second          ${up1}ms / ${up2}ms"
  echo "    Talon overhead, first / second            $(awk -v a="$tot1" -v b="$up1" 'BEGIN { printf "%.0f", a - b }')ms / $(awk -v a="$tot2" -v b="$up2" 'BEGIN { printf "%.0f", a - b }')ms"
  echo "    verification (agents show, audit verify)  ${t_ver}s"
  echo "    paid requests                             $(forwarded)"
  kill "$pt_pid" 2>/dev/null || true
  stop_talon_pid "$serve_pid" "$port" || true
  cd "$REPO_ROOT" || true
}

