#!/usr/bin/env bash
# Smoke test section: 42_anthropic
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 42 — LLM API Gateway, Anthropic Messages API against the REAL provider
# (docs/guides/claude-code-integration.md, docs/reference/configuration.md)
#
# The only smoke proof that Talon governs Anthropic traffic end to end with a
# real `api.anthropic.com` round trip: every other Anthropic test in the
# repository runs against fixtures or a mock. Needs ANTHROPIC_API_KEY (or
# anthropic-api-key already in the vault). Spend is a handful of requests of a
# few dozen tokens each against the cheapest priced Claude model
# (SMOKE_ANTHROPIC_MODEL in tests/smoke_lib.sh).
#
#   A) connectivity: agent key in (x-api-key, then Claude Code's bearer form),
#      vault-stored provider key out; a real Anthropic message envelope comes
#      back with the requested model identity and usage; no provider key leaks.
#   B) provider-native compatibility: streaming SSE (message_start … message_stop)
#      with usage parsed from the stream; count_tokens governed at cost 0; an
#      upstream 4xx (the provider's own request validation) is returned as an
#      error, never as a success, and evidenced as a failed execution.
#   C) policy enforcement: a wrong agent key → 401; a priced model outside the
#      provider allow list → 403 model_not_allowed, attributed to Talon's
#      policy in evidence (allowed=false, reason), with no failover; an unpriced
#      model under the agent's cap → 403 pricing_unavailable. The suite has no
#      provider-side counter against the real Anthropic API, so it does NOT
#      claim an independently measured zero-call result for denials.
#   D) evidence and accounting: the successful request's signed record carries
#      the provider, the model, the exact usage the provider reported and the
#      cost derived from pricing/models.yaml; `talon audit verify` accepts it;
#      `talon costs --by-provider` lists anthropic.
#
# Not asserted on purpose: any natural-language content of the answer.
# -----------------------------------------------------------------------------
test_section_42_anthropic() {
  local section="42_anthropic"
  local port="8080"
  local base="http://127.0.0.1:${port}"
  local agent_key="talon-gw-smoke-042"
  local model="$SMOKE_ANTHROPIC_MODEL"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  if ! wait_port_free "$port" 180 10; then
    log_failure "anthropic section could not acquire port ${port}" "$(smoke_port_owner "$port")"
    cd "$REPO_ROOT" || true
    return 0
  fi
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  # The provider key goes into the vault and nowhere else; the harness redacts
  # `secrets set` command lines before they reach any log.
  if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    run_talon secrets set anthropic-api-key "$ANTHROPIC_API_KEY" &>/dev/null; true
  fi
  smoke_tighten_limits "$dir"
  smoke_bind_agent_key "$dir" "$agent_key"
  if [[ ! -f "$dir/talon.config.yaml" ]]; then
    log_failure "anthropic section: scaffold produced no talon.config.yaml"
    cd "$REPO_ROOT" || true
    return 0
  fi
  if grep -q "^gateway:" "$dir/talon.config.yaml" 2>/dev/null; then
    log_failure "anthropic section: scaffold config already has a gateway block (section expects to add its own)"
    dump_diag_file "talon.config.yaml" "$dir/talon.config.yaml"
    cd "$REPO_ROOT" || true
    return 0
  fi
  # Anthropic provider only. allowed_models pins the smoke model so case C can
  # deny a priced sibling model on policy; the response PII action is warn so
  # the real stream is delivered as it arrives (post-delivery observation).
  cat >> "$dir/talon.config.yaml" <<GWEOF

gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    anthropic:
      enabled: true
      secret_name: "anthropic-api-key"
      base_url: "${SMOKE_ANTHROPIC_BASE_URL}"
      allowed_models: ["${model}"]
  organization_policy:
    defaults:
      pii_action: "warn"
      response_pii_action: "warn"
      daily_cost: 100.00
GWEOF
  local gw_log="$dir/gateway_serve.log"
  if ! start_owned_talon_server "anthropic gateway" "$gw_log" "$port" \
      serve --port "$port" --gateway --gateway-config "$dir/talon.config.yaml"; then
    dump_diag_file "talon.config.yaml" "$dir/talon.config.yaml"
    dump_diag_env
    cd "$REPO_ROOT" || true
    return 0
  fi
  local gw_pid="$SMOKE_SERVER_PID"
  local admin_key="${TALON_ADMIN_KEY}"
  local hdr="$dir/resp_headers.txt" body="$dir/resp_body.json"

  # =========================================================================
  # A. Basic connectivity: real request, real Anthropic response
  # =========================================================================
  echo "  -- 42.A: connectivity (${model} via ${SMOKE_ANTHROPIC_BASE_URL}) --"
  local code
  code="$(smoke_gw_post_anthropic "$base" x-api-key "$agent_key" "$(smoke_body_anthropic false)" "$hdr" "$body")"
  if ! assert_pass "A: POST /v1/proxy/anthropic/v1/messages with the agent key as x-api-key → 200" test "$code" = "200"; then
    dump_diag_kv "section 42 messages POST" "http_code=$code" "model=$model" "endpoint=${base}${SMOKE_PATH_GW_ANTHROPIC_MESSAGES}" "upstream=${SMOKE_ANTHROPIC_BASE_URL}"
    dump_diag_json "anthropic response body" "$(cat "$body" 2>/dev/null || echo '(missing)')"
    dump_diag_file "anthropic response headers" "$hdr"
    dump_diag_file "section 42 serve log" "$gw_log" 50
  fi
  assert_pass "A: response is an Anthropic message envelope (type=message, role=assistant)" \
    jq -e '.type == "message" and .role == "assistant"' "$body"
  assert_pass "A: response model identity matches the requested model" \
    jq -e --arg m "$model" '(.model | tostring | startswith($m))' "$body"
  assert_pass "A: response carries a text content block and a stop_reason" \
    jq -e '(.content | type == "array" and length > 0) and (.content[0].type == "text") and (.stop_reason | type == "string")' "$body"
  assert_pass "A: usage reports input and output tokens" \
    jq -e '.usage.input_tokens > 0 and .usage.output_tokens > 0' "$body"
  assert_fail "A: response never contains a provider key (sk-ant-)" grep -q "sk-ant-" "$body"
  assert_pass "A: gateway response includes X-Talon-Session-ID" \
    test -n "$(smoke_header_value "$hdr" "X-Talon-Session-ID")"
  local sid; sid="$(smoke_header_value "$hdr" "X-Talon-Session-ID")"
  # Usage as the provider reported it: the evidence must match these exactly.
  local in_tok out_tok cache_read cache_write
  in_tok="$(jq -r '.usage.input_tokens // 0' "$body" 2>/dev/null || echo 0)"
  out_tok="$(jq -r '.usage.output_tokens // 0' "$body" 2>/dev/null || echo 0)"
  cache_read="$(jq -r '.usage.cache_read_input_tokens // 0' "$body" 2>/dev/null || echo 0)"
  cache_write="$(jq -r '.usage.cache_creation_input_tokens // 0' "$body" 2>/dev/null || echo 0)"
  sleep 1
  local ev_a; ev_a="$(smoke_get_latest_evidence "$base" "$admin_key" 2>/dev/null)" || ev_a=""
  local ev_a_id; ev_a_id="$(jq -r '.id // empty' <<< "$ev_a" 2>/dev/null)"

  # Claude Code presents the agent key as Authorization: Bearer (ANTHROPIC_AUTH_TOKEN).
  local hdr2="$dir/resp_headers_bearer.txt" body2="$dir/resp_body_bearer.json"
  code="$(smoke_gw_post_anthropic "$base" bearer "$agent_key" "$(smoke_body_anthropic false)" "$hdr2" "$body2" \
    "$SMOKE_PATH_GW_ANTHROPIC_MESSAGES" -H "X-Talon-Session-ID: ${sid}")"
  if ! assert_pass "A: the agent key as Authorization: Bearer (Claude Code's form) → 200" test "$code" = "200"; then
    dump_diag_json "bearer response body" "$(cat "$body2" 2>/dev/null || echo '(missing)')"
  fi
  assert_pass "A: bearer-form response is an Anthropic message for the same model" \
    jq -e --arg m "$model" '.type == "message" and (.model | tostring | startswith($m))' "$body2"
  sleep 1
  local ev_join; ev_join="$(smoke_get_latest_evidence "$base" "$admin_key" 2>/dev/null)" || ev_join=""
  if [[ -n "$sid" ]] && jq -e --arg s "$sid" '.session_id == $s' <<< "$ev_join" &>/dev/null; then
    echo "  ✓  A: evidence of the joined request carries the provided session id"
    record_pass
  else
    log_failure "A: evidence of the joined request should carry the provided session id" "session_id=$sid evidence_session=$(jq -r '.session_id // empty' <<< "$ev_join" 2>/dev/null)"
  fi

  # =========================================================================
  # B. Provider-native compatibility: streaming, count_tokens, provider errors
  # =========================================================================
  echo "  -- 42.B: provider-native compatibility --"
  local shdr="$dir/stream_headers.txt" sbody="$dir/stream_body.sse"
  code="$(smoke_gw_post_anthropic "$base" x-api-key "$agent_key" "$(smoke_body_anthropic true)" "$shdr" "$sbody" \
    "$SMOKE_PATH_GW_ANTHROPIC_MESSAGES" -H "Accept: text/event-stream" -N)"
  if ! assert_pass "B: streaming request (stream:true) → 200" test "$code" = "200"; then
    dump_diag_file "stream body" "$sbody" 40
    dump_diag_file "stream headers" "$shdr"
    dump_diag_file "section 42 serve log" "$gw_log" 50
  fi
  assert_pass "B: streamed response is text/event-stream" \
    grep -qi "^content-type:.*text/event-stream" "$shdr"
  assert_pass "B: stream carries Anthropic's lifecycle events (message_start, content_block_delta, message_delta, message_stop)" \
    bash -c 'grep -q "^event: message_start" "$1" && grep -q "^event: content_block_delta" "$1" && grep -q "^event: message_delta" "$1" && grep -q "^event: message_stop" "$1"' _ "$sbody"
  assert_pass "B: message_start names the requested model" \
    bash -c 'grep -A1 "^event: message_start" "$1" | grep "^data:" | sed "s/^data: *//" | jq -e --arg m "$2" ".message.model | tostring | startswith(\$m)"' _ "$sbody" "$model"
  assert_fail "B: stream never contains a provider key (sk-ant-)" grep -q "sk-ant-" "$sbody"
  # The final message_delta carries cumulative output_tokens: Talon settles the
  # stream's usage from it (and input tokens from message_start).
  local stream_out_tok
  stream_out_tok="$(grep -A1 "^event: message_delta" "$sbody" | grep "^data:" | tail -1 | sed 's/^data: *//' | jq -r '.usage.output_tokens // 0' 2>/dev/null || echo 0)"
  sleep 1
  local ev_s; ev_s="$(smoke_get_latest_evidence "$base" "$admin_key" 2>/dev/null)" || ev_s=""
  if [[ -n "$ev_s" ]] && jq -e --argjson o "${stream_out_tok:-0}" '.policy_decision.allowed == true and .execution.tokens.input > 0 and .execution.tokens.output == $o and .execution.cost > 0' <<< "$ev_s" &>/dev/null; then
    echo "  ✓  B: streamed usage settled in evidence (input > 0, output = ${stream_out_tok} as streamed, cost > 0)"
    record_pass
  else
    log_failure "B: streamed usage should be settled in evidence from message_start/message_delta" "stream_output_tokens=$stream_out_tok evidence=$(jq -c '{allowed:.policy_decision.allowed, tokens:.execution.tokens, cost:.execution.cost, error:.execution.error}' <<< "$ev_s" 2>/dev/null)"
    dump_diag_file "stream body" "$sbody" 40
  fi

  # count_tokens: governed like any request, free at the provider, cost 0 in evidence.
  local chdr="$dir/count_headers.txt" cbody="$dir/count_body.json"
  local count_req; count_req="$(printf '{"model":"%s","messages":[{"role":"user","content":"Reply with the single word PONG"}]}' "$model")"
  code="$(smoke_gw_post_anthropic "$base" x-api-key "$agent_key" "$count_req" "$chdr" "$cbody" "$SMOKE_PATH_GW_ANTHROPIC_COUNT_TOKENS")"
  if ! assert_pass "B: POST /v1/messages/count_tokens through the gateway → 200" test "$code" = "200"; then
    dump_diag_json "count_tokens response body" "$(cat "$cbody" 2>/dev/null || echo '(missing)')"
  fi
  assert_pass "B: count_tokens answers with input_tokens > 0" jq -e '.input_tokens > 0' "$cbody"
  sleep 1
  local ev_c; ev_c="$(smoke_get_latest_evidence "$base" "$admin_key" 2>/dev/null)" || ev_c=""
  if [[ -n "$ev_c" ]] && jq -e '.invocation_type == "gateway_count_tokens" and .execution.cost == 0 and .policy_decision.allowed == true' <<< "$ev_c" &>/dev/null; then
    echo "  ✓  B: count_tokens evidenced as gateway_count_tokens at cost 0"
    record_pass
  else
    log_failure "B: count_tokens should be evidenced as gateway_count_tokens at cost 0" "evidence=$(jq -c '{invocation_type, cost:.execution.cost, allowed:.policy_decision.allowed}' <<< "$ev_c" 2>/dev/null)"
  fi

  # Provider error: a temperature outside the documented 0..1 range fails
  # Anthropic's request validation (400 invalid_request_error) before any
  # generation. (max_tokens 0 is NOT a validation error: the live API answers
  # it with an empty message and stop_reason max_tokens — observed 2026-11-07.)
  # Talon must relay the error status, not report a success, and evidence
  # the failed execution without usage.
  local ehdr="$dir/err_headers.txt" ebody="$dir/err_body.json"
  local err_req; err_req="$(printf '{"model":"%s","max_tokens":24,"temperature":2.0,"messages":[{"role":"user","content":"Reply with the single word PONG"}]}' "$model")"
  code="$(smoke_gw_post_anthropic "$base" x-api-key "$agent_key" "$err_req" "$ehdr" "$ebody")"
  if ! assert_pass "B: provider validation error (temperature out of range) is relayed as HTTP 400, never 200" test "$code" = "400"; then
    dump_diag_kv "section 42 provider error" "http_code=$code"
    dump_diag_json "provider error body" "$(cat "$ebody" 2>/dev/null || echo '(missing)')"
  fi
  assert_pass "B: provider error body is an Anthropic error envelope (type=error with error.type)" \
    jq -e '.type == "error" and (.error.type | type == "string" and length > 0)' "$ebody"
  sleep 1
  local ev_e; ev_e="$(smoke_get_latest_evidence "$base" "$admin_key" 2>/dev/null)" || ev_e=""
  if [[ -n "$ev_e" ]] && jq -e '(((.execution.error // "") | length) > 0 or .status == "failed") and .execution.tokens.output == 0' <<< "$ev_e" &>/dev/null; then
    echo "  ✓  B: provider error evidenced as a failed execution with no output usage"
    record_pass
  else
    log_failure "B: provider error should be evidenced as a failed execution with no output usage" "evidence=$(jq -c '{status, error:.execution.error, tokens:.execution.tokens, allowed:.policy_decision.allowed}' <<< "$ev_e" 2>/dev/null)"
  fi

  # =========================================================================
  # C. Policy enforcement: Talon denies before the provider is addressed
  # =========================================================================
  echo "  -- 42.C: policy enforcement --"
  local whdr="$dir/wrong_headers.txt" wbody="$dir/wrong_body.json"
  code="$(smoke_gw_post_anthropic "$base" x-api-key "wrong-agent-key" "$(smoke_body_anthropic false)" "$whdr" "$wbody")"
  assert_pass "C: unknown agent key → 401" test "$code" = "401"
  assert_pass "C: 401 body is an Anthropic error envelope" jq -e '.type == "error"' "$wbody"

  local dhdr="$dir/deny_headers.txt" dbody="$dir/deny_body.json"
  code="$(smoke_gw_post_anthropic "$base" x-api-key "$agent_key" "$(smoke_body_anthropic false "$SMOKE_ANTHROPIC_DENIED_MODEL")" "$dhdr" "$dbody")"
  if ! assert_pass "C: priced model outside the provider allow list (${SMOKE_ANTHROPIC_DENIED_MODEL}) → 403" test "$code" = "403"; then
    dump_diag_json "deny body" "$(cat "$dbody" 2>/dev/null || echo '(missing)')"
  fi
  assert_pass "C: denial carries Talon's machine code model_not_allowed in the Anthropic envelope" \
    jq -e '.type == "error" and .error.type == "model_not_allowed"' "$dbody"
  sleep 1
  local ev_d; ev_d="$(smoke_get_latest_evidence "$base" "$admin_key" 2>/dev/null)" || ev_d=""
  local d_allowed d_reasons d_model d_out
  d_allowed="$(jq -r '.policy_decision.allowed' <<< "$ev_d" 2>/dev/null)"
  d_reasons="$(jq -r '.policy_decision.reasons // [] | join(",")' <<< "$ev_d" 2>/dev/null)"
  d_model="$(jq -r '.execution.model_used // empty' <<< "$ev_d" 2>/dev/null)"
  d_out="$(jq -r '.execution.tokens.output // 0' <<< "$ev_d" 2>/dev/null)"
  if [[ "$d_allowed" == "false" && "$d_reasons" == *model_not_allowed* && "$d_model" == "$SMOKE_ANTHROPIC_DENIED_MODEL" ]]; then
    echo "  ✓  C: denial attributed to Talon policy in evidence (allowed=false, model_not_allowed, model=${d_model})"
    record_pass
  else
    log_failure "C: denial should be attributed to Talon policy in evidence" "allowed=$d_allowed reasons=$d_reasons model=$d_model"
  fi
  # No fallback, no usage: the denied record has no failover context and no
  # output tokens. (No provider-side counter exists against the real API, so
  # this is Talon's own account, not an independently measured zero.)
  if jq -e '(.failover == null) and (.execution.tokens.output == 0) and (.execution.cost == 0)' <<< "$ev_d" &>/dev/null; then
    echo "  ✓  C: denied request records no failover, no usage and no cost"
    record_pass
  else
    log_failure "C: denied request should record no failover, no usage and no cost" "failover=$(jq -c '.failover' <<< "$ev_d" 2>/dev/null) output_tokens=$d_out cost=$(jq -r '.execution.cost' <<< "$ev_d" 2>/dev/null)"
  fi

  local uhdr="$dir/unpriced_headers.txt" ubody="$dir/unpriced_body.json"
  code="$(smoke_gw_post_anthropic "$base" x-api-key "$agent_key" "$(smoke_body_anthropic false claude-unpriced-smoke-model)" "$uhdr" "$ubody")"
  assert_pass "C: unpriced model under the agent's spending cap → 403" test "$code" = "403"
  assert_pass "C: unpriced-model denial carries pricing_unavailable" jq -e '.error.type == "pricing_unavailable"' "$ubody"

  # =========================================================================
  # D. Evidence and accounting for the successful request (A)
  # =========================================================================
  echo "  -- 42.D: evidence and accounting --"
  if [[ -z "$ev_a" ]] || ! jq -e '.' <<< "$ev_a" &>/dev/null; then
    log_failure "D: no evidence record found for the successful request"
  else
    assert_pass "D: evidence attributes the request to provider anthropic" \
      jq -e '.routing_decision.selected_provider == "anthropic"' <<< "$ev_a"
    assert_pass "D: evidence records the model (${model}) and an allowed policy decision" \
      jq -e --arg m "$model" '(.execution.model_used | startswith($m)) and .policy_decision.allowed == true' <<< "$ev_a"
    assert_pass "D: evidence usage equals the usage the provider reported (input ${in_tok}, output ${out_tok})" \
      jq -e --argjson i "$in_tok" --argjson o "$out_tok" --argjson cr "$cache_read" --argjson cw "$cache_write" \
        '.execution.tokens.input == $i and .execution.tokens.output == $o and ((.execution.tokens.cache_read // 0) == $cr) and ((.execution.tokens.cache_write // 0) == $cw)' <<< "$ev_a"
    assert_pass "D: evidence is signed (HMAC signature present)" \
      jq -e '(.signature | type == "string" and length > 0)' <<< "$ev_a"
    # Cost = usage × the model's rates in pricing/models.yaml (the scaffold's
    # pricing file is the embedded default; the rates are read from it, not
    # hard-coded here, so a price change does not break the smoke).
    local pricing_file="$dir/pricing/models.yaml"
    local rate_in rate_out rate_cr rate_cw
    rate_in="$(smoke42_rate "$pricing_file" "$model" input_per_1m)"
    rate_out="$(smoke42_rate "$pricing_file" "$model" output_per_1m)"
    rate_cr="$(smoke42_rate "$pricing_file" "$model" cache_read_per_1m)"
    rate_cw="$(smoke42_rate "$pricing_file" "$model" cache_write_per_1m)"
    local ev_cost; ev_cost="$(jq -r '.execution.cost' <<< "$ev_a")"
    if [[ -n "$rate_in" && -n "$rate_out" ]]; then
      local cost_ok
      cost_ok="$(awk -v c="$ev_cost" -v i="$in_tok" -v o="$out_tok" -v cr="$cache_read" -v cw="$cache_write" \
        -v ri="$rate_in" -v ro="$rate_out" -v rcr="${rate_cr:-0}" -v rcw="${rate_cw:-0}" \
        'BEGIN { want = (i*ri + o*ro + cr*rcr + cw*rcw) / 1000000; d = c - want; if (d < 0) d = -d; printf "%s %.9f", (d <= 0.0000001 && c > 0) ? "ok" : "mismatch", want }')"
      if [[ "$cost_ok" == ok* ]]; then
        echo "  ✓  D: evidence cost ${ev_cost} matches usage × pricing table (expected ${cost_ok#ok })"
        record_pass
      else
        log_failure "D: evidence cost should equal usage × pricing table" "cost=$ev_cost expected=${cost_ok#mismatch } in=$in_tok out=$out_tok cache_read=$cache_read cache_write=$cache_write rates=$rate_in/$rate_out/$rate_cr/$rate_cw"
      fi
    else
      log_failure "D: pricing table has no rates for ${model} (needed to check the evidence cost)" "pricing_file=$pricing_file"
    fi
    assert_pass "D: evidence states the pricing basis as known" jq -e '.execution.pricing_known == true' <<< "$ev_a"
    if [[ -n "$ev_a_id" ]]; then
      assert_pass "D: talon audit verify accepts the record (${ev_a_id})" run_talon audit verify "$ev_a_id"
      assert_pass "D: talon audit verify reports it valid" \
        bash -c 'grep -qi valid <<< "$(env TALON_DATA_DIR="$1" talon audit verify "$2" 2>/dev/null)"' _ "$TALON_DATA_DIR" "$ev_a_id"
    else
      log_failure "D: evidence record for the successful request has no id"
    fi
  fi
  assert_pass "D: talon costs --by-provider lists anthropic" \
    bash -c 'env TALON_DATA_DIR="$1" talon costs --by-provider 2>/dev/null | grep -qi anthropic' _ "$TALON_DATA_DIR"

  stop_owned_talon_server "$gw_pid" "$port" || true
  cd "$REPO_ROOT" || true
}

# smoke42_rate <pricing.yaml> <model> <field>: the model's per-1M rate under
# providers.anthropic.models in the YAML Talon wrote at init (plain-text read;
# yq is optional in the smoke environment).
smoke42_rate() {
  local file="$1" model="$2" field="$3"
  [[ -f "$file" ]] || return 0
  awk -v m="$model" -v f="$field" '
    $1 == "anthropic:" { in_prov = 1; next }
    in_prov && /^  [a-z]/ && $1 != "anthropic:" { in_prov = 0 }
    in_prov && $1 == m ":" { in_model = 1; next }
    in_model && /^      [a-z]/ { in_model = 0 }
    in_model && $1 == f ":" { print $2; exit }
  ' "$file" 2>/dev/null
}
