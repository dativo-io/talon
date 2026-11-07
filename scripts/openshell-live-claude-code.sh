# shellcheck shell=bash
# Real-Claude-Code lane of the OpenShell live smoke (#528). Sourced by
# scripts/openshell-live.sh when TALON_OPENSHELL_LANE=claude-code, after the
# shared setup (verified OpenShell release, Talon with the middleware
# listener, the real gateway with Talon registered over TLS, the mock
# provider, the Anthropic provider profile and the sandbox policy).
#
#   claude (REAL pinned executable, in the REAL sandbox)
#     --POST /v1/messages (x-api-key = OpenShell placeholder, stream:true)-->
#     OpenShell supervisor (network admission: host + port + binary)
#       --gRPC EvaluateHttpRequest (gateway-signed JWT)--> talon PRE_CREDENTIALS
#       <-- ALLOW / transformed body / DENY --
#       --credential injection (x-api-key := provider secret)--> Anthropic-shaped provider
#       <-- SSE --> talon PRE_RETURN (held, inspected, usage settled) --> claude
#
# Nothing in the sandbox is a credential: ANTHROPIC_API_KEY is OpenShell's
# placeholder, there is no Talon agent key, no reviewer credential, no
# provider key. In the deterministic mode ANTHROPIC_BASE_URL names the mock
# PROVIDER endpoint (the host the sandbox policy admits with the talon
# middleware bound) — never Talon's /v1/proxy: Talon is reached only through
# OpenShell's hook. In the opt-in real-provider mode
# (TALON_CLAUDE_LIVE_ANTHROPIC=1) the client dials api.anthropic.com as it
# does by default, the key lives only in OpenShell's provider store, and the
# assertions that read the mock's records are replaced by Talon's signed
# records (the real provider's request count is not observable).
#
# Cases (C01–C03 of the ratified Full Demo contract, producer side):
#   CC0 fixture: the pinned executable is in the sandbox at the policy's
#       path, reports its version, its sha256 is the release manifest's,
#       and its HOME is writable
#   CC1 allowed turn (C01): one /v1/messages call reached the provider,
#       streamed (SSE), with the user agent of the real executable, under the
#       OpenShell-injected x-api-key; claude printed the answer; Talon's
#       record verifies the sandbox identity, delegated_expected
#   CC2 PII in the prompt: the provider received Talon's redacted body
#       (real-provider mode: the decision record says it was redacted)
#   CC3 denied model (C02): Talon DENY before credentials; claude fails with
#       the middleware denial; provider count unchanged — including the
#       client's own retry behaviour (none observed for a 403)
#   CC4 unbound sandbox (C02 identity): a second real sandbox, not bound to
#       any use case, is denied workload_identity_unbound; count unchanged
#   CC5 Talon unavailable: OpenShell fails closed (middleware_failed); count
#       unchanged; the sandbox's own request never reached a provider
#   CC6 direct bypass: curl (not an admitted binary) to the provider, and
#       claude to a provider port the policy does not admit — both refused
#       by OpenShell network policy; the shadow provider saw zero calls
#       (OpenShell containment, imported as external_asserted at most)
#   CC7 credential isolation (C03): the sandbox env holds the placeholder,
#       not the secret; the provider saw the secret; Talon's state, logs and
#       export hold neither the secret nor any Talon key
#   CC8 count_tokens: observed count with this client in this flow
#       (documented; Talon's delegated count_tokens handling is proven by
#       the fixture lanes)
#   CC9 truncated stream (mock only): the provider closes mid-stream; claude
#       reports an error; Talon's settlement for that exchange does not
#       claim a completed response
#   CC10 streamed response PII: OpenShell holds each STREAM_BYTES unit;
#        talon withholds the stream from the unit carrying PII on
#        (preventive_per_unit); the client never prints the value
#   evidence: decision + settlement records with the provider's actual usage
#       from the SSE, verified offline; run facts printed
#
# Every assertion is against the real runtime's observable state: the mock
# provider's counters and records (independent of Talon), claude's exit
# status and JSON result, OpenShell's error envelopes, and Talon's signed
# evidence. Nothing is asserted from a Talon decision alone.

mock_mode() { [[ "${LIVE_ANTHROPIC:-0}" != "1" ]]; }
MODE_LABEL="deterministic (mock Anthropic provider, no provider key)"
mock_mode || MODE_LABEL="REAL provider (api.anthropic.com; key in OpenShell's provider store only; opt-in, spends)"

# ---------------------------------------------------------------- client invocations
# claude_turn sandbox prompt [extra --env args...] -> prints "<exit code>\n<stdout json>" (stderr to the setup log)
# The real executable in print mode: one turn, JSON result, no session
# persistence (the sandbox filesystem is not the product), hooks and MCP
# off (C04/C05 belong to the Full Demo harness), nonessential traffic off
# (telemetry/update checks would only be denied by the sandbox policy and
# clutter the OCSF log). The mock mode points the client at the mock
# provider endpoint; the real-provider mode leaves the client's default.
# Observed on the real runtime (PR #531 run 42385751830): when a stream is
# cut or withheld, claude-cli/2.1.319 retries the streaming request about
# ten times with backoff over ~3 minutes, then retries WITHOUT streaming;
# the turn timeout must outlast that, or the client keeps running in the
# sandbox after the harness moved on and its late calls land in the next
# case's counters.
CLAUDE_BASE_URL_ENV=()
mock_mode && CLAUDE_BASE_URL_ENV=(--env "ANTHROPIC_BASE_URL=http://host.openshell.internal:$MOCK_PORT")
claude_turn() {
  local sb="$1" prompt="$2"; shift 2
  local out code
  set +e
  out="$("${CLI[@]}" sandbox exec --name "$sb" --no-tty --no-login-shell --timeout 360 \
    "${CLAUDE_BASE_URL_ENV[@]}" \
    --env "HOME=$CLAUDE_HOME" --env "CLAUDE_CONFIG_DIR=$CLAUDE_HOME/.claude" \
    --env "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1" --env "DISABLE_TELEMETRY=1" --env "DISABLE_AUTOUPDATER=1" --env "CI=1" \
    --env "TALON_PROMPT=$prompt" "$@" -- \
    "$SH_BIN" -c "cd \"$CLAUDE_HOME\" && $CLAUDE_BIN -p \"\$TALON_PROMPT\" --output-format json --model \"\${TALON_MODEL:-$CLAUDE_MODEL}\" --bare --no-session-persistence --max-turns 1 --strict-mcp-config </dev/null" 2>>"$LOGS/setup.log")"
  code=$?
  set -e
  printf '%s\n%s\n' "$code" "$out"
}
turn_code() { head -n1 <<<"$1"; }
turn_json() { tail -n +2 <<<"$1"; }
turn_field() { jq -r "($2) | if . == null then \"\" else tostring end" <<<"$(turn_json "$1")" 2>/dev/null || true; }
# Talon's signed records of the bound sandbox, read through the export
# (the real-provider mode's only view of what reached the provider).
talon_export() { ( cd "$TALON_HOME" && "$TALON" audit export --format signed-json 2>>"$LOGS/setup.log" ); }
talon_count() { talon_export | jq "[.records[] | select($1)] | length"; }

# ---------------------------------------------------------------- CC0 — fixture: the pinned executable, in the real sandbox
# home_writable is the first candidate the sandbox user can create
# $HOME/.claude in (none otherwise); claude_turn uses exactly that one.
FIXTURE="$(sandbox_sh "$SANDBOX_A" "home=none; for d in $CLAUDE_HOME_CANDIDATES; do if mkdir -p \"\$d/.claude\" 2>/dev/null && touch \"\$d/.claude/.probe\" 2>/dev/null; then home=\"\$d\"; break; fi; done; printf 'claude=%s\nsh=%s\ncurl=%s\nuser=%s\nhome_writable=%s\n' \"\$(command -v claude || echo missing)\" \"\$(command -v sh || echo missing)\" \"\$(command -v curl || echo missing)\" \"\$(id -u 2>/dev/null || echo unknown)\" \"\$home\"; $CLAUDE_BIN --version 2>/dev/null | head -n1; sha256sum $CLAUDE_BIN | cut -d' ' -f1" || true)"
printf '%s\n' "$FIXTURE" >>"$LOGS/setup.log"
DETECTED_CLAUDE="$(sed -n 's/^claude=//p' <<<"$FIXTURE" | head -n1)"
DETECTED_CURL="$(sed -n 's/^curl=//p' <<<"$FIXTURE" | head -n1)"
HOME_WRITABLE="$(sed -n 's/^home_writable=//p' <<<"$FIXTURE" | head -n1)"
CLAUDE_VERSION_LINE="$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$FIXTURE" | head -n1 || true)"
CLAUDE_SHA_IN_SANDBOX="$(grep -E '^[0-9a-f]{64}$' <<<"$FIXTURE" | head -n1 || true)"
[[ "$DETECTED_CLAUDE" == "$CLAUDE_BIN" ]] || die "CC0 workload fixture: expected claude at $CLAUDE_BIN, image $WORKLOAD_IMAGE reported '${DETECTED_CLAUDE:-missing}' (sandbox output: $FIXTURE)"
[[ "$CLAUDE_VERSION_LINE" == "$CLAUDE_CODE_VERSION"* ]] || die "CC0 workload fixture: claude --version in the sandbox is '${CLAUDE_VERSION_LINE:-empty}', want $CLAUDE_CODE_VERSION"
[[ "$CLAUDE_SHA_IN_SANDBOX" == "$CLAUDE_CODE_SHA256" ]] || die "CC0 workload fixture: sha256 of $CLAUDE_BIN in the sandbox is '${CLAUDE_SHA_IN_SANDBOX:-empty}', want the release manifest's $CLAUDE_CODE_SHA256"
[[ "$DETECTED_CURL" == "$CURL_BIN" ]] || die "CC0 workload fixture: expected curl at $CURL_BIN for the bypass probe, image reported '${DETECTED_CURL:-missing}'"
[[ -n "$HOME_WRITABLE" && "$HOME_WRITABLE" != "none" ]] || die "CC0 workload fixture: none of [$CLAUDE_HOME_CANDIDATES] is writable by the sandbox user (Claude Code keeps its config under HOME); set TALON_OPENSHELL_CLAUDE_HOME to a tree the sandbox user may write (sandbox output: $FIXTURE)"
CLAUDE_HOME="$HOME_WRITABLE"
pass "CC0 fixture: real Claude Code $CLAUDE_VERSION_LINE at $CLAUDE_BIN in the real sandbox, sha256 = release manifest pin, HOME $CLAUDE_HOME writable (candidates: $CLAUDE_HOME_CANDIDATES)"

# Bind the REAL sandbox identity to the Talon use case (agent reload, no restart).
python3 - "$AGENT_FILE" "$AGENT" "$SANDBOX_A_ID" <<'PY' || die "binding edit"
import sys
p, agent, sid = sys.argv[1:]
s = open(p).read()
key = '  key:\n    secret_name: "%s-talon-key"\n' % agent
assert key in s, "scaffold key block"
s = s.replace(key, key + '  workload_identity:\n    bindings:\n      - runtime: openshell\n        subject: "spiffe://openshell/sandbox/%s"\n' % sid, 1)
open(p, "w").write(s)
PY
for ((i=0; i<40; i++)); do
  grep -q "agent_config_reload_activated" "$LOGS/talon-serve.log" && break
  sleep 0.5
done
grep -q "agent_config_reload_activated" "$LOGS/talon-serve.log" || die "talon did not activate the binding generation"
SUBJECT="spiffe://openshell/sandbox/$SANDBOX_A_ID"; ISSUER="openshell-gateway:$GATEWAY_ID"
DELEGATED_SEL=".invocation_type==\"gateway\" and .enforcement.provenance==\"delegated_expected\" and .workload_identity.subject==\"$SUBJECT\""

# ---------------------------------------------------------------- CC1 — allowed turn through the delegated path (C01)
OUT="$(claude_turn "$SANDBOX_A" "Reply with exactly the text the assistant is given.")"
CODE="$(turn_code "$OUT")"
[[ "$CODE" == "0" ]] || die "CC1 claude exited $CODE: $(turn_json "$OUT")"
[[ "$(turn_field "$OUT" .is_error)" == "false" && "$(turn_field "$OUT" .subtype)" == "success" ]] || die "CC1 claude result is not a success: $(turn_json "$OUT")"
CC1_QUERY=""
if mock_mode; then
  [[ "$(turn_field "$OUT" .result)" == "mock anthropic completion 1" ]] || die "CC1 claude did not print the mock provider's streamed answer: $(turn_json "$OUT")"
  [[ "$(provider_calls)" == "1" ]] || die "CC1 provider calls = $(provider_calls), want exactly 1"
  [[ "$(provider_record 0 path)" == "/v1/messages" ]] || die "CC1 provider path: $(provider_record 0 path)"
  [[ "$(provider_record 0 method)" == "POST" ]] || die "CC1 provider method: $(provider_record 0 method)"
  [[ "$(provider_record 0 stream)" == "true" ]] || die "CC1 the client did not stream (stream:true absent)"
  [[ "$(provider_record 0 x_api_key)" == "$PROVIDER_SECRET" ]] || die "CC1 provider did not receive the OpenShell-injected x-api-key"
  [[ -z "$(provider_record 0 authorization)" || "$(provider_record 0 authorization)" == "null" ]] || die "CC1 unexpected Authorization header at the provider (the Anthropic family uses x-api-key)"
  grep -q "claude-cli/$CLAUDE_CODE_VERSION" <<<"$(provider_record 0 user_agent)" || die "CC1 provider user agent is not the pinned executable: $(provider_record 0 user_agent)"
  grep -q "\"model\":\"$CLAUDE_MODEL\"" <<<"$(provider_record 0 body | tr -d ' ')" || die "CC1 provider body model: $(provider_record 0 body | head -c 300)"
  CC1_QUERY="$(provider_record 0 query)"
  pass "CC1 allowed (C01): real claude → OpenShell → talon ALLOW → OpenShell injected x-api-key → provider /v1/messages${CC1_QUERY:+?$CC1_QUERY} (stream, ua claude-cli/$CLAUDE_CODE_VERSION); claude printed the streamed answer"
else
  [[ -n "$(turn_field "$OUT" .result)" ]] || die "CC1 claude printed no answer: $(turn_json "$OUT")"
  CC1_DECISIONS="$(talon_count "$DELEGATED_SEL and .policy_decision.allowed==true and .execution.model_used==\"$CLAUDE_MODEL\"")"
  [[ "${CC1_DECISIONS:-0}" -ge 1 ]] || die "CC1 Talon recorded no allowed delegated decision for $SUBJECT / $CLAUDE_MODEL"
  pass "CC1 allowed (C01, real provider): real claude → OpenShell → talon ALLOW → OpenShell injected the key → api.anthropic.com; claude answered ($(turn_field "$OUT" .usage.input_tokens) in / $(turn_field "$OUT" .usage.output_tokens) out tokens by the client's own count)"
fi

# ---------------------------------------------------------------- CC2 — PII in the prompt reaches the provider redacted
PII_EMAIL="jane.doe@example.com"
OUT="$(claude_turn "$SANDBOX_A" "Draft a refund note for $PII_EMAIL about order 42.")"
[[ "$(turn_code "$OUT")" == "0" ]] || die "CC2 claude exited $(turn_code "$OUT"): $(turn_json "$OUT")"
if mock_mode; then
  [[ "$(provider_calls)" == "2" ]] || die "CC2 provider calls = $(provider_calls), want 2"
  FORWARDED="$(provider_record 1 body)"
  grep -qF "$PII_EMAIL" <<<"$FORWARDED" && die "CC2 provider received the original sensitive value"
  grep -q "order 42" <<<"$FORWARDED" || die "CC2 forwarded body is not the transformed prompt: $(head -c 400 <<<"$FORWARDED")"
  pass "CC2 PII redacted: the provider received Talon's transformed Anthropic body, never $PII_EMAIL"
else
  REDACTED="$(talon_count "$DELEGATED_SEL and .classification.pii_redacted==true")"
  [[ "${REDACTED:-0}" -ge 1 ]] || die "CC2 Talon recorded no redacted delegated decision for the PII prompt"
  pass "CC2 PII redacted (real provider): Talon's signed decision records the redaction; the provider's copy is not observable here"
fi

# ---------------------------------------------------------------- CC3 — denied model: Talon DENY before credentials (C02)
OUT="$(claude_turn "$SANDBOX_A" "hi" --env "TALON_MODEL=$CLAUDE_BLOCKED_MODEL")"
CODE="$(turn_code "$OUT")"
[[ "$CODE" != "0" ]] || die "CC3 claude succeeded on a model Talon denies: $(turn_json "$OUT")"
[[ "$(turn_field "$OUT" .is_error)" == "true" || "$(turn_field "$OUT" .terminal_reason)" == "api_error" ]] || die "CC3 claude did not report an API error for the denial: $(turn_json "$OUT")"
grep -qE 'middleware_denied|model_not_allowed|403' <<<"$(turn_json "$OUT")" || log "CC3 note: claude's JSON does not echo the denial body (exit $CODE, terminal_reason=$(turn_field "$OUT" .terminal_reason)); the provider count below is the proof"
if mock_mode; then
  [[ "$(provider_calls)" == "2" ]] || die "CC3 provider was called on a Talon DENY (calls=$(provider_calls)); the client's retries, if any, must also have been denied"
fi
DENIED_SO_FAR="$(talon_count "$DELEGATED_SEL and .policy_decision.allowed==false and .execution.model_used==\"$CLAUDE_BLOCKED_MODEL\"")"
[[ "${DENIED_SO_FAR:-0}" -ge 1 ]] || die "CC3 Talon recorded no DENY for $CLAUDE_BLOCKED_MODEL"
pass "CC3 denied model (C02): talon DENY at PRE_CREDENTIALS ($DENIED_SO_FAR record(s)), claude exit $CODE$(mock_mode && echo ', provider count unchanged across the client'"'"'s retry behaviour')"

# ---------------------------------------------------------------- CC4 — unbound sandbox identity (C02): a second real sandbox, real claude
create_sandbox "$SANDBOX_B"
RECORDS_BEFORE="$(talon_count 'true')"
OUT="$(claude_turn "$SANDBOX_B" "hi")"
CODE="$(turn_code "$OUT")"
[[ "$CODE" != "0" ]] || die "CC4 an unbound sandbox completed a model call: $(turn_json "$OUT")"
if mock_mode; then [[ "$(provider_calls)" == "2" ]] || die "CC4 provider was called for an unbound sandbox"; fi
[[ "$(talon_count 'true')" == "$RECORDS_BEFORE" ]] || die "CC4 an unbound sandbox produced a Talon record"
# OpenShell's denial for this sandbox is in the gateway's OCSF log; Talon
# writes no record for an unbound identity (nothing was evaluated).
pass "CC4 unbound sandbox: real claude denied (exit $CODE), no Talon record$(mock_mode && echo ', provider count unchanged')"

# ---------------------------------------------------------------- CC5 — Talon unavailable → OpenShell fails closed
kill "$TALON_PID"; wait "$TALON_PID" 2>/dev/null || true; TALON_PID=""
OUT="$(claude_turn "$SANDBOX_A" "hi")"
CODE="$(turn_code "$OUT")"
[[ "$CODE" != "0" ]] || die "CC5 claude succeeded while talon was down: $(turn_json "$OUT")"
if mock_mode; then [[ "$(provider_calls)" == "2" ]] || die "CC5 provider was reached while talon was unavailable"; fi
start_talon
pass "CC5 talon unavailable: OpenShell failed closed (claude exit $CODE)$(mock_mode && echo ', provider count unchanged') — enforced by OpenShell, not Talon"

# ---------------------------------------------------------------- CC6 — direct bypass refused by OpenShell (containment, not Talon)
# (a) a binary the policy does not admit to the provider (curl) on the admitted endpoint
PROVIDER_SCHEME="http"; [[ "$PROVIDER_PORT" == "443" ]] && PROVIDER_SCHEME="https"
OUT="$("${CLI[@]}" sandbox exec --name "$SANDBOX_A" --no-tty --no-login-shell --timeout 60 -- "$SH_BIN" -c 'out=$('"$CURL_BIN"' -sS --max-time 20 -w "\n__CODE__%{http_code}" -X POST "'"$PROVIDER_SCHEME"'://'"$PROVIDER_HOST"':'"$PROVIDER_PORT"'/v1/messages" -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" --data "{\"model\":\"'"$CLAUDE_MODEL"'\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"bypass\"}]}" 2>&1); echo "${out##*__CODE__}"; printf "%s\n" "${out%__CODE__*}"' 2>>"$LOGS/setup.log" || true)"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" != "200" ]] || die "CC6a curl (not an admitted binary) reached the provider: $OUT"
if mock_mode; then [[ "$(provider_calls)" == "2" ]] || die "CC6a provider count changed on a non-admitted binary's call"; fi
# (b) the real client to a provider port the policy does not admit (the shadow provider)
OUT="$(claude_turn "$SANDBOX_A" "hi" --env "ANTHROPIC_BASE_URL=http://host.openshell.internal:$SHADOW_PORT")"
CODE="$(turn_code "$OUT")"
[[ "$CODE" != "0" ]] || die "CC6b claude reached a provider endpoint outside the policy: $(turn_json "$OUT")"
[[ "$(shadow_calls)" == "0" ]] || die "CC6b the shadow provider received $(shadow_calls) call(s) from the sandbox"
pass "CC6 direct bypass: non-admitted binary (code ${CODE:-none}) and non-admitted endpoint both refused by OpenShell network policy; shadow provider calls = 0 (OpenShell containment; Talon claims nothing here)"

# ---------------------------------------------------------------- CC7 — credential isolation (C03)
SANDBOX_ENV="$(sandbox_sh "$SANDBOX_A" 'env' || true)"
# Only variable NAMES go to the collected log; values stay in the harness.
printf 'sandbox env names: %s\n' "$(cut -d= -f1 <<<"$SANDBOX_ENV" | sort | tr '\n' ' ')" >>"$LOGS/setup.log"
grep -q '^ANTHROPIC_API_KEY=' <<<"$SANDBOX_ENV" || die "CC7 the sandbox has no ANTHROPIC_API_KEY placeholder (the provider was attached with --provider)"
grep -qF "$PROVIDER_SECRET" <<<"$SANDBOX_ENV" && die "CC7 the REAL provider secret is visible in the sandbox environment"
for needle in "$TALON_SECRETS_KEY" "$TALON_SIGNING_KEY" "$TALON_ADMIN_KEY" "$LEAD_KEY" "$TALON_VAULT_DECOY" "talon_appr_cred_"; do
  grep -qF -- "$needle" <<<"$SANDBOX_ENV" && die "CC7 Talon material ($(printf '%s' "$needle" | cut -c1-10)…) is visible in the sandbox environment"
done
grep -qE '^(TALON_[A-Z_]*KEY|OPENAI_API_KEY)=' <<<"$SANDBOX_ENV" && die "CC7 a Talon or foreign provider key variable is set in the sandbox"
if mock_mode; then [[ "$(provider_record 0 x_api_key)" == "$PROVIDER_SECRET" ]] || die "CC7 the provider did not see the injected secret"; fi
if grep -rqF "$PROVIDER_SECRET" "$TALON_HOME" "$LOGS/talon-serve.log" 2>/dev/null; then die "CC7 provider secret found in Talon state or logs"; fi
pass "CC7 credential isolation (C03): sandbox env holds the OpenShell placeholder only; $(mock_mode && echo 'the provider saw the injected secret; ')Talon never held it; no Talon key, reviewer credential or vault value in the sandbox"

# ---------------------------------------------------------------- CC8 — count_tokens: observed with this client
if mock_mode; then
  COUNT_TOKENS_CALLS="$(provider_state | jq '[.records[] | select(.path | endswith("/count_tokens"))] | length')"
else
  COUNT_TOKENS_CALLS="$(talon_count '.invocation_type=="gateway_count_tokens"')"
fi
if [[ "$COUNT_TOKENS_CALLS" == "0" ]]; then
  log "CC8 count_tokens: claude-cli/$CLAUDE_CODE_VERSION emitted no /v1/messages/count_tokens call in this flow (print mode, single turn); Talon's delegated count_tokens handling is proven by TestE2E_OpenShell_DelegatedAnthropicMessages and TestDelegatedResponse_CountTokensSettlesAtZero, not by this client"
else
  log "CC8 count_tokens: $COUNT_TOKENS_CALLS count_tokens call(s) governed (cost 0)"
fi
pass "CC8 count_tokens observed: $COUNT_TOKENS_CALLS call(s) (documented, see log)"

# ---------------------------------------------------------------- CC9 — truncated stream: no invented success (mock only)
CALLS_AFTER_TRUNCATED="n/a"
if mock_mode; then
  OUT="$(claude_turn "$SANDBOX_A" "hi" --env "ANTHROPIC_CUSTOM_HEADERS=X-Mock-Scenario: truncated-stream")"
  CODE="$(turn_code "$OUT")"
  CALLS_AFTER_TRUNCATED="$(provider_calls)"
  [[ "$CALLS_AFTER_TRUNCATED" -ge 3 ]] || die "CC9 the truncated-stream request never reached the provider (calls=$CALLS_AFTER_TRUNCATED)"
  [[ "$(turn_field "$OUT" .result)" != "mock anthropic completion 3" ]] || die "CC9 claude reported the full answer of a stream the provider cut short"
  # The client is expected to RECOVER (observed: ~10 stream retries, then a
  # non-streaming request answered in full); CC9 does not claim it fails.
  CC9_STREAM_RETRIES="$(provider_state | jq '[.records[] | select(.scenario=="truncated-stream" and .stream==true)] | length')"
  CC9_FALLBACK="$(provider_state | jq '[.records[] | select(.scenario=="truncated-stream" and .stream==false)] | length')"
  log "CC9 truncated stream: claude exit $CODE, is_error=$(turn_field "$OUT" .is_error), provider calls now $CALLS_AFTER_TRUNCATED ($CC9_STREAM_RETRIES streaming attempts, $CC9_FALLBACK non-streaming fallback(s); each a fresh Talon decision)"
  pass "CC9 truncated stream: the client never reported the cut stream's answer; it recovered through its own non-streaming fallback (exit $CODE, $CC9_STREAM_RETRIES stream attempts, $CC9_FALLBACK fallback); provider calls $CALLS_AFTER_TRUNCATED — the lane's claim is the settlement property, not a client failure"
else
  log "CC9 truncated stream: not exercised against the real provider (mock scenario)"
fi

# ---------------------------------------------------------------- CC10 — streamed response carrying PII: withheld unit by unit (mock only)
# OpenShell v0.1.3 never offers WHOLE_BODY_BYTES for text/event-stream, so
# under the redact policy Talon inspects each STREAM_BYTES unit while OpenShell
# holds it and withholds the stream from the first unit carrying PII
# (enforcement preventive_per_unit). The client must never print the value.
CC10_RESULT="n/a"
if mock_mode; then
  CALLS_BEFORE_CC10="$(provider_calls)"
  OUT="$(claude_turn "$SANDBOX_A" "hi" --env "ANTHROPIC_CUSTOM_HEADERS=X-Mock-Scenario: response-pii")"
  CODE="$(turn_code "$OUT")"
  grep -qF "$PII_EMAIL" <<<"$(turn_json "$OUT")" && die "CC10 the client printed the provider's PII: the withheld unit reached the sandbox"
  [[ "$(provider_calls)" -gt "$CALLS_BEFORE_CC10" ]] || die "CC10 the response-pii request never reached the provider"
  WITHHELD="$(talon_count '.invocation_type=="gateway_response" and .policy_decision.allowed==false and .classification.output_pii_detected==true and .classification.response_scan.enforcement=="preventive_per_unit" and (.gateway_annotations|index("stream_unit_guarded")!=null)')"
  [[ "${WITHHELD:-0}" -ge 1 ]] || die "CC10 Talon recorded no withheld (preventive_per_unit, output_pii_detected, blocked) settlement: $(talon_export | jq -c '[.records[] | select(.invocation_type=="gateway_response")] | map({allowed: .policy_decision.allowed, scan: .classification.response_scan, annotations: .gateway_annotations})' | head -c 1200)"
  CC10_FALLBACK_REDACTED="$(talon_count '.invocation_type=="gateway_response" and .policy_decision.allowed==true and .classification.output_pii_detected==true and .classification.response_scan.enforcement=="preventive"')"
  CC10_RESULT="withheld (claude exit $CODE, is_error=$(turn_field "$OUT" .is_error); $WITHHELD withheld per-unit settlement(s); the client's non-streaming fallback: $CC10_FALLBACK_REDACTED whole-body redacted settlement(s))"
  pass "CC10 streamed response PII: OpenShell held each unit, talon withheld the stream from the unit carrying $PII_EMAIL on; the client never printed it (exit $CODE)"
else
  log "CC10 streamed response PII: not exercised against the real provider (mock scenario)"
fi

# ---------------------------------------------------------------- evidence
EXPORT="$WORK/export.json"
talon_export >"$EXPORT" || die "talon audit export"
DELEGATED="$(jq --arg iss "$ISSUER" --arg sub "$SUBJECT" '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .enforcement.mechanism=="delegate" and .enforcement.boundary=="external_runtime" and .enforcement.decision_authority=="talon" and .enforcement.decision_returned_via=="openshell_middleware" and .workload_identity.status=="verified" and .workload_identity.runtime=="openshell" and .workload_identity.issuer==$iss and .workload_identity.subject==$sub and .upstream_auth_mode=="external_runtime")] | length' "$EXPORT")"
[[ "${DELEGATED:-0}" -ge 3 ]] || die "expected >=3 delegated_expected decision records verified for $ISSUER / $SUBJECT, found ${DELEGATED:-0}"
ANTHROPIC_RECORDS="$(jq --arg m "$CLAUDE_MODEL" '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .routing_decision.selected_provider=="anthropic" and .execution.model_used==$m)] | length' "$EXPORT")"
[[ "${ANTHROPIC_RECORDS:-0}" -ge 2 ]] || die "expected >=2 delegated decisions for provider anthropic model $CLAUDE_MODEL, found ${ANTHROPIC_RECORDS:-0} (seen: $(jq -c '[.records[] | select(.invocation_type=="gateway")] | map({provider: .routing_decision.selected_provider, model: .execution.model_used}) | unique' "$EXPORT"))"
DENIED="$(jq --arg m "$CLAUDE_BLOCKED_MODEL" '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .policy_decision.allowed==false and .execution.model_used==$m)] | length' "$EXPORT")"
[[ "${DENIED:-0}" -ge 1 ]] || die "expected a delegated DENY record for $CLAUDE_BLOCKED_MODEL, found ${DENIED:-0}"
jq -e '[.records[] | select(.enforcement.provenance=="talon_enforced" and .workload_identity.runtime=="openshell" and (.invocation_type=="gateway" or .invocation_type=="gateway_response" or .invocation_type=="gateway_count_tokens"))] | length == 0' "$EXPORT" >/dev/null || die "a delegated model decision or settlement was labelled talon_enforced"
# Settlement: the allowed turns' responses were SSE; Talon settled each
# under its decision's correlation id with the provider's actual usage
# (mock: 12 in / 3 out from message_start + message_delta), decisions booked 0.
ALLOWED="$(jq '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .policy_decision.allowed==true)] | length' "$EXPORT")"
AWAITING="$(jq '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .policy_decision.allowed==true and .execution.pricing_basis=="awaiting_settlement" and .execution.cost==0)] | length' "$EXPORT")"
[[ "$AWAITING" == "$ALLOWED" && "${ALLOWED:-0}" -ge 2 ]] || die "allowed decisions=$ALLOWED, awaiting_settlement=$AWAITING"
if mock_mode; then
  # Released streams (CC1, CC2): guarded unit by unit (v0.1.3 offers no whole
  # body for SSE), settled allowed with the usage the guard parsed.
  SETTLED_SSE="$(jq '[.records[] | select(.invocation_type=="gateway_response" and .policy_decision.allowed==true and .execution.tokens.input==12 and .execution.tokens.output==3 and .execution.cost>0 and .classification.response_scan.enforcement=="preventive_per_unit" and (.gateway_annotations|index("response_observed")!=null) and (.gateway_annotations|index("stream_unit_guarded")!=null))] | length' "$EXPORT")"
  [[ "${SETTLED_SSE:-0}" -ge 2 ]] || die "expected >=2 released guarded-stream settlements carrying the SSE usage 12/3 priced from the table, found ${SETTLED_SSE:-0}: $(jq -c '[.records[] | select(.invocation_type=="gateway_response")] | map({allowed: .policy_decision.allowed, pricing_basis: .execution.pricing_basis, tokens: .execution.tokens, scan: .classification.response_scan.enforcement, annotations: .gateway_annotations})' "$EXPORT" | head -c 1500)"
  # The truncated stream (CC9) never settles as the full answer. Pinned from
  # the provider side, where the counts are exact: every allowed settlement
  # carrying the full output usage is either one of the clean complete
  # streams (CC1, CC2 — guarded, released unit by unit) or one of the
  # client's non-streaming fallbacks (JSON, held whole); the attempts the
  # provider cut (streamed truncated-stream calls) account for none of them.
  CLEAN_STREAMED="$(provider_state | jq '[.records[] | select(.stream==true and (.scenario // "")=="")] | length')"
  NONSTREAM_CALLS="$(provider_state | jq '[.records[] | select(.stream==false)] | length')"
  TRUNC_ATTEMPTS="$(provider_state | jq '[.records[] | select(.stream==true and .scenario=="truncated-stream")] | length')"
  ALLOWED_FULL="$(jq '[.records[] | select(.invocation_type=="gateway_response" and .policy_decision.allowed==true and .execution.tokens.output==3)] | length' "$EXPORT")"
  GUARDED_FULL="$(jq '[.records[] | select(.invocation_type=="gateway_response" and .policy_decision.allowed==true and .execution.tokens.output==3 and (.gateway_annotations|index("stream_unit_guarded")!=null))] | length' "$EXPORT")"
  [[ "${TRUNC_ATTEMPTS:-0}" -ge 1 ]] || die "CC9 produced no streamed truncated-stream call at the provider"
  [[ "$GUARDED_FULL" == "$CLEAN_STREAMED" && "$SETTLED_SSE" == "$CLEAN_STREAMED" ]] || die "guarded streams settled with the full output usage ($GUARDED_FULL, released complete $SETTLED_SSE) do not match the clean complete streamed calls the provider answered ($CLEAN_STREAMED): a cut attempt settled as the full answer. gateway_response records: $(jq -c '.records[] | select(.invocation_type=="gateway_response") | {allowed: .policy_decision.allowed, tokens: .execution.tokens, basis: .execution.pricing_basis, status: .status, failure: .failure_reason, scan: .classification.response_scan.status, annotations: .gateway_annotations}' "$EXPORT")"
  [[ "$ALLOWED_FULL" == "$((CLEAN_STREAMED + NONSTREAM_CALLS))" ]] || die "allowed settlements with the full output usage ($ALLOWED_FULL) must be the clean complete streams ($CLEAN_STREAMED) plus the client's non-streaming fallbacks ($NONSTREAM_CALLS). gateway_response records: $(jq -c '.records[] | select(.invocation_type=="gateway_response") | {allowed: .policy_decision.allowed, tokens: .execution.tokens, basis: .execution.pricing_basis, status: .status, failure: .failure_reason, scan: .classification.response_scan.status, annotations: .gateway_annotations}' "$EXPORT")"
  # How the cut attempts were settled is recorded, not assumed. Observed on
  # v0.1.3 (PR #531): OpenShell ends a stream the provider cut before its
  # first unit WITHOUT delivering any unit, so Talon settles the exchange
  # at once with no body — allowed, no usage (estimate_no_usage), the scan
  # recorded as incomplete with the abnormal-end reason. A cut after some
  # units were released would settle as a guarded partial stream instead.
  GUARDED_PARTIAL="$(jq '[.records[] | select(.invocation_type=="gateway_response" and .policy_decision.allowed==true and .execution.tokens.output!=3 and (.gateway_annotations|index("stream_unit_guarded")!=null))] | length' "$EXPORT")"
  NO_UNIT="$(jq '[.records[] | select(.invocation_type=="gateway_response" and .policy_decision.allowed==true and .execution.tokens.input==0 and .execution.pricing_basis=="estimate_no_usage" and .classification.response_scan.status=="incomplete" and (.gateway_annotations|index("stream_unit_guarded")!=null))] | length' "$EXPORT")"
  [[ "$((GUARDED_PARTIAL))" -ge "$TRUNC_ATTEMPTS" ]] || die "the $TRUNC_ATTEMPTS cut attempts must each settle as a guarded stream with less than the full usage (found $GUARDED_PARTIAL, of which $NO_UNIT with no unit delivered). gateway_response records: $(jq -c '.records[] | select(.invocation_type=="gateway_response") | {allowed: .policy_decision.allowed, tokens: .execution.tokens, basis: .execution.pricing_basis, scan: .classification.response_scan, annotations: .gateway_annotations}' "$EXPORT")"
  log "CC9 settlements of the $TRUNC_ATTEMPTS cut attempts: $GUARDED_PARTIAL guarded with less than the full usage, of which $NO_UNIT reached the hook with no unit at all (estimate_no_usage, scan incomplete); none as the full answer"
  jq -c '.records[] | select(.invocation_type=="gateway_response") | {id: .id, allowed: .policy_decision.allowed, tokens: .execution.tokens, basis: .execution.pricing_basis, status: .status, failure: .failure_reason, scan: .classification.response_scan, annotations: .gateway_annotations}' "$EXPORT" >"$LOGS/gateway-response-settlements.jsonl"
else
  SETTLED_SSE="$(jq '[.records[] | select(.invocation_type=="gateway_response" and .execution.tokens.input>0 and .execution.tokens.output>0 and .execution.cost>0 and (.gateway_annotations|index("response_observed")!=null))] | length' "$EXPORT")"
  [[ "${SETTLED_SSE:-0}" -ge 2 ]] || die "expected >=2 settlements carrying the real provider's observed usage priced from the table, found ${SETTLED_SSE:-0}: $(jq -c '[.records[] | select(.invocation_type=="gateway_response")] | map({pricing_basis: .execution.pricing_basis, tokens: .execution.tokens, annotations: .gateway_annotations})' "$EXPORT" | head -c 1200)"
fi
jq -e '[.records[] | select(.invocation_type=="gateway_response" and (.gateway_annotations|index("decision_unmatched")!=null))] | length == 0' "$EXPORT" >/dev/null || die "a settlement lost its request half"
grep -qF "$PII_EMAIL" "$EXPORT" && die "the prompt's sensitive value appears in Talon's evidence export"
grep -qF "$PII_EMAIL" "$LOGS/talon-serve.log" && die "the prompt's sensitive value appears in Talon's logs"
ALLOW_ID="$(jq -r '[.records[] | select(.enforcement.provenance=="delegated_expected" and .policy_decision.allowed==true)][0].id // empty' "$EXPORT")"
[[ -n "$ALLOW_ID" ]] || die "no allowed delegated record id found"
( cd "$TALON_HOME" && "$TALON" audit verify "$ALLOW_ID" ) >>"$LOGS/setup.log" 2>&1 || die "talon audit verify $ALLOW_ID"
( cd "$TALON_HOME" && "$TALON" audit list --runtime-ref "$SANDBOX_A_ID" --report ) >"$LOGS/claude-sandbox-report.txt" 2>>"$LOGS/setup.log" || die "talon audit list --runtime-ref $SANDBOX_A_ID --report"
grep -qF "$PROVIDER_SECRET" "$LOGS/claude-sandbox-report.txt" && die "provider secret in the walkthrough report"
if grep -rqF "$PROVIDER_SECRET" "$TALON_HOME" "$LOGS/talon-serve.log" "$EXPORT" 2>/dev/null; then die "provider secret found in Talon state, evidence or logs"; fi
grep -qF "$TALON_VAULT_DECOY" <<<"$(provider_state)" && die "Talon's vault value reached the provider"
pass "evidence: $DELEGATED delegated_expected decisions for the real sandbox ($ANTHROPIC_RECORDS anthropic/$CLAUDE_MODEL, $DENIED denied $CLAUDE_BLOCKED_MODEL), $SETTLED_SSE SSE settlements with observed usage, offline verification OK, walkthrough report written, no secret in Talon"

hygiene_check || die "log hygiene check failed"
pass "log hygiene: collected logs carry no provider secret, Talon key, private key or bearer token"

CLIENT_WIRE="not observable (real provider)"
if mock_mode; then CLIENT_WIRE="POST /v1/messages${CC1_QUERY:+?$CC1_QUERY} stream=true, anthropic-version $(provider_record 0 anthropic_version), anthropic-beta $(provider_record 0 anthropic_beta | cut -c1-120)"; fi
cat <<EOT
ALL PASS openshell live smoke
  lane:               claude-code (#528, C01–C03 producer conformance); mode: $MODE_LABEL
  openshell cli:      $("$CLI_BIN" --version)   sha256 ${CLI_SHA[$ARCH]}
  openshell gateway:  $("$GW_BIN" --version)   sha256 ${GW_SHA[$ARCH]}
  talon commit:       $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo untracked)
  claude code:        $CLAUDE_VERSION_LINE at $CLAUDE_BIN, sha256 $CLAUDE_SHA_IN_SANDBOX (release manifest linux-x64 pin)
  claude home:        $CLAUDE_HOME (first writable of: $CLAUDE_HOME_CANDIDATES; /sandbox is root-owned in OpenShell v0.1.3)
  workload image:     $WORKLOAD_IMAGE (image id $WORKLOAD_IMAGE_ID)
  model / profile:    $CLAUDE_MODEL allowed, $CLAUDE_BLOCKED_MODEL denied by company policy; OpenShell provider profile $PROFILE_ID → $PROVIDER_HOST:$PROVIDER_PORT (x-api-key injected after talon PRE_CREDENTIALS)
  client wire:        $CLIENT_WIRE; count_tokens calls $COUNT_TOKENS_CALLS
  provider calls:     $(mock_mode && echo "$(provider_calls) governed (mock)" || echo "real provider (count not observable; $ALLOWED allowed decisions)"), shadow (ungoverned endpoint) $(shadow_calls), truncated-stream probe $CALLS_AFTER_TRUNCATED
  response path:      SSE guarded unit by unit (OpenShell v0.1.3 offers no WHOLE_BODY_BYTES for text/event-stream); $SETTLED_SSE released complete settlements; cut attempts: $(mock_mode && echo "$GUARDED_PARTIAL guarded with less than the full usage ($NO_UNIT with no unit delivered: OpenShell v0.1.3 ends a stream cut before its first unit without delivering any)" || echo "n/a"); streamed response PII: $CC10_RESULT
  client behaviour:   on a cut or withheld stream claude-cli/$CLAUDE_CODE_VERSION retries the stream with backoff, then falls back to a non-streaming request$(mock_mode && echo " (CC9: ${CC9_STREAM_RETRIES:-?} stream attempts, ${CC9_FALLBACK:-?} fallback; each attempt a fresh Talon decision and provider call)")
  driver:             docker $(docker version --format '{{.Server.Version}}') on $(uname -r) ($ARCH)
  openshell images:   $(docker ps -a --format '{{.Image}}' | grep -i openshell | sort -u | tr '\n' ' ')
  host address:       $HOST_IP (talon middleware https://$HOST_IP:$TALON_GRPC_PORT, talon http :$TALON_HTTP_PORT, mock provider :$MOCK_PORT, shadow provider :$SHADOW_PORT)
  provenance:         model decisions delegated_expected (Talon decided; OpenShell enforced — not observed by Talon); bypass refusals are OpenShell containment (external, not Talon)
  ocsf (gateway):     $LOGS/gateway-ocsf.jsonl ($(if [[ -f "$LOGS/gateway-ocsf.jsonl" ]]; then wc -l <"$LOGS/gateway-ocsf.jsonl"; else echo 0; fi) lines)
EOT
