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
#       --credential injection (x-api-key := provider secret)--> mock Anthropic provider
#       <-- SSE --> talon PRE_RETURN (held, inspected, usage settled) --> claude
#
# Nothing in the sandbox is a credential: ANTHROPIC_API_KEY is OpenShell's
# placeholder, there is no Talon agent key, no reviewer credential, no
# provider key. ANTHROPIC_BASE_URL names the PROVIDER endpoint (the mock, on
# the host the sandbox policy admits with the talon middleware bound) —
# never Talon's /v1/proxy: Talon is reached only through OpenShell's hook.
#
# Cases (C01–C03 of the ratified Full Demo contract, producer side):
#   CC0 fixture: the pinned executable is in the sandbox at the policy's
#       path, reports its version, and its sha256 is the release manifest's
#   CC1 allowed turn (C01): one /v1/messages call reached the provider,
#       streamed (SSE), with the user agent of the real executable, under the
#       OpenShell-injected x-api-key; claude printed the mock's answer;
#       Talon's record verifies the sandbox identity, delegated_expected
#   CC2 PII in the prompt: the provider received Talon's redacted body
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
#   CC8 count_tokens: observed absence with this client in this flow
#       (documented, not asserted as governed-by-conformance)
#   CC9 truncated stream: the provider closes mid-stream; claude reports an
#       error; Talon's settlement for that exchange does not claim a
#       completed response
#   evidence: decision + settlement records with the provider's actual usage
#       from the SSE (12/3), verified offline; run facts printed
#
# Every assertion is against the real runtime's observable state: the mock
# provider's counters and records (independent of Talon), claude's exit
# status and JSON result, OpenShell's error envelopes, and Talon's signed
# evidence. Nothing is asserted from a Talon decision alone.

# ---------------------------------------------------------------- client invocations
# claude_turn sandbox prompt [extra --env args...] -> prints "<exit code>\n<stdout json>" (stderr to the setup log)
# The real executable in print mode: one turn, JSON result, no session
# persistence (the sandbox filesystem is not the product), hooks and MCP
# off (C04/C05 belong to the Full Demo harness), nonessential traffic off
# (telemetry/update checks would only be denied by the sandbox policy and
# clutter the OCSF log).
claude_turn() {
  local sb="$1" prompt="$2"; shift 2
  local out code
  set +e
  out="$("${CLI[@]}" sandbox exec --name "$sb" --no-tty --no-login-shell --timeout 180 \
    --env "ANTHROPIC_BASE_URL=http://host.openshell.internal:$MOCK_PORT" \
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

# ---------------------------------------------------------------- CC0 — fixture: the pinned executable, in the real sandbox
FIXTURE="$(sandbox_sh "$SANDBOX_A" "printf 'claude=%s\nsh=%s\ncurl=%s\nuser=%s\nhome_writable=%s\n' \"\$(command -v claude || echo missing)\" \"\$(command -v sh || echo missing)\" \"\$(command -v curl || echo missing)\" \"\$(id -u 2>/dev/null || echo unknown)\" \"\$(mkdir -p $CLAUDE_HOME/.claude 2>/dev/null && touch $CLAUDE_HOME/.claude/.probe 2>/dev/null && echo yes || echo no)\"; $CLAUDE_BIN --version 2>/dev/null | head -n1; sha256sum $CLAUDE_BIN | cut -d' ' -f1" || true)"
printf '%s\n' "$FIXTURE" >>"$LOGS/setup.log"
DETECTED_CLAUDE="$(sed -n 's/^claude=//p' <<<"$FIXTURE" | head -n1)"
DETECTED_CURL="$(sed -n 's/^curl=//p' <<<"$FIXTURE" | head -n1)"
HOME_WRITABLE="$(sed -n 's/^home_writable=//p' <<<"$FIXTURE" | head -n1)"
[[ "$HOME_WRITABLE" == "yes" ]] || die "CC0 workload fixture: $CLAUDE_HOME is not writable in the sandbox (Claude Code keeps its config under HOME); set TALON_OPENSHELL_CLAUDE_HOME to the sandbox's writable workspace (sandbox output: $FIXTURE)"
CLAUDE_VERSION_LINE="$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$FIXTURE" | head -n1 || true)"
CLAUDE_SHA_IN_SANDBOX="$(grep -E '^[0-9a-f]{64}$' <<<"$FIXTURE" | head -n1 || true)"
[[ "$DETECTED_CLAUDE" == "$CLAUDE_BIN" ]] || die "CC0 workload fixture: expected claude at $CLAUDE_BIN, image $WORKLOAD_IMAGE reported '${DETECTED_CLAUDE:-missing}' (sandbox output: $FIXTURE)"
[[ "$CLAUDE_VERSION_LINE" == "$CLAUDE_CODE_VERSION"* ]] || die "CC0 workload fixture: claude --version in the sandbox is '${CLAUDE_VERSION_LINE:-empty}', want $CLAUDE_CODE_VERSION"
[[ "$CLAUDE_SHA_IN_SANDBOX" == "$CLAUDE_CODE_SHA256" ]] || die "CC0 workload fixture: sha256 of $CLAUDE_BIN in the sandbox is '${CLAUDE_SHA_IN_SANDBOX:-empty}', want the release manifest's $CLAUDE_CODE_SHA256"
[[ "$DETECTED_CURL" == "$CURL_BIN" ]] || die "CC0 workload fixture: expected curl at $CURL_BIN for the bypass probe, image reported '${DETECTED_CURL:-missing}'"
pass "CC0 fixture: real Claude Code $CLAUDE_VERSION_LINE at $CLAUDE_BIN in the real sandbox, sha256 = release manifest pin"

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

# ---------------------------------------------------------------- CC1 — allowed turn through the delegated path (C01)
OUT="$(claude_turn "$SANDBOX_A" "Reply with exactly the text the assistant is given.")"
CODE="$(turn_code "$OUT")"
[[ "$CODE" == "0" ]] || die "CC1 claude exited $CODE: $(turn_json "$OUT")"
[[ "$(turn_field "$OUT" .is_error)" == "false" && "$(turn_field "$OUT" .subtype)" == "success" ]] || die "CC1 claude result is not a success: $(turn_json "$OUT")"
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

# ---------------------------------------------------------------- CC2 — PII in the prompt reaches the provider redacted
PII_EMAIL="jane.doe@example.com"
OUT="$(claude_turn "$SANDBOX_A" "Draft a refund note for $PII_EMAIL about order 42.")"
[[ "$(turn_code "$OUT")" == "0" ]] || die "CC2 claude exited $(turn_code "$OUT"): $(turn_json "$OUT")"
[[ "$(provider_calls)" == "2" ]] || die "CC2 provider calls = $(provider_calls), want 2"
FORWARDED="$(provider_record 1 body)"
grep -qF "$PII_EMAIL" <<<"$FORWARDED" && die "CC2 provider received the original sensitive value"
grep -q "order 42" <<<"$FORWARDED" || die "CC2 forwarded body is not the transformed prompt: $(head -c 400 <<<"$FORWARDED")"
pass "CC2 PII redacted: the provider received Talon's transformed Anthropic body, never $PII_EMAIL"

# ---------------------------------------------------------------- CC3 — denied model: Talon DENY before credentials (C02)
OUT="$(claude_turn "$SANDBOX_A" "hi" --env "TALON_MODEL=$CLAUDE_BLOCKED_MODEL")"
CODE="$(turn_code "$OUT")"
[[ "$CODE" != "0" ]] || die "CC3 claude succeeded on a model Talon denies: $(turn_json "$OUT")"
[[ "$(turn_field "$OUT" .is_error)" == "true" || "$(turn_field "$OUT" .terminal_reason)" == "api_error" ]] || die "CC3 claude did not report an API error for the denial: $(turn_json "$OUT")"
grep -qE 'middleware_denied|model_not_allowed|403' <<<"$(turn_json "$OUT")" || log "CC3 note: claude's JSON does not echo the denial body (exit $CODE, terminal_reason=$(turn_field "$OUT" .terminal_reason)); the provider count below is the proof"
[[ "$(provider_calls)" == "2" ]] || die "CC3 provider was called on a Talon DENY (calls=$(provider_calls)); the client's retries, if any, must also have been denied"
pass "CC3 denied model (C02): talon DENY at PRE_CREDENTIALS, claude exit $CODE, provider count unchanged across the client's retry behaviour"

# ---------------------------------------------------------------- CC4 — unbound sandbox identity (C02): a second real sandbox, real claude
create_sandbox "$SANDBOX_B"
OUT="$(claude_turn "$SANDBOX_B" "hi")"
CODE="$(turn_code "$OUT")"
[[ "$CODE" != "0" ]] || die "CC4 an unbound sandbox completed a model call: $(turn_json "$OUT")"
[[ "$(provider_calls)" == "2" ]] || die "CC4 provider was called for an unbound sandbox"
# OpenShell's denial for this sandbox is in the gateway's OCSF log; Talon
# writes no record for an unbound identity (nothing was evaluated).
pass "CC4 unbound sandbox: real claude denied (exit $CODE), provider count unchanged, no Talon record"

# ---------------------------------------------------------------- CC5 — Talon unavailable → OpenShell fails closed
kill "$TALON_PID"; wait "$TALON_PID" 2>/dev/null || true; TALON_PID=""
OUT="$(claude_turn "$SANDBOX_A" "hi")"
CODE="$(turn_code "$OUT")"
[[ "$CODE" != "0" ]] || die "CC5 claude succeeded while talon was down: $(turn_json "$OUT")"
[[ "$(provider_calls)" == "2" ]] || die "CC5 provider was reached while talon was unavailable"
start_talon
pass "CC5 talon unavailable: OpenShell failed closed (claude exit $CODE), provider count unchanged — enforced by OpenShell, not Talon"

# ---------------------------------------------------------------- CC6 — direct bypass refused by OpenShell (containment, not Talon)
# (a) a binary the policy does not admit to the provider (curl) on the admitted port
OUT="$("${CLI[@]}" sandbox exec --name "$SANDBOX_A" --no-tty --no-login-shell --timeout 60 -- "$SH_BIN" -c 'out=$('"$CURL_BIN"' -sS --max-time 20 -w "\n__CODE__%{http_code}" -X POST "http://host.openshell.internal:'"$MOCK_PORT"'/v1/messages" -H "x-api-key: $ANTHROPIC_API_KEY" -H "content-type: application/json" --data "{\"model\":\"'"$CLAUDE_MODEL"'\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"bypass\"}]}" 2>&1); echo "${out##*__CODE__}"; printf "%s\n" "${out%__CODE__*}"' 2>>"$LOGS/setup.log" || true)"; CODE="$(head -n1 <<<"$OUT")"
[[ "$CODE" != "200" ]] || die "CC6a curl (not an admitted binary) reached the provider: $OUT"
[[ "$(provider_calls)" == "2" ]] || die "CC6a provider count changed on a non-admitted binary's call"
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
[[ "$(provider_record 0 x_api_key)" == "$PROVIDER_SECRET" ]] || die "CC7 the provider did not see the injected secret"
if grep -rqF "$PROVIDER_SECRET" "$TALON_HOME" "$LOGS/talon-serve.log" 2>/dev/null; then die "CC7 provider secret found in Talon state or logs"; fi
pass "CC7 credential isolation (C03): sandbox env holds the OpenShell placeholder only; the provider saw the injected secret; Talon never held it; no Talon key, reviewer credential or vault value in the sandbox"

# ---------------------------------------------------------------- CC8 — count_tokens: observed absence with this client
COUNT_TOKENS_CALLS="$(provider_state | jq '[.records[] | select(.path | endswith("/count_tokens"))] | length')"
if [[ "$COUNT_TOKENS_CALLS" == "0" ]]; then
  log "CC8 count_tokens: claude-cli/$CLAUDE_CODE_VERSION emitted no /v1/messages/count_tokens call in this flow (print mode, single turn); Talon's delegated count_tokens handling is covered by the fixture/unit lanes, not by this client"
else
  log "CC8 count_tokens: $COUNT_TOKENS_CALLS count_tokens call(s) reached the provider under the injected credential"
fi
pass "CC8 count_tokens observed: $COUNT_TOKENS_CALLS call(s) (documented, see log)"

# ---------------------------------------------------------------- CC9 — truncated stream: no invented success
OUT="$(claude_turn "$SANDBOX_A" "hi" --env "ANTHROPIC_CUSTOM_HEADERS=X-Mock-Scenario: truncated-stream")"
CODE="$(turn_code "$OUT")"
CALLS_AFTER_TRUNCATED="$(provider_calls)"
[[ "$CALLS_AFTER_TRUNCATED" -ge 3 ]] || die "CC9 the truncated-stream request never reached the provider (calls=$CALLS_AFTER_TRUNCATED)"
[[ "$(turn_field "$OUT" .result)" != "mock anthropic completion 3" ]] || die "CC9 claude reported the full answer of a stream the provider cut short"
log "CC9 truncated stream: claude exit $CODE, is_error=$(turn_field "$OUT" .is_error), provider calls now $CALLS_AFTER_TRUNCATED (client retries counted, each a fresh Talon decision)"
pass "CC9 truncated stream: the client did not report a completed answer (exit $CODE); provider calls $CALLS_AFTER_TRUNCATED"

# ---------------------------------------------------------------- evidence
EXPORT="$WORK/export.json"
( cd "$TALON_HOME" && "$TALON" audit export --format signed-json ) >"$EXPORT" 2>>"$LOGS/setup.log" || die "talon audit export"
SUBJECT="spiffe://openshell/sandbox/$SANDBOX_A_ID"; ISSUER="openshell-gateway:$GATEWAY_ID"
DELEGATED="$(jq --arg iss "$ISSUER" --arg sub "$SUBJECT" '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .enforcement.mechanism=="delegate" and .enforcement.boundary=="external_runtime" and .enforcement.decision_authority=="talon" and .enforcement.decision_returned_via=="openshell_middleware" and .workload_identity.status=="verified" and .workload_identity.runtime=="openshell" and .workload_identity.issuer==$iss and .workload_identity.subject==$sub and .upstream_auth_mode=="external_runtime")] | length' "$EXPORT")"
[[ "${DELEGATED:-0}" -ge 4 ]] || die "expected >=4 delegated_expected decision records verified for $ISSUER / $SUBJECT, found ${DELEGATED:-0}"
ANTHROPIC_RECORDS="$(jq --arg m "$CLAUDE_MODEL" '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .routing_decision.selected_provider=="anthropic" and .execution.model_used==$m)] | length' "$EXPORT")"
[[ "${ANTHROPIC_RECORDS:-0}" -ge 3 ]] || die "expected >=3 delegated decisions for provider anthropic model $CLAUDE_MODEL, found ${ANTHROPIC_RECORDS:-0} (seen: $(jq -c '[.records[] | select(.invocation_type=="gateway")] | map({provider: .routing_decision.selected_provider, model: .execution.model_used}) | unique' "$EXPORT"))"
DENIED="$(jq --arg m "$CLAUDE_BLOCKED_MODEL" '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .policy_decision.allowed==false and .execution.model_used==$m)] | length' "$EXPORT")"
[[ "${DENIED:-0}" -ge 1 ]] || die "expected a delegated DENY record for $CLAUDE_BLOCKED_MODEL, found ${DENIED:-0}"
jq -e '[.records[] | select(.enforcement.provenance=="talon_enforced" and .workload_identity.runtime=="openshell" and (.invocation_type=="gateway" or .invocation_type=="gateway_response" or .invocation_type=="gateway_count_tokens"))] | length == 0' "$EXPORT" >/dev/null || die "a delegated model decision or settlement was labelled talon_enforced"
# Settlement: the allowed turns' responses were SSE; Talon settled each
# under its decision's correlation id with the provider's actual usage
# (12 in / 3 out from message_start + message_delta), decisions booked 0.
ALLOWED="$(jq '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .policy_decision.allowed==true)] | length' "$EXPORT")"
AWAITING="$(jq '[.records[] | select(.invocation_type=="gateway" and .enforcement.provenance=="delegated_expected" and .policy_decision.allowed==true and .execution.pricing_basis=="awaiting_settlement" and .execution.cost==0)] | length' "$EXPORT")"
[[ "$AWAITING" == "$ALLOWED" && "${ALLOWED:-0}" -ge 2 ]] || die "allowed decisions=$ALLOWED, awaiting_settlement=$AWAITING"
SETTLED_SSE="$(jq '[.records[] | select(.invocation_type=="gateway_response" and .execution.tokens.input==12 and .execution.tokens.output==3 and .execution.cost>0 and (.gateway_annotations|index("response_observed")!=null))] | length' "$EXPORT")"
[[ "${SETTLED_SSE:-0}" -ge 2 ]] || die "expected >=2 settlements carrying the SSE usage 12/3 priced from the table, found ${SETTLED_SSE:-0}: $(jq -c '[.records[] | select(.invocation_type=="gateway_response")] | map({pricing_basis: .execution.pricing_basis, tokens: .execution.tokens, annotations: .gateway_annotations})' "$EXPORT" | head -c 1200)"
TRUNCATED_CLAIMED="$(jq '[.records[] | select(.invocation_type=="gateway_response" and .execution.tokens.output==3)] | length' "$EXPORT")"
[[ "$TRUNCATED_CLAIMED" == "$SETTLED_SSE" ]] || die "a settlement claims the full output usage for the truncated stream (settled=$SETTLED_SSE, with output 3=$TRUNCATED_CLAIMED)"
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
pass "evidence: $DELEGATED delegated_expected decisions for the real sandbox ($ANTHROPIC_RECORDS anthropic/$CLAUDE_MODEL, $DENIED denied $CLAUDE_BLOCKED_MODEL), $SETTLED_SSE SSE settlements with actual usage 12/3, offline verification OK, walkthrough report written, no secret in Talon"

hygiene_check || die "log hygiene check failed"
pass "log hygiene: collected logs carry no provider secret, Talon key, private key or bearer token"

cat <<EOT
ALL PASS openshell live smoke
  lane:               claude-code (#528, C01–C03 producer conformance; deterministic, no provider key)
  openshell cli:      $("$CLI_BIN" --version)   sha256 ${CLI_SHA[$ARCH]}
  openshell gateway:  $("$GW_BIN" --version)   sha256 ${GW_SHA[$ARCH]}
  talon commit:       $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo untracked)
  claude code:        $CLAUDE_VERSION_LINE at $CLAUDE_BIN, sha256 $CLAUDE_SHA_IN_SANDBOX (release manifest linux-x64 pin)
  workload image:     $WORKLOAD_IMAGE (image id $WORKLOAD_IMAGE_ID)
  model / profile:    $CLAUDE_MODEL allowed, $CLAUDE_BLOCKED_MODEL denied by company policy; OpenShell provider profile $PROFILE_ID (x-api-key injected after talon PRE_CREDENTIALS)
  client wire:        POST /v1/messages${CC1_QUERY:+?$CC1_QUERY} stream=true, anthropic-version $(provider_record 0 anthropic_version), anthropic-beta $(provider_record 0 anthropic_beta | cut -c1-120), count_tokens calls $COUNT_TOKENS_CALLS
  provider calls:     $(provider_calls) governed (mock), shadow (ungoverned endpoint) $(shadow_calls)
  driver:             docker $(docker version --format '{{.Server.Version}}') on $(uname -r) ($ARCH)
  openshell images:   $(docker ps -a --format '{{.Image}}' | grep -i openshell | sort -u | tr '\n' ' ')
  host address:       $HOST_IP (talon middleware https://$HOST_IP:$TALON_GRPC_PORT, talon http :$TALON_HTTP_PORT, mock provider :$MOCK_PORT, shadow provider :$SHADOW_PORT)
  provenance:         model decisions delegated_expected (Talon decided; OpenShell enforced — not observed by Talon); bypass refusals are OpenShell containment (external, not Talon)
  ocsf (gateway):     $LOGS/gateway-ocsf.jsonl ($(if [[ -f "$LOGS/gateway-ocsf.jsonl" ]]; then wc -l <"$LOGS/gateway-ocsf.jsonl"; else echo 0; fi) lines)
EOT
