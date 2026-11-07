# shellcheck shell=bash
# shellcheck disable=SC2034  # canonical paths/bodies are consumed by the scripts that source this lib
#
# Smoke test request layer — central place for all Talon HTTP requests and canonical payloads.
# Sourced by smoke_test.sh. Use these helpers so we don't duplicate URLs or request bodies.
#
# Usage: set SMOKE_BASE_URL (e.g. http://127.0.0.1:8080), then call the functions below.
# Gateway agent auth: pass "Bearer <agent key value>" for proxy calls (#266).

# --- Canonical paths (single source of truth) ---
SMOKE_PATH_HEALTH="/health"
SMOKE_PATH_GW_PROXY="/v1/proxy/openai/v1/chat/completions"
SMOKE_PATH_METRICS="/api/v1/metrics"
SMOKE_PATH_METRICS_STREAM="/api/v1/metrics/stream"
SMOKE_PATH_GATEWAY_DASHBOARD="/gateway/dashboard"
SMOKE_PATH_EVIDENCE="/v1/evidence"
SMOKE_PATH_EVENTS_RECENT="/api/v1/events/recent"
SMOKE_PATH_EVENTS_STREAM="/api/v1/events/stream"
SMOKE_PATH_STATUS="/v1/status"

# --- Canonical request bodies (reused across sections; no duplicate JSON) ---
# PII: email + IBAN (used for redact path, block path, and metrics volume)
SMOKE_BODY_PII='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact jan.kowalski@example.com about IBAN DE89370400440532013000"}]}'

# Cache: identical prompt for miss-then-hit (section 23 cache test)
SMOKE_BODY_CACHE='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Reply exactly: CACHE_SEMANTIC_OK"}]}'

# Normal: parameterised for variety (use SMOKE_BODY_NORMAL "3" for "Reply METRICS_OK 3")
smoke_body_normal() { echo "{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply METRICS_OK ${1:-1}\"}]}"; }

# Tool block: request with forbidden tool delete_all (organization_policy constraints.forbidden_tools)
SMOKE_BODY_TOOL_BLOCK='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"delete_all","description":"x","parameters":{"type":"object"}}}]}'

# Tool filter: request with read_file + exec_cmd (exec_cmd forbidden for the tool-filter agent)
SMOKE_BODY_TOOL_FILTER='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"read_file","description":"x","parameters":{"type":"object"}}},{"type":"function","function":{"name":"exec_cmd","description":"x","parameters":{"type":"object"}}}]}'

# Minimal (empty messages) for 401/probe
SMOKE_BODY_EMPTY='{"model":"gpt-4o-mini","messages":[]}'

# Simple one-line prompt (section 13 gateway probe)
SMOKE_BODY_SIMPLE='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Reply PONG"}]}'

# --- Health ---
# Usage: smoke_health "http://127.0.0.1:8080"
# Returns: 0 if GET /health returns 200, else 1
smoke_health() {
  local base="${1:-$SMOKE_BASE_URL}"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 "${base}${SMOKE_PATH_HEALTH}" 2>/dev/null)"
  [[ "$code" == "200" ]]
}

# --- Gateway proxy: POST chat completions ---
# Usage: smoke_gw_post_chat base_url "Bearer <key>" body
# Returns: HTTP status code (stdout)
smoke_gw_post_chat() {
  local base="$1" auth="$2" body="$3"
  curl -s -o /dev/null -w '%{http_code}' -X POST "${base}${SMOKE_PATH_GW_PROXY}" \
    -H "Authorization: $auth" -H "Content-Type: application/json" -d "$body" 2>/dev/null
}

# Same but write response body to a file (for section 13 that checks response)
# Usage: smoke_gw_post_chat_to_file base_url auth body outfile
# Returns: HTTP status code (stdout)
smoke_gw_post_chat_to_file() {
  local base="$1" auth="$2" body="$3" out="$4"
  curl -s -o "$out" -w '%{http_code}' -X POST "${base}${SMOKE_PATH_GW_PROXY}" \
    -H "Authorization: $auth" -H "Content-Type: application/json" -d "$body" 2>/dev/null
}

# Gateway POST with captured response headers and body.
# Usage: smoke_gw_post_chat_capture base_url auth body headers_out body_out
# Returns: HTTP status code (stdout)
smoke_gw_post_chat_capture() {
  local base="$1" auth="$2" body="$3" headers_out="$4" body_out="$5"
  curl -s -D "$headers_out" -o "$body_out" -w '%{http_code}' -X POST "${base}${SMOKE_PATH_GW_PROXY}" \
    -H "Authorization: $auth" -H "Content-Type: application/json" -d "$body" 2>/dev/null
}

# --- GET with optional auth, return HTTP status code (stdout) ---
# Usage: smoke_get_code base_url path [auth_header]
# Example: smoke_get_code "http://127.0.0.1:8080" "/api/v1/metrics" "Bearer token"
smoke_get_code() {
  local base="$1" path="$2" auth="${3:-}"
  if [[ -n "$auth" ]]; then
    curl -s -o /dev/null -w '%{http_code}' -H "Authorization: $auth" "${base}${path}" 2>/dev/null
  else
    curl -s -o /dev/null -w '%{http_code}' "${base}${path}" 2>/dev/null
  fi
}

# --- Dashboard: GET metrics JSON ---
# Usage: smoke_gw_get_metrics base_url "<admin_key>"
# Outputs: JSON body (stdout)
smoke_gw_get_metrics() {
  local base="$1" admin_key="$2"
  curl -s -H "X-Talon-Admin-Key: $admin_key" "${base}${SMOKE_PATH_METRICS}" 2>/dev/null
}

# --- Dashboard: GET dashboard HTML ---
# Usage: smoke_gw_get_dashboard base_url "<admin_key>"
smoke_gw_get_dashboard() {
  local base="$1" admin_key="$2"
  curl -s -H "X-Talon-Admin-Key: $admin_key" "${base}${SMOKE_PATH_GATEWAY_DASHBOARD}" 2>/dev/null
}

# --- Evidence: fetch most recent evidence record (full JSON) via admin API ---
# Usage: smoke_get_latest_evidence base_url admin_key
# Outputs: full evidence JSON (stdout); returns 1 if no evidence found.
smoke_get_latest_evidence() {
  local base="$1" admin_key="$2"
  local idx ev_id
  idx="$(curl -s -H "X-Talon-Admin-Key: $admin_key" "${base}${SMOKE_PATH_EVIDENCE}?limit=1")"
  ev_id="$(echo "$idx" | jq -r '.entries[0].id // empty')"
  [[ -z "$ev_id" ]] && return 1
  curl -s -H "X-Talon-Admin-Key: $admin_key" "${base}${SMOKE_PATH_EVIDENCE}/${ev_id}"
}

# --- Events API: GET recent operational events JSON ---
# Usage: smoke_get_events_recent base_url admin_key [limit]
# Outputs: JSON body (stdout) shaped { "events": [...], "cursor": "..." }
smoke_get_events_recent() {
  local base="$1" admin_key="$2" limit="${3:-50}"
  curl -s -H "X-Talon-Admin-Key: $admin_key" "${base}${SMOKE_PATH_EVENTS_RECENT}?limit=${limit}" 2>/dev/null
}

# --- Events API: capture a short SSE window from the events stream ---
# Usage: smoke_capture_events_stream base_url admin_key [seconds] [last_event_id]
# Outputs: raw SSE body (stdout)
smoke_capture_events_stream() {
  local base="$1" admin_key="$2" seconds="${3:-3}" since="${4:-}"
  local hdr=()
  [[ -n "$since" ]] && hdr=(-H "Last-Event-ID: $since")
  timeout "$seconds" curl -s -H "X-Talon-Admin-Key: $admin_key" "${hdr[@]}" \
    "${base}${SMOKE_PATH_EVENTS_STREAM}" 2>/dev/null || true
}

# --- Status: GET /v1/status JSON ---
# Usage: smoke_get_status base_url admin_key
# Outputs: JSON body (stdout)
smoke_get_status() {
  local base="$1" admin_key="$2"
  curl -s -H "X-Talon-Admin-Key: $admin_key" "${base}${SMOKE_PATH_STATUS}" 2>/dev/null
}

# --- Evidence index (admin): list recent evidence records ---
# Usage: smoke_get_evidence_index base_url admin_key [limit]
# Outputs: JSON body (stdout) shaped { "entries": [...] }
smoke_get_evidence_index() {
  local base="$1" admin_key="$2" limit="${3:-50}"
  curl -s -H "X-Talon-Admin-Key: $admin_key" "${base}${SMOKE_PATH_EVIDENCE}?limit=${limit}" 2>/dev/null
}

# --- Wait until health returns 200 (for server startup) ---
# Usage: smoke_wait_health base_url [max_attempts] [sleep_sec]
smoke_wait_health() {
  local base="$1" max="${2:-10}" sleep_sec="${3:-1}" i=0
  while ! smoke_health "$base"; do
    sleep "$sleep_sec"
    ((i++)) || true
    [[ $i -ge "$max" ]] && return 1
  done
  return 0
}

# smoke_run_response_text <talon run stdout>: the model/cached response
# block of `talon run` output — everything between the "Policy check"
# line and the "Evidence stored" line — trimmed, so two runs can be
# compared byte-for-byte without cost/duration/evidence-id noise.
smoke_run_response_text() {
  awk '
    /^✓ Policy check:/ { started = 1; next }
    /^✓ Evidence stored:/ { exit }
    started { print }
  ' <<< "$1" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'
}

# --- Anthropic Messages API through the gateway (section 42) -----------------
# One provider path, one model, one request builder: the section asserts
# Talon's governance of the real Anthropic wire, not provider prose.
SMOKE_PATH_GW_ANTHROPIC_MESSAGES="/v1/proxy/anthropic/v1/messages"
SMOKE_PATH_GW_ANTHROPIC_COUNT_TOKENS="/v1/proxy/anthropic/v1/messages/count_tokens"
# The smoke model must be priced in pricing/models.yaml (an unpriced model is
# denied pricing_unavailable under the agent's cap) and cheap: Haiku 4.5 is
# the least expensive priced Claude model. TALON_SMOKE_ANTHROPIC_MODEL
# overrides it; the override must be priced too.
SMOKE_ANTHROPIC_MODEL="${TALON_SMOKE_ANTHROPIC_MODEL:-claude-haiku-4-5}"
# A priced model that is deliberately outside the provider allow list, so the
# denial below is a policy decision (model_not_allowed), not a pricing gap.
SMOKE_ANTHROPIC_DENIED_MODEL="claude-sonnet-4-6"
# Upstream base URL. The default is the real provider; a development override
# may point at an Anthropic-shaped stand-in to validate the section's logic
# offline. An override never counts as real-provider verification.
SMOKE_ANTHROPIC_BASE_URL="${TALON_SMOKE_ANTHROPIC_BASE_URL:-https://api.anthropic.com}"
SMOKE_ANTHROPIC_VERSION="2023-06-01"

# smoke_body_anthropic <stream:true|false> [model] [max_tokens]
# A minimal Messages request: one short user turn, a tiny output budget.
smoke_body_anthropic() {
  local stream="${1:-false}" model="${2:-$SMOKE_ANTHROPIC_MODEL}" max_tokens="${3:-24}"
  printf '{"model":"%s","max_tokens":%s,"stream":%s,"messages":[{"role":"user","content":"Reply with the single word PONG"}]}' \
    "$model" "$max_tokens" "$stream"
}

# smoke_gw_post_anthropic base auth_scheme auth_value body headers_out body_out [path] [extra curl args...]
#   auth_scheme: x-api-key  → "x-api-key: <agent key>"      (Anthropic SDK convention)
#                bearer     → "Authorization: Bearer <key>" (Claude Code's ANTHROPIC_AUTH_TOKEN)
# Sends anthropic-version like a real client would. Returns the HTTP status
# code on stdout; headers and body land in the given files.
smoke_gw_post_anthropic() {
  local base="$1" scheme="$2" value="$3" body="$4" headers_out="$5" body_out="$6"
  local path="${7:-$SMOKE_PATH_GW_ANTHROPIC_MESSAGES}"
  shift 7 2>/dev/null || shift $#
  local auth_header
  case "$scheme" in
    bearer) auth_header="Authorization: Bearer ${value}" ;;
    *) auth_header="x-api-key: ${value}" ;;
  esac
  curl -s -D "$headers_out" -o "$body_out" -w '%{http_code}' -X POST "${base}${path}" \
    -H "$auth_header" -H "anthropic-version: ${SMOKE_ANTHROPIC_VERSION}" \
    -H "Content-Type: application/json" "$@" -d "$body" 2>/dev/null
}

# smoke_header_value <headers_file> <header-name>: first value, CR stripped,
# case-insensitive name match.
smoke_header_value() {
  local file="$1" name="$2"
  awk -v n="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')" '
    { h = tolower($1) } h == n ":" { sub(/^[^:]*:[[:space:]]*/, ""); gsub("\r", ""); print; exit }
  ' "$file" 2>/dev/null
}
