# Smoke test request layer — central place for all Talon HTTP requests and canonical payloads.
# Sourced by smoke_test.sh. Use these helpers so we don't duplicate URLs or request bodies.
#
# Usage: set SMOKE_BASE_URL (e.g. http://127.0.0.1:8080), then call the functions below.
# Gateway auth: pass "Bearer <token>" or "Bearer <api_key>" for caller keys.

# --- Canonical paths (single source of truth) ---
SMOKE_PATH_HEALTH="/health"
SMOKE_PATH_GW_PROXY="/v1/proxy/openai/v1/chat/completions"
SMOKE_PATH_METRICS="/api/v1/metrics"
SMOKE_PATH_METRICS_STREAM="/api/v1/metrics/stream"
SMOKE_PATH_GATEWAY_DASHBOARD="/gateway/dashboard"

# --- Canonical request bodies (reused across sections; no duplicate JSON) ---
# PII: email + IBAN (used for redact path, block path, and metrics volume)
SMOKE_BODY_PII='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact jan.kowalski@example.com about IBAN DE89370400440532013000"}]}'

# Cache: identical prompt for miss-then-hit (section 23 cache test)
SMOKE_BODY_CACHE='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Reply exactly: CACHE_SEMANTIC_OK"}]}'

# Normal: parameterised for variety (use SMOKE_BODY_NORMAL "3" for "Reply METRICS_OK 3")
smoke_body_normal() { echo "{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply METRICS_OK ${1:-1}\"}]}"; }

# Tool block: request with forbidden tool delete_all (default_policy block)
SMOKE_BODY_TOOL_BLOCK='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"tools":[{"type":"function","function":{"name":"delete_all","description":"x","parameters":{"type":"object"}}}]}'

# Tool filter: request with read_file + exec_cmd (exec_cmd forbidden for tool-filter-caller)
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
# Usage: smoke_gw_get_metrics base_url "Bearer <dash_token>"
# Outputs: JSON body (stdout)
smoke_gw_get_metrics() {
  local base="$1" auth="$2"
  curl -s -H "Authorization: $auth" "${base}${SMOKE_PATH_METRICS}" 2>/dev/null
}

# --- Dashboard: GET dashboard HTML ---
# Usage: smoke_gw_get_dashboard base_url "Bearer <dash_token>"
smoke_gw_get_dashboard() {
  local base="$1" auth="$2"
  curl -s -H "Authorization: $auth" "${base}${SMOKE_PATH_GATEWAY_DASHBOARD}" 2>/dev/null
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
