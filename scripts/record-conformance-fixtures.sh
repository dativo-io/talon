#!/usr/bin/env bash
# Recapture gateway conformance fixtures against the live Anthropic API.
#
# Produces raw request/response pairs for the shapes covered in
# internal/gateway/testdata/conformance/anthropic/. Output goes to a scratch
# directory and MUST be sanitized by hand before updating fixtures:
#   - replace any real key material (fixtures use sk-ant-test-000-*)
#   - replace any real emails/PII with *@example.com corpus values
#   - replace response ids with msg_conf_* synthetics
# See internal/gateway/testdata/conformance/README.md for the fixture schema.
#
# Requires: RECORD=1 (explicit opt-in), ANTHROPIC_API_KEY, curl, jq.
set -euo pipefail

if [[ "${RECORD:-}" != "1" ]]; then
  echo "refusing to run without RECORD=1 (this script calls the live Anthropic API and spends tokens)" >&2
  exit 1
fi
: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY to record}"

OUT="${OUT:-$(mktemp -d)/conformance-capture}"
mkdir -p "$OUT"
API="https://api.anthropic.com"
MODEL="${MODEL:-claude-sonnet-5}"
HDRS=(-H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json")

capture() { # name path body
  local name="$1" path="$2" body="$3"
  echo "== $name"
  printf '%s' "$body" >"$OUT/$name.request.json"
  curl -sS "${HDRS[@]}" -d "$body" "$API$path" | jq . >"$OUT/$name.response.json"
}

capture non_streaming_basic /v1/messages \
  '{"model":"'"$MODEL"'","max_tokens":64,"messages":[{"role":"user","content":"Say hi in one word"}]}'

capture count_tokens /v1/messages/count_tokens \
  '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"Count the tokens of this prompt"}]}'

capture system_block_array /v1/messages \
  '{"model":"'"$MODEL"'","max_tokens":64,"system":[{"type":"text","text":"You are terse.","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"Say hi"}]}'

echo "== streaming_sse (raw SSE)"
curl -sS "${HDRS[@]}" -d '{"model":"'"$MODEL"'","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"Say hi in one word"}]}' \
  "$API/v1/messages" >"$OUT/streaming_sse.response.sse"

echo
echo "captures in $OUT — sanitize before touching testdata/ (see README)."
echo "then update the 'Last verified against' line in testdata/conformance/README.md."
