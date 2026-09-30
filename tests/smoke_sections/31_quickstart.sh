#!/usr/bin/env bash
# Smoke test section: 31_quickstart
# Sourced by tests/smoke_test.sh — do not run directly.

test_section_31_quickstart() {
  local section="31_quickstart"
  local quick_port; quick_port="$(smoke_free_port)"   # quickstart needs no fixed port
  local quick_base="http://127.0.0.1:${quick_port}"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1

  run_talon init --scaffold --name smoke-quickstart &>/dev/null; true

  local mock_port="18081"
  local mock_log="$dir/quickstart_mock.log"
  local mock_pid=""
  cat > "$dir/mock_openai.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        if self.path.startswith("/v1/chat/completions"):
            payload = {"id":"chatcmpl_quick","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"quickstart smoke ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}
        elif self.path.startswith("/v1/responses"):
            payload = {"id":"resp_quick","output":[{"type":"message","content":[{"type":"output_text","text":"quickstart smoke response"}]}],"usage":{"input_tokens":1,"output_tokens":1}}
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))
    def log_message(self, format, *args):
        return

HTTPServer(("127.0.0.1", 18081), Handler).serve_forever()
PY
  python3 "$dir/mock_openai.py" >"$mock_log" 2>&1 &
  mock_pid=$!

  local qs_log="$dir/quickstart_serve.log"
  if ! OPENAI_API_KEY="" TALON_QUICKSTART_OPENAI_BASE_URL="http://127.0.0.1:${mock_port}" \
    start_owned_talon_server "quickstart server" "$qs_log" "$quick_port" serve --proxy-quickstart --port "$quick_port"; then
    kill "$mock_pid" 2>/dev/null || true
    wait "$mock_pid" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi
  TALON_GATEWAY_PID="$SMOKE_SERVER_PID"

  assert_pass "quickstart banner includes base URL" grep -q "openai_base_url" "$qs_log"
  assert_pass "quickstart banner includes pii default redact" grep -q "pii_default" "$qs_log"

  local code_chat
  code_chat="$(curl -s -o /tmp/talon_qs_chat.json -w '%{http_code}' -X POST "${quick_base}/v1/chat/completions" \
    -H "Authorization: Bearer sk-smoke-test" -H "Content-Type: application/json" \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}')"
  assert_pass "quickstart chat with BYOK returns 200" test "$code_chat" = "200"

  local code_resp
  code_resp="$(curl -s -o /tmp/talon_qs_resp.json -w '%{http_code}' -X POST "${quick_base}/v1/responses" \
    -H "Authorization: Bearer sk-smoke-test" -H "Content-Type: application/json" \
    -d '{"model":"gpt-4o-mini","input":"hello"}')"
  assert_pass "quickstart responses returns 200" test "$code_resp" = "200"

  local code_no_key
  code_no_key="$(curl -s -o /tmp/talon_qs_no_key.json -w '%{http_code}' -X POST "${quick_base}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}')"
  assert_pass "quickstart no-key request returns 401" test "$code_no_key" = "401"

  # Quickstart must NOT inject a synthetic agent key, and tenant agent chat
  # is not mounted in quickstart at all (#285): quickstart never builds the
  # identity registry (#266), so the facade is the only surface. A 404 here
  # proves both: no synthetic agent key exists AND the tenant chat route is
  # absent.
  local code_relocated
  code_relocated="$(curl -s -o /tmp/talon_qs_agent.json -w '%{http_code}' -X POST "${quick_base}/v1/agents/chat/completions" \
    -H "Content-Type: application/json" -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}')"
  assert_pass "tenant agent chat is not mounted in quickstart" test "$code_relocated" = "404"

  local code_emb
  code_emb="$(curl -s -o /tmp/talon_qs_emb.json -w '%{http_code}' -X POST "${quick_base}/v1/embeddings" \
    -H "Authorization: Bearer sk-smoke-test" -H "Content-Type: application/json" -d '{"model":"x","input":"x"}')"
  assert_pass "unsupported embeddings path returns 404 in quickstart mode" test "$code_emb" = "404"

  assert_fail "proxy quickstart is mutually exclusive with gateway flag" run_talon serve --proxy-quickstart --gateway --port 18090
  assert_fail "proxy quickstart non-loopback host fails without unsafe-listen" run_talon serve --proxy-quickstart --host 0.0.0.0 --port 18091

  stop_owned_talon_server "$TALON_GATEWAY_PID" "$quick_port" || true
  TALON_GATEWAY_PID=""
  kill "$mock_pid" 2>/dev/null || true
  wait "$mock_pid" 2>/dev/null || true
  rm -f /tmp/talon_qs_chat.json /tmp/talon_qs_resp.json /tmp/talon_qs_no_key.json /tmp/talon_qs_agent.json /tmp/talon_qs_emb.json
  cd "$REPO_ROOT" || true
}

