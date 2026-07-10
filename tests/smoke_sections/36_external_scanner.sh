#!/usr/bin/env bash
# Smoke test section: 36_external_scanner
# Sourced by tests/smoke_test.sh — do not run directly.

# -----------------------------------------------------------------------------
# SECTION 36 — External scanner engines: llama/llm (issue #181)
# Talon's PII scanner replaced by a local llama-style model behind the
# OpenAI-compatible wire protocol (scanner.type: llm — exactly how Ollama is
# consumed). Hermetic by default: a deterministic llama stand-in (mock NER
# model speaking /v1/models + /v1/chat/completions) plays the engine, and a
# second mock plays the upstream LLM provider so no external services or API
# keys are needed.
#   A) startup fail-closed: scanner configured against a dead endpoint ->
#      talon serve refuses to start (eager health probe).
#   B) detection + redaction end-to-end: PII prompt -> llm engine detects ->
#      gateway redacts before the upstream provider sees it -> evidence
#      records engine identity llm:<model> and prompt version llm-ner/v1.
#   C) runtime fail-closed: engine killed mid-flight -> request blocked with
#      502 scanner_unavailable, denial evidenced (allowed=false).
#   D) optional real llama: set TALON_SMOKE_OLLAMA_URL (e.g.
#      http://localhost:11434) to re-run the detection scenario against a
#      real Ollama with TALON_SMOKE_OLLAMA_MODEL (default llama3.2:1b).
#      Only pipeline health is asserted there — recall is model-dependent.
# -----------------------------------------------------------------------------

# Ports for the two mocks; nothing may listen on the dead one.
readonly SMOKE36_ENGINE_PORT="59981"
readonly SMOKE36_UPSTREAM_PORT="59982"
readonly SMOKE36_DEAD_PORT="59979"
readonly SMOKE36_MODEL="llama3.2:1b"

# smoke36_write_mock writes the llama stand-in: an OpenAI-compatible server
# that either answers NER requests deterministically (MODE=ner: regex over the
# user message for emails and DE IBANs, returned as the {"entities":[...]}
# JSON Talon's llm scanner prompt demands) or plays the upstream LLM provider
# (MODE=upstream: logs each request body to REQLOG, returns a canned reply).
smoke36_write_mock() {
  local dir="$1"
  cat > "$dir/llm_mock.go" <<'GOEOF'
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"
)

type chatReq struct {
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

func completion(content string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"id": "chatcmpl-smoke36", "object": "chat.completion",
		"choices": []map[string]interface{}{{
			"message":       map[string]string{"role": "assistant", "content": content},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
	})
	return b
}

func main() {
	mode := flag.String("mode", "ner", "ner | upstream")
	port := flag.String("port", "0", "listen port")
	model := flag.String("model", "mock", "model id for /v1/models")
	reqlog := flag.String("reqlog", "", "upstream request log file")
	flag.Parse()
	emailRe := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	ibanRe := regexp.MustCompile(`DE[0-9]{20}`)
	var mu sync.Mutex

	http.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"object":"list","data":[{"id":%q}]}`, *model)
	})
	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req chatReq
		raw := json.NewDecoder(r.Body)
		if err := raw.Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		user := ""
		for _, m := range req.Messages {
			if m.Role == "user" {
				user = m.Content
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if *mode == "upstream" {
			if *reqlog != "" {
				mu.Lock()
				f, err := os.OpenFile(*reqlog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
				if err == nil {
					body, _ := json.Marshal(req)
					fmt.Fprintf(f, "%s\n", body)
					_ = f.Close()
				}
				mu.Unlock()
			}
			_, _ = w.Write(completion("All done."))
			return
		}
		// NER mode: deterministic llama stand-in for Talon's llm-ner prompt.
		type det struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		dets := []det{}
		seen := map[string]bool{}
		for _, v := range emailRe.FindAllString(user, -1) {
			if !seen[v] {
				seen[v] = true
				dets = append(dets, det{Type: "EMAIL_ADDRESS", Value: v})
			}
		}
		for _, v := range ibanRe.FindAllString(user, -1) {
			if !seen[v] {
				seen[v] = true
				dets = append(dets, det{Type: "IBAN_CODE", Value: v})
			}
		}
		ner, _ := json.Marshal(map[string]interface{}{"entities": dets})
		_, _ = w.Write(completion(string(ner)))
	})
	//nolint:errcheck
	_ = http.ListenAndServe("127.0.0.1:"+*port, nil)
}
GOEOF
}

smoke36_wait_port() {
  local port="$1" waited=0
  while ! is_port_in_use "$port" && [[ $waited -lt 60 ]]; do
    sleep 1
    ((waited += 1))
  done
  is_port_in_use "$port"
}

# smoke36_scanner_config appends/replaces the scanner block in talon.config.yaml.
smoke36_scanner_config() {
  local cfg="$1" endpoint="$2" model="$3"
  # Drop any previous scanner block (ours is always appended last).
  sed -i.bak '/^# smoke36 scanner$/,$d' "$cfg" && rm -f "$cfg.bak"
  cat >> "$cfg" <<SCEOF

# smoke36 scanner
scanner:
  type: llm
  endpoint: "${endpoint}"
  timeout: "30s"
  llm:
    model: "${model}"
SCEOF
}

test_section_36_external_scanner() {
  local section="36_external_scanner"
  local gateway_port="8080"
  local gateway_base_url="http://127.0.0.1:${gateway_port}"
  local dir; dir="$(setup_section_dir "$section")"
  cd "$dir" || exit 1
  if ! wait_port_free "$gateway_port" 180 10; then
    log_failure "external-scanner section could not acquire port ${gateway_port}" "port remained busy"
    cd "$REPO_ROOT" || true
    return 0
  fi
  run_talon init --scaffold --name smoke-agent &>/dev/null; true
  smoke_bind_agent_key "$dir" "${scan_key}"
  smoke_tighten_limits "$dir"
  if [[ ! -f "$dir/talon.config.yaml" ]]; then
    echo "  -  (skip external-scanner: no config)"
    cd "$REPO_ROOT" || true
    return 0
  fi

  local scan_key="talon-gw-scanner-001"
  local reqlog="$dir/upstream_requests.log"
  smoke36_write_mock "$dir"

  # Upstream provider mock uses client_bearer so no vault credential is needed.
  local gw_cfg="$dir/talon.gateway.scanner.yaml"
  cat > "$gw_cfg" <<GWEOF
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "enforce"
  providers:
    openai:
      enabled: true
      upstream_auth_mode: "client_bearer"
      base_url: "http://127.0.0.1:${SMOKE36_UPSTREAM_PORT}"
      region: "EU"
  organization_policy:
    default_pii_action: "redact"
    max_daily_cost: 100.00
GWEOF

  # --- Scenario A: dead engine endpoint -> serve refuses to start ---
  smoke36_scanner_config "$dir/talon.config.yaml" "http://127.0.0.1:${SMOKE36_DEAD_PORT}/v1" "$SMOKE36_MODEL"
  local dead_log="$dir/serve_dead_engine.log"
  env TALON_DATA_DIR="$TALON_DATA_DIR" talon serve --port "$gateway_port" --gateway --gateway-config "$gw_cfg" >"$dead_log" 2>&1 &
  local dead_pid=$! waited=0
  while kill -0 "$dead_pid" 2>/dev/null && [[ $waited -lt 20 ]]; do
    sleep 1
    ((waited += 1))
  done
  if kill -0 "$dead_pid" 2>/dev/null; then
    log_failure "serve must refuse to start when the llm scanner engine is unreachable" "process still alive after ${waited}s"
    smoke_stop_gateway_35 "$dead_pid" "$gateway_port"
  else
    assert_pass "serve refuses to start against a dead llm scanner engine (fail-closed startup)" \
      grep -q "refuses to start" "$dead_log"
  fi

  # --- Start the llama stand-in (NER engine) and the upstream provider mock ---
  # Built once and run directly so PIDs point at the servers themselves
  # (backgrounding go run through a subshell leaves $! on a wrapper; killing
  # it would orphan the listener — same trap section 35 documents).
  local engine_log="$dir/engine_mock.log" upstream_log="$dir/upstream_mock.log"
  if ! go build -o "$dir/llm_mock" "$dir/llm_mock.go" 2>"$dir/mock_build.log"; then
    log_failure "llama stand-in mock failed to build" "$(cat "$dir/mock_build.log" 2>/dev/null)"
    cd "$REPO_ROOT" || true
    return 0
  fi
  "$dir/llm_mock" -mode=ner -port="$SMOKE36_ENGINE_PORT" -model="$SMOKE36_MODEL" >"$engine_log" 2>&1 &
  local engine_pid=$!
  "$dir/llm_mock" -mode=upstream -port="$SMOKE36_UPSTREAM_PORT" -model="mock-upstream" -reqlog="$reqlog" >"$upstream_log" 2>&1 &
  local upstream_pid=$!
  if ! smoke36_wait_port "$SMOKE36_ENGINE_PORT" || ! smoke36_wait_port "$SMOKE36_UPSTREAM_PORT"; then
    log_failure "llama stand-in mocks did not start" "engine_port=${SMOKE36_ENGINE_PORT} upstream_port=${SMOKE36_UPSTREAM_PORT}"
    dump_diag_file "engine mock log" "$engine_log"
    kill "$engine_pid" "$upstream_pid" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi

  # --- Scenario B: detection + redaction through the llm engine ---
  smoke36_scanner_config "$dir/talon.config.yaml" "http://127.0.0.1:${SMOKE36_ENGINE_PORT}/v1" "$SMOKE36_MODEL"
  local gw_log="$dir/gateway_scanner.log"
  env TALON_DATA_DIR="$TALON_DATA_DIR" talon serve --port "$gateway_port" --gateway --gateway-config "$gw_cfg" >"$gw_log" 2>&1 &
  local gw_pid=$!
  if ! smoke_wait_health "$gateway_base_url" 15 1; then
    log_failure "gateway with llm scanner did not start" "pid=$gw_pid"
    dump_diag_file "section 36 serve log" "$gw_log"
    smoke_stop_gateway_35 "$gw_pid" "$gateway_port"
    kill "$engine_pid" "$upstream_pid" 2>/dev/null || true
    cd "$REPO_ROOT" || true
    return 0
  fi
  assert_pass "serve announces the llm scanner engine as active" \
    grep -q "external PII scanner engine active" "$gw_log"

  local code
  code="$(smoke_gw_post_chat "$gateway_base_url" "Bearer $scan_key" "$SMOKE_BODY_PII")"
  if ! assert_pass "PII prompt through llm scanner is redacted and forwarded (200)" test "$code" = "200"; then
    dump_diag_kv "section 36 PII POST" "http_code=$code"
    dump_diag_file "section 36 serve log" "$gw_log" 50
  fi
  assert_pass "raw email never reaches the upstream provider" \
    bash -c "! grep -q 'jan.kowalski@example.com' '$reqlog'"
  assert_pass "upstream provider receives [EMAIL] placeholder instead" \
    grep -q '\[EMAIL\]' "$reqlog"
  assert_pass "upstream provider receives [IBAN] placeholder instead" \
    grep -q '\[IBAN\]' "$reqlog"

  local export_out
  export_out="$(run_talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)"; true
  assert_pass "evidence records the llm engine identity (llm:${SMOKE36_MODEL})" \
    grep -q "llm:${SMOKE36_MODEL}" <<< "$export_out"
  assert_pass "evidence records the versioned NER prompt (llm-ner/v1)" \
    grep -q "llm-ner/v1" <<< "$export_out"

  # --- Scenario C: engine dies mid-flight -> fail-closed 502 + denial evidence ---
  kill "$engine_pid" 2>/dev/null || true
  wait "$engine_pid" 2>/dev/null || true
  local waited_engine=0
  while is_port_in_use "$SMOKE36_ENGINE_PORT" && [[ $waited_engine -lt 10 ]]; do
    pkill -f "llm_mock -mode=ner" 2>/dev/null || true
    sleep 1
    ((waited_engine += 1))
  done

  local fc_body="/tmp/talon_scanner_fc.json" fc_code
  fc_code="$(smoke_gw_post_chat_to_file "$gateway_base_url" "Bearer $scan_key" "$SMOKE_BODY_PII" "$fc_body")"
  if ! assert_pass "request is blocked fail-closed when the llm engine dies (502)" test "$fc_code" = "502"; then
    dump_diag_kv "section 36 fail-closed POST" "http_code=$fc_code"
    dump_diag_json "fail-closed body" "$(cat "$fc_body" 2>/dev/null || echo '(missing)')"
  fi
  assert_pass "fail-closed body names the scanner outage (scanner_unavailable)" \
    grep -q "scanner" "$fc_body"

  export_out="$(run_talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)"; true
  assert_pass "scanner outage denial is evidenced (scanner unavailable reason)" \
    grep -q "scanner unavailable" <<< "$export_out"

  smoke_stop_gateway_35 "$gw_pid" "$gateway_port"

  # --- Scenario D (optional): real llama via Ollama ---
  if [[ -n "${TALON_SMOKE_OLLAMA_URL:-}" ]]; then
    local ollama_model="${TALON_SMOKE_OLLAMA_MODEL:-llama3.2:1b}"
    if curl -fsS "${TALON_SMOKE_OLLAMA_URL}/v1/models" 2>/dev/null | grep -q "$ollama_model"; then
      smoke36_scanner_config "$dir/talon.config.yaml" "${TALON_SMOKE_OLLAMA_URL}/v1" "$ollama_model"
      # Real models are slow on CPU: widen the scan budget.
      sed -i.bak 's/timeout: "30s"/timeout: "120s"/' "$dir/talon.config.yaml" && rm -f "$dir/talon.config.yaml.bak"
      if wait_port_free "$gateway_port" 60 5; then
        local gw_log_d="$dir/gateway_ollama.log"
        env TALON_DATA_DIR="$TALON_DATA_DIR" talon serve --port "$gateway_port" --gateway --gateway-config "$gw_cfg" >"$gw_log_d" 2>&1 &
        local gw_pid_d=$!
        if smoke_wait_health "$gateway_base_url" 20 1; then
          local code_d
          code_d="$(smoke_gw_post_chat "$gateway_base_url" "Bearer $scan_key" "$SMOKE_BODY_PII")"
          # Recall is model-dependent; assert only that the real-llama scan
          # pipeline completes (no engine failure) and is evidenced.
          if ! assert_pass "real Ollama llama engine scans end-to-end (200, model ${ollama_model})" test "$code_d" = "200"; then
            dump_diag_file "section 36 ollama serve log" "$gw_log_d" 50
          fi
          export_out="$(run_talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)"; true
          assert_pass "real Ollama engine identity is evidenced (llm:${ollama_model})" \
            grep -q "llm:${ollama_model}" <<< "$export_out"
        else
          log_failure "gateway with real Ollama scanner did not start" "pid=$gw_pid_d"
          dump_diag_file "section 36 ollama serve log" "$gw_log_d"
        fi
        smoke_stop_gateway_35 "$gw_pid_d" "$gateway_port"
      fi
    else
      echo "  -  (skip real-Ollama scenario: ${ollama_model} not available at ${TALON_SMOKE_OLLAMA_URL})"
    fi
  else
    echo "  -  (real-Ollama scenario off: set TALON_SMOKE_OLLAMA_URL to enable)"
  fi

  # Cleanup: mocks and any stragglers (wait suppresses job-control noise).
  kill "$engine_pid" "$upstream_pid" 2>/dev/null || true
  wait "$engine_pid" "$upstream_pid" 2>/dev/null || true
  pkill -f "llm_mock -mode=" 2>/dev/null || true
  rm -f "$fc_body" 2>/dev/null || true
  cd "$REPO_ROOT" || true
}
