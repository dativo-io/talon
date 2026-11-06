package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type providerClient struct {
	t      *testing.T
	base   string
	client *http.Client
}

func newProviderClient(t *testing.T, base string) *providerClient {
	return &providerClient{t: t, base: base, client: &http.Client{Timeout: 3 * time.Second}}
}

// do performs one request and returns status and body; a timeout is a failure
// (the deadlock this test guards against surfaces as a hung call).
func (c *providerClient) do(method, path, body, auth string) (status int, respBody []byte) {
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s did not complete within the timeout: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (c *providerClient) completion(content, auth string) (status int, id string) {
	code, b := c.do(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"`+content+`"}]}`, auth)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	id, _ = out["id"].(string)
	return code, id
}

func (c *providerClient) state() view {
	code, b := c.do(http.MethodGet, "/__state", "", "")
	if code != http.StatusOK {
		c.t.Fatalf("__state: %d", code)
	}
	var v view
	if err := json.Unmarshal(b, &v); err != nil {
		c.t.Fatal(err)
	}
	return v
}

// The provider handler must complete a call (record under lock, snapshot,
// persist, answer) without ever re-entering its own mutex, serve /__state
// consistently, and tolerate concurrent calls (run with -race).
func TestMockProvider_RecordsCallsWithoutDeadlock(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	srv := httptest.NewServer(newHandler(&state{}, stateFile, 1<<20))
	t.Cleanup(srv.Close)
	c := newProviderClient(t, srv.URL)
	const auth = "Bearer sk-injected-by-openshell"

	code, id := c.completion("one", auth)
	if code != http.StatusOK || id != "chatcmpl-mock-1" {
		t.Fatalf("first call: %d %q", code, id)
	}
	st := c.state()
	if st.Calls != 1 || len(st.Records) != 1 || st.Records[0].Authorization != auth || !strings.Contains(st.Records[0].Body, `"content":"one"`) {
		t.Fatalf("state after one call: %+v", st)
	}

	// A second call proves the first did not leave the lock held.
	code, id = c.completion("two", auth)
	if code != http.StatusOK || id != "chatcmpl-mock-2" {
		t.Fatalf("second call: %d %q", code, id)
	}
	if st = c.state(); st.Calls != 2 || len(st.Records) != 2 || st.Records[1].Seq != 2 {
		t.Fatalf("state after two calls: %+v", st)
	}

	persisted := readFile(t, stateFile)
	var fromFile view
	if err := json.Unmarshal(persisted, &fromFile); err != nil || fromFile.Calls != 2 || len(fromFile.Records) != 2 {
		t.Fatalf("state file is not a consistent snapshot: %v %s", err, persisted)
	}
}

// Concurrent calls: count and records stay consistent and the state file is
// a valid snapshot of some prefix of the call sequence.
func TestMockProvider_ConcurrentCalls(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	srv := httptest.NewServer(newHandler(&state{}, stateFile, 1<<20))
	t.Cleanup(srv.Close)
	c := newProviderClient(t, srv.URL)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, _ := c.completion("n", "Bearer x"); code != http.StatusOK {
				t.Errorf("concurrent call status %d", code)
			}
		}()
	}
	wg.Wait()
	if st := c.state(); st.Calls != 16 || len(st.Records) != 16 {
		t.Fatalf("after concurrent calls: calls=%d records=%d", st.Calls, len(st.Records))
	}
	var fromFile view
	if err := json.Unmarshal(readFile(t, stateFile), &fromFile); err != nil || fromFile.Calls == 0 || len(fromFile.Records) != fromFile.Calls {
		t.Fatalf("state file is not a consistent snapshot: %v", err)
	}
}

func TestMockProvider_ResetAndBodyBound(t *testing.T) {
	srv := httptest.NewServer(newHandler(&state{}, "", 128))
	t.Cleanup(srv.Close)
	c := newProviderClient(t, srv.URL)

	if code, _ := c.completion("x", "Bearer x"); code != http.StatusOK {
		t.Fatalf("call: %d", code)
	}
	if code, _ := c.do(http.MethodPost, "/__reset", "", ""); code != http.StatusNoContent {
		t.Fatalf("reset: %d", code)
	}
	if st := c.state(); st.Calls != 0 || len(st.Records) != 0 {
		t.Fatalf("after reset: %+v", st)
	}
	if code, _ := c.do(http.MethodPost, "/v1/chat/completions", strings.Repeat("x", 256), "Bearer x"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", code)
	}
	if st := c.state(); st.Calls != 0 {
		t.Fatalf("an oversized body must not count as a provider call: %+v", st)
	}
}

func TestDescribeAuth_NeverRevealsTheValue(t *testing.T) {
	for in, want := range map[string]string{"": "none", "Bearer sk-secret-123": "bearer(13 chars)", "Basic abc": "other(9 chars)"} {
		if got := describeAuth(in); got != want || strings.Contains(got, "secret") {
			t.Errorf("describeAuth(%q) = %q, want %q", in, got, want)
		}
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The response scenarios the live lane selects per request: PII in the
// body, PII beyond a 4 KiB capture bound, an error envelope with PII, and a
// held answer; the default completion is unchanged.
//
//nolint:gocyclo // one scripted sequence of scenarios
func TestMockProvider_ResponseScenarios(t *testing.T) {
	srv := httptest.NewServer(newHandler(&state{}, "", 1<<20))
	t.Cleanup(srv.Close)
	c := newProviderClient(t, srv.URL)
	call := func(scenario, delay string) (int, []byte) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o-mini","messages":[]}`))
		if scenario != "" {
			req.Header.Set("X-Mock-Scenario", scenario)
		}
		if delay != "" {
			req.Header.Set("X-Mock-Delay-Ms", delay)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	if code, b := call("", ""); code != 200 || !strings.Contains(string(b), "mock completion 1") || strings.Contains(string(b), mockPII) {
		t.Fatalf("default: %d %s", code, b)
	}
	if code, b := call(scenarioResponsePII, ""); code != 200 || !strings.Contains(string(b), mockPII) || !strings.Contains(string(b), `"usage"`) {
		t.Fatalf("response-pii: %d %s", code, b)
	}
	code, b := call(scenarioOversized, "")
	if code != 200 || len(b) < 4096 || !strings.HasSuffix(strings.TrimSpace(string(b)), `}`) || !strings.Contains(string(b), mockPII) {
		t.Fatalf("oversized: %d %d bytes", code, len(b))
	}
	if idx := bytes.Index(b, []byte(mockPII)); idx < 4096 {
		t.Fatalf("oversized: the PII must sit beyond a 4 KiB capture bound, found at %d", idx)
	}
	if code, b := call(scenarioErrorPII, ""); code != http.StatusBadRequest || !strings.Contains(string(b), mockPII) || !strings.Contains(string(b), `"error"`) {
		t.Fatalf("error-pii: %d %s", code, b)
	}
	start := time.Now()
	if code, _ := call("", "300"); code != 200 || time.Since(start) < 300*time.Millisecond {
		t.Fatalf("delay: %d after %s", code, time.Since(start))
	}
	if st := c.state(); st.Calls != 5 || st.Records[1].Scenario != scenarioResponsePII {
		t.Fatalf("state: %+v", st)
	}
	_ = os.Getpid
	var _ sync.Mutex
	_ = json.Valid
}

// A request carrying a tools array is answered by the scripted model: the
// next tool call keyed by the tool results already in the conversation,
// ending in a final answer — the same script the fixture e2e drives.
func TestMockProvider_ToolCallingScript(t *testing.T) {
	srv := httptest.NewServer(newHandler(&state{}, "", 1<<20))
	t.Cleanup(srv.Close)
	c := newProviderClient(t, srv.URL)
	conv := func(toolResults int) string {
		msgs := `{"role":"user","content":"handle the refund"}`
		for i := 0; i < toolResults; i++ {
			msgs += `,{"role":"tool","tool_call_id":"c","content":"{}"}`
		}
		return `{"model":"gpt-4o-mini","messages":[` + msgs + `],"tools":[{"type":"function","function":{"name":"lookup_ticket"}}]}`
	}
	for i, want := range []string{"lookup_ticket", "delete_customer", "create_refund_request", ""} {
		code, b := c.do(http.MethodPost, "/v1/chat/completions", conv(i), "Bearer x")
		if code != 200 {
			t.Fatalf("turn %d: %d %s", i, code, b)
		}
		var out struct {
			Choices []struct {
				FinishReason string `json:"finish_reason"`
				Message      struct {
					ToolCalls []struct {
						Function struct {
							Name string `json:"name"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(b, &out); err != nil || len(out.Choices) != 1 {
			t.Fatalf("turn %d: %v %s", i, err, b)
		}
		if want == "" {
			if out.Choices[0].FinishReason != "stop" || len(out.Choices[0].Message.ToolCalls) != 0 {
				t.Fatalf("turn %d: expected the final answer: %s", i, b)
			}
			continue
		}
		if len(out.Choices[0].Message.ToolCalls) != 1 || out.Choices[0].Message.ToolCalls[0].Function.Name != want {
			t.Fatalf("turn %d: expected tool %s: %s", i, want, b)
		}
	}
	if st := c.state(); st.Calls != 4 || st.Records[0].Scenario != scenarioTools {
		t.Fatalf("state: %+v", st)
	}
}

// The Anthropic Messages API the real Claude Code executable speaks (#528):
// /v1/messages answers JSON, or the complete SSE event sequence (message_start
// with input usage … message_delta with output usage … message_stop) when the
// request streams; /v1/messages/count_tokens answers a count and is recorded
// as its own call; the x-api-key credential, the query string and the user
// agent are recorded so the live lane can assert which binary called and
// with whose credential. Usage is 12/3 on both wires.
func TestMockProvider_AnthropicMessages(t *testing.T) {
	srv := httptest.NewServer(newHandler(&state{}, "", 1<<20))
	t.Cleanup(srv.Close)
	c := newProviderClient(t, srv.URL)
	call := func(path, body string) (int, string, []byte) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", "sk-ant-injected-by-openshell")
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("User-Agent", "claude-cli/2.1.319 (external, sdk-cli)")
		resp, err := c.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Content-Type"), b
	}
	// Non-streaming.
	code, ct, b := call("/v1/messages", `{"model":"claude-sonnet-4-5","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`)
	if code != 200 || ct != "application/json" {
		t.Fatalf("messages json: %d %s %s", code, ct, b)
	}
	var msg struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type, Text string
		} `json:"content"`
		Usage struct{ InputTokens, OutputTokens int }
	}
	if err := json.Unmarshal(b, &msg); err != nil || msg.ID != "msg_mock_1" || msg.Type != "message" || msg.Model != "claude-sonnet-4-5" || msg.StopReason != "end_turn" || len(msg.Content) != 1 || msg.Content[0].Text != "mock anthropic completion 1" {
		t.Fatalf("messages json shape: %v %s", err, b)
	}
	if !strings.Contains(string(b), `"usage":{"input_tokens":12,"output_tokens":3}`) {
		t.Fatalf("messages json usage: %s", b)
	}
	// Streaming: the event order a client needs to terminate, usage split
	// between message_start (input) and message_delta (output).
	code, ct, b = call("/v1/messages?beta=true", `{"model":"claude-sonnet-4-5","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if code != 200 || ct != "text/event-stream" {
		t.Fatalf("messages sse: %d %s %s", code, ct, b)
	}
	events := []string{}
	for _, block := range strings.Split(strings.TrimSpace(string(b)), "\n\n") {
		lines := strings.SplitN(block, "\n", 2)
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "event: ") || !strings.HasPrefix(lines[1], "data: ") || !json.Valid([]byte(strings.TrimPrefix(lines[1], "data: "))) {
			t.Fatalf("malformed SSE block %q", block)
		}
		events = append(events, strings.TrimPrefix(lines[0], "event: "))
	}
	if strings.Join(events, ",") != "message_start,content_block_start,content_block_delta,content_block_stop,message_delta,message_stop" {
		t.Fatalf("sse event order: %v", events)
	}
	if !strings.Contains(string(b), `"usage":{"input_tokens":12,"output_tokens":1}`) || !strings.Contains(string(b), `"usage":{"output_tokens":3}`) || !strings.Contains(string(b), `"text":"mock anthropic completion 2"`) {
		t.Fatalf("sse usage/text: %s", b)
	}
	// count_tokens is its own recorded call and never a completion.
	code, _, b = call("/v1/messages/count_tokens", `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`)
	if code != 200 || string(b) != `{"input_tokens":42}` {
		t.Fatalf("count_tokens: %d %s", code, b)
	}
	// Error scenario keeps the Anthropic error envelope.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/messages", strings.NewReader(`{"model":"m","messages":[]}`))
	req.Header.Set("X-Mock-Scenario", scenarioErrorPII)
	resp, err := c.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	eb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(eb), `"type":"error"`) || !strings.Contains(string(eb), mockPII) {
		t.Fatalf("error-pii anthropic: %d %s", resp.StatusCode, eb)
	}
	// Truncated stream: the head and the first events arrive, then the
	// connection closes before message_delta/message_stop.
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/messages", strings.NewReader(`{"model":"m","stream":true,"messages":[]}`))
	req.Header.Set("X-Mock-Scenario", scenarioTruncatedStream)
	resp, err = c.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	tb, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("truncated-stream head: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(tb), "event: message_start") || strings.Contains(string(tb), "message_stop") || strings.Contains(string(tb), "message_delta") {
		t.Fatalf("truncated-stream body must start and never terminate: err=%v body=%q", readErr, tb)
	}
	st := c.state()
	if st.Calls != 5 || len(st.Records) != 5 {
		t.Fatalf("calls: %+v", st)
	}
	r0, r1, r2 := st.Records[0], st.Records[1], st.Records[2]
	if r0.Path != "/v1/messages" || r0.XAPIKey != "sk-ant-injected-by-openshell" || r0.Authorization != "" || r0.Stream || !strings.Contains(r0.UserAgent, "claude-cli/2.1.319") || r0.AnthropicVersion != "2023-06-01" {
		t.Fatalf("record 0: %+v", r0)
	}
	if r1.Path != "/v1/messages" || r1.Query != "beta=true" || !r1.Stream {
		t.Fatalf("record 1 (streamed, with query): %+v", r1)
	}
	if r2.Path != "/v1/messages/count_tokens" || r2.Stream {
		t.Fatalf("record 2 (count_tokens): %+v", r2)
	}
	if got := describeKey("sk-ant-secret"); got != "key(13 chars)" || strings.Contains(got, "secret") {
		t.Fatalf("describeKey = %q", got)
	}
	// The chat-completions route is unchanged by the Anthropic additions.
	if code, id := c.completion("still here", "Bearer x"); code != 200 || id != "chatcmpl-mock-6" {
		t.Fatalf("chat completions after anthropic calls: %d %q", code, id)
	}
}
