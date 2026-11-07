// Command mockprovider is the deterministic provider used by the
// real-OpenShell live smoke (scripts/openshell-live.sh, #482): OpenAI
// chat-completions for the curl and SDK-agent lanes, and the Anthropic
// Messages API (/v1/messages incl. SSE, /v1/messages/count_tokens) for the
// real Claude Code lane (#528). It is the provider boundary of the
// composition: it records exactly what reached it (path, query, credential
// headers, body bytes) and answers a fixed completion, so the harness can
// prove ALLOW count, exact transformed bytes, DENY = zero dispatch, and that
// OpenShell — not Talon — injected the provider credential.
// No real LLM, no spend, no private key.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type record struct {
	Seq           int    `json:"seq"`
	Path          string `json:"path"`
	Method        string `json:"method"`
	Authorization string `json:"authorization"`
	// XAPIKey is the Anthropic-family credential header as received; like
	// Authorization it is the value OpenShell injected (the state file is
	// never collected, the logs only ever carry its shape).
	XAPIKey string `json:"x_api_key,omitempty"`
	// Query is the raw query string (Claude Code calls /v1/messages?beta=true).
	Query     string `json:"query,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	// AnthropicVersion / AnthropicBeta are the Anthropic protocol headers as
	// received (forwarded verbatim by OpenShell; recorded as run facts).
	AnthropicVersion string `json:"anthropic_version,omitempty"`
	AnthropicBeta    string `json:"anthropic_beta,omitempty"`
	// Stream is the request's "stream": true (an SSE answer was produced).
	Stream     bool   `json:"stream"`
	Body       string `json:"body"`
	ReceivedAt string `json:"received_at"`
	// Scenario is the response shape the caller asked for (X-Mock-Scenario).
	Scenario string `json:"scenario,omitempty"`
}

// Response scenarios the harness selects per request through the
// X-Mock-Scenario header (carried from the sandbox through OpenShell to the
// provider untouched). They exercise Talon's RESPONSE side against the
// real runtime: a body with PII, a body beyond the capture bound with PII
// past the bound, and an error envelope echoing PII. X-Mock-Delay-Ms holds
// the answer so the harness can restart Talon between request and response.
const (
	scenarioDefault     = ""
	scenarioResponsePII = "response-pii"
	scenarioOversized   = "oversized"
	scenarioErrorPII    = "error-pii"
	// scenarioTools is the deterministic MODEL for the tool-using agent: it
	// reads the conversation and chooses the next tool — look the ticket up,
	// try the forbidden deletion, request the refund, then answer — keyed by
	// how many tool results the conversation already carries. Selected
	// automatically when the request carries a tools array.
	scenarioTools = "tools"
	// scenarioTruncatedStream (Anthropic wire, streamed requests only): the
	// provider closes the connection after the first events, before the
	// terminal message_delta/message_stop — the "interrupted SSE" case whose
	// settlement must not claim a completed response.
	scenarioTruncatedStream = "truncated-stream"
	// mockPII is the sensitive value the scenarios carry; the harness asserts
	// it never reaches the sandbox under a preventive policy and never
	// appears in Talon's evidence or logs.
	mockPII      = "jane.doe@example.com"
	maxDelayMs   = 30000
	oversizedPad = 5000
)

type state struct {
	mu      sync.Mutex
	calls   int
	records []record
}

// view is the serialized shape of the state.
type view struct {
	Calls   int      `json:"calls"`
	Records []record `json:"records"`
}

// record appends one provider call under the lock and returns the record
// plus a snapshot of the state taken in the SAME critical section, so the
// count, the record list and what gets persisted/served can never
// disagree. sync.Mutex is not reentrant: nothing here calls back into a
// locking method.
func (s *state) record(r *http.Request, body []byte) (record, view) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	rec := record{Seq: s.calls, Path: r.URL.Path, Method: r.Method, Authorization: r.Header.Get("Authorization"), XAPIKey: r.Header.Get("X-Api-Key"), Query: r.URL.RawQuery, UserAgent: r.Header.Get("User-Agent"), AnthropicVersion: r.Header.Get("Anthropic-Version"), AnthropicBeta: r.Header.Get("Anthropic-Beta"), Stream: wantsStream(body), Body: string(body), ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano), Scenario: r.Header.Get("X-Mock-Scenario")}
	s.records = append(s.records, rec)
	return rec, s.viewLocked()
}

// viewLocked copies the state; the caller holds s.mu.
func (s *state) viewLocked() view {
	return view{Calls: s.calls, Records: append([]record(nil), s.records...)}
}

func (s *state) snapshot() view {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewLocked()
}

func (s *state) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls, s.records = 0, nil
}

func (v view) json() []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// recorder is the part of every provider route that is independent of the
// wire: it reads the body within the bound, records the call under the
// state lock, persists the snapshot (serialized by fileMu so writes never
// interleave) and honours X-Mock-Delay-Ms before the route answers.
type recorder struct {
	st        *state
	stateFile string
	maxBody   int64
	fileMu    sync.Mutex
}

// take returns false when the request was refused unrecorded (an oversized
// body is not a provider call) or abandoned while delaying.
func (rc *recorder) take(w http.ResponseWriter, r *http.Request) (record, []byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, rc.maxBody+1))
	if err != nil || int64(len(body)) > rc.maxBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return record{}, nil, false
	}
	rec, snap := rc.st.record(r, body)
	if rc.stateFile != "" {
		rc.fileMu.Lock()
		_ = os.WriteFile(rc.stateFile, snap.json(), 0o600) //nolint:gosec // operator-provided --state-file path of the test harness
		rc.fileMu.Unlock()
	}
	log.Printf("provider call %d: %s %s body=%d bytes auth=%s x-api-key=%s stream=%t scenario=%q ua=%q", rec.Seq, rec.Method, rec.Path, len(body), describeAuth(rec.Authorization), describeKey(rec.XAPIKey), rec.Stream, rec.Scenario, rec.UserAgent)
	if ms := delayMs(r.Header.Get("X-Mock-Delay-Ms")); ms > 0 {
		select {
		case <-time.After(time.Duration(ms) * time.Millisecond):
		case <-r.Context().Done():
			return record{}, nil, false
		}
	}
	return rec, body, true
}

// newHandler builds the provider mux: the OpenAI-compatible route, the
// Anthropic Messages routes and the harness's state/reset routes.
// stateFile, when set, is rewritten after every provider call with the
// snapshot taken in that call's critical section.
func newHandler(st *state, stateFile string, maxBody int64) http.Handler {
	rc := &recorder{st: st, stateFile: stateFile, maxBody: maxBody}
	mux := http.NewServeMux()
	mux.HandleFunc("/__state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(st.snapshot().json())
	})
	mux.HandleFunc("/__reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		st.reset()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/chat/completions", rc.chatCompletions)
	// Anthropic Messages API — what the real Claude Code executable speaks.
	// count_tokens is answered with a fixed count and never a completion;
	// /v1/messages answers JSON or, when the request says "stream": true,
	// the SSE event sequence a client needs to terminate cleanly
	// (message_start … message_delta with usage … message_stop).
	mux.HandleFunc("/v1/messages/count_tokens", rc.countTokens)
	mux.HandleFunc("/v1/messages", rc.messages)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "mock provider: unknown route "+r.URL.Path, http.StatusNotFound)
	})
	return mux
}

// chatCompletions is the OpenAI-compatible route. Tool-calling conversations
// (the SDK agent) get the scripted tool choices; plain prompts (the curl
// cases) get the fixed completion. Decided before recording so the record
// carries the scenario.
func (rc *recorder) chatCompletions(w http.ResponseWriter, r *http.Request) {
	if scenario := r.Header.Get("X-Mock-Scenario"); scenario == "" && r.ContentLength != 0 {
		peek, err := io.ReadAll(io.LimitReader(r.Body, rc.maxBody+1))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(peek))
		if int64(len(peek)) <= rc.maxBody && bytes.Contains(peek, []byte(`"tools"`)) {
			r.Header.Set("X-Mock-Scenario", scenarioTools)
		}
	}
	rec, body, ok := rc.take(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var status int
	var answer []byte
	if rec.Scenario == scenarioTools {
		status, answer = toolsResponse(body, rec.Seq)
	} else {
		status, answer = scenarioResponse(rec.Scenario, rec.Seq)
	}
	w.WriteHeader(status)
	_, _ = w.Write(answer)
}

func (rc *recorder) countTokens(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := rc.take(w, r); !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"input_tokens":42}`))
}

func (rc *recorder) messages(w http.ResponseWriter, r *http.Request) {
	rec, body, ok := rc.take(w, r)
	if !ok {
		return
	}
	status, contentType, answer := anthropicResponse(rec.Scenario, rec.Seq, requestModel(body), rec.Stream)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	if rec.Scenario == scenarioTruncatedStream && rec.Stream {
		writeTruncatedStream(w, answer)
		return
	}
	_, _ = w.Write(answer)
}

// writeTruncatedStream is the provider dying mid-stream: the head and the
// first events go out, then the connection is closed without
// message_delta / message_stop. Hijack so no framing is completed for the
// client.
func writeTruncatedStream(w http.ResponseWriter, answer []byte) {
	cut := bytes.Index(answer, []byte("event: content_block_stop"))
	if cut < 0 {
		cut = len(answer) / 2
	}
	_, _ = w.Write(answer[:cut])
	if f, ok := w.(http.Flusher); ok {
		f.Flush() // the partial events must reach the wire before the connection is dropped
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	if conn, buf, err := hj.Hijack(); err == nil {
		_ = buf.Flush()
		_ = conn.Close()
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18090", "address to serve on (must be reachable from the OpenShell sandbox containers)")
	stateFile := flag.String("state-file", "", "optional path rewritten with the JSON state after every provider call")
	maxBody := flag.Int64("max-body", 4<<20, "maximum accepted request body in bytes")
	flag.Parse()
	srv := &http.Server{Addr: *listen, Handler: newHandler(&state{}, *stateFile, *maxBody), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("mock provider listening on %s", *listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// toolsResponse is the scripted model's next step for a tool-calling
// conversation on the OpenAI chat-completions wire. The script ignores the
// tool list it was offered — a model asking for a tool it was not given is
// exactly the case Talon's execution boundary must refuse.
func toolsResponse(reqBody []byte, seq int) (status int, body []byte) {
	var req struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(reqBody, &req)
	toolResults := 0
	for _, m := range req.Messages {
		if m.Role == "tool" {
			toolResults++
		}
	}
	var msg, finish string
	switch toolResults {
	case 0:
		msg, finish = `{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup_ticket","arguments":"{\"ticket_id\":\"T-1842\"}"}}]}`, "tool_calls"
	case 1:
		msg, finish = `{"role":"assistant","content":null,"tool_calls":[{"id":"call_2","type":"function","function":{"name":"delete_customer","arguments":"{\"customer_id\":\"c-9\"}"}}]}`, "tool_calls"
	case 2:
		msg, finish = `{"role":"assistant","content":null,"tool_calls":[{"id":"call_3","type":"function","function":{"name":"create_refund_request","arguments":"{\"ticket_id\":\"T-1842\",\"amount\":50,\"currency\":\"EUR\"}"}}]}`, "tool_calls"
	default:
		msg, finish = `{"role":"assistant","content":"Ticket T-1842 handled: the EUR 50 refund request was approved by a reviewer and submitted once."}`, "stop"
	}
	return http.StatusOK, []byte(fmt.Sprintf(`{"id":"chatcmpl-mock-%d","object":"chat.completion","created":%d,"model":"gpt-4o-mini","choices":[{"index":0,"message":%s,"finish_reason":"%s"}],"usage":{"prompt_tokens":%d,"completion_tokens":12,"total_tokens":%d}}`,
		seq, time.Now().Unix(), msg, finish, 40+10*toolResults, 52+10*toolResults))
}

// scenarioResponse is the provider's answer for one scenario: the default
// completion carries usage 12/3 so the harness can assert priced actuals.
func scenarioResponse(scenario string, seq int) (status int, body []byte) {
	completion := func(content string) []byte {
		return []byte(fmt.Sprintf(`{"id":"chatcmpl-mock-%d","object":"chat.completion","created":%d,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"%s"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":3,"total_tokens":15}}`, seq, time.Now().Unix(), content))
	}
	switch scenario {
	case scenarioResponsePII:
		return http.StatusOK, completion("please contact " + mockPII + " about the refund")
	case scenarioOversized:
		return http.StatusOK, completion(strings.Repeat("x", oversizedPad) + " then mail " + mockPII)
	case scenarioErrorPII:
		return http.StatusBadRequest, []byte(`{"error":{"message":"invalid request: the input mentions ` + mockPII + `","type":"invalid_request_error"}}`)
	default:
		return http.StatusOK, completion(fmt.Sprintf("mock completion %d", seq))
	}
}

// anthropicResponse is the Messages API answer for one scenario. Usage is the
// same 12 input / 3 output tokens as the chat-completions default, so the
// harness's priced-settlement assertions hold on either wire. The streamed
// form carries the usage split the way Anthropic does: input tokens in
// message_start, output tokens in message_delta.
func anthropicResponse(scenario string, seq int, model string, stream bool) (status int, contentType string, body []byte) {
	text := fmt.Sprintf("mock anthropic completion %d", seq)
	switch scenario {
	case scenarioResponsePII:
		text = "please contact " + mockPII + " about the refund"
	case scenarioOversized:
		text = strings.Repeat("x", oversizedPad) + " then mail " + mockPII
	case scenarioErrorPII:
		return http.StatusBadRequest, "application/json", []byte(`{"type":"error","error":{"type":"invalid_request_error","message":"invalid request: the input mentions ` + mockPII + `"}}`)
	}
	id := fmt.Sprintf("msg_mock_%d", seq)
	// Every body is marshalled from typed values: the model echoes a
	// request-derived string and must be JSON-escaped, never quoted by hand.
	usageOf := func(in, out int) anthropicUsage { return anthropicUsage{InputTokens: &in, OutputTokens: out} }
	if !stream {
		msg := anthropicMessage{ID: id, Type: "message", Role: "assistant", Model: model, Content: []anthropicBlock{{Type: "text", Text: text}}, StopReason: strPtr("end_turn"), Usage: usageOf(12, 3)}
		return http.StatusOK, "application/json", mustJSON(msg)
	}
	var b strings.Builder
	event := func(name string, data any) { fmt.Fprintf(&b, "event: %s\ndata: %s\n\n", name, mustJSON(data)) }
	event("message_start", map[string]any{"type": "message_start", "message": anthropicMessage{ID: id, Type: "message", Role: "assistant", Model: model, Content: []anthropicBlock{}, Usage: usageOf(12, 1)}})
	event("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": anthropicBlock{Type: "text", Text: ""}})
	event("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": text}})
	event("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	event("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": anthropicUsage{OutputTokens: 3}})
	event("message_stop", map[string]any{"type": "message_stop"})
	return http.StatusOK, "text/event-stream", []byte(b.String())
}

// anthropicMessage is the Messages API object the mock returns (field order
// as Anthropic emits it; stop_reason/stop_sequence are null while open).
type anthropicMessage struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"`
	Role         string           `json:"role"`
	Model        string           `json:"model"`
	Content      []anthropicBlock `json:"content"`
	StopReason   *string          `json:"stop_reason"`
	StopSequence *string          `json:"stop_sequence"`
	Usage        anthropicUsage   `json:"usage"`
}

type anthropicBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// anthropicUsage is the usage object; input_tokens is absent in
// message_delta, where only the output count is reported.
type anthropicUsage struct {
	InputTokens  *int `json:"input_tokens,omitempty"`
	OutputTokens int  `json:"output_tokens"`
}

func strPtr(s string) *string { return &s }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // fixed shapes of the test double; a marshal failure is a programming error
	}
	return b
}

// requestModel reads the model field of a JSON request body ("" when absent).
func requestModel(body []byte) string {
	var req struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &req)
	if req.Model == "" {
		return "mock-model"
	}
	return req.Model
}

// wantsStream reports a JSON request body carrying "stream": true.
func wantsStream(body []byte) bool {
	var req struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &req)
	return req.Stream
}

// describeKey logs the SHAPE of an x-api-key credential, never its value.
func describeKey(h string) string {
	if h == "" {
		return "none"
	}
	return fmt.Sprintf("key(%d chars)", len(h))
}

func delayMs(h string) int {
	if h == "" {
		return 0
	}
	n, err := strconv.Atoi(h)
	if err != nil || n < 0 {
		return 0
	}
	if n > maxDelayMs {
		return maxDelayMs
	}
	return n
}

// describeAuth logs the SHAPE of the credential, never its value.
func describeAuth(h string) string {
	switch {
	case h == "":
		return "none"
	case len(h) > 7 && h[:7] == "Bearer ":
		return fmt.Sprintf("bearer(%d chars)", len(h)-7)
	default:
		return fmt.Sprintf("other(%d chars)", len(h))
	}
}
