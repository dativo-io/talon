// Command mockprovider is the deterministic OpenAI-compatible provider used
// by the real-OpenShell live smoke (scripts/openshell-live.sh, #482). It is
// the provider boundary of the composition: it records exactly what reached
// it (path, Authorization header, body bytes) and answers a fixed completion,
// so the harness can prove ALLOW count, exact transformed bytes, DENY = zero
// dispatch, and that OpenShell — not Talon — injected the provider credential.
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
	Body          string `json:"body"`
	ReceivedAt    string `json:"received_at"`
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
	rec := record{Seq: s.calls, Path: r.URL.Path, Method: r.Method, Authorization: r.Header.Get("Authorization"), Body: string(body), ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano), Scenario: r.Header.Get("X-Mock-Scenario")}
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

// newHandler builds the provider mux: the OpenAI-compatible route plus the
// harness's state/reset routes. stateFile, when set, is rewritten after
// every provider call with the snapshot taken in that call's critical
// section (serialized by a dedicated mutex so writes never interleave).
func newHandler(st *state, stateFile string, maxBody int64) http.Handler {
	var fileMu sync.Mutex
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
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || int64(len(body)) > maxBody {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		// Tool-calling conversations (the SDK agent) get the scripted tool
		// choices; plain prompts (the curl cases) get the fixed completion.
		if scenario := r.Header.Get("X-Mock-Scenario"); scenario == "" && bytes.Contains(body, []byte(`"tools"`)) {
			r.Header.Set("X-Mock-Scenario", scenarioTools)
		}
		rec, snap := st.record(r, body)
		if stateFile != "" {
			fileMu.Lock()
			_ = os.WriteFile(stateFile, snap.json(), 0o600) //nolint:gosec // operator-provided --state-file path of the test harness
			fileMu.Unlock()
		}
		log.Printf("provider call %d: %s %s body=%d bytes auth=%s scenario=%q", rec.Seq, rec.Method, rec.Path, len(body), describeAuth(rec.Authorization), rec.Scenario)
		if ms := delayMs(r.Header.Get("X-Mock-Delay-Ms")); ms > 0 {
			select {
			case <-time.After(time.Duration(ms) * time.Millisecond):
			case <-r.Context().Done():
				return
			}
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
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "mock provider: unknown route "+r.URL.Path, http.StatusNotFound)
	})
	return mux
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
