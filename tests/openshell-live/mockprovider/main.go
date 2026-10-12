// Command mockprovider is the deterministic OpenAI-compatible provider used
// by the real-OpenShell live smoke (scripts/openshell-live.sh, #482). It is
// the provider boundary of the composition: it records exactly what reached
// it (path, Authorization header, body bytes) and answers a fixed completion,
// so the harness can prove ALLOW count, exact transformed bytes, DENY = zero
// dispatch, and that OpenShell — not Talon — injected the provider credential.
// No real LLM, no spend, no private key.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
}

type state struct {
	mu      sync.Mutex
	Calls   int      `json:"calls"`
	Records []record `json:"records"`
}

func (s *state) snapshot() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.MarshalIndent(struct {
		Calls   int      `json:"calls"`
		Records []record `json:"records"`
	}{s.Calls, s.Records}, "", "  ")
	return b
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18090", "address to serve on (must be reachable from the OpenShell sandbox containers)")
	stateFile := flag.String("state-file", "", "optional path rewritten with the JSON state after every provider call")
	maxBody := flag.Int64("max-body", 4<<20, "maximum accepted request body in bytes")
	flag.Parse()

	st := &state{}
	mux := http.NewServeMux()
	mux.HandleFunc("/__state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(st.snapshot())
	})
	mux.HandleFunc("/__reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		st.mu.Lock()
		st.Calls, st.Records = 0, nil
		st.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, *maxBody+1))
		if err != nil || int64(len(body)) > *maxBody {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		st.mu.Lock()
		st.Calls++
		rec := record{Seq: st.Calls, Path: r.URL.Path, Method: r.Method, Authorization: r.Header.Get("Authorization"), Body: string(body), ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		st.Records = append(st.Records, rec)
		snap := st.snapshot()
		st.mu.Unlock()
		if *stateFile != "" {
			_ = os.WriteFile(*stateFile, snap, 0o600)
		}
		log.Printf("provider call %d: %s %s body=%d bytes auth=%s", rec.Seq, rec.Method, rec.Path, len(body), describeAuth(rec.Authorization))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"chatcmpl-mock-%d","object":"chat.completion","created":%d,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"mock completion %d"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":3,"total_tokens":15}}`, rec.Seq, time.Now().Unix(), rec.Seq)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "mock provider: unknown route "+r.URL.Path, http.StatusNotFound)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("mock provider listening on %s", *listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
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
