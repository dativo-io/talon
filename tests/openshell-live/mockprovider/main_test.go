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
