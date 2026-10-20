package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestProtectedService_CountsPerRouteAndRecordsIdempotencyKey(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	srv := httptest.NewServer(newHandler(newState(), stateFile, 1<<20))
	defer srv.Close()

	post := func(path, idem, body string) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Idempotency-Key", idem)
		req.Header.Set("X-Talon-Operation-Ref", "op_x")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := post("/tickets", "talon-op_1", `{"ticket_id":"T-1"}`); got != 200 {
		t.Fatalf("tickets status %d", got)
	}
	if got := post("/refunds", "talon-op_2", `{"amount":50}`); got != 201 {
		t.Fatalf("refunds status %d", got)
	}
	if got := post("/nope", "", ""); got != 404 {
		t.Fatalf("unknown route status %d", got)
	}
	stateReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/__state", nil)
	resp, err := http.DefaultClient.Do(stateReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var v view
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Tickets != 1 || v.Refunds != 1 || v.Customers != 0 || len(v.Records) != 2 {
		t.Fatalf("state %+v", v)
	}
	if v.Records[1].IdempotencyKey != "talon-op_2" || v.Records[1].OperationRef != "op_x" || v.Records[1].Body != `{"amount":50}` {
		t.Fatalf("record %+v", v.Records[1])
	}
}

func TestProtectedService_ConcurrentCallsNeverLoseACount(t *testing.T) {
	st := newState()
	srv := httptest.NewServer(newHandler(st, "", 1<<20))
	defer srv.Close()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/refunds", strings.NewReader(`{}`))
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if v := st.snapshot(); v.Refunds != 40 || len(v.Records) != 40 {
		t.Fatalf("lost calls: %+v", v.Refunds)
	}
}

func TestProtectedService_OversizedBodyRefused(t *testing.T) {
	srv := httptest.NewServer(newHandler(newState(), "", 16))
	defer srv.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/refunds", strings.NewReader(strings.Repeat("x", 17)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
