package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Identity injection hygiene (#266): agent identity comes from key resolution
// or the trusted in-process quickstart context — never from client-asserted
// headers. These tests drive the full ServeHTTP pipeline; unit-level
// resolution semantics live in resolve_test.go.

func TestGateway_QuickstartIdentityFromContextOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	gw, evStore, agent := newBYOKGateway(t, upstream.URL)

	// No context identity and no key: rejected outright — there is no
	// anonymous or source-IP fallback in the agent identity model.
	req := gatewayRequest(t, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without an agent key, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid or missing agent key") {
		t.Fatalf("unexpected 401 body: %s", rec.Body.String())
	}
	records, err := evStore.List(context.Background(), "", "", time.Time{}, time.Time{}, 20)
	if err != nil {
		t.Fatalf("listing evidence: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("rejected request must not mint evidence, got %d records", len(records))
	}

	// Context identity must be honored (the bearer key becomes the BYOK
	// upstream credential, not an identity claim).
	req2 := gatewayRequest(t, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	req2.Header.Set("Authorization", "Bearer sk-context")
	req2 = req2.WithContext(WithQuickstartIdentity(req2.Context(), agent))
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec2.Code, rec2.Body.String())
	}
	got, err := evStore.List(context.Background(), agent.TenantID, agent.Name, time.Time{}, time.Time{}, 20)
	if err != nil {
		t.Fatalf("listing evidence by agent: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected quickstart evidence record")
	}

	// Header-only "claim" must not impersonate the quickstart identity:
	// X-Talon-Agent-ID is client-asserted orchestration metadata, never an
	// identity, and an unknown key is rejected before anything is recorded.
	before, err := evStore.List(context.Background(), "", "", time.Time{}, time.Time{}, 50)
	if err != nil {
		t.Fatalf("listing all evidence: %v", err)
	}
	req3 := gatewayRequest(t, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	req3.Header.Set("X-Talon-Agent-ID", agent.Name)
	req3.Header.Set("Authorization", "Bearer sk-no-context")
	rec3 := httptest.NewRecorder()
	gw.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unknown key with a header-claimed identity, got %d", rec3.Code)
	}
	if !strings.Contains(rec3.Body.String(), "Invalid or missing agent key") {
		t.Fatalf("unexpected 401 body: %s", rec3.Body.String())
	}
	after, err := evStore.List(context.Background(), "", "", time.Time{}, time.Time{}, 50)
	if err != nil {
		t.Fatalf("listing all evidence: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("header-claimed identity must not mint evidence: %d -> %d records", len(before), len(after))
	}
}

func TestQuickstartIdentityContextHelpers(t *testing.T) {
	ctx := context.Background()
	if QuickstartIdentityFromContext(ctx) != nil {
		t.Fatalf("unexpected identity in empty context")
	}
	id := NewQuickstartIdentity()
	ctx = WithQuickstartIdentity(ctx, id)
	got := QuickstartIdentityFromContext(ctx)
	if got == nil || got.Name != id.Name || got.TenantID != id.TenantID {
		t.Fatalf("unexpected identity: %+v", got)
	}
}
