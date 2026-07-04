package adapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/dativo-io/talon/internal/classifier/adapter"
)

// FuzzAdapterResponseDecode feeds arbitrary bytes as the engine response and
// asserts the adapter either returns a valid classification or a classified
// Error — never a panic, and never entities pointing outside the text.
func FuzzAdapterResponseDecode(f *testing.F) {
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"entity_type":"EMAIL_ADDRESS","start":0,"end":4,"score":0.9}]`))
	f.Add([]byte(`[{"entity_type":"X","start":-1,"end":99,"score":2.5}]`))
	f.Add([]byte(`{"not":"an array"}`))
	f.Add([]byte(`garbage`))
	f.Add([]byte(`[{"entity_type":"EMAIL_ADDRESS","start":2,"end":1,"score":0.9,"offset_encoding":"rune"}]`))

	// One shared server for all executions: a server per exec exhausts
	// ephemeral ports (TIME_WAIT) at fuzzing rates.
	var response atomic.Value
	response.Store([]byte(`[]`))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response.Load().([]byte))
	}))
	f.Cleanup(srv.Close)

	a, err := adapter.New(adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL})
	if err != nil {
		f.Fatalf("adapter.New: %v", err)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		response.Store(body)

		text := "text with test@example.com inside"
		cls, err := a.Analyze(context.Background(), text)
		if err != nil {
			if adapter.FailureKind(err) == "" {
				t.Fatalf("non-Error failure: %v", err)
			}
			return
		}
		for _, e := range cls.Entities {
			if e.Position < 0 || e.Position+len(e.Value) > len(text) {
				t.Fatalf("entity out of bounds: %+v", e)
			}
			if text[e.Position:e.Position+len(e.Value)] != e.Value {
				t.Fatalf("entity value does not match text at position: %+v", e)
			}
		}
	})
}
