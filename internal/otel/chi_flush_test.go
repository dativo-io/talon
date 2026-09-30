package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type flushCountingWriter struct {
	*httptest.ResponseRecorder
	flushes int
}

func (f *flushCountingWriter) Flush() { f.flushes++ }

// The status middleware must not hide http.Flusher from handlers: a streamed
// response flushed per SSE event has to reach the client per event (#476).
func TestMiddlewareWithStatus_PropagatesFlush(t *testing.T) {
	down := &flushCountingWriter{ResponseRecorder: httptest.NewRecorder()}
	handler := MiddlewareWithStatus()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		require.True(t, ok, "wrapped writer must implement http.Flusher")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: 1\n\n"))
		f.Flush()
		_, _ = w.Write([]byte("data: 2\n\n"))
		f.Flush()
		rc := http.NewResponseController(w)
		assert.NoError(t, rc.Flush(), "ResponseController must reach the underlying writer via Unwrap")
	}))
	handler.ServeHTTP(down, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/stream", nil))
	assert.Equal(t, 3, down.flushes, "every flush must be delegated")
	assert.Equal(t, "data: 1\n\ndata: 2\n\n", down.Body.String())
}
