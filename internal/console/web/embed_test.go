package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAppRoute(t *testing.T) {
	for _, p := range []string{"/overview", "/use-cases", "/use-cases/hr-analytics-assistant", "/sessions", "/sessions/s-1", "/sessions/s-1/", "/evidence/proxy_ab12", "/costs", "/configuration", "/system"} {
		assert.True(t, IsAppRoute(p), p)
	}
	for _, p := range []string{"/evidence", "/decisions", "/agents", "/sessions/a/b", "/console/v1/overview", "/console/auth/pair", "/v1/secrets", "/static", "/overview/x", "/../etc/passwd", "/sessions//x", "", "overview"} {
		assert.False(t, IsAppRoute(p), p)
	}
}

func TestHandler_DeepLinksServeTheAppAndUnknownPathsAre404(t *testing.T) {
	h := Handler()
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
		return rec
	}
	root := get("/")
	assert.Equal(t, http.StatusOK, root.Code)
	for _, p := range []string{"/sessions/abc", "/use-cases/x", "/evidence/e1", "/system"} {
		rec := get(p)
		assert.Equal(t, http.StatusOK, rec.Code, p)
		assert.Equal(t, root.Body.String(), rec.Body.String(), "%s serves the same app document", p)
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	}
	for _, p := range []string{"/nope", "/evidence", "/console/v1/whatever", "/sessions/a/b"} {
		assert.Equal(t, http.StatusNotFound, get(p).Code, p)
	}
}
