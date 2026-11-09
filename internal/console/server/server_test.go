package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/console"
	"github.com/dativo-io/talon/internal/console/access"
)

func newServer(t *testing.T, out *bytes.Buffer) (*Server, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	svc, err := console.New(console.Config{Currency: "USD", Version: "test", Now: func() time.Time { return now }})
	require.NoError(t, err)
	s, err := New(svc, Options{Listen: "127.0.0.1:8787", CodeOutput: out, Now: func() time.Time { return now }})
	require.NoError(t, err)
	return s, &now
}

func request(t *testing.T, h http.Handler, method, path, body string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, "http://127.0.0.1:8787"+path, strings.NewReader(body))
	req.Host = "127.0.0.1:8787"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// codeFromOutput extracts the code exactly as an operator reading the log would.
func codeFromOutput(t *testing.T, out string) string {
	t.Helper()
	const marker = "Talon console pairing code: "
	i := strings.LastIndex(out, marker)
	require.GreaterOrEqual(t, i, 0, "no code line in output:\n%s", out)
	line, _, _ := strings.Cut(out[i+len(marker):], "\n")
	return strings.TrimSpace(line)
}

func TestNew_ListenerPolicy(t *testing.T) {
	svc, err := console.New(console.Config{Currency: "USD"})
	require.NoError(t, err)
	_, err = New(svc, Options{Listen: "0.0.0.0:8787"})
	assert.ErrorIs(t, err, ErrNonLoopbackRefused)
	_, err = New(svc, Options{Listen: "192.168.1.9:8787"})
	assert.ErrorIs(t, err, ErrNonLoopbackRefused)
	_, err = New(svc, Options{Listen: "0.0.0.0:8787", AllowNonLoopback: true})
	assert.NoError(t, err)
	_, err = New(svc, Options{Listen: "127.0.0.1"})
	assert.Error(t, err, "needs host:port")
	_, err = New(svc, Options{Listen: "127.0.0.1:0"})
	assert.Error(t, err, "an explicit port is part of the pairing instructions")
	s, err := New(svc, Options{Listen: "localhost:8787"})
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8787/", s.opts.PublicURL)
	s, err = New(svc, Options{Listen: "[::1]:8787"})
	require.NoError(t, err)
	assert.Equal(t, "http://[::1]:8787/", s.opts.PublicURL)
}

func TestServer_PairThenReadAPI_ShellAndHealthUnauthenticated(t *testing.T) {
	var out bytes.Buffer
	s, now := newServer(t, &out)
	h := s.Handler()

	rec := request(t, h, http.MethodGet, "/healthz", "", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())

	rec = request(t, h, http.MethodGet, "/", "", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `<form id="pair-form"`)
	assert.NotContains(t, rec.Body.String(), "<script>", "no inline script under the CSP")
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "script-src 'self'")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	rec = request(t, h, http.MethodGet, "/static/app.js", "", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "javascript")
	rec = request(t, h, http.MethodGet, "/static/../index.html", "", nil)
	assert.NotEqual(t, http.StatusOK, rec.Code)

	rec = request(t, h, http.MethodGet, "/console/v1/system", "", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), access.ReasonSessionRequired)
	rec = request(t, h, http.MethodGet, "/console/v1/overview", "", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	exp, err := s.IssueCode()
	require.NoError(t, err)
	assert.Equal(t, now.Add(access.DefaultCodeTTL), exp)
	printed := out.String()
	code := codeFromOutput(t, printed)
	assert.Regexp(t, `^[A-Z2-9]{5}(-[A-Z2-9]{5}){3}$`, code)
	assert.Contains(t, printed, "http://127.0.0.1:8787/")
	assert.Contains(t, printed, "talon ui pair")

	*now = now.Add(time.Second)
	rec = request(t, h, http.MethodPost, "/console/auth/pair", `{"code":"`+code+`"}`, map[string]string{"Content-Type": "application/json"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	ck := cookies[0]
	assert.Equal(t, access.CookieName, ck.Name)
	assert.True(t, ck.HttpOnly)

	rec = request(t, h, http.MethodGet, "/console/v1/system", "", nil, ck)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var sys console.System
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &sys))
	assert.Equal(t, "test", sys.Console.Version)
	assert.Equal(t, "USD", sys.Console.Currency)
	assert.Equal(t, console.StateUnavailable, sys.Store.Availability.State, "no store was opened: unavailable, not zero")
	assert.Equal(t, console.StateUnknown, sys.Runtime.Availability.State)

	// Reads only: a write verb on the read API is refused even with a session.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec = request(t, h, m, "/console/v1/system", "{}", map[string]string{"Content-Type": "application/json"}, ck)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, m)
	}

	// The code was consumed; the printed output holds it exactly once.
	assert.Equal(t, 1, strings.Count(printed, code))
	*now = now.Add(time.Second)
	rec = request(t, h, http.MethodPost, "/console/auth/pair", `{"code":"`+code+`"}`, map[string]string{"Content-Type": "application/json"})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Reissue voids nothing that is paired and prints a different code.
	_, err = s.IssueCode()
	require.NoError(t, err)
	second := codeFromOutput(t, out.String())
	assert.NotEqual(t, code, second)
	rec = request(t, h, http.MethodGet, "/console/v1/system", "", nil, ck)
	assert.Equal(t, http.StatusOK, rec.Code, "existing sessions survive a reissue")
}

// TestServer_NoPrivilegedRouteExists pins the boundary of #537: the console
// process has none of the data-plane routes, so a browser session can reach
// no secret, run, policy, approval or legacy admin operation through it,
// with or without a cookie.
func TestServer_NoPrivilegedRouteExists(t *testing.T) {
	var out bytes.Buffer
	s, now := newServer(t, &out)
	h := s.Handler()
	require.NoError(t, func() error { _, err := s.IssueCode(); return err }())
	*now = now.Add(time.Second)
	rec := request(t, h, http.MethodPost, "/console/auth/pair", `{"code":"`+codeFromOutput(t, out.String())+`"}`, map[string]string{"Content-Type": "application/json"})
	require.Equal(t, http.StatusOK, rec.Code)
	ck := rec.Result().Cookies()[0]

	privileged := []struct{ method, path string }{
		{http.MethodGet, "/v1/secrets"},
		{http.MethodPost, "/v1/secrets"},
		{http.MethodPost, "/v1/runs/abc/approve"},
		{http.MethodPost, "/v1/runs/abc/cancel"},
		{http.MethodGet, "/v1/runs"},
		{http.MethodPut, "/v1/policies/agent"},
		{http.MethodPost, "/v1/policies/reload"},
		{http.MethodPost, "/v1/plans/p1/decision"},
		{http.MethodPost, "/v1/approvals/a1"},
		{http.MethodPost, "/v1/agents/run"},
		{http.MethodPost, "/v1/chat/completions"},
		{http.MethodPost, "/v1/proxy/openai/v1/chat/completions"},
		{http.MethodPost, "/mcp"},
		{http.MethodPost, "/mcp/proxy"},
		{http.MethodGet, "/v1/evidence"},
		{http.MethodGet, "/v1/agents/fleet"},
		{http.MethodGet, "/v1/costs/budget"},
		{http.MethodGet, "/api/v1/metrics"},
		{http.MethodGet, "/v1/dashboard/summary"},
		{http.MethodGet, "/dashboard"},
		{http.MethodGet, "/gateway/dashboard"},
		{http.MethodGet, "/v1/status"},
		{http.MethodGet, "/health"},
		{http.MethodGet, "/metrics"},
	}
	for _, p := range privileged {
		for _, withCookie := range []bool{false, true} {
			var cookies []*http.Cookie
			if withCookie {
				cookies = append(cookies, ck)
			}
			rec := request(t, h, p.method, p.path, "{}", map[string]string{"Content-Type": "application/json"}, cookies...)
			assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s (cookie=%v) must not exist on the console process", p.method, p.path, withCookie)
		}
	}
}
