package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock { return &clock{t: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)} }

func TestPairer_CodeShapeAndEntropy(t *testing.T) {
	p := NewPairer(0, 0, newClock().now)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		code, exp, err := p.Issue()
		require.NoError(t, err)
		assert.Regexp(t, `^[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}$`, code)
		assert.NotContains(t, code, "0")
		assert.NotContains(t, code, "O")
		assert.NotContains(t, code, "1")
		assert.NotContains(t, code, "I")
		assert.False(t, seen[code], "codes repeat")
		seen[code] = true
		assert.Equal(t, DefaultCodeTTL, exp.Sub(newClock().t))
	}
	assert.Equal(t, DefaultCodeTTL, NewPairer(time.Hour, 0, nil).TTL(), "a TTL above the cap falls back to the default")
	assert.Equal(t, 3*time.Minute, NewPairer(3*time.Minute, 0, nil).TTL())
}

func TestPairer_SingleUseExpiryExhaustionThrottle(t *testing.T) {
	c := newClock()
	p := NewPairer(10*time.Minute, 3, c.now)
	assert.ErrorIs(t, p.Redeem("AAAAA-AAAAA-AAAAA-AAAAA"), ErrNoCode)

	code, _, err := p.Issue()
	require.NoError(t, err)
	c.advance(time.Second)
	assert.ErrorIs(t, p.Redeem("not it"), ErrCodeMismatch)
	assert.ErrorIs(t, p.Redeem(code), ErrThrottled, "a second attempt within the gap is throttled, not counted")
	c.advance(time.Second)
	assert.NoError(t, p.Redeem(strings.ToLower(strings.ReplaceAll(code, "-", " "))), "case and separators do not matter")
	c.advance(time.Second)
	assert.ErrorIs(t, p.Redeem(code), ErrNoCode, "single use: the code is gone after success")

	code, _, err = p.Issue()
	require.NoError(t, err)
	c.advance(11 * time.Minute)
	assert.ErrorIs(t, p.Redeem(code), ErrCodeExpired)
	c.advance(time.Second)
	assert.ErrorIs(t, p.Redeem(code), ErrNoCode, "an expired code is discarded")

	code, _, err = p.Issue()
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		c.advance(time.Second)
		assert.ErrorIs(t, p.Redeem("wrong"), ErrCodeMismatch)
	}
	c.advance(time.Second)
	assert.ErrorIs(t, p.Redeem("wrong"), ErrCodeExhausted, "third failure voids the code")
	c.advance(time.Second)
	assert.ErrorIs(t, p.Redeem(code), ErrNoCode, "the right code no longer works after exhaustion")

	_, _, err = p.Issue()
	require.NoError(t, err, "reissue after exhaustion works")
	assert.False(t, p.ExpiresAt().IsZero())
}

func TestSessions_TTLIdleBoundAndRevoke(t *testing.T) {
	c := newClock()
	s := NewSessions(8*time.Hour, time.Hour, 2, c.now)
	a, err := s.Create()
	require.NoError(t, err)
	assert.Len(t, a.ID, 43, "32 random bytes, base64url without padding")
	_, ok := s.Validate(a.ID)
	assert.True(t, ok)
	_, ok = s.Validate("")
	assert.False(t, ok)
	_, ok = s.Validate(a.ID + "x")
	assert.False(t, ok)

	c.advance(59 * time.Minute)
	_, ok = s.Validate(a.ID)
	assert.True(t, ok, "touched before idle expiry")
	c.advance(61 * time.Minute)
	_, ok = s.Validate(a.ID)
	assert.False(t, ok, "idle for more than an hour")

	b, err := s.Create()
	require.NoError(t, err)
	c.advance(9 * time.Hour)
	_, ok = s.Validate(b.ID)
	assert.False(t, ok, "absolute TTL")

	x, _ := s.Create()
	c.advance(time.Second)
	y, _ := s.Create()
	c.advance(time.Second)
	z, _ := s.Create()
	assert.Equal(t, 2, s.Len(), "bounded")
	_, ok = s.Validate(x.ID)
	assert.False(t, ok, "oldest evicted")
	_, ok = s.Validate(y.ID)
	assert.True(t, ok)
	s.Revoke(z.ID)
	_, ok = s.Validate(z.ID)
	assert.False(t, ok)
	s.Revoke("unknown")
}

func newGate(c *clock) *Gate {
	return &Gate{
		Pairer:       NewPairer(10*time.Minute, 5, c.now),
		Sessions:     NewSessions(0, 0, 0, c.now),
		AllowedHosts: HostsForListener("127.0.0.1:8787", nil),
	}
}

func router(g *Gate) http.Handler {
	r := chi.NewRouter()
	r.Use(g.HostCheck, SecurityHeaders)
	r.Post("/console/auth/pair", g.PairHandler())
	r.Post("/console/auth/logout", g.LogoutHandler())
	r.Get("/console/auth/session", g.SessionHandler())
	r.Group(func(r chi.Router) {
		r.Use(g.RequireSession)
		r.Get("/console/v1/ping", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	})
	return r
}

func do(t *testing.T, h http.Handler, method, path, host, body string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, "http://"+host+path, strings.NewReader(body))
	req.Host = host
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

func reason(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	return env["error"]
}

var jsonHdr = map[string]string{"Content-Type": "application/json"}

func TestGate_PairFlowSetsScopedCookieAndGuardsReads(t *testing.T) {
	c := newClock()
	g := newGate(c)
	h := router(g)

	rec := do(t, h, http.MethodGet, "/console/v1/ping", "127.0.0.1:8787", "", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, ReasonSessionRequired, reason(t, rec))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))

	rec = do(t, h, http.MethodGet, "/console/auth/session", "localhost:8787", "", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"paired":false}`, rec.Body.String())

	rec = do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":"AAAAA-AAAAA-AAAAA-AAAAA"}`, jsonHdr)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, ReasonPairingNoCode, reason(t, rec))

	code, _, err := g.Pairer.Issue()
	require.NoError(t, err)
	c.advance(time.Second)
	rec = do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":"`+code+`"}`, jsonHdr)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), code, "the code is never echoed")
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	ck := cookies[0]
	assert.Equal(t, CookieName, ck.Name)
	assert.True(t, ck.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, ck.SameSite)
	assert.Equal(t, "/", ck.Path)
	assert.False(t, ck.Secure, "plain HTTP on loopback: Secure would make the browser drop the cookie")
	assert.NotEqual(t, code, ck.Value)
	assert.Len(t, ck.Value, 43)

	rec = do(t, h, http.MethodGet, "/console/v1/ping", "127.0.0.1:8787", "", nil, ck)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	rec = do(t, h, http.MethodGet, "/console/auth/session", "127.0.0.1:8787", "", nil, ck)
	assert.Contains(t, rec.Body.String(), `"paired":true`)

	// A forged cookie of the right shape is not a session.
	rec = do(t, h, http.MethodGet, "/console/v1/ping", "127.0.0.1:8787", "", nil, &http.Cookie{Name: CookieName, Value: strings.Repeat("A", 43)})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Replay of the consumed code fails.
	c.advance(time.Second)
	rec = do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":"`+code+`"}`, jsonHdr)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, ReasonPairingNoCode, reason(t, rec))

	// Logout revokes server-side: the old cookie is dead afterwards.
	rec = do(t, h, http.MethodPost, "/console/auth/logout", "127.0.0.1:8787", `{}`, jsonHdr, ck)
	assert.Equal(t, http.StatusOK, rec.Code)
	cleared := rec.Result().Cookies()
	require.Len(t, cleared, 1)
	assert.Equal(t, "", cleared[0].Value)
	assert.Equal(t, -1, cleared[0].MaxAge)
	rec = do(t, h, http.MethodGet, "/console/v1/ping", "127.0.0.1:8787", "", nil, ck)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGate_SecureCookieUnderTLSOrFlag(t *testing.T) {
	c := newClock()
	g := newGate(c)
	g.SecureCookie = true
	code, _, _ := g.Pairer.Issue()
	c.advance(time.Second)
	rec := do(t, router(g), http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":"`+code+`"}`, jsonHdr)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, rec.Result().Cookies()[0].Secure)
}

func TestGate_RejectsRebindingCrossOriginAndForms(t *testing.T) {
	c := newClock()
	g := newGate(c)
	h := router(g)
	code, _, _ := g.Pairer.Issue()
	body := `{"code":"` + code + `"}`

	cases := []struct {
		name   string
		host   string
		hdr    map[string]string
		status int
		reason string
	}{
		{"unknown host (DNS rebinding)", "evil.example:8787", jsonHdr, http.StatusMisdirectedRequest, ReasonHostNotAllowed},
		{"wrong port on a loopback name", "127.0.0.1:9999", jsonHdr, http.StatusMisdirectedRequest, ReasonHostNotAllowed},
		{"cross-site fetch", "127.0.0.1:8787", map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden, ReasonCrossOrigin},
		{"foreign Origin", "127.0.0.1:8787", map[string]string{"Content-Type": "application/json", "Origin": "http://evil.example"}, http.StatusForbidden, ReasonCrossOrigin},
		{"opaque Origin", "127.0.0.1:8787", map[string]string{"Content-Type": "application/json", "Origin": "null"}, http.StatusForbidden, ReasonCrossOrigin},
		{"HTML form post", "127.0.0.1:8787", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, http.StatusForbidden, ReasonCrossOrigin},
		{"no content type", "127.0.0.1:8787", nil, http.StatusForbidden, ReasonCrossOrigin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c.advance(time.Second)
			rec := do(t, h, http.MethodPost, "/console/auth/pair", tc.host, body, tc.hdr)
			assert.Equal(t, tc.status, rec.Code)
			assert.Equal(t, tc.reason, reason(t, rec))
			assert.Empty(t, rec.Result().Cookies(), "no session was minted")
		})
	}
	assert.Equal(t, 0, g.Sessions.Len())

	// The same code still pairs from the console's own origin: the rejected
	// requests never reached the Pairer and did not count as attempts.
	c.advance(time.Second)
	rec := do(t, h, http.MethodPost, "/console/auth/pair", "localhost:8787", body, map[string]string{"Content-Type": "application/json", "Origin": "http://localhost:8787", "Sec-Fetch-Site": "same-origin"})
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestGate_BruteForceIsThrottledThenVoided(t *testing.T) {
	c := newClock()
	g := newGate(c)
	h := router(g)
	code, _, _ := g.Pairer.Issue()

	c.advance(time.Second)
	rec := do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":"AAAAA-AAAAA-AAAAA-AAAAA"}`, jsonHdr)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, ReasonPairingMismatch, reason(t, rec))
	rec = do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":"BBBBB-BBBBB-BBBBB-BBBBB"}`, jsonHdr)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, ReasonPairingThrottled, reason(t, rec))
	for i := 0; i < 3; i++ {
		c.advance(time.Second)
		rec = do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":"CCCCC-CCCCC-CCCCC-CCCCC"}`, jsonHdr)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, ReasonPairingMismatch, reason(t, rec))
	}
	c.advance(time.Second)
	rec = do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":"DDDDD-DDDDD-DDDDD-DDDDD"}`, jsonHdr)
	assert.Equal(t, ReasonPairingExhausted, reason(t, rec))
	c.advance(time.Second)
	rec = do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":"`+code+`"}`, jsonHdr)
	assert.Equal(t, ReasonPairingNoCode, reason(t, rec), "the genuine code is dead after the attempts; the operator reissues")

	c.advance(time.Second)
	rec = do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", `{"code":""}`, jsonHdr)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	rec = do(t, h, http.MethodPost, "/console/auth/pair", "127.0.0.1:8787", strings.Repeat("x", 5000), jsonHdr)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHostsForListener(t *testing.T) {
	assert.ElementsMatch(t, []string{"localhost:8787", "127.0.0.1:8787", "[::1]:8787"}, HostsForListener("127.0.0.1:8787", nil))
	assert.ElementsMatch(t, []string{"localhost:8787", "127.0.0.1:8787", "[::1]:8787", "console.internal:8787", "10.0.0.5:8787"},
		HostsForListener("0.0.0.0:8787", []string{"console.internal", " 10.0.0.5:8787 ", ""}), "a wildcard bind contributes no public name by itself")
	assert.ElementsMatch(t, []string{"localhost:9000", "127.0.0.1:9000", "[::1]:9000", "192.168.1.2:9000"}, HostsForListener("192.168.1.2:9000", nil))
	assert.Contains(t, HostsForListener("127.0.0.1:80", nil), "localhost")
}
