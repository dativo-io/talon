package access

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// CookieName is the browser session cookie. Its value is the opaque session
// id and nothing else.
const CookieName = "talon_console_session"

// Reason codes of the access endpoints (the `error` field of the envelope).
const (
	ReasonHostNotAllowed   = "host_not_allowed"
	ReasonCrossOrigin      = "cross_origin_rejected"
	ReasonBadRequest       = "invalid_request"
	ReasonSessionRequired  = "console_session_required"
	ReasonPairingNoCode    = "pairing_code_not_issued"
	ReasonPairingExpired   = "pairing_code_expired"
	ReasonPairingMismatch  = "pairing_code_invalid"
	ReasonPairingExhausted = "pairing_code_exhausted"
	ReasonPairingThrottled = "pairing_throttled"
)

const maxPairBody = 1 << 10

// Gate is the access boundary of the console process.
type Gate struct {
	Pairer   *Pairer
	Sessions *Sessions
	// AllowedHosts are the Host header values (host or host:port, case
	// insensitive) the process answers; anything else is 421. Loopback names
	// are always accepted when they carry one of the listening ports.
	AllowedHosts []string
	// SecureCookie marks the cookie Secure even over plain HTTP (behind a TLS
	// terminator); over TLS it is always Secure.
	SecureCookie bool
}

// HostCheck rejects requests whose Host is not an allowed name (DNS
// rebinding: a hostile page resolving its own name to 127.0.0.1 would
// otherwise reach the console with the browser's cookie).
func (g *Gate) HostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.hostAllowed(r.Host) {
			writeError(w, http.StatusMisdirectedRequest, ReasonHostNotAllowed, "this console does not serve the requested host name")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gate) hostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, a := range g.AllowedHosts {
		if strings.EqualFold(strings.TrimSpace(a), host) {
			return true
		}
	}
	return false
}

// SecurityHeaders applies the response headers every console response
// carries: a strict CSP (no inline script or style, no framing), nosniff,
// no referrer, and no caching of API/auth bodies.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/console/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSession admits only requests carrying a live session cookie. The
// cookie is validated server-side on every request; nothing is inferred
// from its presence.
func (g *Gate) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := g.sessionOf(r); !ok {
			writeError(w, http.StatusUnauthorized, ReasonSessionRequired, "pair this browser with the console first")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gate) sessionOf(r *http.Request) (*Session, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return nil, false
	}
	return g.Sessions.Validate(c.Value)
}

// sameOrigin enforces, for state-changing requests, that the browser sent
// the request from this origin: Sec-Fetch-Site (when present) must be
// same-origin or none, Origin (when present) must equal the request's own
// origin exactly (scheme, host and port: a browser addressing
// http://127.0.0.1:8787 sends that Origin and no alias of it), and the body
// must be declared JSON (a plain HTML form cannot send that).
func (g *Gate) sameOrigin(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return errors.New("Sec-Fetch-Site " + site)
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if expected := g.expectedOrigin(r); !strings.EqualFold(strings.TrimSuffix(origin, "/"), expected) {
			return errors.New("Origin " + origin + " is not " + expected)
		}
	}
	ct := r.Header.Get("Content-Type")
	if mt := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0])); mt != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	return nil
}

// PairHandler is POST /console/auth/pair with body {"code": "..."}. Success
// voids the code, mints a session and sets the cookie; every failure is a
// JSON envelope with a reason code and never echoes the code.
func (g *Gate) PairHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := g.sameOrigin(r); err != nil {
			writeError(w, http.StatusForbidden, ReasonCrossOrigin, "pairing is accepted from this console's own page only ("+err.Error()+")")
			return
		}
		var body struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxPairBody)).Decode(&body); err != nil || strings.TrimSpace(body.Code) == "" {
			writeError(w, http.StatusBadRequest, ReasonBadRequest, `body must be {"code": "<pairing code>"}`)
			return
		}
		if err := g.Pairer.Redeem(body.Code); err != nil {
			status, reason := pairingFailure(err)
			writeError(w, status, reason, err.Error())
			return
		}
		sess, err := g.Sessions.Create()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "session_unavailable", "could not create a session")
			return
		}
		http.SetCookie(w, g.cookie(r, sess.ID, sess.ExpiresAt))
		writeJSON(w, http.StatusOK, map[string]interface{}{"paired": true, "expires_at": sess.ExpiresAt})
	}
}

func pairingFailure(err error) (status int, reason string) {
	switch {
	case errors.Is(err, ErrThrottled):
		return http.StatusTooManyRequests, ReasonPairingThrottled
	case errors.Is(err, ErrNoCode):
		return http.StatusUnauthorized, ReasonPairingNoCode
	case errors.Is(err, ErrCodeExpired):
		return http.StatusUnauthorized, ReasonPairingExpired
	case errors.Is(err, ErrCodeExhausted):
		return http.StatusUnauthorized, ReasonPairingExhausted
	default:
		return http.StatusUnauthorized, ReasonPairingMismatch
	}
}

// LogoutHandler is POST /console/auth/logout: revokes the session server-side
// and clears the cookie. Without a session it still clears the cookie.
func (g *Gate) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := g.sameOrigin(r); err != nil {
			writeError(w, http.StatusForbidden, ReasonCrossOrigin, "logout is accepted from this console's own page only ("+err.Error()+")")
			return
		}
		if c, err := r.Cookie(CookieName); err == nil {
			g.Sessions.Revoke(c.Value)
		}
		http.SetCookie(w, g.cookie(r, "", time.Unix(0, 0)))
		writeJSON(w, http.StatusOK, map[string]interface{}{"paired": false})
	}
}

// SessionHandler is GET /console/auth/session: {"paired": bool, "expires_at"}.
// It is the only read the shell makes before pairing.
func (g *Gate) SessionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := g.sessionOf(r)
		if !ok {
			writeJSON(w, http.StatusOK, map[string]interface{}{"paired": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"paired": true, "expires_at": sess.ExpiresAt})
	}
}

// expectedOrigin is the origin a browser sends when it addresses this
// request's Host over this request's scheme. The scheme is https when the
// connection is TLS or the deployment declared a TLS terminator in front
// (SecureCookie); the Host has already passed the allowlist.
func (g *Gate) expectedOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || g.SecureCookie {
		scheme = "https"
	}
	return scheme + "://" + strings.ToLower(r.Host)
}

func (g *Gate) cookie(r *http.Request, value string, expires time.Time) *http.Cookie {
	c := &http.Cookie{ //nolint:gosec // G124: HttpOnly and SameSite=Strict are set; Secure follows TLS or the flag (a Secure cookie over loopback HTTP is dropped by browsers)
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   g.SecureCookie || r.TLS != nil,
		Expires:  expires,
	}
	if value == "" {
		c.MaxAge = -1
	}
	return c
}

// LoopbackHosts lists the Host values a loopback listener on port answers.
func LoopbackHosts(port string) []string {
	names := []string{"localhost", "127.0.0.1", "[::1]"}
	out := make([]string, 0, 2*len(names))
	for _, n := range names {
		out = append(out, n+":"+port)
		if port == "80" {
			out = append(out, n)
		}
	}
	return out
}

// HostsForListener derives the allowed hosts from a listen address: the
// address itself when it names a host, loopback names on that port, and
// every extra name given. A wildcard host (0.0.0.0, [::]) contributes only
// the loopback names and the extras: the operator names the public host.
func HostsForListener(listen string, extra []string) []string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return extra
	}
	out := LoopbackHosts(port)
	if host != "" && host != "0.0.0.0" && host != "::" && !isLoopbackIP(host) {
		out = append(out, net.JoinHostPort(host, port))
	}
	for _, e := range extra {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(e); err != nil {
			e = net.JoinHostPort(e, port)
		}
		out = append(out, e)
	}
	return out
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}
