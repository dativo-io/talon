// Package server is the console process (#536, #537): one HTTP listener that
// serves the embedded shell, the pairing endpoints and the read API of
// internal/console/httpapi behind the browser-session gate. It has no
// privileged route: anything outside the shell, /healthz, /console/auth/*
// and GET /console/v1/* is 404, so a browser session can reach nothing the
// data-plane server protects with TALON_ADMIN_KEY.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/dativo-io/talon/internal/console"
	"github.com/dativo-io/talon/internal/console/access"
	"github.com/dativo-io/talon/internal/console/httpapi"
	"github.com/dativo-io/talon/internal/console/web"
)

// Options configure the process.
type Options struct {
	// Listen is host:port. A non-loopback host is refused unless
	// AllowNonLoopback is set (the operator states that the network, or a
	// TLS terminator in front, is trusted).
	Listen           string
	AllowNonLoopback bool
	// AllowedHosts are extra Host names answered besides the loopback names
	// (and the listen host when it is a concrete address).
	AllowedHosts []string
	SecureCookie bool
	CodeTTL      time.Duration
	SessionTTL   time.Duration
	IdleTTL      time.Duration
	MaxAttempts  int
	// CodeOutput receives the pairing code lines (stdout: the container log
	// or the operator's terminal). Nothing else is ever written to it.
	CodeOutput io.Writer
	// PublicURL is the address printed next to the code; derived from Listen
	// when empty.
	PublicURL string
	Now       func() time.Time
}

// Server is the console process.
type Server struct {
	opts    Options
	gate    *access.Gate
	handler http.Handler

	mu       sync.Mutex
	listener net.Listener
	http     *http.Server
}

// ErrNonLoopbackRefused is returned when Listen names a non-loopback host
// without AllowNonLoopback.
var ErrNonLoopbackRefused = errors.New("console: refusing to listen on a non-loopback address without --allow-non-loopback; the console has no transport security of its own")

// CheckListen validates a listen address against the loopback policy
// without opening anything; callers run it before touching the store so a
// flag mistake fails first.
func CheckListen(listen string, allowNonLoopback bool) (host, port string, err error) {
	if strings.TrimSpace(listen) == "" {
		listen = "127.0.0.1:8787"
	}
	host, port, err = net.SplitHostPort(listen)
	if err != nil {
		return "", "", fmt.Errorf("console: --listen must be host:port: %w", err)
	}
	if port == "" || port == "0" {
		return "", "", errors.New("console: --listen needs an explicit port (the pairing instructions name it)")
	}
	if !isLoopback(host) && !allowNonLoopback {
		return "", "", ErrNonLoopbackRefused
	}
	return host, port, nil
}

// New validates opts and assembles the handler. Nothing listens yet.
func New(svc *console.Service, opts Options) (*Server, error) {
	if strings.TrimSpace(opts.Listen) == "" {
		opts.Listen = "127.0.0.1:8787"
	}
	host, port, err := CheckListen(opts.Listen, opts.AllowNonLoopback)
	if err != nil {
		return nil, err
	}
	if opts.CodeOutput == nil {
		opts.CodeOutput = io.Discard
	}
	if opts.PublicURL == "" {
		shown := host
		if shown == "" || shown == "0.0.0.0" || shown == "::" {
			shown = "127.0.0.1"
		}
		opts.PublicURL = "http://" + net.JoinHostPort(shown, port) + "/"
	}
	gate := &access.Gate{
		Pairer:       access.NewPairer(opts.CodeTTL, opts.MaxAttempts, opts.Now),
		Sessions:     access.NewSessions(opts.SessionTTL, opts.IdleTTL, 0, opts.Now),
		AllowedHosts: access.HostsForListener(opts.Listen, opts.AllowedHosts),
		SecureCookie: opts.SecureCookie,
	}
	s := &Server{opts: opts, gate: gate}
	s.handler = s.routes(svc)
	return s, nil
}

func (s *Server) routes(svc *console.Service) http.Handler {
	r := chi.NewRouter()
	r.Use(s.gate.HostCheck, access.SecurityHeaders)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		// Liveness only: no store fact, no session fact, no version.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	})
	r.Post("/console/auth/pair", s.gate.PairHandler())
	r.Post("/console/auth/logout", s.gate.LogoutHandler())
	r.Get("/console/auth/session", s.gate.SessionHandler())
	api := httpapi.Handler(svc)
	r.Group(func(r chi.Router) {
		r.Use(s.gate.RequireSession)
		r.Handle(httpapi.Prefix+"/*", api)
	})
	r.NotFound(web.Handler().ServeHTTP)
	return r
}

// Handler is the process's HTTP handler (tests mount it on httptest).
func (s *Server) Handler() http.Handler { return s.handler }

// Gate exposes the access boundary (tests and the reissue signal).
func (s *Server) Gate() *access.Gate { return s.gate }

// IssueCode mints a fresh pairing code and prints it, once, to CodeOutput.
// Any previous code is void. The returned expiry is for the caller's log
// line, which must not include the code.
func (s *Server) IssueCode() (time.Time, error) {
	code, exp, err := s.gate.Pairer.Issue()
	if err != nil {
		return time.Time{}, err
	}
	_, err = fmt.Fprintf(s.opts.CodeOutput,
		"\nTalon console pairing code: %s\n  single use, valid until %s (%s). Open %s and enter it.\n  Reissue: talon ui pair (or restart the console process).\n\n",
		code, exp.UTC().Format(time.RFC3339), s.gate.Pairer.TTL().Truncate(time.Second), s.opts.PublicURL)
	return exp, err
}

// Listen binds the address; it fails without ever starting the handler when
// the port is taken.
func (s *Server) Listen(ctx context.Context) (net.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("console: listen %s: %w", s.opts.Listen, err)
	}
	s.listener = ln
	s.http = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return ln.Addr(), nil
}

// Serve runs until ctx is done, then shuts down gracefully. Listen must have
// succeeded.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	ln, srv := s.listener, s.http
	s.mu.Unlock()
	if ln == nil || srv == nil {
		return errors.New("console: Serve before Listen")
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func isLoopback(host string) bool {
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
