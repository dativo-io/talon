package openshell

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/dativo-io/talon/internal/gateway"
)

// Server is the gRPC (HTTP/2) listener for the middleware contract.
type Server struct {
	srv      *http.Server
	insecure bool
	listen   string
}

// NewServer builds the listener from config: TLS with ALPN h2 normally, or
// plaintext h2c when allow_insecure_transport is set (fixtures only —
// OpenShell sends no caller token over an insecure registration, so every
// evaluation is denied for missing identity).
func NewServer(cfg gateway.OpenShellConfig, h http.Handler) (*Server, error) {
	if strings.TrimSpace(cfg.Listen) == "" {
		return nil, fmt.Errorf("openshell listen address is required")
	}
	s := &Server{listen: cfg.Listen, insecure: cfg.AllowInsecureTransport}
	s.srv = &http.Server{
		Addr:              cfg.Listen,
		ReadHeaderTimeout: 10 * time.Second,
		// A single evaluation is bounded by OpenShell's request timeout
		// (≤30s); the write timeout leaves headroom for body transfer.
		WriteTimeout: 2 * time.Minute,
		IdleTimeout:  5 * time.Minute,
	}
	if cfg.AllowInsecureTransport {
		s.srv.Handler = h2c.NewHandler(h, &http2.Server{})
		return s, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("openshell tls: %w", err)
	}
	s.srv.Handler = h
	s.srv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}
	return s, nil
}

// ListenAndServe blocks until the listener stops. ctx bounds the listen
// setup (bind), not the serving lifetime — use Shutdown for that.
func (s *Server) ListenAndServe(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.listen)
	if err != nil {
		return err
	}
	if s.insecure {
		log.Warn().Str("listen", s.listen).Msg("openshell_middleware_insecure_transport: plaintext h2c; OpenShell presents no caller identity over insecure registrations, so every evaluation will be denied — fixtures only")
		return s.srv.Serve(ln)
	}
	log.Info().Str("listen", s.listen).Str("upstream_contract", UpstreamVersion).Msg("openshell_middleware_listening")
	return s.srv.ServeTLS(ln, "", "")
}

// Shutdown stops the listener gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
