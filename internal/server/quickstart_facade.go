package server

import (
	"net/http"
	"strings"

	"github.com/dativo-io/talon/internal/gateway"
)

const quickstartPartialCompatibilityMsg = "partial OpenAI compatibility in quickstart mode; see docs"

// NewQuickstartFacade builds a host-root OpenAI-compatible facade that
// forwards supported routes to the gateway with the trusted synthetic
// quickstart identity — the only identity not backed by a vault key, and
// reachable only through this in-process facade (#266).
func NewQuickstartFacade(gw *gateway.Gateway, listenPrefix string, identity *gateway.ResolvedIdentity) http.Handler {
	return newQuickstartFacade(gw, listenPrefix, identity)
}

func newQuickstartFacade(gw *gateway.Gateway, listenPrefix string, identity *gateway.ResolvedIdentity) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not_found", quickstartPartialCompatibilityMsg)
			return
		}
		switch r.URL.Path {
		case "/v1/chat/completions":
			proxyToGateway(gw, identity, listenPrefix, "/openai/v1/chat/completions", w, r)
		case "/v1/responses":
			proxyToGateway(gw, identity, listenPrefix, "/openai/v1/responses", w, r)
		default:
			if strings.HasPrefix(r.URL.Path, "/v1/") {
				writeError(w, http.StatusNotFound, "not_found", quickstartPartialCompatibilityMsg)
				return
			}
			writeError(w, http.StatusNotFound, "not_found", "not found")
		}
	})
}

func proxyToGateway(gw *gateway.Gateway, identity *gateway.ResolvedIdentity, listenPrefix, pathSuffix string, w http.ResponseWriter, r *http.Request) {
	clone := r.Clone(gateway.WithQuickstartIdentity(r.Context(), identity))
	prefix := strings.TrimSuffix(listenPrefix, "/")
	clone.URL.Path = prefix + pathSuffix
	if clone.URL.RawPath != "" {
		clone.URL.RawPath = clone.URL.Path
	}
	gw.ServeHTTP(w, clone)
}
