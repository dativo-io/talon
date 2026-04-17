package server

import (
	"net/http"
	"strings"

	"github.com/dativo-io/talon/internal/gateway"
)

const quickstartPartialCompatibilityMsg = "partial OpenAI compatibility in quickstart mode; see docs"

// NewQuickstartFacade builds a host-root OpenAI-compatible facade that forwards
// supported routes to the gateway with a trusted synthetic quickstart caller.
func NewQuickstartFacade(gw *gateway.Gateway, listenPrefix string, caller *gateway.CallerConfig) http.Handler {
	return newQuickstartFacade(gw, listenPrefix, caller)
}

func newQuickstartFacade(gw *gateway.Gateway, listenPrefix string, caller *gateway.CallerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not_found", quickstartPartialCompatibilityMsg)
			return
		}
		switch r.URL.Path {
		case "/v1/chat/completions":
			proxyToGateway(gw, caller, listenPrefix, "/openai/v1/chat/completions", w, r)
		case "/v1/responses":
			proxyToGateway(gw, caller, listenPrefix, "/openai/v1/responses", w, r)
		default:
			if strings.HasPrefix(r.URL.Path, "/v1/") {
				writeError(w, http.StatusNotFound, "not_found", quickstartPartialCompatibilityMsg)
				return
			}
			writeError(w, http.StatusNotFound, "not_found", "not found")
		}
	})
}

func proxyToGateway(gw *gateway.Gateway, caller *gateway.CallerConfig, listenPrefix, pathSuffix string, w http.ResponseWriter, r *http.Request) {
	clone := r.Clone(gateway.WithQuickstartCaller(r.Context(), caller))
	prefix := strings.TrimSuffix(listenPrefix, "/")
	clone.URL.Path = prefix + pathSuffix
	if clone.URL.RawPath != "" {
		clone.URL.RawPath = clone.URL.Path
	}
	gw.ServeHTTP(w, clone)
}
