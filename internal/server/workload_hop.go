package server

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/workload"
)

// Workload hop ingress (#457/#482).
//
// A request that arrives through an external runtime's egress hop carries
// X-Talon-Workload-Assertion: a Talon-minted, request-bound statement of the
// principal Talon verified at the hop and the use case it is bound to. This
// middleware verifies the assertion against the exact method, path and body
// it receives, re-resolves the binding against the CURRENT generation, and
// sets the same agent identity the agent-key path would — so every handler
// downstream is identity-source-agnostic. The sandbox never holds a Talon
// secret; a value it writes into the header itself is overwritten at the hop
// and, from any other path, fails signature verification.

// Stable ingress codes for assertion outcomes.
const (
	CodeWorkloadIdentityInvalid  = "workload_identity_invalid"
	CodeWorkloadIdentityUnbound  = "workload_identity_unbound"
	CodeWorkloadIdentityConflict = "workload_identity_conflict"
)

// HopVerifier verifies a hop assertion against the exact request binding.
type HopVerifier interface {
	Verify(token, method, path, bodySHA256 string) (*workload.HopClaims, error)
}

// HopBinder confirms, on the CURRENT runtime generation, that the verified
// principal is still bound to the asserted agent/tenant and returns that
// identity (with the generation it was resolved on). false = not bound.
type HopBinder func(claims *workload.HopClaims) (requestctx.AgentIdentity, bool)

// WithWorkloadHop enables hop-assertion authentication on the Action
// Gateway routes alongside the agent key.
func WithWorkloadHop(v HopVerifier, b HopBinder) Option {
	return func(s *Server) {
		if v != nil && b != nil {
			s.hopVerifier, s.hopBinder = v, b
		}
	}
}

// ActionIdentityMiddleware authenticates the Action Gateway's agent-facing
// routes: a workload hop assertion when present, the agent key otherwise.
// The two are not interchangeable fallbacks — a present assertion MUST
// verify, and a presented agent key MUST name the same use case; anything
// else is refused before any domain call.
func ActionIdentityMiddleware(agentKeys AgentKeyResolver, adminKey string, verifier HopVerifier, binder HopBinder, maxBody int64) func(http.Handler) http.Handler {
	agentKeys = normalizeResolver(agentKeys)
	keyOnly := TenantKeyMiddleware(agentKeys, adminKey)
	return func(next http.Handler) http.Handler {
		viaKey := keyOnly(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimSpace(r.Header.Get(workload.HopAssertionHeader))
			if token == "" {
				viaKey.ServeHTTP(w, r)
				return
			}
			if verifier == nil || binder == nil {
				writeActionError(w, http.StatusUnauthorized, CodeWorkloadIdentityInvalid, "workload assertions are not accepted on this deployment", nil)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
			if err != nil {
				writeActionError(w, http.StatusBadRequest, "invalid_request", "reading request body", nil)
				return
			}
			if int64(len(body)) > maxBody {
				writeActionError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body exceeds the Action Gateway bound", nil)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			claims, err := verifier.Verify(token, r.Method, r.URL.Path, workload.BodyDigest(body))
			if err != nil {
				code := workload.FailureCode(err)
				log.Warn().Str("failure", code).Str("path", r.URL.Path).Msg("workload_assertion_rejected")
				writeActionError(w, http.StatusUnauthorized, CodeWorkloadIdentityInvalid, "workload assertion rejected ("+code+")", nil)
				return
			}
			id, ok := binder(claims)
			if !ok {
				log.Warn().Str("runtime", claims.Runtime).Str("agent", claims.Agent).Msg("workload_assertion_unbound")
				writeActionError(w, http.StatusForbidden, CodeWorkloadIdentityUnbound, "the verified workload principal is not bound to the asserted AI use case", nil)
				return
			}
			// An agent key presented alongside the assertion must be the
			// SAME use case: a sandbox cannot borrow another agent's key to
			// widen what its verified identity is bound to, nor the reverse.
			if bearer := bearerToken(r); bearer != "" {
				auth := agentKeys.AuthenticateAgentKey(bearer)
				if !auth.Found || auth.Identity.AgentID != id.AgentID || auth.Identity.TenantID != id.TenantID {
					writeActionError(w, http.StatusUnauthorized, CodeWorkloadIdentityConflict, "the agent key and the workload assertion name different AI use cases", nil)
					return
				}
			}
			facts := requestctx.WorkloadFacts{
				Runtime: claims.Runtime, RuntimeIssuer: claims.RuntimeIssuer, Subject: claims.Subject, PrincipalID: claims.PrincipalID,
				AuthMethod: workload.AuthMethodHopAssertion, SandboxRef: claims.SandboxRef, RequestID: claims.RequestID,
				VerifiedAt: time.Unix(claims.IssuedAt, 0).UTC().Format(time.RFC3339),
			}
			if sid := strings.TrimSpace(claims.SessionID); sid != "" {
				if _, err := evidence.ValidateOrchValue("session_id", sid); err == nil {
					facts.SessionID = sid
				}
			}
			ctx := withAgentAuth(r.Context(), id)
			ctx = requestctx.SetWorkloadFacts(ctx, facts)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
