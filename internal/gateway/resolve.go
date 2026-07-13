package gateway

import (
	"errors"
	"net/http"
	"strings"
)

var (
	// ErrUnknownKey is returned when a presented key matches no agent.
	ErrUnknownKey = errors.New("unknown agent key")
	// ErrKeyRequired is returned when a request carries no key at all.
	ErrKeyRequired = errors.New("agent key required")
)

// resolveIdentityFrom authenticates a gateway request (#266) against ONE
// registry generation, captured by the caller at request entry (#267): every
// identity fact this request uses — authentication, tenant canonicalization,
// cache scoping — derives from the SAME snapshot, so a reload swap mid-flight
// can never split a request across two generations.
//
//	presented key ──► known agent? ──yes──► *ResolvedIdentity
//	                        │ no
//	                        ▼
//	                     reject
//
// The only exception is the explicit quickstart synthetic identity, injected
// via request context by the in-process facade. There is no source-IP
// identification and no anonymous fallback — a request either presents a key
// bound to an agent or it is rejected.
func resolveIdentityFrom(reg *IdentityRegistry, r *http.Request) (*ResolvedIdentity, error) {
	if id := QuickstartIdentityFromContext(r.Context()); id != nil {
		return id, nil
	}
	key := extractKey(r)
	if key == "" {
		return nil, ErrKeyRequired
	}
	if id, ok := reg.ResolveKey(key); ok {
		return id, nil
	}
	return nil, ErrUnknownKey
}

// extractKey pulls the presented agent key from the request: OpenAI-style
// `Authorization: Bearer <key>` or Anthropic-style `x-api-key`.
func extractKey(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	if k := r.Header.Get("x-api-key"); k != "" {
		return strings.TrimSpace(k)
	}
	return ""
}
