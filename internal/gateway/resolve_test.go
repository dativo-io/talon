package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Resolution semantics (#266): a presented key resolves to exactly one agent
// or the request is rejected. No source-IP identification, no anonymous
// fallback; the quickstart synthetic identity (context-injected by the
// in-process facade) is the only non-key path.

func resolveReq(t *testing.T, mutate func(*http.Request)) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://test/v1/proxy/openai/v1/chat/completions", nil)
	require.NoError(t, err)
	if mutate != nil {
		mutate(req)
	}
	return req
}

func TestResolveIdentityByBearerKey(t *testing.T) {
	g := &Gateway{registry: NewRegistryHolder(testRegistry(
		testIdentity("customer-support", "acme", "tk-support-1", nil),
		testIdentity("coding", "default", "tk-coding-1", nil),
	))}

	id, err := g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tk-support-1")
	}))
	require.NoError(t, err)
	assert.Equal(t, "customer-support", id.Name)
	assert.Equal(t, "acme", id.TenantID, "tenant is derived key → agent → tenant_id")

	// Whitespace around the bearer token is tolerated.
	id, err = g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer   tk-coding-1  ")
	}))
	require.NoError(t, err)
	assert.Equal(t, "coding", id.Name)
}

func TestResolveIdentityByXAPIKey(t *testing.T) {
	g := &Gateway{registry: NewRegistryHolder(testRegistry(testIdentity("customer-support", "acme", "tk-support-1", nil)))}
	id, err := g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("x-api-key", "tk-support-1")
	}))
	require.NoError(t, err)
	assert.Equal(t, "customer-support", id.Name)
}

func TestResolveIdentityUnknownKeyRejected(t *testing.T) {
	g := &Gateway{registry: NewRegistryHolder(testRegistry(testIdentity("customer-support", "acme", "tk-support-1", nil)))}
	_, err := g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer tk-wrong")
	}))
	assert.ErrorIs(t, err, ErrUnknownKey)
}

func TestResolveIdentityMissingKeyRejected(t *testing.T) {
	g := &Gateway{registry: NewRegistryHolder(testRegistry(testIdentity("customer-support", "acme", "tk-support-1", nil)))}
	_, err := g.resolveIdentity(resolveReq(t, nil))
	assert.ErrorIs(t, err, ErrKeyRequired)

	// A non-bearer Authorization scheme is not a key.
	_, err = g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	}))
	assert.ErrorIs(t, err, ErrKeyRequired)
}

func TestResolveIdentityEmptyRegistryRejectsEverything(t *testing.T) {
	g := &Gateway{registry: NewRegistryHolder(testRegistry())}
	_, err := g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer any-key")
	}))
	assert.ErrorIs(t, err, ErrUnknownKey)

	// Nil registry (quickstart-mode gateway) behaves the same for keyed requests.
	g = &Gateway{}
	_, err = g.resolveIdentity(resolveReq(t, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer any-key")
	}))
	assert.ErrorIs(t, err, ErrUnknownKey)
}

func TestResolveIdentityQuickstartContext(t *testing.T) {
	// The synthetic identity short-circuits resolution — and only via the
	// request context, which only the in-process facade can set.
	g := &Gateway{}
	req := resolveReq(t, nil)
	req = req.WithContext(WithQuickstartIdentity(req.Context(), NewQuickstartIdentity()))
	id, err := g.resolveIdentity(req)
	require.NoError(t, err)
	assert.Equal(t, "quickstart", id.TenantID)
	assert.True(t, id.HasTag("quickstart"))

	// A quickstart-context request with a bogus key still resolves to the
	// synthetic identity (the facade owns the context; headers are irrelevant).
	req = resolveReq(t, func(r *http.Request) { r.Header.Set("Authorization", "Bearer junk") })
	req = req.WithContext(WithQuickstartIdentity(req.Context(), NewQuickstartIdentity()))
	id, err = g.resolveIdentity(req)
	require.NoError(t, err)
	assert.Equal(t, "quickstart-local", id.Name)
}
