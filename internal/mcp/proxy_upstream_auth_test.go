package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// authTestVault builds a real vault with one upstream credential under the
// given ACL.
func authTestVault(t *testing.T, name, value string, acl secrets.ACL) *secrets.SecretStore {
	t.Helper()
	store, err := secrets.NewSecretStore(t.TempDir()+"/s.db", "0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Set(context.Background(), name, []byte(value), acl))
	return store
}

// authProxy builds an intercept proxy with a vault-backed upstream auth block.
func authProxy(t *testing.T, upstreamURL string, vault UpstreamSecretGetter) (*ProxyHandler, *evidence.Store) {
	t.Helper()
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode: policy.ProxyModeIntercept,
			Upstream: policy.UpstreamConfig{
				URL:    upstreamURL,
				Vendor: "testvendor",
				Auth:   &policy.UpstreamAuthConfig{SecretName: "vendor-upstream-key"},
			},
			AllowedTools: []policy.ToolMapping{{Name: "crm_lookup"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return NewProxyHandler(cfg, engine, store, nil, vault), store
}

// TestProxyUpstreamAuth_HeaderInjected pins #358: the vault-resolved
// credential arrives at the upstream as "Authorization: Bearer <secret>",
// and the caller-side response never contains it.
func TestProxyUpstreamAuth_HeaderInjected(t *testing.T) {
	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"ok"}}`))
	}))
	t.Cleanup(up.Close)

	vault := authTestVault(t, "vendor-upstream-key", "vendor-token-123", secrets.ACL{})
	h, _ := authProxy(t, up.URL, vault)

	rec, resp := attribCall(t, h, context.Background(), nil, "crm_lookup")
	require.Nil(t, resp.Error)
	assert.Equal(t, "Bearer vendor-token-123", gotAuth, "vault credential injected as Bearer by default")
	assert.NotContains(t, rec.Body.String(), "vendor-token-123", "the credential never leaks to the caller")
}

// TestProxyUpstreamAuth_Rotation pins the per-request resolution contract:
// `talon secrets set` with a new value takes effect on the NEXT request,
// no restart.
func TestProxyUpstreamAuth_Rotation(t *testing.T) {
	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"ok"}}`))
	}))
	t.Cleanup(up.Close)

	vault := authTestVault(t, "vendor-upstream-key", "token-v1", secrets.ACL{})
	h, _ := authProxy(t, up.URL, vault)

	_, resp := attribCall(t, h, context.Background(), nil, "crm_lookup")
	require.Nil(t, resp.Error)
	assert.Equal(t, "Bearer token-v1", gotAuth)

	require.NoError(t, vault.Set(context.Background(), "vendor-upstream-key", []byte("token-v2"), secrets.ACL{}))
	_, resp = attribCall(t, h, context.Background(), nil, "crm_lookup")
	require.Nil(t, resp.Error)
	assert.Equal(t, "Bearer token-v2", gotAuth, "rotation lands on the next request without restart")
}

// TestProxyUpstreamAuth_VaultMissFailsClosed pins the fail-closed contract:
// a missing vault entry means the request NEVER reaches the upstream; the
// caller sees a generic configuration error (no vault detail leaks) and
// signed evidence carries the typed reason.
func TestProxyUpstreamAuth_VaultMissFailsClosed(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	// Vault exists but holds a DIFFERENT secret name.
	vault := authTestVault(t, "some-other-secret", "x", secrets.ACL{})
	h, store := authProxy(t, up.URL, vault)

	_, resp := attribCall(t, h, context.Background(), nil, "crm_lookup")
	require.NotNil(t, resp.Error)
	assert.Equal(t, "Service configuration error", resp.Error.Message, "no vault detail leaks to the vendor")
	assert.Equal(t, TalonCodeUpstreamError, talonCodeOf(t, resp.Error))
	assert.False(t, hit, "the request must never leave without its credential")

	records := listRecords(t, store, "default")
	require.Len(t, records, 1)
	assert.Equal(t, "proxy_upstream_error", records[0].InvocationType)
	assert.Contains(t, records[0].PolicyDecision.Reasons, "secret retrieval error")
	assert.Equal(t, "secret", records[0].UpstreamAuthMode, "auth mode recorded, gateway parity")
	assert.Nil(t, records[0].DataFlow, "nothing egressed")
}

// TestProxyUpstreamAuth_ACLDenied pins the vault ACL path: the proxy reads
// the secret as its own declared agent; an ACL that forbids that agent
// fails closed exactly like a miss.
func TestProxyUpstreamAuth_ACLDenied(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	vault := authTestVault(t, "vendor-upstream-key", "secret", secrets.ACL{
		ForbiddenAgents: []string{"vendor-proxy-agent"},
	})
	h, store := authProxy(t, up.URL, vault)

	_, resp := attribCall(t, h, context.Background(), nil, "crm_lookup")
	require.NotNil(t, resp.Error)
	assert.Equal(t, "Service configuration error", resp.Error.Message)
	assert.False(t, hit)

	records := listRecords(t, store, "default")
	require.Len(t, records, 1)
	assert.Contains(t, records[0].PolicyDecision.Reasons, "secret retrieval error")
}

// TestProxyUpstreamAuth_CustomHeaderAndRawScheme pins the header/scheme
// surface: a custom header name with an explicit empty scheme sends the raw
// secret value.
func TestProxyUpstreamAuth_CustomHeaderAndRawScheme(t *testing.T) {
	var gotKey string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"ok"}}`))
	}))
	t.Cleanup(up.Close)

	vault := authTestVault(t, "vendor-upstream-key", "raw-key-9", secrets.ACL{})
	h, _ := authProxy(t, up.URL, vault)
	raw := ""
	h.config.Proxy.Upstream.Auth.Header = "X-Api-Key"
	h.config.Proxy.Upstream.Auth.Scheme = &raw

	_, resp := attribCall(t, h, context.Background(), nil, "crm_lookup")
	require.Nil(t, resp.Error)
	assert.Equal(t, "raw-key-9", gotKey, "explicit empty scheme sends the raw value in the custom header")
}
