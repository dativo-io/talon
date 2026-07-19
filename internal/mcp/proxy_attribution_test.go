package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// attribUpstream is a permissive fake vendor that records whether it was hit.
func attribUpstream(t *testing.T, hit *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hit = true
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]string{"content": "ok"},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// attribHandler builds a proxy with the given mode and forbidden list. The
// classifier stays nil so allowed calls produce exactly one evidence record.
func attribHandler(t *testing.T, mode, upstreamURL string, forbidden []string) (*ProxyHandler, *evidence.Store) {
	t.Helper()
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode:           mode,
			Upstream:       policy.UpstreamConfig{URL: upstreamURL, Vendor: "testvendor"},
			AllowedTools:   []policy.ToolMapping{{Name: "crm_lookup"}},
			ForbiddenTools: forbidden,
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return NewProxyHandler(cfg, engine, store, nil), store
}

func attribCall(t *testing.T, h *ProxyHandler, ctx context.Context, headers map[string]string, tool string) (*httptest.ResponseRecorder, jsonrpcResponse) {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{"name": tool, "arguments": map[string]string{"q": "hello"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader(body)).WithContext(ctx)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var resp jsonrpcResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp
}

func listRecords(t *testing.T, store *evidence.Store, tenant string) []evidence.Evidence {
	t.Helper()
	records, err := store.List(context.Background(), tenant, "", time.Now().Add(-time.Minute), time.Now().Add(time.Minute), 20)
	require.NoError(t, err)
	return records
}

// TestProxyUnsetMode_ForbiddenBlocked pins the #346 fail-open: a handler
// constructed with an unset mode (bypassing the loaders) must still block
// forbidden tools — empty mode used to silently behave as passthrough while
// evidence claimed the call was blocked.
func TestProxyUnsetMode_ForbiddenBlocked(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, "" /* unset */, up.URL, []string{"user_delete"})

	_, resp := attribCall(t, h, context.Background(), nil, "user_delete")
	require.NotNil(t, resp.Error, "forbidden tool must be blocked with unset mode")
	assert.Contains(t, resp.Error.Message, "tool not allowed by policy")
	assert.False(t, hit, "forbidden tool must never reach the upstream outside explicit passthrough")

	records := listRecords(t, store, "default")
	require.Len(t, records, 1)
	assert.Equal(t, "proxy_tool_blocked", records[0].InvocationType)
	assert.False(t, records[0].PolicyDecision.Allowed)
}

// TestProxyLoader_ModeDefaultAndValidation pins the #346 loader contract:
// unset mode defaults to intercept; unknown values are rejected.
func TestProxyLoader_ModeDefaultAndValidation(t *testing.T) {
	cfg := &policy.ProxyPolicyConfig{}
	cfg.Proxy.Upstream.URL = "http://example.com/mcp"
	cfg.Proxy.AllowedTools = []policy.ToolMapping{{Name: "t"}}
	require.NoError(t, validateAndApplyDefaults(cfg))
	assert.Equal(t, policy.ProxyModeIntercept, cfg.Proxy.Mode, "unset mode must default to intercept")

	cfg.Proxy.Mode = "intercpt" // typo must fail loudly, not fail open
	err := validateAndApplyDefaults(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `proxy.mode "intercpt" is invalid`)
}

// TestProxyPassthrough_ForbiddenForwarded_HonestEvidence pins the #346
// evidence-honesty fix: explicit passthrough forwards a forbidden tool, and
// the record says so — an ALLOWED shadow-violation record, not a fake
// "blocked" one.
func TestProxyPassthrough_ForbiddenForwarded_HonestEvidence(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, policy.ProxyModePassthrough, up.URL, []string{"user_delete"})

	_, resp := attribCall(t, h, context.Background(), nil, "user_delete")
	require.Nil(t, resp.Error, "passthrough forwards forbidden tools")
	assert.True(t, hit)

	records := listRecords(t, store, "default")
	var sv *evidence.Evidence
	for i := range records {
		if records[i].InvocationType == "proxy_shadow_violation" {
			sv = &records[i]
		}
		assert.NotEqual(t, "proxy_tool_blocked", records[i].InvocationType,
			"a forwarded call must not be recorded as blocked")
	}
	require.NotNil(t, sv, "passthrough must record the would-have-denied verdict")
	assert.True(t, sv.PolicyDecision.Allowed, "the call was forwarded; the deny verdict lives in ShadowViolations")
	assert.True(t, sv.ObservationModeOverride)
	require.Len(t, sv.ShadowViolations, 1)
	assert.Equal(t, "tool_block", sv.ShadowViolations[0].Type)
}

// TestProxyShadow_PolicyDeny_RecordsWouldDeny pins the #346 gap where shadow
// mode produced no evidence at all for a policy deny: the deny must land as a
// would-have-denied shadow violation while the call is forwarded.
func TestProxyShadow_PolicyDeny_RecordsWouldDeny(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, policy.ProxyModeShadow, up.URL, nil)

	// not_in_allowlist is not in AllowedTools -> tool-access policy denies it.
	_, resp := attribCall(t, h, context.Background(), nil, "not_in_allowlist")
	require.Nil(t, resp.Error, "shadow mode forwards policy denials")
	assert.True(t, hit)

	records := listRecords(t, store, "default")
	var found bool
	for _, rec := range records {
		if rec.InvocationType == "proxy_shadow_violation" {
			found = true
			require.Len(t, rec.ShadowViolations, 1)
			assert.Equal(t, "policy_deny", rec.ShadowViolations[0].Type)
		}
	}
	assert.True(t, found, "shadow mode must record the would-have-denied policy decision")
}

// TestProxyEvidence_AuthenticatedAttribution pins #350: records carry the
// authenticated agent, the asserted session, and ONE correlation ID across
// all records of the request — never the hardcoded "mcp-proxy".
func TestProxyEvidence_AuthenticatedAttribution(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	// Passthrough + forbidden produces two records for one call (shadow
	// violation + final proxy_tool_call), exercising correlation reuse.
	h, store := attribHandler(t, policy.ProxyModePassthrough, up.URL, []string{"user_delete"})

	ctx := requestctx.SetTenantID(context.Background(), "acme")
	ctx = requestctx.SetAgentIdentity(ctx, requestctx.AgentIdentity{
		AgentID: "coding-assistant", TenantID: "acme", Team: "coding",
	})
	rec, resp := attribCall(t, h, ctx, map[string]string{
		"X-Talon-Session-ID": "sess-demo-1",
		"X-Correlation-ID":   "corr-demo-1",
	}, "user_delete")
	require.Nil(t, resp.Error)
	assert.Equal(t, "corr-demo-1", rec.Header().Get("X-Correlation-ID"), "resolved correlation is echoed")
	assert.Equal(t, "sess-demo-1", rec.Header().Get("X-Talon-Session-ID"), "asserted session is echoed")

	records := listRecords(t, store, "acme")
	require.GreaterOrEqual(t, len(records), 2, "one call in passthrough with a forbidden tool yields at least two records")
	for _, r := range records {
		assert.Equal(t, "coding-assistant", r.AgentID, "evidence must carry the authenticated agent")
		assert.Equal(t, "acme", r.TenantID)
		assert.Equal(t, "coding", r.Team)
		assert.Equal(t, "sess-demo-1", r.SessionID)
		assert.Equal(t, "corr-demo-1", r.CorrelationID, "every record of one call shares the inbound correlation ID")
	}
}

// TestProxyEvidence_NoIdentity_FallsBackToConfigAgent pins the admin/dev-open
// attribution: with no authenticated identity, records attribute to the proxy
// config's own agent name (not the legacy hardcoded "mcp-proxy").
func TestProxyEvidence_NoIdentity_FallsBackToConfigAgent(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, policy.ProxyModeIntercept, up.URL, nil)

	_, resp := attribCall(t, h, context.Background(), nil, "crm_lookup")
	require.Nil(t, resp.Error)

	records := listRecords(t, store, "default")
	require.Len(t, records, 1)
	assert.Equal(t, "vendor-proxy-agent", records[0].AgentID)
	assert.NotEmpty(t, records[0].CorrelationID)
	assert.Empty(t, records[0].SessionID, "no session is synthesized when none is asserted")
}

// TestProxyEvidence_BlockedCarriesPolicyDeniedTool pins the #350 acceptance
// criterion: a forbidden-tool deny in intercept mode carries the
// deterministic POLICY_DENIED_TOOL explanation code.
func TestProxyEvidence_BlockedCarriesPolicyDeniedTool(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, policy.ProxyModeIntercept, up.URL, []string{"user_delete"})

	_, resp := attribCall(t, h, context.Background(), nil, "user_delete")
	require.NotNil(t, resp.Error)
	assert.False(t, hit)

	records := listRecords(t, store, "default")
	require.Len(t, records, 1)
	require.NotEmpty(t, records[0].Explanations)
	primary, ok := explanation.Primary(records[0].Explanations)
	require.True(t, ok)
	assert.Equal(t, explanation.CodePolicyDeniedTool, primary.Code)
}

// TestProxyInvalidAttributionHeader_Rejected400 pins the hygiene contract
// shared with the gateway: an oversized or non-token session header is
// rejected with HTTP 400 before any evidence is written.
func TestProxyInvalidAttributionHeader_Rejected400(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, policy.ProxyModeIntercept, up.URL, nil)

	rec, _ := attribCall(t, h, context.Background(), map[string]string{
		"X-Talon-Session-ID": strings.Repeat("a", evidence.OrchHeaderMaxLen+1),
	}, "crm_lookup")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.False(t, hit, "rejected requests must not reach the upstream")
	assert.Empty(t, listRecords(t, store, "default"), "rejected requests must not write evidence")
}
