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

	"github.com/dativo-io/talon/internal/classifier"
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
	return NewProxyHandler(cfg, engine, store, nil, nil), store
}

func attribCall(t *testing.T, h *ProxyHandler, ctx context.Context, headers map[string]string, tool string) (*httptest.ResponseRecorder, jsonrpcResponse) {
	t.Helper()
	return attribCallArgs(t, h, ctx, headers, tool, map[string]string{"q": "hello"})
}

func attribCallArgs(t *testing.T, h *ProxyHandler, ctx context.Context, headers map[string]string, tool string, args map[string]string) (*httptest.ResponseRecorder, jsonrpcResponse) {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{"name": tool, "arguments": args},
	})
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
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
	svTypes := map[string]*evidence.Evidence{}
	for i := range records {
		if records[i].InvocationType == "proxy_shadow_violation" {
			require.Len(t, records[i].ShadowViolations, 1)
			svTypes[records[i].ShadowViolations[0].Type] = &records[i]
		}
		assert.NotEqual(t, "proxy_tool_blocked", records[i].InvocationType,
			"a forwarded call must not be recorded as blocked")
	}
	// user_delete is both explicitly forbidden AND absent from allowed_tools,
	// so passthrough must record BOTH would-have-denied verdicts (#346): the
	// forbidden-tool match and the tool-access policy deny.
	require.Contains(t, svTypes, "tool_block", "passthrough must record the forbidden-tool would-deny")
	require.Contains(t, svTypes, "policy_deny", "passthrough must record the policy would-deny")
	for _, sv := range svTypes {
		assert.True(t, sv.PolicyDecision.Allowed, "the call was forwarded; the deny verdict lives in ShadowViolations")
		assert.True(t, sv.ObservationModeOverride)
	}
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

// TestProxyEvidence_OrchestrationBlockEmission pins the #350 orchestration
// contract on the MCP wire: identity headers populate the record's
// orchestration block (client defaulting to "generic", client_asserted
// provenance), and each identity header is hygiene-validated.
func TestProxyEvidence_OrchestrationBlockEmission(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, policy.ProxyModeIntercept, up.URL, nil)

	_, resp := attribCall(t, h, context.Background(), map[string]string{
		"X-Talon-Session-ID":      "sess-orch-1",
		"X-Talon-Agent-ID":        "reviewer-subagent",
		"X-Talon-Parent-Agent-ID": "orchestrator",
	}, "crm_lookup")
	require.Nil(t, resp.Error)

	records := listRecords(t, store, "default")
	require.Len(t, records, 1)
	orch := records[0].Orchestration
	require.NotNil(t, orch, "identity headers must emit the orchestration block")
	assert.Equal(t, "reviewer-subagent", orch.AgentID)
	assert.Equal(t, "orchestrator", orch.ParentAgentID)
	assert.Equal(t, "generic", orch.Client, "client defaults to generic when identity is asserted without X-Talon-Client")
	assert.Equal(t, "sess-orch-1", orch.SessionID)
	assert.Equal(t, "client_asserted", orch.SessionSource)
	assert.Equal(t, "client_asserted", orch.Provenance)

	// A bare session (no identity headers) must NOT emit the block —
	// the session_id column alone carries it (gateway emission rule).
	h2, store2 := attribHandler(t, policy.ProxyModeIntercept, up.URL, nil)
	_, resp = attribCall(t, h2, context.Background(), map[string]string{"X-Talon-Session-ID": "sess-bare"}, "crm_lookup")
	require.Nil(t, resp.Error)
	recs2 := listRecords(t, store2, "default")
	require.Len(t, recs2, 1)
	assert.Nil(t, recs2[0].Orchestration)
	assert.Equal(t, "sess-bare", recs2[0].SessionID)

	// Identity headers are hygiene-validated like the session header.
	rec, _ := attribCall(t, h2, context.Background(), map[string]string{
		"X-Talon-Agent-ID": "bad value with spaces",
	}, "crm_lookup")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestProxyShadow_PIIWouldDeny_RecordsShadowViolation pins the #346 gap on
// the PII gate: in shadow mode a PII policy deny (detected PII with no
// redaction rule) is recorded as a would-have-denied shadow violation while
// the (redacted) call is forwarded — and the allowed records carry no
// Execution.Error, so session summaries do not count them as errors.
func TestProxyShadow_PIIWouldDeny_RecordsShadowViolation(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode:         policy.ProxyModeShadow,
			Upstream:     policy.UpstreamConfig{URL: up.URL, Vendor: "testvendor"},
			AllowedTools: []policy.ToolMapping{{Name: "crm_lookup"}},
		},
		// No redaction rules: rego proxy_pii_redaction denies any detected PII.
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner(), nil)

	_, resp := attribCallArgs(t, h, context.Background(), map[string]string{"X-Talon-Session-ID": "sess-pii-1"}, "crm_lookup",
		map[string]string{"email": "jane.doe@example.com"})
	require.Nil(t, resp.Error, "shadow mode forwards the PII would-deny")
	assert.True(t, hit)

	records := listRecords(t, store, "default")
	// #357: exactly TWO records — the shadow violation (non-request class)
	// and the terminal proxy_tool_call. The old separate allowed PII "note"
	// is folded into the terminal record.
	require.Len(t, records, 2, "shadow PII call = shadow violation + ONE terminal record")
	var sv, terminal *evidence.Evidence
	for i := range records {
		switch records[i].InvocationType {
		case "proxy_shadow_violation":
			sv = &records[i]
		case "proxy_tool_call":
			terminal = &records[i]
		}
		if records[i].PolicyDecision.Allowed {
			assert.Empty(t, records[i].Execution.Error,
				"allowed records must not carry Execution.Error (session summaries count it as an error)")
		}
	}
	require.NotNil(t, sv, "shadow mode must record the PII would-deny")
	require.Len(t, sv.ShadowViolations, 1)
	assert.Equal(t, "pii_block", sv.ShadowViolations[0].Type)
	assert.True(t, sv.ObservationModeOverride)
	assert.Equal(t, "sess-pii-1", sv.SessionID)
	require.NotNil(t, terminal, "the terminal record must exist")
	assert.Contains(t, terminal.Classification.PIIDetected, "email",
		"#357 fold: request-side PII classification rides on the terminal record")
}

// TestProxyPIIAllowed_OneRequestClassRecord pins the #357 fold directly:
// an ALLOWED PII-bearing call in intercept mode (redaction rules present)
// produces exactly ONE record, carrying the request-side classification and
// data flow that used to live on the separate note record.
func TestProxyPIIAllowed_OneRequestClassRecord(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode:         policy.ProxyModeIntercept,
			Upstream:     policy.UpstreamConfig{URL: up.URL, Vendor: "testvendor"},
			AllowedTools: []policy.ToolMapping{{Name: "crm_lookup"}},
		},
		// Redaction rule present -> rego proxy_pii_redaction allows the call.
		PIIHandling: policy.PIIHandlingConfig{
			RedactionRules: []policy.RedactionRule{{Field: "email", Method: "hash"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner(), nil)

	_, resp := attribCallArgs(t, h, context.Background(), nil, "crm_lookup",
		map[string]string{"email": "jane.doe@example.com"})
	require.Nil(t, resp.Error)
	assert.True(t, hit)

	records := listRecords(t, store, "default")
	require.Len(t, records, 1, "#357: one allowed PII call = ONE request-class record (was two)")
	r := records[0]
	assert.Equal(t, "proxy_tool_call", r.InvocationType)
	assert.True(t, r.PolicyDecision.Allowed)
	assert.Contains(t, r.Classification.PIIDetected, "email")
	require.NotNil(t, r.DataFlow, "request-side data flow must ride on the terminal record")
}

// TestProxyUpstreamError_RecordsTrail pins #357 accompaniment 3: a call whose
// upstream fails must still leave its evidence trail — a policy-ALLOWED
// record with Status failed, carrying the request-side PII classification.
func TestProxyUpstreamError_RecordsTrail(t *testing.T) {
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode: policy.ProxyModeIntercept,
			// Closed port: the upstream request fails.
			Upstream:     policy.UpstreamConfig{URL: "http://127.0.0.1:1", Vendor: "testvendor"},
			AllowedTools: []policy.ToolMapping{{Name: "crm_lookup"}},
		},
		PIIHandling: policy.PIIHandlingConfig{
			RedactionRules: []policy.RedactionRule{{Field: "email", Method: "hash"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner(), nil)

	_, resp := attribCallArgs(t, h, context.Background(), nil, "crm_lookup",
		map[string]string{"email": "jane.doe@example.com"})
	require.NotNil(t, resp.Error, "upstream failure surfaces as a JSON-RPC error")

	records := listRecords(t, store, "default")
	require.Len(t, records, 1, "the upstream failure is the call's terminal record")
	r := records[0]
	assert.Equal(t, "proxy_upstream_error", r.InvocationType)
	assert.True(t, r.PolicyDecision.Allowed, "policy allowed the call; the vendor failed — not a deny")
	assert.Equal(t, "failed", r.Status)
	assert.Equal(t, "upstream_error", r.FailureReason)
	assert.NotEmpty(t, r.Execution.Error, "execution failure must count in session summaries")
	assert.Contains(t, r.Classification.PIIDetected, "email",
		"the request-side PII trail survives the upstream failure")
	assert.Nil(t, r.DataFlow,
		"transport failure: a signed flow item must never assert delivery the wire may not have made")
}

// upstreamErrorHandler builds an intercept proxy with a redaction rule whose
// upstream is the given httptest handler — for the non-transport failure shapes.
func upstreamErrorHandler(t *testing.T, upstream http.HandlerFunc) (*ProxyHandler, *evidence.Store) {
	t.Helper()
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode:         policy.ProxyModeIntercept,
			Upstream:     policy.UpstreamConfig{URL: srv.URL, Vendor: "testvendor"},
			AllowedTools: []policy.ToolMapping{{Name: "crm_lookup"}},
		},
		PIIHandling: policy.PIIHandlingConfig{
			RedactionRules: []policy.RedactionRule{{Field: "email", Method: "hash"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return NewProxyHandler(cfg, engine, store, classifier.MustNewScanner(), nil), store
}

// TestProxyUpstreamDecodeFailure_RecordsTrail pins the second upstream-error
// shape (#357 review): a 200 with a non-JSON body. Egress DID happen, so the
// record keeps its data-flow item, unlike the transport case.
func TestProxyUpstreamDecodeFailure_RecordsTrail(t *testing.T) {
	h, store := upstreamErrorHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>gateway timeout</html>"))
	})

	_, resp := attribCallArgs(t, h, context.Background(), nil, "crm_lookup",
		map[string]string{"email": "jane.doe@example.com"})
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "upstream response invalid")

	records := listRecords(t, store, "default")
	require.Len(t, records, 1)
	r := records[0]
	assert.Equal(t, "proxy_upstream_error", r.InvocationType)
	assert.Equal(t, "failed", r.Status)
	assert.Contains(t, r.PolicyDecision.Reasons, "upstream_response_invalid")
	assert.Contains(t, r.Classification.PIIDetected, "email")
	require.NotNil(t, r.DataFlow, "a response arrived, so the egress flow item is truthful and must stay")
}

// TestProxyUpstreamJSONRPCError_RecordsFailure pins the third shape (#357
// review): the vendor answers with a valid JSON-RPC error body. The call
// executed and failed — it must never be recorded as a clean allowed
// completion, and the vendor's error passes through to the caller.
func TestProxyUpstreamJSONRPCError_RecordsFailure(t *testing.T) {
	h, store := upstreamErrorHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal error"}}`))
	})

	_, resp := attribCallArgs(t, h, context.Background(), nil, "crm_lookup",
		map[string]string{"email": "jane.doe@example.com"})
	require.NotNil(t, resp.Error, "the vendor's JSON-RPC error passes through")
	assert.Equal(t, -32603, resp.Error.Code)

	records := listRecords(t, store, "default")
	require.Len(t, records, 1)
	r := records[0]
	assert.Equal(t, "proxy_upstream_error", r.InvocationType)
	assert.Equal(t, "failed", r.Status)
	require.NotEmpty(t, r.PolicyDecision.Reasons)
	assert.Contains(t, r.PolicyDecision.Reasons[0], "upstream_jsonrpc_error")
	assert.NotEmpty(t, r.Execution.Error)
}

// TestProxyEvidence_GeneratedCorrelationSharedAcrossRecords pins the #350
// correlation contract for the no-header case: one generated request-scoped
// ID is shared by every record of the call.
func TestProxyEvidence_GeneratedCorrelationSharedAcrossRecords(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	// Passthrough + forbidden yields multiple records for one call.
	h, store := attribHandler(t, policy.ProxyModePassthrough, up.URL, []string{"user_delete"})

	rec, resp := attribCall(t, h, context.Background(), nil, "user_delete")
	require.Nil(t, resp.Error)

	records := listRecords(t, store, "default")
	require.GreaterOrEqual(t, len(records), 2)
	corr := records[0].CorrelationID
	assert.True(t, strings.HasPrefix(corr, "mcp_proxy_"), "generated correlation keeps the mcp_proxy_ prefix")
	for _, r := range records {
		assert.Equal(t, corr, r.CorrelationID, "all records of one call share the generated correlation ID")
	}
	assert.Equal(t, corr, rec.Header().Get("X-Correlation-ID"), "generated correlation is echoed to the caller")
}

// TestProxyUnknownMethod_RejectedFailClosed pins #356: the proxy governs
// tools/list and tools/call only; any other MCP method (resources/read,
// prompts/get, initialize, ...) is rejected with -32601 and an attributed
// deny record — never forwarded ungoverned, mirroring the native /mcp
// server. The contract is mode-INDEPENDENT: passthrough and shadow reject
// exactly like intercept ("in every mode" is the documented surface, and
// "passthrough forwards everything" must never grow to cover methods).
// talonCodeOf extracts error.data.talon_code from a decoded response (#369).
func talonCodeOf(t *testing.T, e *rpcError) string {
	t.Helper()
	require.NotNil(t, e)
	data, ok := e.Data.(map[string]interface{})
	require.True(t, ok, "error.data must carry the talon_code object, got %T", e.Data)
	code, _ := data["talon_code"].(string)
	return code
}

func TestProxyUnknownMethod_RejectedFailClosed(t *testing.T) {
	methods := []string{"resources/read", "prompts/get", "logging/setLevel"}
	for _, mode := range []string{policy.ProxyModeIntercept, policy.ProxyModePassthrough, policy.ProxyModeShadow} {
		t.Run(mode, func(t *testing.T) {
			hit := false
			up := attribUpstream(t, &hit)
			h, store := attribHandler(t, mode, up.URL, nil)

			for _, method := range methods {
				body, _ := json.Marshal(map[string]interface{}{
					"jsonrpc": "2.0", "id": 7, "method": method,
					"params": map[string]interface{}{"uri": "file:///etc/passwd"},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				var resp jsonrpcResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				require.NotNil(t, resp.Error, "method %s must be rejected in mode %s", method, mode)
				assert.Equal(t, codeMethodNotFound, resp.Error.Code)
				assert.Contains(t, resp.Error.Message, method)
				assert.Equal(t, TalonCodeMethodNotAllowed, talonCodeOf(t, resp.Error),
					"rejections carry the stable #369 code, not just prose")
			}
			assert.False(t, hit, "ungoverned methods must never reach the upstream (mode %s)", mode)

			records := listRecords(t, store, "default")
			require.Len(t, records, len(methods), "each rejection is the request's terminal record")
			gotReasons := make([]string, 0, len(records))
			for _, r := range records {
				assert.Equal(t, "proxy_method_rejected", r.InvocationType)
				assert.False(t, r.PolicyDecision.Allowed)
				assert.Equal(t, "vendor-proxy-agent", r.AgentID, "rejections carry full #350 attribution")
				require.NotEmpty(t, r.PolicyDecision.Reasons, "deny records must name their reason")
				gotReasons = append(gotReasons, r.PolicyDecision.Reasons[0])
				primary, ok := explanation.Primary(r.Explanations)
				require.True(t, ok)
				assert.Equal(t, explanation.CodePolicyDeniedTool, primary.Code)
			}
			wantReasons := make([]string, 0, len(methods))
			for _, m := range methods {
				wantReasons = append(wantReasons, "unsupported_method:"+m)
			}
			assert.ElementsMatch(t, wantReasons, gotReasons,
				"every rejection reason names the rejected method")
		})
	}
}

// TestProxyMCPHandshake pins #367: the mandatory MCP lifecycle completes
// against the proxy — initialize answered LOCALLY (tools capability only,
// protocolVersion echoed, NEVER forwarded upstream), notifications/initialized
// accepted with 202 and no body, then governed tools/call proceeds normally.
func TestProxyMCPHandshake(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, _ := attribHandler(t, policy.ProxyModeIntercept, up.URL, nil)

	// 1. initialize — answered locally.
	initBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "mcp-inspector", "version": "1.0"},
		},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(initBody))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var initResp jsonrpcResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &initResp))
	require.Nil(t, initResp.Error, "initialize must succeed: %v", initResp.Error)
	result, ok := initResp.Result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "2025-03-26", result["protocolVersion"], "the client's protocolVersion is echoed")
	caps, ok := result["capabilities"].(map[string]interface{})
	require.True(t, ok)
	_, hasTools := caps["tools"]
	assert.True(t, hasTools, "the tools capability is advertised")
	assert.NotContains(t, caps, "resources", "resources are NOT advertised — not part of the governed surface")
	assert.NotContains(t, caps, "prompts", "prompts are NOT advertised")
	assert.False(t, hit, "initialize is answered locally — NEVER forwarded upstream")

	// 2. notifications/initialized — 202, no body.
	notifBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "notifications/initialized",
	})
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(notifBody))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Empty(t, rec.Body.String(), "notifications get no response body")
	assert.False(t, hit, "notifications/initialized is never forwarded upstream")

	// 3. Governed traffic proceeds.
	_, resp := attribCall(t, h, context.Background(), nil, "crm_lookup")
	require.Nil(t, resp.Error)
	assert.True(t, hit, "tools/call still reaches the upstream")
}

// TestNativeMCPHandshake pins #367 on the native /mcp server: same local
// initialize + accepted initialized notification.
func TestNativeMCPHandshake(t *testing.T) {
	h := &Handler{}
	initBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{"protocolVersion": "2025-06-18"},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(initBody))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp jsonrpcResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Nil(t, resp.Error, "native initialize must succeed")
	result, ok := resp.Result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "2025-06-18", result["protocolVersion"])

	notifBody, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"})
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(notifBody))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.Empty(t, rec.Body.String())
}

// TestProxyDenialCodes pins #369 on the two most load-bearing denials:
// integrators key on error.data.talon_code, never on prose.
func TestProxyDenialCodes(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, _ := attribHandler(t, policy.ProxyModeIntercept, up.URL, []string{"user_delete"})

	_, resp := attribCall(t, h, context.Background(), nil, "user_delete")
	assert.Equal(t, TalonCodeToolForbidden, talonCodeOf(t, resp.Error))

	_, resp = attribCall(t, h, context.Background(), nil, "not_in_allowlist")
	assert.Equal(t, TalonCodePolicyDenied, talonCodeOf(t, resp.Error))
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
