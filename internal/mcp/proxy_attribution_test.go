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
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// attribUpstream is a permissive fake vendor that records whether it was hit.
func attribUpstream(t *testing.T, hit *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerToolsList(w, r, "crm_lookup", "user_delete", "not_in_allowlist") {
			return
		}
		*hit = true
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]string{"resultType": "complete", "content": "ok"},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// attribHandler builds a proxy with the given forbidden list. The
// classifier stays nil so allowed calls produce exactly one evidence record.
func attribHandler(t *testing.T, upstreamURL string, forbidden []string) (*ProxyHandler, *evidence.Store) {
	t.Helper()
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
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
	req = stamp(req)
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

// TestProxyForbiddenTool_Blocked_ZeroUpstream pins the #442 contract on the
// forbidden list: an explicitly forbidden tool is blocked with
// TALON_TOOL_FORBIDDEN, never reaches the upstream, and yields exactly one
// honest deny record — no observation-posture vocabulary survives.
func TestProxyForbiddenTool_Blocked_ZeroUpstream(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, []string{"user_delete"})

	_, resp := attribCall(t, h, context.Background(), nil, "user_delete")
	require.NotNil(t, resp.Error, "forbidden tool must be blocked")
	assert.Contains(t, resp.Error.Message, "tool not allowed by policy")
	assert.Equal(t, TalonCodeToolForbidden, talonCodeOf(t, resp.Error))
	assert.False(t, hit, "forbidden tool must never reach the upstream")

	records := listRecords(t, store, "default")
	require.Len(t, records, 1, "one blocked call = exactly one record")
	r := records[0]
	assert.Equal(t, "proxy_tool_blocked", r.InvocationType)
	assert.False(t, r.PolicyDecision.Allowed)
	assert.False(t, r.ObservationModeOverride, "no observation posture exists to override")
	assert.Empty(t, r.ShadowViolations, "denials are enforced, never recorded as would-have-denied")
}

// TestProxyPolicyDeny_Blocked_ZeroUpstream pins the #442 contract on the
// tool-access policy: a tool outside allowed_tools is blocked with
// TALON_POLICY_DENIED and never reaches the upstream.
func TestProxyPolicyDeny_Blocked_ZeroUpstream(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, nil)

	// not_in_allowlist is not in AllowedTools -> tool-access policy denies it.
	_, resp := attribCall(t, h, context.Background(), nil, "not_in_allowlist")
	require.NotNil(t, resp.Error, "policy-denied tool must be blocked")
	assert.Equal(t, TalonCodePolicyDenied, talonCodeOf(t, resp.Error))
	assert.False(t, hit, "policy-denied tool must never reach the upstream")

	records := listRecords(t, store, "default")
	require.Len(t, records, 1, "one blocked call = exactly one record")
	r := records[0]
	assert.Equal(t, "proxy_tool_blocked", r.InvocationType)
	assert.False(t, r.PolicyDecision.Allowed)
	require.NotEmpty(t, r.PolicyDecision.Reasons, "deny records must name their reason")
	assert.False(t, r.ObservationModeOverride)
	assert.Empty(t, r.ShadowViolations)
}

// TestProxyEvidence_AuthenticatedAttribution pins #350: the record carries
// the authenticated agent, the asserted session, and the inbound
// correlation ID — never the hardcoded "mcp-proxy".
func TestProxyEvidence_AuthenticatedAttribution(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, nil)

	ctx := requestctx.SetTenantID(context.Background(), "acme")
	ctx = requestctx.SetAgentIdentity(ctx, requestctx.AgentIdentity{
		AgentID: "coding-assistant", TenantID: "acme", Team: "coding",
	})
	rec, resp := attribCall(t, h, ctx, map[string]string{
		"X-Talon-Session-ID": "sess-demo-1",
		"X-Correlation-ID":   "corr-demo-1",
	}, "crm_lookup")
	require.Nil(t, resp.Error)
	assert.True(t, hit, "an allowed call reaches the upstream")
	assert.Equal(t, "corr-demo-1", rec.Header().Get("X-Correlation-ID"), "resolved correlation is echoed")
	assert.Equal(t, "sess-demo-1", rec.Header().Get("X-Talon-Session-ID"), "asserted session is echoed")

	records := listRecords(t, store, "acme")
	require.Len(t, records, 1, "one allowed call yields exactly one record")
	r := records[0]
	assert.Equal(t, "proxy_tool_call", r.InvocationType)
	assert.True(t, r.PolicyDecision.Allowed)
	assert.Equal(t, "coding-assistant", r.AgentID, "evidence must carry the authenticated agent")
	assert.Equal(t, "acme", r.TenantID)
	assert.Equal(t, "coding", r.Team)
	assert.Equal(t, "sess-demo-1", r.SessionID)
	assert.Equal(t, "corr-demo-1", r.CorrelationID, "the record carries the inbound correlation ID")
}

// TestProxyEvidence_NoIdentity_FallsBackToConfigAgent pins the admin/dev-open
// attribution: with no authenticated identity, records attribute to the proxy
// config's own agent name (not the legacy hardcoded "mcp-proxy").
func TestProxyEvidence_NoIdentity_FallsBackToConfigAgent(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, nil)

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
	h, store := attribHandler(t, up.URL, []string{"user_delete"})

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
	h, store := attribHandler(t, up.URL, nil)

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
	h2, store2 := attribHandler(t, up.URL, nil)
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

// piiDenyHandler builds a proxy with the given classifier and NO redaction
// rules, so rego proxy_pii_redaction denies any detected PII.
func piiDenyHandler(t *testing.T, upstreamURL string, cls classifier.Facade) (*ProxyHandler, *evidence.Store) {
	t.Helper()
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:     policy.UpstreamConfig{URL: upstreamURL, Vendor: "testvendor"},
			AllowedTools: []policy.ToolMapping{{Name: "crm_lookup"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return NewProxyHandler(cfg, engine, store, cls, nil), store
}

// TestProxyPIIDeny_Blocked_ZeroUpstream pins the #442 contract on the PII
// gate: a PII policy deny (detected PII with no redaction rule) blocks with
// TALON_PII_BLOCKED, never reaches the upstream, and yields exactly ONE deny
// record carrying the request-side classification (#357 fold).
func TestProxyPIIDeny_Blocked_ZeroUpstream(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := piiDenyHandler(t, up.URL, classifier.MustNewScanner())

	_, resp := attribCallArgs(t, h, context.Background(), map[string]string{"X-Talon-Session-ID": "sess-pii-1"}, "crm_lookup",
		map[string]string{"email": "jane.doe@example.com"})
	require.NotNil(t, resp.Error, "PII policy deny must block")
	assert.Equal(t, TalonCodePIIBlocked, talonCodeOf(t, resp.Error))
	assert.False(t, hit, "PII-denied arguments must never reach the upstream")

	records := listRecords(t, store, "default")
	require.Len(t, records, 1, "one blocked call = exactly one record")
	r := records[0]
	assert.Equal(t, "proxy_pii_request_detected", r.InvocationType)
	assert.False(t, r.PolicyDecision.Allowed)
	assert.Equal(t, "sess-pii-1", r.SessionID)
	assert.Contains(t, r.Classification.PIIDetected, "email")
	assert.False(t, r.ObservationModeOverride)
	assert.Empty(t, r.ShadowViolations)
	primary, ok := explanation.Primary(r.Explanations)
	require.True(t, ok)
	assert.Equal(t, explanation.CodePolicyDeniedPIIInput, primary.Code)
}

// engineBreakingClassifier wraps a real scanner and, once PII is detected,
// runs a hook. Tool access is evaluated BEFORE the argument scan and the PII
// policy AFTER it, so the hook is the one deterministic seam that can fail
// exactly the PII evaluation (OPA's context cancellation is asynchronous).
type engineBreakingClassifier struct {
	classifier.Facade
	onDetected func()
}

func (c *engineBreakingClassifier) Analyze(ctx context.Context, text string) (*classifier.Classification, error) {
	res, err := c.Facade.Analyze(ctx, text)
	if err == nil && res != nil && len(res.Entities) > 0 {
		c.onDetected()
	}
	return res, err
}

// TestProxyPIIEvalError_Blocked_ZeroUpstream pins the previously untested
// fail-closed branch: a PII policy evaluation ERROR blocks with
// TALON_PII_BLOCKED and a proxy_pii_eval_error record, and the upstream is
// never reached (#442: no posture forwards on an evaluation failure).
func TestProxyPIIEvalError_Blocked_ZeroUpstream(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	cls := &engineBreakingClassifier{Facade: classifier.MustNewScanner()}
	h, store := piiDenyHandler(t, up.URL, cls)
	// A zero-value engine has no prepared queries, so EvaluateProxyPII errors.
	cls.onDetected = func() { h.proxyEngine = &policy.ProxyEngine{} }

	_, resp := attribCallArgs(t, h, context.Background(), nil, "crm_lookup",
		map[string]string{"email": "jane.doe@example.com"})
	require.NotNil(t, resp.Error, "PII evaluation error must block fail-closed")
	assert.Contains(t, resp.Error.Message, "PII policy evaluation failed")
	assert.Equal(t, TalonCodePIIBlocked, talonCodeOf(t, resp.Error))
	assert.False(t, hit, "arguments with an unknown PII verdict must never reach the upstream")

	records := listRecords(t, store, "default")
	require.Len(t, records, 1, "one blocked call = exactly one record")
	r := records[0]
	assert.Equal(t, "proxy_pii_eval_error", r.InvocationType)
	assert.False(t, r.PolicyDecision.Allowed)
	assert.NotEmpty(t, r.Execution.Error)
	assert.False(t, r.ObservationModeOverride)
	assert.Empty(t, r.ShadowViolations)
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
// correlation contract for the no-header case: the request-scoped generated
// ID is the one on the record AND the one echoed to the caller.
func TestProxyEvidence_GeneratedCorrelationSharedAcrossRecords(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, nil)

	rec, resp := attribCall(t, h, context.Background(), nil, "crm_lookup")
	require.Nil(t, resp.Error)
	assert.True(t, hit)

	records := listRecords(t, store, "default")
	require.Len(t, records, 1, "one allowed call yields exactly one record")
	corr := records[0].CorrelationID
	assert.True(t, strings.HasPrefix(corr, "mcp_proxy_"), "generated correlation keeps the mcp_proxy_ prefix")
	assert.Equal(t, corr, rec.Header().Get("X-Correlation-ID"), "generated correlation is echoed to the caller")
}

// TestProxyUnknownMethod_RejectedFailClosed pins #356: the proxy governs
// tools/list and tools/call only; any other MCP method (resources/read,
// prompts/get, initialize, ...) is rejected with -32601 and an attributed
// deny record — never forwarded ungoverned, mirroring the native /mcp
// server.
// talonCodeOf extracts error.data.talon_code from a decoded response (#369).
func talonCodeOf(t *testing.T, e *rpcError) string {
	t.Helper()
	require.NotNil(t, e)
	data, ok := e.Data.(map[string]interface{})
	require.True(t, ok, "error.data must carry the talon_code object, got %T", e.Data)
	code, _ := data["talon_code"].(string)
	return code
}

// TestProxyUnsupportedMethod_ProtocolRejection pins the 2026-07-28 method
// allowlist: anything but server/discover, tools/list and tools/call is a
// protocol -32601 / 404 — no talon_code, no upstream call and, because no
// trustworthy action was ever extracted, NO governance evidence (#447 keeps
// protocol rejections out of the policy trail).
func TestProxyUnsupportedMethod_ProtocolRejection(t *testing.T) {
	methods := []string{"resources/read", "prompts/get", "logging/setLevel", "initialize", "ping", "subscriptions/listen"}
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, nil)

	for _, method := range methods {
		params := map[string]interface{}{"uri": "file:///etc/passwd", "name": "x"}
		body := mcpBody(t, 7, method, params)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
		req = stamp(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code, method)
		var resp jsonrpcResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.NotNil(t, resp.Error, "method %s must be rejected", method)
		assert.Equal(t, wire.CodeMethodNotFound, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, method)
		assert.Nil(t, resp.Error.Data, "a protocol rejection carries no talon_code")
		assert.Equal(t, json.RawMessage("7"), resp.ID)
	}
	assert.False(t, hit, "ungoverned methods must never reach the upstream")
	assert.Empty(t, listRecords(t, store, "default"), "protocol rejections write no governance evidence")
}

// TestNotifications_Rejected pins that this surface defines NO client-to-
// server notification under 2026-07-28: the removed lifecycle notifications
// (initialized, cancelled) and unknown ones alike are Method not found on
// BOTH routes — HTTP 404, -32601, no id, nothing forwarded, no evidence.
// An id-carrying unknown method stays a proper -32601 with the id echoed.
func TestNotifications_Rejected(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	proxy, store := attribHandler(t, up.URL, nil)
	native := NewHandler(nil, nil, nil, nil)

	for name, h := range map[string]http.Handler{"proxy": proxy, "native": native} {
		for _, method := range []string{"notifications/initialized", "notifications/cancelled", "notifications/progress", "tools/call"} {
			body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": method, "params": map[string]interface{}{"requestId": "1", "name": "crm_lookup"}})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
			req = stamp(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusNotFound, rec.Code, "%s: id-less %s is not a supported notification", name, method)
			var resp jsonrpcResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), name)
			require.NotNil(t, resp.Error, name)
			assert.Equal(t, wire.CodeMethodNotFound, resp.Error.Code, name)
			assert.Nil(t, resp.ID, "%s: an error for a notification carries no id", name)
		}
		assert.False(t, hit, "%s: notifications are never forwarded upstream", name)

		body := mcpBody(t, 7, "totally/unknown", nil)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
		req = stamp(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code, name)
		var resp jsonrpcResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), name)
		require.NotNil(t, resp.Error, name)
		assert.Equal(t, wire.CodeMethodNotFound, resp.Error.Code, name)
		assert.Equal(t, json.RawMessage("7"), resp.ID, "%s: the request id is echoed", name)
	}
	assert.Empty(t, listRecords(t, store, "default"), "protocol rejections write no evidence")
}

// TestLegacyInitialize_Unavailable pins the clean cutover on BOTH routes: a
// pre-2026 client's initialize (no headers, no _meta) is rejected with a
// modern error that names the supported versions; a modern-looking
// initialize is simply an unknown method; Mcp-Session-Id is ignored and
// never minted; GET/DELETE session transport is 405.
func TestLegacyInitialize_Unavailable(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	proxy, _ := attribHandler(t, up.URL, nil)
	native := NewHandler(nil, nil, nil, nil)

	for name, h := range map[string]http.Handler{"proxy": proxy, "native": native} {
		initBody, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "method": "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]interface{}{},
				"clientInfo":      map[string]interface{}{"name": "mcp-inspector", "version": "1.0"},
			},
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(initBody))
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Mcp-Session-Id", "legacy-session")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%s: legacy initialize is not served", name)
		var resp jsonrpcResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), name)
		require.NotNil(t, resp.Error, name)
		assert.NotContains(t, rec.Body.String(), "\"protocolVersion\":\"2025", "%s: no legacy version is echoed", name)
		assert.Empty(t, rec.Header().Get("Mcp-Session-Id"), "%s: no session is minted or echoed", name)

		req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(mcpBody(t, 1, "initialize", nil)))
		req = stamp(req)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s: initialize is an unknown method under 2026-07-28", name)

		for _, m := range []string{http.MethodGet, http.MethodDelete} {
			req = httptest.NewRequestWithContext(context.Background(), m, "/mcp", nil)
			req.Header.Set("Mcp-Session-Id", "legacy-session")
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, "%s: %s session transport is gone", name, m)
		}
	}
	assert.False(t, hit, "nothing legacy reaches the upstream")
}

// TestProxyDenialCodes pins #369 on the two most load-bearing denials:
// integrators key on error.data.talon_code, never on prose.
func TestProxyDenialCodes(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, _ := attribHandler(t, up.URL, []string{"user_delete"})

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
	h, store := attribHandler(t, up.URL, nil)

	rec, _ := attribCall(t, h, context.Background(), map[string]string{
		"X-Talon-Session-ID": strings.Repeat("a", evidence.OrchHeaderMaxLen+1),
	}, "crm_lookup")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.False(t, hit, "rejected requests must not reach the upstream")
	assert.Empty(t, listRecords(t, store, "default"), "rejected requests must not write evidence")
}
