package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
)

const proxyFlowEmail = "anna.schmidt@example.com"

// proxyFlowUpstream answers any JSON-RPC request with a result containing PII.
func proxyFlowUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result": map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "Contact is " + proxyFlowEmail},
				},
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func proxyFlowHandler(t *testing.T, upstreamURL string, withRedactionRule bool) (*ProxyHandler, *evidence.Store) {
	t.Helper()
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "flow-proxy", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode: "intercept",
			Upstream: policy.UpstreamConfig{
				Vendor: "testvendor",
				URL:    upstreamURL,
				Region: "EU",
			},
			AllowedTools: []policy.ToolMapping{{Name: "crm_lookup"}},
		},
	}
	if withRedactionRule {
		cfg.PIIHandling = policy.PIIHandlingConfig{
			RedactionRules: []policy.RedactionRule{{Field: "email", Method: "hash"}},
		}
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return NewProxyHandler(cfg, engine, store, classifier.MustNewScanner()), store
}

func callProxyTool(t *testing.T, h *ProxyHandler, arguments string) *jsonrpcResponse {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm_lookup","arguments":` + arguments + `}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	return &resp
}

func proxyEvidenceByType(t *testing.T, store *evidence.Store, invocationType string) *evidence.Evidence {
	t.Helper()
	records, err := store.List(context.Background(), "default", "", time.Time{}, time.Time{}, 20)
	require.NoError(t, err)
	for i := range records {
		if records[i].InvocationType == invocationType {
			return &records[i]
		}
	}
	t.Fatalf("no evidence record with invocation type %q", invocationType)
	return nil
}

func TestProxyDataFlow_ToolArgsToVendorAndResultToClient(t *testing.T) {
	upstream := proxyFlowUpstream(t)
	h, store := proxyFlowHandler(t, upstream.URL, true)

	resp := callProxyTool(t, h, `{"query":"lookup `+proxyFlowEmail+`"}`)
	require.Nil(t, resp.Error)

	ev := proxyEvidenceByType(t, store, "proxy_tool_call")
	require.NotNil(t, ev.DataFlow)
	assert.Equal(t, "talon-regex", ev.DataFlow.Detector)

	// Classification block must be populated too.
	assert.Contains(t, ev.Classification.PIIDetected, "email")
	assert.True(t, ev.Classification.OutputPIIDetected)
	assert.Contains(t, ev.Classification.OutputPIITypes, "email")
	assert.True(t, ev.Classification.PIIRedacted)

	var args, result *evidence.DataFlowItem
	for i := range ev.DataFlow.Items {
		switch ev.DataFlow.Items[i].Source {
		case evidence.FlowSourceToolArgs:
			args = &ev.DataFlow.Items[i]
		case evidence.FlowSourceToolResult:
			result = &ev.DataFlow.Items[i]
		}
	}
	require.NotNil(t, args, "tool_args flow item missing")
	require.NotNil(t, result, "tool_result flow item missing")

	assert.Equal(t, "crm_lookup", args.SourceDetail)
	assert.Equal(t, evidence.FlowDispositionForwarded, args.Disposition)
	assert.Equal(t, evidence.FlowDestMCPTool, args.Destination.Kind)
	assert.Equal(t, "testvendor", args.Destination.Name)
	assert.Equal(t, "EU", args.Destination.Region)
	u, _ := url.Parse(upstream.URL)
	assert.Equal(t, u.Host, args.Destination.Endpoint)
	assert.Contains(t, args.EntityTypes, "email")
	assert.NotEmpty(t, args.ValueDigests)

	assert.Equal(t, evidence.FlowDispositionRedacted, result.Disposition)
	assert.Equal(t, evidence.FlowDestClient, result.Destination.Kind)
	assert.Contains(t, result.EntityTypes, "email")

	// Same logical value in args and result -> same digest within the record.
	digest := evidence.FlowDigest(ev.TenantID, ev.CorrelationID, "email", proxyFlowEmail)
	assert.Contains(t, args.ValueDigests, digest)
	assert.Contains(t, result.ValueDigests, digest)

	// No raw PII anywhere in the serialized record.
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), proxyFlowEmail)

	assert.True(t, store.VerifyRecord(ev), "signed proxy record with data_flow must verify")
}

func TestProxyDataFlow_BlockedPIIRequest(t *testing.T) {
	upstream := proxyFlowUpstream(t)
	// No redaction rules: intercept mode fails closed on detected PII.
	h, store := proxyFlowHandler(t, upstream.URL, false)

	resp := callProxyTool(t, h, `{"query":"lookup `+proxyFlowEmail+`"}`)
	require.NotNil(t, resp.Error, "intercept mode must block PII without redaction rules")

	ev := proxyEvidenceByType(t, store, "proxy_pii_request_detected")
	require.NotNil(t, ev.DataFlow)
	require.Len(t, ev.DataFlow.Items, 1)
	item := ev.DataFlow.Items[0]
	assert.Equal(t, evidence.FlowSourceToolArgs, item.Source)
	assert.Equal(t, evidence.FlowDispositionBlocked, item.Disposition,
		"blocked egress must leave a flow trail with disposition=blocked")
	assert.Equal(t, "EU", item.Destination.Region)
	assert.False(t, ev.PolicyDecision.Allowed)
}

func TestProxyDataFlow_AbsentWhenNoPII(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "no findings"}}},
		})
	}))
	t.Cleanup(srv.Close)
	h, store := proxyFlowHandler(t, srv.URL, true)

	resp := callProxyTool(t, h, `{"query":"weekly report"}`)
	require.Nil(t, resp.Error)

	ev := proxyEvidenceByType(t, store, "proxy_tool_call")
	require.NotNil(t, ev.DataFlow, "every proxied call must record its tool_args egress flow")
	require.Len(t, ev.DataFlow.Items, 1, "only the tool_args -> vendor item; no classified response items")
	item := ev.DataFlow.Items[0]
	assert.Equal(t, evidence.FlowSourceToolArgs, item.Source)
	assert.Equal(t, evidence.FlowDispositionForwarded, item.Disposition)
	assert.Equal(t, evidence.FlowDestMCPTool, item.Destination.Kind)
	assert.Empty(t, item.EntityTypes, "no PII detected, no entity types")
}
