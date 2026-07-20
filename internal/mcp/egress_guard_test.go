package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mcpResidualScanner(t *testing.T) *classifier.Scanner {
	t.Helper()
	score := 0.95
	s, err := classifier.NewScanner(classifier.WithCustomRecognizers([]classifier.RecognizerConfig{
		{
			Name:            "Placeholder Email Residual",
			SupportedEntity: "EMAIL_ADDRESS",
			Patterns: []classifier.PatternConfig{
				{Name: "email-placeholder", Regex: `\[EMAIL\]`, Score: &score},
			},
		},
	}))
	require.NoError(t, err)
	return s
}

func proxyHandlerWithScanner(t *testing.T, upstreamURL string, scanner *classifier.Scanner) *ProxyHandler {
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
		PIIHandling: policy.PIIHandlingConfig{
			RedactionRules: []policy.RedactionRule{{Field: "email", Method: "hash"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return NewProxyHandler(cfg, engine, store, scanner, nil)
}

func TestNoPIIEgressAfterRedaction_MCPProxy(t *testing.T) {
	rawEmail := "anna.schmidt@example.com"
	var forwardedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "Contact is " + rawEmail},
				},
			},
		})
	}))
	t.Cleanup(upstream.Close)

	h := proxyHandlerWithScanner(t, upstream.URL, classifier.MustNewScanner())
	resp := callProxyTool(t, h, `{"query":"lookup `+rawEmail+`"}`)
	require.Nil(t, resp.Error)

	assert.NotContains(t, string(forwardedBody), rawEmail, "raw PII must not egress to upstream tool")
	serialized, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(serialized), rawEmail, "raw PII must not egress back to client response")
}

func TestMCPProxyResidualPIIApprovalCannotBypass(t *testing.T) {
	rawEmail := "anna.schmidt@example.com"
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "ok"}}},
		})
	}))
	t.Cleanup(upstream.Close)

	h := proxyHandlerWithScanner(t, upstream.URL, mcpResidualScanner(t))
	resp := callProxyTool(t, h, `{"query":"lookup `+rawEmail+`","approval":"approved"}`)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "recognized PII remains after redaction")
	assert.Equal(t, 0, upstreamCalls, "approval marker must not bypass residual-PII block")
}
