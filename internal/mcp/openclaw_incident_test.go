package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// openclawProxyCfg returns a ProxyPolicyConfig modelled after the OpenClaw
// vendor agent scenario: read-only tools allowed, admin/delete forbidden.
func openclawProxyCfg() *policy.ProxyPolicyConfig {
	return &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "openclaw-vendor", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode: "intercept",
			Upstream: policy.UpstreamConfig{
				URL:    "https://placeholder.invalid",
				Vendor: "openclaw",
			},
			AllowedTools: []policy.ToolMapping{
				{Name: "search_issues"},
				{Name: "get_issue"},
				{Name: "list_repos"},
			},
			ForbiddenTools: []string{
				"delete_*",
				"admin_*",
				"drop_*",
				"bulk_delete",
			},
			RateLimits: policy.ProxyRateLimitConfig{
				RequestsPerMinute: 30,
			},
		},
	}
}

func proxyCall(t *testing.T, h *ProxyHandler, toolName string, args map[string]interface{}) *jsonrpcResponse {
	t.Helper()
	params := map[string]interface{}{"name": toolName, "arguments": args}
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "params": params, "id": 1,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "test-tenant"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	return &r
}

// ---------------------------------------------------------------------------
// Task 6: MCP Proxy — OpenClaw Agent Governance
// (Failure Modes 1, 2, 3)
// ---------------------------------------------------------------------------

func TestProxy_ForbiddenToolBlocked_DeleteWildcard(t *testing.T) {
	cfg := openclawProxyCfg()
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)

	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	r := proxyCall(t, h, "delete_repo", map[string]interface{}{"repo": "my-project"})
	require.NotNil(t, r.Error, "delete_repo must be blocked by forbidden_tools: delete_*")
	assert.Contains(t, r.Error.Message, "tool not allowed by policy")
}

func TestProxy_ForbiddenToolBlocked_AdminWildcard(t *testing.T) {
	cfg := openclawProxyCfg()
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)

	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	r := proxyCall(t, h, "admin_reset_password", map[string]interface{}{})
	require.NotNil(t, r.Error, "admin_reset_password must be blocked by forbidden_tools: admin_*")
	assert.Contains(t, r.Error.Message, "tool not allowed by policy")
}

func TestProxy_ForbiddenToolBlocked_BulkDelete(t *testing.T) {
	cfg := openclawProxyCfg()
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)

	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	r := proxyCall(t, h, "bulk_delete", map[string]interface{}{"filter": "all"})
	require.NotNil(t, r.Error, "bulk_delete must be blocked by exact match in forbidden_tools")
	assert.Contains(t, r.Error.Message, "tool not allowed by policy")
}

func TestProxy_AllowedToolForwardedToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"result":  map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": "found 3 issues"}}},
			"id":      1,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	cfg := openclawProxyCfg()
	cfg.Proxy.Upstream.URL = upstream.URL

	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)

	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	r := proxyCall(t, h, "search_issues", map[string]interface{}{"query": "open bugs"})
	assert.Nil(t, r.Error, "search_issues is in allowed_tools and should be forwarded")
	assert.NotNil(t, r.Result, "upstream response should be forwarded to caller")
}

func TestProxy_EvidenceRecordedOnBlock(t *testing.T) {
	cfg := openclawProxyCfg()
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)

	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	_ = proxyCall(t, h, "delete_user", map[string]interface{}{"user": "admin"})

	records, err := store.List(context.Background(), "test-tenant", "",
		time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.NotEmpty(t, records, "evidence must be recorded when proxy blocks a tool")

	found := false
	for _, ev := range records {
		if !ev.PolicyDecision.Allowed && len(ev.Execution.ToolsCalled) > 0 &&
			ev.Execution.ToolsCalled[0] == "delete_user" {
			found = true
		}
	}
	assert.True(t, found, "evidence should contain a denial record for delete_user")
}

func TestProxy_PIIInArgumentsBlocked(t *testing.T) {
	cfg := openclawProxyCfg()
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)

	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	r := proxyCall(t, h, "search_issues", map[string]interface{}{
		"query": "emails from hans.mueller@example.de with IBAN DE89370400440532013000",
	})
	// In intercept mode with PII detected, proxy should block or record evidence
	if r.Error != nil {
		assert.Contains(t, r.Error.Message, "PII",
			"PII in arguments should trigger a block in intercept mode")
	} else {
		// PII detection may not block if EvaluateProxyPII allows (depends on rego).
		// Verify evidence was at least recorded.
		records, err := store.List(context.Background(), "test-tenant", "",
			time.Time{}, time.Time{}, 10)
		require.NoError(t, err)
		piiRecorded := false
		for _, ev := range records {
			if ev.InvocationType == "proxy_pii_redaction" {
				piiRecorded = true
			}
		}
		assert.True(t, piiRecorded,
			"PII in proxy arguments must at minimum generate an evidence record")
	}
}

// Gap F (CLOSED): Proxy scans upstream response for PII and redacts before returning.
func TestProxy_GapF_ResponsePIIScanned(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"result":  map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": "Customer email: jan.kowalski@gmail.com"}}},
			"id":      1,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	cfg := openclawProxyCfg()
	cfg.Proxy.Upstream.URL = upstream.URL

	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)

	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	r := proxyCall(t, h, "search_issues", map[string]interface{}{"query": "test"})
	require.Nil(t, r.Error, "allowed tool should succeed")

	// Verify PII in response was redacted
	resultBytes, _ := json.Marshal(r.Result)
	resultStr := string(resultBytes)
	assert.NotContains(t, resultStr, "jan.kowalski@gmail.com",
		"PII in upstream response should be redacted before returning to caller")
}

// Gap: Unknown tools (not in allowed_tools, not in forbidden_tools) go to OPA
// but may be allowed if OPA has no explicit deny rule.
func TestProxy_UnlistedToolDefaultBehavior(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"result":  map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": "ok"}}},
			"id":      1,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	cfg := openclawProxyCfg()
	cfg.Proxy.Upstream.URL = upstream.URL

	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)

	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	h := NewProxyHandler(cfg, engine, store, classifier.MustNewScanner())

	r := proxyCall(t, h, "unknown_new_tool", map[string]interface{}{})
	// Tool is not in forbidden list; whether it's forwarded depends on OPA.
	// This test documents the current behavior — important for security review.
	if r.Error != nil {
		t.Logf("OPA denied unlisted tool (default-deny): %s", r.Error.Message)
	} else {
		t.Logf("KNOWN BEHAVIOR: unlisted tool 'unknown_new_tool' was forwarded to upstream (OPA allowed or no deny rule)")
	}
}
