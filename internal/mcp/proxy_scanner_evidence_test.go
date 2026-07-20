package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/adapter"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// markerFacade is a scanner engine driven by markers in the scanned text:
// failMarker makes the scan error (engine down), piiMarker is detected as an
// email entity, and redaction is deliberately sloppy (returns text unchanged)
// so only the VerifyEgress pass can catch residual PII.
type markerFacade struct {
	failMarker string
	piiMarker  string
}

func (f *markerFacade) Analyze(_ context.Context, text string) (*classifier.Classification, error) {
	if f.failMarker != "" && strings.Contains(text, f.failMarker) {
		return nil, &adapter.Error{Kind: adapter.KindTimeout, Detector: "marker-engine", Err: errEngineTimedOut}
	}
	if f.piiMarker != "" {
		if idx := strings.Index(text, f.piiMarker); idx >= 0 {
			entities := []classifier.PIIEntity{{
				Type: "email", Value: f.piiMarker, Position: idx, Confidence: 0.9, Sensitivity: 1,
			}}
			return &classifier.Classification{HasPII: true, Entities: entities, Tier: 1}, nil
		}
	}
	return &classifier.Classification{Entities: []classifier.PIIEntity{}}, nil
}

func (f *markerFacade) Detector() string { return "marker-engine" }

func (f *markerFacade) RedactText(_ context.Context, text string) (string, error) {
	if f.failMarker != "" && strings.Contains(text, f.failMarker) {
		return "", &adapter.Error{Kind: adapter.KindTimeout, Detector: "marker-engine", Err: errEngineTimedOut}
	}
	return text, nil // sloppy: leaves PII in place
}

func (f *markerFacade) VerifyEgress(ctx context.Context, text string) error {
	return classifier.NewRedactGuard(f).Verify(ctx, text)
}

var errEngineTimedOut = errors.New("engine timed out")

var _ classifier.Facade = (*markerFacade)(nil)

// newProxyWithUpstream builds a proxy handler whose upstream tool returns the
// given result string.
func newProxyWithUpstream(t *testing.T, cls classifier.Facade, upstreamResult string) (*ProxyHandler, *evidence.Store) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]string{"content": upstreamResult},
		})
		_, _ = w.Write(resp)
	}))
	t.Cleanup(upstream.Close)

	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "t", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Mode:         "intercept",
			Upstream:     policy.UpstreamConfig{URL: upstream.URL, Vendor: "test"},
			AllowedTools: []policy.ToolMapping{{Name: "echo_tool"}},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return NewProxyHandler(cfg, engine, store, cls, nil), store
}

func callProxyEchoTool(t *testing.T, h *ProxyHandler, args map[string]interface{}) *jsonrpcResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "id": 1,
		"params": map[string]interface{}{"name": "echo_tool", "arguments": args},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/proxy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var r jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&r))
	return &r
}

func latestProxyEvidence(t *testing.T, store *evidence.Store) evidence.Evidence {
	t.Helper()
	records, err := store.List(context.Background(), "default", "", time.Now().Add(-time.Minute), time.Now().Add(time.Minute), 10)
	require.NoError(t, err)
	require.NotEmpty(t, records, "expected proxy evidence")
	return records[0]
}

func TestProxyEvidence_OutputScannerUnavailable_Denied(t *testing.T) {
	const failMarker = "RESULT-FAIL-MARKER"
	h, store := newProxyWithUpstream(t, &markerFacade{failMarker: failMarker}, "result with "+failMarker)

	resp := callProxyEchoTool(t, h, map[string]interface{}{"q": "clean args"})
	require.NotNil(t, resp.Error, "unscannable tool result must be blocked")
	assert.Contains(t, resp.Error.Message, "scanner unavailable")

	ev := latestProxyEvidence(t, store)
	assert.False(t, ev.PolicyDecision.Allowed,
		"evidence must record the denial: the caller got a blocked result")
	assert.Equal(t, "deny", ev.PolicyDecision.Action)
	assert.Contains(t, ev.PolicyDecision.Reasons, "output_scanner_unavailable")
	require.NotNil(t, ev.Classification.Scanner, "proxy evidence must identify the scan engine")
	assert.Equal(t, "marker-engine", ev.Classification.Scanner.Engine)
	assert.Equal(t, "timeout", ev.Classification.Scanner.Failure,
		"adapter-backed failures record the typed kind, not a generic label")
}

func TestProxyEvidence_OutputResidualPII_Denied(t *testing.T) {
	const piiMarker = "kai.nova@example.com"
	h, store := newProxyWithUpstream(t, &markerFacade{piiMarker: piiMarker}, "contact "+piiMarker+" today")

	resp := callProxyEchoTool(t, h, map[string]interface{}{"q": "clean args"})
	require.NotNil(t, resp.Error, "residual PII after sloppy redaction must block the result")
	assert.Contains(t, resp.Error.Message, "remains after redaction")

	ev := latestProxyEvidence(t, store)
	assert.False(t, ev.PolicyDecision.Allowed,
		"a proxy_tool_call record with a blocked flow must not be marked allowed")
	assert.Contains(t, ev.PolicyDecision.Reasons, "output_pii_blocked_residual")
	require.NotNil(t, ev.Classification.Scanner)
	assert.Equal(t, "marker-engine", ev.Classification.Scanner.Engine)
	assert.Empty(t, ev.Classification.Scanner.Failure, "residual PII is a policy block, not an engine failure")
}

func TestProxyEvidence_CleanCall_AllowedWithScannerInfo(t *testing.T) {
	h, store := newProxyWithUpstream(t, &markerFacade{}, "clean result")

	resp := callProxyEchoTool(t, h, map[string]interface{}{"q": "clean args"})
	require.Nil(t, resp.Error)

	ev := latestProxyEvidence(t, store)
	assert.True(t, ev.PolicyDecision.Allowed)
	require.NotNil(t, ev.Classification.Scanner, "allowed records also identify the engine")
	assert.Equal(t, "marker-engine", ev.Classification.Scanner.Engine)
	assert.Empty(t, ev.Classification.Scanner.Failure)
}

func TestServerEvidence_IncludesScannerInfo(t *testing.T) {
	h := &Handler{classifier: classifier.MustNewScanner()}

	ev := h.newServerEvidence("t", "a", "corr", "tool",
		evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"output_scanner_unavailable"}},
		"", 0, &serverFlowState{})
	require.NotNil(t, ev.Classification.Scanner, "native MCP evidence must identify the scan engine")
	assert.Equal(t, "talon-regex", ev.Classification.Scanner.Engine)
	assert.Equal(t, "regex", ev.Classification.Scanner.Type)
	assert.Equal(t, "scanner_unavailable", ev.Classification.Scanner.Failure,
		"scanner-driven denials carry the failure kind")

	allowedEv := h.newServerEvidence("t", "a", "corr", "tool",
		evidence.PolicyDecision{Allowed: true, Action: "allow"}, "", 0, &serverFlowState{})
	require.NotNil(t, allowedEv.Classification.Scanner)
	assert.Empty(t, allowedEv.Classification.Scanner.Failure)
}
