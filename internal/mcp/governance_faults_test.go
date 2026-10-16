package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/govcode"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
)

// Fault-injection coverage for the #372 review findings:
//   P1 policy-evaluation failures must be evidenced (or refused as
//      evidence_commit_failed) before the response, with zero execution;
//   P1 reasonCode must be the signed record's explanation;
//   P1 a post-handoff ambiguous answer is UNKNOWN, never a known failure,
//      and never retried;
//   P2 raw internal errors never cross the public boundary or enter a
//      signed record unsanitized.

// Sentinel strings an attacker or a buggy dependency might put into an
// error. None may reach a public message, the extension, or a record.
const (
	sentinelBearer   = "Bearer sk-SECRET-TOKEN-0123456789abcdef"
	sentinelURLCreds = "http://svc:P4ssw0rd@internal.corp:9000/vault?api_key=XYZSECRET"
	sentinelPath     = "/var/lib/talon/secrets/vault.db"
)

func adversarialError() error {
	return errors.New("engine failed: " + sentinelBearer + " " + sentinelURLCreds + " " + sentinelPath + "\nline2\x01\x02" + strings.Repeat("Z", 2000))
}

func assertNoSecret(t *testing.T, where, s string) {
	t.Helper()
	for _, bad := range []string{"sk-SECRET", "P4ssw0rd", "XYZSECRET", "vault.db", "\x01", "\n"} {
		assert.NotContains(t, s, bad, "%s leaks %q", where, bad)
	}
}

type failingToolEvaluator struct{ err error }

func (f failingToolEvaluator) EvaluateToolAccess(context.Context, string, map[string]interface{}, []map[string]interface{}) (*policy.Decision, error) {
	return nil, f.err
}

type failingProxyEvaluator struct{ err error }

func (f failingProxyEvaluator) EvaluateProxyToolAccess(context.Context, *policy.ProxyInput) (*policy.Decision, error) {
	return nil, f.err
}

func (f failingProxyEvaluator) EvaluateProxyPII(context.Context, *policy.ProxyInput) (*policy.Decision, error) {
	return nil, f.err
}

// Native: a policy-engine failure is evidenced BEFORE the response; the tool
// never runs; the public message and the record are free of the raw error.
func TestGovernance_NativePolicyEvaluationFailure_EvidencedZeroExecution(t *testing.T) {
	h, store, _ := nativeDenyFixture(t)
	tool := &capturingTool{name: "only_this"}
	h.registry = tools.NewRegistry()
	h.registry.Register(tool)
	h.policyEngine = failingToolEvaluator{err: adversarialError()}

	out := callNative(t, h, "only_this", 11)
	e := out["error"].(map[string]any)
	ext := governanceOf(t, out)
	require.NotNil(t, ext)
	assert.Equal(t, govcode.PolicyEvaluationFailed, ext["code"])
	assert.Equal(t, govcode.DecisionFailed, ext["decision"])
	assert.Equal(t, "not_dispatched", ext["provenance"])
	assert.Equal(t, publicPolicyEvaluationFailed, e["message"])
	ev := ext["evidence"].(map[string]any)
	require.Equal(t, true, ev["committed"], "the failure must be evidenced before the response")
	rec, err := store.Get(context.Background(), ev["id"].(string))
	require.NoError(t, err)
	assert.False(t, rec.PolicyDecision.Allowed)
	assert.Equal(t, rec.Explanations[0].Code, ext["reasonCode"], "reasonCode is the signed explanation")
	assert.Equal(t, 0, tool.executions(), "zero execution")
	raw, _ := json.Marshal(out)
	assertNoSecret(t, "public response", string(raw))
	stored, _ := json.Marshal(rec)
	assertNoSecret(t, "signed record", string(stored))
	assert.True(t, len(rec.Execution.Error) <= maxDiagnosticBytes+3, "record diagnostic is bounded: %d", len(rec.Execution.Error))
}

// Native: when the policy-evaluation failure record cannot commit, the
// response is evidence_commit_failed with no id and still zero execution —
// a nil or absent evidence attempt can never pass silently.
func TestGovernance_NativePolicyEvaluationFailure_CommitOutage(t *testing.T) {
	h, store, _ := nativeDenyFixture(t)
	tool := &capturingTool{name: "only_this"}
	h.registry = tools.NewRegistry()
	h.registry.Register(tool)
	h.policyEngine = failingToolEvaluator{err: errors.New("engine down")}
	require.NoError(t, store.Close())

	out := callNative(t, h, "only_this", 12)
	ext := governanceOf(t, out)
	require.NotNil(t, ext)
	assert.Equal(t, govcode.EvidenceCommitFailed, ext["code"])
	ev := ext["evidence"].(map[string]any)
	assert.Equal(t, false, ev["committed"])
	_, hasID := ev["id"]
	assert.False(t, hasID)
	assert.Equal(t, 0, tool.executions())

	// A route with NO evidence store at all cannot commit mandatory
	// evidence: the same fail-closed outcome, never a silent pass.
	h.evidenceStore = nil
	h.policyEngine = failingToolEvaluator{err: errors.New("engine down")}
	out = callNative(t, h, "only_this", 13)
	ext = governanceOf(t, out)
	require.NotNil(t, ext)
	assert.Equal(t, govcode.EvidenceCommitFailed, ext["code"])
	assert.Equal(t, 0, tool.executions())
}

// Native: a tool's own error is a trustworthy failure report; its text never
// crosses the public boundary and is sanitized/bounded in the record.
type leakyTool struct{ calls atomic.Int32 }

func (l *leakyTool) Name() string                 { return "leaky" }
func (l *leakyTool) Description() string          { return "fails with secrets in the error" }
func (l *leakyTool) InputSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (l *leakyTool) Execute(context.Context, json.RawMessage) (json.RawMessage, error) {
	l.calls.Add(1)
	return nil, adversarialError()
}

func TestGovernance_NativeToolErrorIsSanitized(t *testing.T) {
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := &policy.Policy{Agent: policy.AgentConfig{Name: "test", Version: "1.0"}, VersionTag: "v1", Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"leaky"}}}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	leaky := &leakyTool{}
	reg.Register(leaky)
	h := NewHandler(reg, engine, store, classifier.MustNewScanner())

	out := callNative(t, h, "leaky", 14)
	e := out["error"].(map[string]any)
	assert.Equal(t, publicToolExecutionFailed, e["message"])
	ext := governanceOf(t, out)
	assert.Equal(t, govcode.UpstreamToolFailed, ext["code"], "the tool reported its own failure: trustworthy, a known failure")
	assert.Equal(t, "observed", ext["provenance"])
	raw, _ := json.Marshal(out)
	assertNoSecret(t, "public response", string(raw))
	rec, err := store.Get(context.Background(), ext["evidence"].(map[string]any)["id"].(string))
	require.NoError(t, err)
	stored, _ := json.Marshal(rec)
	assertNoSecret(t, "signed record", string(stored))
	assert.Equal(t, int32(1), leaky.calls.Load())
}

// Proxy: policy-engine failure is evidenced before the response with zero
// upstream dispatch; sanitized record; fixed public message.
func TestGovernance_ProxyPolicyEvaluationFailure_EvidencedZeroUpstream(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, nil)
	h.proxyEngine = failingProxyEvaluator{err: adversarialError()}
	_, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
	ext := governanceOf(t, out)
	require.NotNil(t, ext, "%v", out)
	assert.Equal(t, govcode.PolicyEvaluationFailed, ext["code"])
	assert.Equal(t, publicPolicyEvaluationFailed, out["error"].(map[string]any)["message"])
	ev := ext["evidence"].(map[string]any)
	require.Equal(t, true, ev["committed"])
	rec, err := store.Get(context.Background(), ev["id"].(string))
	require.NoError(t, err)
	assert.False(t, rec.PolicyDecision.Allowed)
	assert.Equal(t, rec.Explanations[0].Code, ext["reasonCode"])
	assert.False(t, hit, "zero upstream dispatch")
	raw, _ := json.Marshal(out)
	assertNoSecret(t, "public response", string(raw))
	stored, _ := json.Marshal(rec)
	assertNoSecret(t, "signed record", string(stored))

	require.NoError(t, store.Close())
	_, out = do(t, h, "/mcp/proxy", mcpBody(t, 2, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
	ext = governanceOf(t, out)
	assert.Equal(t, govcode.EvidenceCommitFailed, ext["code"], "commit outage: refused, no id")
	_, hasID := ext["evidence"].(map[string]any)["id"]
	assert.False(t, hasID)
	assert.False(t, hit)
}

// Proxy: reasonCode in error.data / result._meta equals the committed
// record's primary explanation for a denial AND an allowed call.
func TestGovernance_ReasonCodeMatchesSignedExplanation(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, []string{"user_delete"})
	for _, tc := range []struct{ tool, wantDecision string }{{"user_delete", govcode.DecisionDeny}, {"crm_lookup", govcode.DecisionAllow}} {
		_, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": tc.tool, "arguments": map[string]any{}}), nil)
		ext := governanceOf(t, out)
		require.NotNil(t, ext, "%v", out)
		assert.Equal(t, tc.wantDecision, ext["decision"])
		id := ext["evidence"].(map[string]any)["id"].(string)
		rec, err := store.Get(context.Background(), id)
		require.NoError(t, err)
		require.NotEmpty(t, rec.Explanations)
		assert.Equal(t, rec.Explanations[0].Code, ext["reasonCode"], "%s: reasonCode must be the signed explanation", tc.tool)
		assert.True(t, store.VerifyRecord(rec), "the referenced record verifies")
	}
}

// Proxy: the upstream registers the business effect, then answers with a
// broken body / a severed connection / an unsupported shape. Talon must
// report UNKNOWN (non-retryable, provenance unknown), the record must say
// unknown, and exactly one effect may exist — no transparent retry.
func TestGovernance_PostHandoffAmbiguityIsUnknown(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter){
		"malformed JSON": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"comp`))
		},
		"connection severed after accept": func(w http.ResponseWriter) {
			hj, ok := w.(http.Hijacker)
			require.True(t, ok)
			conn, _, err := hj.Hijack()
			require.NoError(t, err)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"jsonrpc\":"))
			_ = conn.(*net.TCPConn).Close()
		},
		"unsupported result shape (task)": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"task","task":{"taskId":"t1"}}}`))
		},
		"wrong content type": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>gateway timeout</html>"))
		},
	}
	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			var effects atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if answerToolsList(w, r, "crm_lookup") {
					return
				}
				effects.Add(1) // the business side effect happens here
				respond(w)
			}))
			t.Cleanup(srv.Close)
			h, store := attribHandler(t, srv.URL, nil)
			_, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
			ext := governanceOf(t, out)
			require.NotNil(t, ext, "%v", out)
			assert.Equal(t, govcode.UpstreamOutcomeUnknown, ext["code"], "a response Talon cannot trust proves nothing about the effect")
			assert.Equal(t, govcode.DecisionUnknown, ext["decision"])
			assert.Equal(t, false, ext["retryable"])
			assert.Equal(t, "unknown", ext["provenance"])
			msg := out["error"].(map[string]any)["message"].(string)
			assert.NotContains(t, msg, "html")
			assert.NotContains(t, msg, "task")
			ev := ext["evidence"].(map[string]any)
			require.Equal(t, true, ev["committed"])
			rec, err := store.Get(context.Background(), ev["id"].(string))
			require.NoError(t, err)
			assert.Equal(t, evidence.StatusUnknown, rec.Status, "the signed record agrees: unknown")
			assert.Equal(t, "upstream_outcome_unknown", rec.FailureReason)
			assert.Equal(t, int32(1), effects.Load(), "exactly one effect; Talon performed no transparent retry")
		})
	}
}

// Proxy: the vendor's own JSON-RPC error is a trustworthy failure report,
// relayed verbatim (contract) and recorded as failed, not unknown.
func TestGovernance_VendorErrorIsTrustworthyFailure(t *testing.T) {
	var effects atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerToolsList(w, r, "crm_lookup") {
			return
		}
		effects.Add(1)
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32001,"message":"vendor says no","data":{"vendor":"x"}}}`))
	}))
	t.Cleanup(srv.Close)
	h, store := attribHandler(t, srv.URL, nil)
	_, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
	e := out["error"].(map[string]any)
	assert.Equal(t, float64(-32001), e["code"])
	assert.Equal(t, "vendor says no", e["message"])
	assert.Equal(t, map[string]any{"vendor": "x"}, e["data"], "the vendor's error object is relayed verbatim, not annotated")
	recs := listRecords(t, store, "default")
	require.Len(t, recs, 1)
	assert.Equal(t, evidence.StatusFailed, recs[0].Status)
	assert.Equal(t, int32(1), effects.Load())
}

// Proxy transport failure after hand-off (connection refused mid-call vs.
// capture): the business call reaches the transport, so the outcome is
// unknown; a capture (tools/list) failure before the call is a known failure.
func TestGovernance_TransportFailureAfterHandoffIsUnknown(t *testing.T) {
	var listed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerToolsList(w, r, "crm_lookup") {
			listed.Add(1)
			return
		}
		// Sever the connection without any bytes: the request was sent.
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	h, store := attribHandler(t, srv.URL, nil)
	_, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
	ext := governanceOf(t, out)
	require.NotNil(t, ext, "%v", out)
	assert.Equal(t, govcode.UpstreamOutcomeUnknown, ext["code"])
	assert.Equal(t, publicUpstreamUnavailable, out["error"].(map[string]any)["message"])
	rec, err := store.Get(context.Background(), ext["evidence"].(map[string]any)["id"].(string))
	require.NoError(t, err)
	assert.Equal(t, evidence.StatusUnknown, rec.Status)
	assert.Nil(t, rec.DataFlow, "egress unconfirmed: no flow item asserts delivery")
	assert.Equal(t, int32(1), listed.Load())
}

// sanitizeDiagnostic: control characters, secret-shaped tokens, URL
// credentials/queries and length are all neutralized; ordinary text survives.
func TestSanitizeDiagnostic(t *testing.T) {
	got := sanitizeDiagnostic(adversarialError().Error())
	assertNoSecret(t, "sanitized", got)
	assert.Contains(t, got, "engine failed")
	assert.Contains(t, got, "[redacted]")
	assert.LessOrEqual(t, len(got), maxDiagnosticBytes+3)
	assert.Equal(t, "plain detail", sanitizeDiagnostic("plain detail"))
	assert.Equal(t, "connect: connection refused", sanitizeDiagnostic("connect: connection refused"))
	assert.Equal(t, "Post https://vendor.example/mcp failed: EOF", sanitizeDiagnostic("Post https://user:pw@vendor.example/mcp?token=abc failed: EOF"))
	assert.Equal(t, "open [path]: permission denied", sanitizeDiagnostic("open /etc/talon/keys/signing.pem: permission denied"))
}

// An invalid extension can never become a 200 with partial data: the
// writer's JSON encoding fails loudly, and Validate refuses incoherent
// decision/retryable pairs.
func TestGovernance_InvalidExtensionCannotSerialize(t *testing.T) {
	ext := govcode.Must(govcode.PolicyDenied)
	ext.Retryable = true // a retryable denial is incoherent
	_, err := json.Marshal(ext)
	require.Error(t, err)
	ext = govcode.Must(govcode.UpstreamOutcomeUnknown)
	ext.Decision = govcode.DecisionFailed // an unknown outcome presented as failure
	_, err = json.Marshal(ext)
	require.Error(t, err)
	ext = govcode.Allowed(govcode.Committed("req_1"))
	ext.Retryable = true
	_, err = json.Marshal(ext)
	require.Error(t, err)
}

// A result that already carries _meta keeps every existing key (serverInfo,
// upstreamServerInfo, vendor keys) when the governance extension is added;
// an input_required (MRTR) result is passed through with the extension and
// without any claim of business success.
func TestGovernance_MetaMergePreservesExistingKeys(t *testing.T) {
	res := map[string]any{"resultType": "input_required", "requestState": "s", "_meta": map[string]any{
		wire.MetaServerInfo: map[string]any{"name": "talon-mcp-proxy"}, "io.dativo.talon/upstreamServerInfo": map[string]any{"name": "vendor"}, "com.vendor/trace": "t-1",
	}}
	out := withGovernanceMeta(res, &evidenceOutcome{ref: govcode.Committed("proxy_1"), reason: "POLICY_ALLOWED"}).(map[string]any)
	meta := out["_meta"].(map[string]any)
	assert.Contains(t, meta, wire.MetaServerInfo)
	assert.Contains(t, meta, "io.dativo.talon/upstreamServerInfo")
	assert.Equal(t, "t-1", meta["com.vendor/trace"])
	ext := meta[govcode.ExtensionID].(govcode.Extension)
	assert.Equal(t, govcode.DecisionAllow, ext.Decision)
	assert.Equal(t, "POLICY_ALLOWED", ext.ReasonCode)
	assert.Equal(t, "input_required", out["resultType"], "MRTR continuation is passed through unchanged")
	// A non-object result is returned untouched.
	assert.Equal(t, "x", withGovernanceMeta("x", nil))
}
