package mcp

import (
	"context"
	"encoding/json"
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
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/govcode"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// Second-review coverage (#372, PR #493):
//   P1 untrusted policy-denial and vendor-error text never reaches a
//      Talon-authored public message or a signed record unsanitized;
//   P2 a nonexistent native tool is a protocol error, never a committed
//      policy-denial receipt; the native resolution matrix;
//   P2 the signed explanation of an UNKNOWN outcome says unknown.

// ---- P1: untrusted text ----------------------------------------------------

type denyingToolEvaluator struct{ reasons []string }

func (d denyingToolEvaluator) EvaluateToolAccess(context.Context, string, map[string]interface{}, []map[string]interface{}) (*policy.Decision, error) {
	return &policy.Decision{Allowed: false, Action: "deny", Reasons: d.reasons, PolicyVersion: "v-test"}, nil
}

type denyingProxyEvaluator struct{ reasons []string }

func (d denyingProxyEvaluator) EvaluateProxyToolAccess(context.Context, *policy.ProxyInput) (*policy.Decision, error) {
	return &policy.Decision{Allowed: false, Action: "deny", Reasons: d.reasons}, nil
}

func (d denyingProxyEvaluator) EvaluateProxyPII(context.Context, *policy.ProxyInput) (*policy.Decision, error) {
	return &policy.Decision{Allowed: true}, nil
}

// zeroWidthSpace is a Unicode format character (Cf): invisible in most
// renderers, so it must be stripped from stored diagnostics.
var zeroWidthSpace = string(rune(0x200b))

// adversarialReasons is what a policy author (or an attacker steering
// argument values the rego interpolates) can put into a denial reason.
func adversarialReasons() []string {
	return []string{
		"argument api_key=" + sentinelBearer + " is forbidden for tool x",
		"argument callback=" + sentinelURLCreds + " is forbidden",
		"file path contains forbidden pattern: " + sentinelPath + "\n\x1b[31mline2" + zeroWidthSpace,
		strings.Repeat("Q", 3000),
	}
}

// Native: a policy denial whose reasons carry secrets, URL credentials,
// paths, control/format characters and oversized text yields a fixed public
// message and a sanitized, bounded, HMAC-valid record. Zero execution.
func TestSafety_NativePolicyDenialReasonsAreUntrusted(t *testing.T) {
	h, store, _ := nativeDenyFixture(t)
	tool := &capturingTool{name: "only_this"}
	h.registry = tools.NewRegistry()
	h.registry.Register(tool)
	h.policyEngine = denyingToolEvaluator{reasons: adversarialReasons()}

	out := callNative(t, h, "only_this", 21)
	e := out["error"].(map[string]any)
	assert.Equal(t, publicPolicyDenied, e["message"], "the public message is fixed; no policy text is echoed")
	ext := governanceOf(t, out)
	require.NotNil(t, ext)
	assert.Equal(t, govcode.PolicyDenied, ext["code"])
	raw, _ := json.Marshal(out)
	assertNoSecret(t, "public response", string(raw))
	assert.NotContains(t, string(raw), "QQQQQQQQ")
	rec, err := store.Get(context.Background(), ext["evidence"].(map[string]any)["id"].(string))
	require.NoError(t, err)
	require.True(t, store.VerifyRecord(rec))
	stored, _ := json.Marshal(rec)
	assertNoSecret(t, "signed record", string(stored))
	assert.NotContains(t, string(stored), zeroWidthSpace, "format characters are removed")
	for _, r := range rec.PolicyDecision.Reasons {
		assert.LessOrEqual(t, len(r), maxDiagnosticBytes+3, "each stored reason is bounded")
	}
	assert.Contains(t, strings.Join(rec.PolicyDecision.Reasons, " "), "is forbidden for tool x", "the policy meaning is retained for audit")
	assert.Equal(t, 0, tool.executions())
}

// Native, through the REAL rego: forbidden_argument_values interpolates the
// caller's argument value into the denial reason. The value is a sentinel
// secret; it must not surface publicly or in the record.
func TestSafety_RegoForbiddenArgumentValueNotEchoed(t *testing.T) {
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "test", Version: "1.0"}, VersionTag: "v1",
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"pay"}},
		ToolPolicies: map[string]policy.ToolPIIPolicy{"pay": {ForbiddenArgumentValues: map[string][]string{"token": {sentinelBearer}}}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	pay := &capturingTool{name: "pay"}
	reg.Register(pay)
	h := NewHandler(reg, engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "method": "tools/call", "id": 22,
		"params": map[string]any{"name": "pay", "arguments": map[string]any{"token": sentinelBearer}},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(string(body)))
	req = stamp(req)
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.NotNil(t, out["error"], rec.Body.String())
	ext := governanceOf(t, out)
	require.NotNil(t, ext, "%v", out)
	assert.Equal(t, govcode.PolicyDenied, ext["code"])
	assertNoSecret(t, "public response", rec.Body.String())
	stored, err := store.Get(context.Background(), ext["evidence"].(map[string]any)["id"].(string))
	require.NoError(t, err)
	js, _ := json.Marshal(stored)
	assertNoSecret(t, "signed record", string(js))
	assert.Equal(t, 0, pay.executions())
}

// Proxy: the same guarantee for a proxy policy denial.
func TestSafety_ProxyPolicyDenialReasonsAreUntrusted(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, nil)
	h.proxyEngine = denyingProxyEvaluator{reasons: adversarialReasons()}
	rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
	assert.Equal(t, publicPolicyDenied, out["error"].(map[string]any)["message"])
	assertNoSecret(t, "public response", rec.Body.String())
	ext := governanceOf(t, out)
	require.NotNil(t, ext)
	stored, err := store.Get(context.Background(), ext["evidence"].(map[string]any)["id"].(string))
	require.NoError(t, err)
	require.True(t, store.VerifyRecord(stored))
	js, _ := json.Marshal(stored)
	assertNoSecret(t, "signed record", string(js))
	assert.LessOrEqual(t, len(stored.Execution.Error), maxDiagnosticBytes+3)
	assert.False(t, hit)
}

// Vendor errors on tools/call and on the definition capture (tools/list):
// the vendor's JSON-RPC error object is relayed to the client unchanged —
// an explicit, scoped pass-through of a third-party error — while Talon's
// own signed record carries only the code and a sanitized, bounded message.
func TestSafety_VendorErrorPassThroughIsScoped(t *testing.T) {
	vendorMsg := "boom " + sentinelBearer + " " + sentinelURLCreds + " " + sentinelPath + strings.Repeat("V", 1000)
	for _, mode := range []string{"tools/call", "tools/list"} {
		t.Run(mode, func(t *testing.T) {
			var effects atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req jsonrpcRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				if r.Header.Get(wire.HeaderMethod) == wire.MethodToolsList && mode == "tools/call" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"resultType":"complete","tools":[{"name":"crm_lookup","inputSchema":{"type":"object"}}],"ttlMs":60000,"cacheScope":"public"}}`))
					return
				}
				if r.Header.Get(wire.HeaderMethod) == wire.MethodToolsCall {
					effects.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				vm, _ := json.Marshal(vendorMsg)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32001,"message":` + string(vm) + `,"data":{"vendor":"x"}}}`))
			}))
			t.Cleanup(srv.Close)
			h, store := attribHandler(t, srv.URL, nil)
			rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
			e := out["error"].(map[string]any)
			// Scoped pass-through: the vendor-owned error object is the vendor's.
			assert.Equal(t, float64(-32001), e["code"])
			assert.Equal(t, vendorMsg, e["message"], "vendor error relayed unchanged (explicit pass-through)")
			assert.Equal(t, map[string]any{"vendor": "x"}, e["data"], "no Talon annotation inside the vendor's object")
			_ = rec
			// Talon-authored artefacts: nothing of the vendor text survives raw.
			// The attempted call leaves exactly one Talon record either way;
			// the vendor text inside it is sanitized and bounded.
			recs := listRecords(t, store, "default")
			require.Len(t, recs, 1)
			r := recs[0]
			require.True(t, store.VerifyRecord(&r))
			js, _ := json.Marshal(r)
			assertNoSecret(t, "signed record", string(js))
			assert.LessOrEqual(t, len(r.Execution.Error), len("definitions_upstream_jsonrpc_error: -32001 ")+maxDiagnosticBytes+3)
			assert.Equal(t, evidence.StatusFailed, r.Status, "a well-formed vendor error is a trustworthy failure")
			assert.Equal(t, explanation.CodeExecutionFailed, r.Explanations[0].Code)
			if mode == "tools/call" {
				assert.True(t, strings.HasPrefix(r.Execution.Error, "upstream_jsonrpc_error: -32001"), r.Execution.Error)
				assert.Equal(t, int32(1), effects.Load())
			} else {
				assert.True(t, strings.HasPrefix(r.Execution.Error, "definitions_upstream_jsonrpc_error: -32001"), r.Execution.Error)
				assert.Equal(t, int32(0), effects.Load(), "the business tool was never called: the vendor failed the definition fetch")
			}
		})
	}
}

// ---- P2: canonical resolution precedes governance ---------------------------

// Native matrix: error family, evidence count and execution count for
// unknown tool, known-denied, known-allowed, invalid schema, header/body
// mismatch and malformed arguments.
func TestSafety_NativeResolutionMatrix(t *testing.T) {
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "test", Version: "1.0"}, VersionTag: "v1",
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"allowed_tool", "strict_tool"}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	allowed := &capturingTool{name: "allowed_tool"}
	denied := &capturingTool{name: "denied_tool"}
	strict := &schemaTool{name: "strict_tool"}
	reg.Register(allowed)
	reg.Register(denied)
	reg.Register(strict)
	h := NewHandler(reg, engine, store, classifier.MustNewScanner())

	type want struct {
		status    int
		rpcCode   float64
		ext       bool // governance extension present
		records   int  // evidence written by this call
		execs     int  // allowed_tool executions by this call
		extCode   string
		aliasFree bool
	}
	cases := []struct {
		name  string
		body  string
		hdrs  map[string]string
		want  want
		count func() int
	}{
		{"unknown tool", `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"no_such_tool","arguments":{}}}`, nil, want{200, float64(codeInvalidParams), false, 0, 0, "", true}, nil},
		{"known denied", `{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"denied_tool","arguments":{}}}`, nil, want{200, float64(codeServerError), true, 1, 0, govcode.PolicyDenied, false}, denied.executions},
		{"known allowed", `{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"allowed_tool","arguments":{}}}`, nil, want{200, 0, true, 1, 1, govcode.CodeAllowed, false}, allowed.executions},
		{"invalid schema", `{"jsonrpc":"2.0","method":"tools/call","id":4,"params":{"name":"strict_tool","arguments":{"n":"not-a-number"}}}`, nil, want{200, float64(codeInvalidParams), false, 0, 0, "", true}, strict.executions},
		{"malformed arguments", `{"jsonrpc":"2.0","method":"tools/call","id":5,"params":{"name":"allowed_tool","arguments":"nope"}}`, nil, want{400, float64(wire.CodeInvalidParams), false, 0, 0, "", true}, allowed.executions},
		{"header/body mismatch", `{"jsonrpc":"2.0","method":"tools/call","id":6,"params":{"name":"allowed_tool","arguments":{}}}`, map[string]string{wire.HeaderName: "denied_tool"}, want{400, float64(wire.CodeHeaderMismatch), false, 0, 0, "", true}, allowed.executions},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := countRecords(t, store)
			execBefore := 0
			if tc.count != nil {
				execBefore = tc.count()
			}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(tc.body))
			req = stamp(req)
			for k, v := range tc.hdrs {
				req.Header.Set(k, v)
			}
			req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var out map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &out)
			assert.Equal(t, tc.want.status, rec.Code, rec.Body.String())
			if tc.want.rpcCode != 0 {
				assert.Equal(t, tc.want.rpcCode, errCode(out), rec.Body.String())
			} else {
				assert.Nil(t, out["error"], rec.Body.String())
			}
			ext := governanceOf(t, out)
			if tc.want.ext {
				require.NotNil(t, ext, "governance extension expected: %s", rec.Body.String())
				assert.Equal(t, tc.want.extCode, ext["code"])
			} else {
				assert.Nil(t, ext, "no governance extension for a protocol outcome: %s", rec.Body.String())
			}
			if tc.want.aliasFree {
				if e, ok := out["error"].(map[string]any); ok {
					data, _ := e["data"].(map[string]any)
					assert.NotContains(t, data, "talon_code", "no legacy alias on a protocol outcome")
				}
			}
			assert.Equal(t, tc.want.records, countRecords(t, store)-before, "evidence written by this call")
			if tc.count != nil {
				assert.Equal(t, tc.want.execs, tc.count()-execBefore, "executions by this call")
			}
		})
	}
}

// schemaTool declares a numeric input so schema validation can fail.
type schemaTool struct {
	name  string
	calls atomic.Int32
}

func (s *schemaTool) Name() string        { return s.name }
func (s *schemaTool) Description() string { return "strict schema" }
func (s *schemaTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"n":{"type":"number"}}}`)
}

func (s *schemaTool) Execute(context.Context, json.RawMessage) (json.RawMessage, error) {
	s.calls.Add(1)
	return json.RawMessage(`{}`), nil
}
func (s *schemaTool) executions() int { return int(s.calls.Load()) }

// Proxy: an allowlisted tool the upstream does not publish is the protocol
// invalid-params error with no governance receipt and zero business calls;
// an explicitly forbidden name is a true policy denial decided before the
// upstream is contacted at all (hidden names never reach the vendor).
func TestSafety_ProxyUnknownVersusForbidden(t *testing.T) {
	var listed, called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerToolsList(w, r, "crm_lookup") {
			listed.Add(1)
			return
		}
		called.Add(1)
	}))
	t.Cleanup(srv.Close)
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:       policy.UpstreamConfig{URL: srv.URL, Vendor: "testvendor"},
			AllowedTools:   []policy.ToolMapping{{Name: "crm_lookup"}, {Name: "ghost_tool"}},
			ForbiddenTools: []string{"user_delete"},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	h := NewProxyHandler(cfg, engine, store, nil, nil)

	// allowlisted but not published upstream → protocol error, no receipt
	rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "ghost_tool", "arguments": map[string]any{}}), nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, float64(codeInvalidParams), errCode(out), rec.Body.String())
	assert.Nil(t, governanceOf(t, out))
	assert.Equal(t, 0, countRecords(t, store), "an unresolvable tool leaves no governance receipt")
	assert.Equal(t, int32(0), called.Load())

	// explicitly forbidden → policy denial before any upstream contact
	listedBefore := listed.Load()
	_, out = do(t, h, "/mcp/proxy", mcpBody(t, 2, wire.MethodToolsCall, map[string]any{"name": "user_delete", "arguments": map[string]any{}}), nil)
	ext := governanceOf(t, out)
	require.NotNil(t, ext)
	assert.Equal(t, govcode.PolicyDenied, ext["code"])
	assert.Equal(t, 1, countRecords(t, store))
	assert.Equal(t, listedBefore, listed.Load(), "a forbidden name does not even trigger a definition fetch")
	assert.Equal(t, int32(0), called.Load())
}

// ---- P2: signed explanation agrees with the outcome -------------------------

// For every outcome class the extension (code, decision, retryable,
// provenance), the record (status, failure reason) and the signed
// explanation (code, decision) must tell the same story, with exactly one
// business invocation where a call was made and never an automatic retry.
func TestSafety_OutcomeSemanticsTable(t *testing.T) {
	type expect struct {
		code, decision, provenance string
		retryable                  bool
		status, failureReason      string
		explCode, explDecision     string
		allowed                    bool
		invocations                int32
		relayedVendorError         bool
	}
	cases := []struct {
		name   string
		up     func(w http.ResponseWriter, id json.RawMessage, effects *atomic.Int32)
		expect expect
	}{
		{"(a) pre-dispatch failure: credential unavailable", nil, expect{govcode.UpstreamAuthUnavailable, govcode.DecisionFailed, "not_dispatched", true, evidence.StatusFailed, "upstream_error", explanation.CodeExecutionFailed, explanation.DecisionFailure, true, 0, false}},
		{"(b) trustworthy vendor JSON-RPC error", func(w http.ResponseWriter, id json.RawMessage, effects *atomic.Int32) {
			effects.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"error":{"code":-32001,"message":"vendor says no"}}`))
		}, expect{"", "", "", false, evidence.StatusFailed, "upstream_error", explanation.CodeExecutionFailed, explanation.DecisionFailure, true, 1, true}},
		{"(c) transport reset after accepted effect", func(w http.ResponseWriter, _ json.RawMessage, effects *atomic.Int32) {
			effects.Add(1)
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}, expect{govcode.UpstreamOutcomeUnknown, govcode.DecisionUnknown, "unknown", false, evidence.StatusUnknown, "upstream_outcome_unknown", explanation.CodeExecutionOutcomeUnknown, explanation.DecisionUnknown, true, 1, false}},
		{"(d) malformed post-dispatch response", func(w http.ResponseWriter, _ json.RawMessage, effects *atomic.Int32) {
			effects.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"comp`))
		}, expect{govcode.UpstreamOutcomeUnknown, govcode.DecisionUnknown, "unknown", false, evidence.StatusUnknown, "upstream_outcome_unknown", explanation.CodeExecutionOutcomeUnknown, explanation.DecisionUnknown, true, 1, false}},
		{"(e) unsupported resultType task", func(w http.ResponseWriter, id json.RawMessage, effects *atomic.Int32) {
			effects.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"resultType":"task","task":{"taskId":"t1"}}}`))
		}, expect{govcode.UpstreamOutcomeUnknown, govcode.DecisionUnknown, "unknown", false, evidence.StatusUnknown, "upstream_outcome_unknown", explanation.CodeExecutionOutcomeUnknown, explanation.DecisionUnknown, true, 1, false}},
		{"(f) allowed success", func(w http.ResponseWriter, id json.RawMessage, effects *atomic.Int32) {
			effects.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"resultType":"complete","content":[]}}`))
		}, expect{govcode.CodeAllowed, govcode.DecisionAllow, "observed", false, "", "", explanation.CodePolicyAllowed, explanation.DecisionAllow, true, 1, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var effects atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if answerToolsList(w, r, "crm_lookup") {
					return
				}
				var req jsonrpcRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				tc.up(w, req.ID, &effects)
			}))
			t.Cleanup(srv.Close)
			cfg := &policy.ProxyPolicyConfig{
				Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
				Proxy: policy.ProxyConfig{Upstream: policy.UpstreamConfig{URL: srv.URL, Vendor: "testvendor"}, AllowedTools: []policy.ToolMapping{{Name: "crm_lookup"}}},
			}
			if tc.up == nil {
				// (a): a vault-backed credential that cannot be retrieved → fail closed before any send.
				cfg.Proxy.Upstream.Auth = &policy.UpstreamAuthConfig{SecretName: "missing-secret"}
			}
			engine, err := policy.NewProxyEngine(context.Background(), cfg)
			require.NoError(t, err)
			store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
			require.NoError(t, err)
			t.Cleanup(func() { _ = store.Close() })
			h := NewProxyHandler(cfg, engine, store, nil, nil)
			_, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)

			recs := listRecords(t, store, "default")
			require.Len(t, recs, 1, "exactly one terminal record")
			r := recs[0]
			require.True(t, store.VerifyRecord(&r), "the record verifies")
			assert.Equal(t, tc.expect.allowed, r.PolicyDecision.Allowed)
			assert.Equal(t, tc.expect.status, r.Status)
			assert.Equal(t, tc.expect.failureReason, r.FailureReason)
			require.NotEmpty(t, r.Explanations)
			assert.Equal(t, tc.expect.explCode, r.Explanations[0].Code, "signed explanation code")
			assert.Equal(t, tc.expect.explDecision, r.Explanations[0].Decision, "signed explanation decision")
			assert.Equal(t, tc.expect.invocations, effects.Load(), "exactly the one invocation; no automatic retry")

			if tc.expect.relayedVendorError {
				e := out["error"].(map[string]any)
				assert.Equal(t, float64(-32001), e["code"])
				assert.Nil(t, governanceOf(t, out), "the vendor's error object is relayed without Talon annotation")
				return
			}
			ext := governanceOf(t, out)
			require.NotNil(t, ext, "%v", out)
			assert.Equal(t, tc.expect.code, ext["code"])
			assert.Equal(t, tc.expect.decision, ext["decision"])
			assert.Equal(t, tc.expect.retryable, ext["retryable"])
			assert.Equal(t, tc.expect.provenance, ext["provenance"])
			assert.Equal(t, r.Explanations[0].Code, ext["reasonCode"], "reasonCode is the signed explanation")
		})
	}
}
