package mcp

import (
	"context"
	"encoding/json"
	"fmt"
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
// message and an HMAC-valid record whose reasons are structured tokens only
// (none of these free-text reasons is a Talon template). Zero execution.
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
	assert.Equal(t, []string{opaquePolicyReason, opaquePolicyReason, opaquePolicyReason, opaquePolicyReason}, rec.PolicyDecision.Reasons,
		"free text is never stored, however familiar its words; only the opaque token")
	assertOnlyEvidenceTokens(t, rec)
	assert.Equal(t, 0, tool.executions())
}

// Native, through the REAL rego. forbidden_argument_values used to interpolate
// the caller's argument value into the denial reason; the values here are
// arbitrary protected strings that no credential-shaped regex would catch
// (an e-mail address, a customer id, a project code name). None may appear
// in any serializable field of the signed record, in the JSON-RPC body, or
// in the record's explanations — while the rule identity and the field name
// survive for audit, the record verifies, and the tool never runs.
func TestSafety_RegoForbiddenArgumentValueNotEchoed(t *testing.T) {
	protected := []string{"private.person@example.test", "CUST-7391-SECRET", "CONFIDENTIAL-PROJECT-ORCHID"}
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "test", Version: "1.0"}, VersionTag: "v1",
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"pay"}},
		ToolPolicies: map[string]policy.ToolPIIPolicy{"pay": {ForbiddenArgumentValues: map[string][]string{
			"recipient": {protected[0]}, "customer": {protected[1]}, "project": {protected[2]},
		}}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	pay := &capturingTool{name: "pay"}
	reg.Register(pay)
	h := NewHandler(reg, engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "method": "tools/call", "id": 22,
		"params": map[string]any{"name": "pay", "arguments": map[string]any{"recipient": protected[0], "customer": protected[1], "project": protected[2]}},
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
	assert.Equal(t, explanation.CodePolicyDeniedTool, ext["reasonCode"])
	assert.Equal(t, publicPolicyDenied, out["error"].(map[string]any)["message"])
	for _, p := range protected {
		assert.NotContains(t, rec.Body.String(), p, "JSON-RPC body leaks %q", p)
	}
	stored, err := store.Get(context.Background(), ext["evidence"].(map[string]any)["id"].(string))
	require.NoError(t, err)
	require.True(t, store.VerifyRecord(stored), "the signed record verifies")
	js, _ := json.Marshal(stored)
	for _, p := range protected {
		assert.NotContains(t, string(js), p, "signed record leaks %q", p)
	}
	require.NotEmpty(t, stored.PolicyDecision.Reasons)
	assert.ElementsMatch(t, []string{"forbidden_argument_value:field=recipient", "forbidden_argument_value:field=customer", "forbidden_argument_value:field=project"},
		stored.PolicyDecision.Reasons, "the rule token and the configured field name are all the record keeps")
	assertOnlyEvidenceTokens(t, stored)
	for _, x := range stored.Explanations {
		for _, p := range protected {
			assert.NotContains(t, x.Trigger+" "+x.Reason+" "+x.Fix, p)
		}
	}
	assert.Equal(t, 0, pay.executions())
}

// A denial reason that is not exactly one of Talon's rule templates is free
// text of unknown provenance: the record keeps the opaque token, never the
// text — even when the text contains the words ("tool", "forbidden") that
// Talon's explanation vocabulary recognizes, and even when it carries only
// ordinary, non-secret-shaped identifiers (an e-mail address, a customer
// id). A template match is reduced to its token.
func TestSafety_UnclassifiedPolicyReasonIsOpaque(t *testing.T) {
	h, store, _ := nativeDenyFixture(t)
	tool := &capturingTool{name: "only_this"}
	h.registry = tools.NewRegistry()
	h.registry.Register(tool)
	h.policyEngine = denyingToolEvaluator{reasons: []string{
		"customer private.person@example.test is on hold",
		"Tool rejected for customer private.person@example.test",
		"Tool 'only_this' is forbidden by policy for account CUST-7391",
		"Tool 'only_this' not in allowed_tools list",
	}}
	out := callNative(t, h, "only_this", 23)
	ext := governanceOf(t, out)
	require.NotNil(t, ext)
	assert.Equal(t, explanation.CodePolicyDeniedTool, ext["reasonCode"])
	rec, err := store.Get(context.Background(), ext["evidence"].(map[string]any)["id"].(string))
	require.NoError(t, err)
	require.True(t, store.VerifyRecord(rec))
	js, _ := json.Marshal(rec)
	for _, p := range []string{"private.person@example.test", "CUST-7391", "on hold", "rejected", "account"} {
		assert.NotContains(t, string(js), p, "the whole signed record is free of %q", p)
	}
	assert.Equal(t, []string{opaquePolicyReason, opaquePolicyReason, opaquePolicyReason, "tool_not_allowed"}, rec.PolicyDecision.Reasons)
	assertOnlyEvidenceTokens(t, rec)
	assert.Equal(t, 0, tool.executions())
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

// Vendor JSON-RPC errors on tools/call and on the definition capture
// (tools/list) are NOT relayed raw: the vendor's numeric code and the
// request id are preserved, the message is the fixed public string, the
// vendor's data object is dropped (only Talon's governance extension is
// present), and the signed record keeps only the vendor's numeric code and
// its JSON-RPC category — never any part of the vendor's message, not even
// a benign-looking one. Sentinels cover credential-shaped and ordinary
// identifiers (an e-mail address, a customer id, a project code name),
// nested data, quoted JSON and an oversized message.
func TestSafety_VendorErrorIsNeverRelayedRaw(t *testing.T) {
	protected := []string{sentinelBearer, sentinelURLCreds, sentinelPath, "private.person@example.test", "CUST-7391-SECRET", "CONFIDENTIAL-PROJECT-ORCHID"}
	ordinary := []string{"ordinary.user@example.org", "CUST-4482", "no open tickets"}
	vendorMsg := "boom " + strings.Join(protected, " ") + ` {"nested":"` + protected[4] + `"}` + strings.Repeat("V", 5000)
	vendorData := `{"vendor":"x","detail":{"customer":"` + protected[4] + `","email":"` + protected[3] + `","token":"` + sentinelBearer + `"},"raw":"{\"quoted\":\"` + protected[5] + `\"}"}`
	for _, tc := range []struct {
		mode   string
		code   int
		msg    string
		data   string
		benign bool
	}{
		{"tools/call", -32001, vendorMsg, vendorData, false},
		{"tools/list", -32001, vendorMsg, vendorData, false},
		{"tools/call", -32602, "Invalid params: ticket must be a string", "", true},
		{"tools/call", -32000, "Customer CUST-4482 <ordinary.user@example.org> has no open tickets", "", false},
		{"tools/list", -32000, "Customer CUST-4482 <ordinary.user@example.org> has no open tickets", "", false},
	} {
		name := tc.mode + "/" + fmt.Sprint(tc.code)
		if tc.benign {
			name += "/benign"
		}
		t.Run(name, func(t *testing.T) {
			var effects atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req jsonrpcRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				if r.Header.Get(wire.HeaderMethod) == wire.MethodToolsList && tc.mode == "tools/call" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"resultType":"complete","tools":[{"name":"crm_lookup","inputSchema":{"type":"object"}}],"ttlMs":60000,"cacheScope":"public"}}`))
					return
				}
				if r.Header.Get(wire.HeaderMethod) == wire.MethodToolsCall {
					effects.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				vm, _ := json.Marshal(tc.msg)
				errObj := `{"code":` + fmt.Sprint(tc.code) + `,"message":` + string(vm)
				if tc.data != "" {
					errObj += `,"data":` + tc.data
				}
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":` + errObj + `}}`))
			}))
			t.Cleanup(srv.Close)
			h, store := attribHandler(t, srv.URL, nil)
			rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 7, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
			e := out["error"].(map[string]any)
			assert.Equal(t, float64(tc.code), e["code"], "the vendor's numeric code is preserved")
			assert.Equal(t, float64(7), out["id"], "the request id is preserved")
			assert.Equal(t, publicVendorError, e["message"], "the vendor's message is never relayed")
			data, _ := e["data"].(map[string]any)
			for k := range data {
				assert.Contains(t, []string{govcode.ExtensionID, "talon_code"}, k, "error.data carries only Talon's objects, never vendor data")
			}
			ext := governanceOf(t, out)
			require.NotNil(t, ext)
			assert.Equal(t, govcode.UpstreamToolFailed, ext["code"], "a vendor-reported failure stays a trustworthy failure, never unknown or a policy denial")
			assert.Equal(t, govcode.DecisionFailed, ext["decision"])
			for _, p := range protected {
				assert.NotContains(t, rec.Body.String(), p, "HTTP response leaks %q", p)
			}
			assert.NotContains(t, rec.Body.String(), "VVVVVVVV")
			recs := listRecords(t, store, "default")
			require.Len(t, recs, 1, "exactly one record")
			r := recs[0]
			require.True(t, store.VerifyRecord(&r), "HMAC verifies")
			js, _ := json.Marshal(&r)
			for _, p := range append(append([]string{"P4ssw0rd", "XYZSECRET", "vault.db", "boom", "ticket must be"}, protected...), ordinary...) {
				assert.NotContains(t, string(js), p, "the whole signed record (reasons, error, explanations) is free of %q", p)
			}
			assert.Equal(t, evidence.StatusFailed, r.Status, "a well-formed vendor error is a trustworthy failure")
			assert.Equal(t, explanation.CodeExecutionFailed, r.Explanations[0].Code)
			assertOnlyEvidenceTokens(t, &r)
			if tc.mode == "tools/call" {
				assert.Equal(t, "observed", ext["provenance"])
				assert.Equal(t, vendorErrorToken("upstream_jsonrpc_error", tc.code), r.Execution.Error, "only the vendor code and its category are stored")
				assert.Equal(t, int32(1), effects.Load(), "exactly one business call, no hidden retry")
			} else {
				assert.Equal(t, "not_dispatched", ext["provenance"], "the vendor failed the definition fetch: nothing was dispatched")
				assert.Equal(t, vendorErrorToken("definitions_upstream_jsonrpc_error", tc.code), r.Execution.Error)
				assert.Equal(t, int32(0), effects.Load(), "the business tool was never called")
			}
		})
	}
}

// ---- P2: canonical resolution precedes governance ---------------------------

// Native matrix: error family, evidence count and execution count for
// unknown tool, known-denied, known-allowed, invalid schema, header/body
// mismatch and malformed arguments. Every protocol failure — whether the
// wire gate or the method handler detects it — is HTTP 4xx; only governed
// outcomes on an accepted request are HTTP 200.
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
		{"unknown tool", `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"no_such_tool","arguments":{}}}`, nil, want{400, float64(codeInvalidParams), false, 0, 0, "", true}, nil},
		{"known denied", `{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"denied_tool","arguments":{}}}`, nil, want{200, float64(codeServerError), true, 1, 0, govcode.PolicyDenied, false}, denied.executions},
		{"known allowed", `{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"allowed_tool","arguments":{}}}`, nil, want{200, 0, true, 1, 1, govcode.CodeAllowed, false}, allowed.executions},
		{"invalid schema", `{"jsonrpc":"2.0","method":"tools/call","id":4,"params":{"name":"strict_tool","arguments":{"n":"not-a-number"}}}`, nil, want{400, float64(codeInvalidParams), false, 0, 0, "", true}, strict.executions},
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
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an unresolvable tool is a protocol failure: HTTP 400")
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
		}, expect{govcode.UpstreamToolFailed, govcode.DecisionFailed, "observed", false, evidence.StatusFailed, "upstream_error", explanation.CodeExecutionFailed, explanation.DecisionFailure, true, 1, true}},
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
				assert.Equal(t, float64(-32001), e["code"], "the vendor's numeric code is preserved")
				assert.Equal(t, publicVendorError, e["message"], "the vendor's message is not")
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
