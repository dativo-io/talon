package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/govcode"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// governanceOf extracts the versioned extension from a JSON-RPC error or
// result; nil when absent.
func governanceOf(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	if e, ok := out["error"].(map[string]any); ok {
		data, _ := e["data"].(map[string]any)
		ext, _ := data[govcode.ExtensionID].(map[string]any)
		return ext
	}
	res, _ := out["result"].(map[string]any)
	meta, _ := res["_meta"].(map[string]any)
	ext, _ := meta[govcode.ExtensionID].(map[string]any)
	return ext
}

func nativeDenyFixture(t *testing.T) (*Handler, *evidence.Store, *capturingTool) {
	t.Helper()
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "test", Version: "1.0"}, VersionTag: "v1",
		Policies:     policy.PoliciesConfig{},
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"only_this"}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	denied := &capturingTool{name: "denied_tool"}
	reg.Register(denied)
	reg.Register(&capturingTool{name: "only_this"})
	return NewHandler(reg, engine, store, classifier.MustNewScanner()), store, denied
}

func callNative(t *testing.T, h http.Handler, tool string, id int) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "method": "tools/call", "id": id,
		"params": map[string]any{"name": tool, "arguments": map[string]any{}},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
	req = stamp(req)
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

// A native policy denial carries the governance extension with the SAME
// stable code the Action Gateway uses for a governed-action DENY
// (policy_denied), and an evidence reference whose id is a committed record.
func TestGovernance_NativeDenyCarriesExtensionAndCommittedEvidence(t *testing.T) {
	h, store, denied := nativeDenyFixture(t)
	out := callNative(t, h, "denied_tool", 1)
	ext := governanceOf(t, out)
	require.NotNil(t, ext, "error.data must carry %s: %v", govcode.ExtensionID, out)
	assert.Equal(t, float64(govcode.SchemaVersion), ext["schemaVersion"])
	assert.Equal(t, govcode.PolicyDenied, ext["code"], "same code as a governed-action DENY (#372 migration test)")
	assert.Equal(t, govcode.DecisionDeny, ext["decision"])
	assert.Equal(t, false, ext["retryable"])
	ev, _ := ext["evidence"].(map[string]any)
	require.NotNil(t, ev)
	assert.Equal(t, true, ev["committed"])
	id, _ := ev["id"].(string)
	require.NotEmpty(t, id)
	rec, err := store.Get(context.Background(), id)
	require.NoError(t, err, "the referenced record must exist")
	assert.False(t, rec.PolicyDecision.Allowed)
	assert.Equal(t, 0, denied.executions(), "zero execution on deny")
	// Safe data: no legacy synthetic identity, no payload, no signature.
	raw, _ := json.Marshal(ext)
	for _, forbidden := range []string{"mcp-client", "signature", "hmac", "arguments"} {
		assert.NotContains(t, strings.ToLower(string(raw)), forbidden)
	}
}

// When the mandatory denial record cannot be committed, the response is
// evidence_commit_failed with NO id, and the tool still never runs.
func TestGovernance_EvidenceCommitFailure_NoIDZeroExecution(t *testing.T) {
	h, store, denied := nativeDenyFixture(t)
	require.NoError(t, store.Close()) // every Store() now fails
	out := callNative(t, h, "denied_tool", 2)
	ext := governanceOf(t, out)
	require.NotNil(t, ext, "%v", out)
	assert.Equal(t, govcode.EvidenceCommitFailed, ext["code"])
	ev, _ := ext["evidence"].(map[string]any)
	require.NotNil(t, ev)
	assert.Equal(t, false, ev["committed"])
	_, hasID := ev["id"]
	assert.False(t, hasID, "an evidence id must never be fabricated")
	assert.Equal(t, 0, denied.executions())
	data := out["error"].(map[string]any)["data"].(map[string]any)
	assert.NotContains(t, data, "talon_code", "#372 codes have no legacy alias")
}

// An allowed native call returns the extension in the result _meta with the
// committed terminal record; a post-execution store failure is reported as
// committed=false under the allowed outcome (the effect already happened).
func TestGovernance_AllowedResultCarriesEvidenceRef(t *testing.T) {
	h, store, _ := nativeDenyFixture(t)
	out := callNative(t, h, "only_this", 3)
	ext := governanceOf(t, out)
	require.NotNil(t, ext, "%v", out)
	assert.Equal(t, govcode.DecisionAllow, ext["decision"])
	ev := ext["evidence"].(map[string]any)
	assert.Equal(t, true, ev["committed"])
	_, err := store.Get(context.Background(), ev["id"].(string))
	require.NoError(t, err)

	require.NoError(t, store.Close())
	out = callNative(t, h, "only_this", 4)
	ext = governanceOf(t, out)
	require.NotNil(t, ext)
	assert.Equal(t, govcode.DecisionAllow, ext["decision"], "a post-execution store failure is not relabelled")
	ev = ext["evidence"].(map[string]any)
	assert.Equal(t, false, ev["committed"])
	_, hasID := ev["id"]
	assert.False(t, hasID)
}

// Protocol rejections never carry the extension and never write evidence.
func TestGovernance_ProtocolErrorsCarryNoExtension(t *testing.T) {
	h, store, _ := nativeDenyFixture(t)
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "method": "tools/call", "id": 5,
		"params": map[string]any{"name": "only_this", "arguments": map[string]any{}},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
	req = stamp(req)
	req.Header.Set(wire.HeaderName, "something_else") // header/body mismatch → -32020
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	e := out["error"].(map[string]any)
	assert.Equal(t, float64(wire.CodeHeaderMismatch), e["code"])
	assert.Nil(t, governanceOf(t, out), "a protocol failure is not a governance outcome")
	assert.Equal(t, 0, countRecords(t, store), "no fake governance evidence for a protocol rejection")
}

// server/discover advertises the governance extension (it is implemented)
// and still no Tasks.
func TestGovernance_DiscoverAdvertisesExtensionOnly(t *testing.T) {
	h, _, _ := nativeDenyFixture(t)
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "server/discover", "id": 6, "params": map[string]any{}})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
	req = stamp(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	caps := out["result"].(map[string]any)["capabilities"].(map[string]any)
	exts, _ := caps["extensions"].(map[string]any)
	require.Len(t, exts, 1)
	settings := exts[govcode.ExtensionID].(map[string]any)
	assert.Equal(t, float64(govcode.SchemaVersion), settings["schemaVersion"])
	assert.NotContains(t, exts, "io.modelcontextprotocol/tasks")
}

// On /mcp/proxy a forbidden tool carries the extension (policy_denied, the
// same code as the Action Gateway DENY) plus the deprecated alias, with a
// committed evidence reference, and the upstream is never reached; an
// allowed call carries the allow extension in the result _meta.
func TestGovernance_ProxyDenyAndAllowCarryExtension(t *testing.T) {
	hit := false
	up := attribUpstream(t, &hit)
	h, store := attribHandler(t, up.URL, []string{"user_delete"})
	_, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "user_delete", "arguments": map[string]any{}}), nil)
	ext := governanceOf(t, out)
	require.NotNil(t, ext, "%v", out)
	assert.Equal(t, govcode.PolicyDenied, ext["code"])
	assert.Equal(t, TalonCodeToolForbidden, out["error"].(map[string]any)["data"].(map[string]any)["talon_code"], "deprecated alias retained for one release")
	ev := ext["evidence"].(map[string]any)
	assert.Equal(t, true, ev["committed"])
	_, err := store.Get(context.Background(), ev["id"].(string))
	require.NoError(t, err)
	assert.False(t, hit, "forbidden tool must never reach the upstream")

	_, out = do(t, h, "/mcp/proxy", mcpBody(t, 2, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
	ext = governanceOf(t, out)
	require.NotNil(t, ext, "%v", out)
	assert.Equal(t, govcode.DecisionAllow, ext["decision"])
	ev = ext["evidence"].(map[string]any)
	assert.Equal(t, true, ev["committed"])
	_, err = store.Get(context.Background(), ev["id"].(string))
	require.NoError(t, err)
	assert.True(t, hit)
}

// The deprecated talon_code alias and the extension agree on every mapped
// code, and #372-only codes carry no alias.
func TestGovernance_LegacyAliasAgreesWithRegistry(t *testing.T) {
	for code, legacy := range map[string]string{
		govcode.PolicyDenied: TalonCodePolicyDenied, govcode.PIIPolicyViolation: TalonCodePIIBlocked,
		govcode.ScannerUnavailable: TalonCodeScannerUnavailable, govcode.UpstreamToolFailed: TalonCodeUpstreamError,
		govcode.UpstreamAuthUnavailable: TalonCodeUpstreamError, govcode.UpstreamOutcomeUnknown: TalonCodeUpstreamError,
		govcode.EvidenceCommitFailed: "", govcode.PolicyEvaluationFailed: "",
	} {
		assert.Equal(t, legacy, legacyTalonCode(code), code)
		data := governanceData(govcode.Must(code), "")
		if legacy == "" {
			assert.NotContains(t, data, "talon_code", code)
		} else {
			assert.Equal(t, legacy, data["talon_code"], code)
		}
	}
	// A pre-dispatch outcome whose record did not commit becomes
	// evidence_commit_failed without an id; a post-dispatch one keeps its code.
	pre := governedError(json.RawMessage(`1`), govcode.PolicyDenied, "m", govcode.NotCommitted(), "", true)
	assert.Equal(t, govcode.EvidenceCommitFailed, pre.Error.Data.(map[string]any)[govcode.ExtensionID].(govcode.Extension).Code)
	post := governedError(json.RawMessage(`1`), govcode.UpstreamOutcomeUnknown, "m", govcode.NotCommitted(), "", false)
	assert.Equal(t, govcode.UpstreamOutcomeUnknown, post.Error.Data.(map[string]any)[govcode.ExtensionID].(govcode.Extension).Code)
}
