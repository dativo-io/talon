package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

// ---- fixtures ------------------------------------------------------------

// headerTool declares a mirrored primitive (x-mcp-header) and counts
// executions so tests can prove zero dispatch.
type headerTool struct {
	name  string
	calls atomic.Int64
}

func (h *headerTool) Name() string        { return h.name }
func (h *headerTool) Description() string { return "ticket lookup" }
func (h *headerTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"ticket_id":{"type":"string","x-mcp-header":"Ticket"},"region":{"type":"string"}},"required":["ticket_id"]}`)
}

func (h *headerTool) Execute(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
	h.calls.Add(1)
	return json.RawMessage(`{"ticket":"ok"}`), nil
}

// badAnnotationTool carries an invalid x-mcp-header declaration (number
// type): it must be excluded from tools/list.
type badAnnotationTool struct{}

func (badAnnotationTool) Name() string        { return "bad_annotation" }
func (badAnnotationTool) Description() string { return "invalid" }
func (badAnnotationTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"amount":{"type":"number","x-mcp-header":"Amount"}}}`)
}

func (badAnnotationTool) Execute(context.Context, json.RawMessage) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}

func nativeFixture(t *testing.T) (*Handler, *headerTool, *evidence.Store) {
	t.Helper()
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := &policy.Policy{
		Agent:        policy.AgentConfig{Name: "support-bot", Version: "1.0"},
		VersionTag:   "v1",
		Policies:     policy.PoliciesConfig{},
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"ticket_lookup", "bad_annotation", "zeta_tool"}, ForbiddenTools: []string{"delete_customer"}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	ht := &headerTool{name: "ticket_lookup"}
	reg.Register(&headerTool{name: "zeta_tool"})
	reg.Register(ht)
	reg.Register(badAnnotationTool{})
	return NewHandler(reg, engine, store, nil), ht, store
}

func do(t *testing.T, h http.Handler, path string, body []byte, headers map[string]string) (rec *httptest.ResponseRecorder, out map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(body))
	req = stamp(req)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func errCode(out map[string]any) float64 {
	e, _ := out["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return c
}

func countRecords(t *testing.T, store *evidence.Store) int {
	t.Helper()
	recs, err := store.List(context.Background(), "default", "", time.Time{}, time.Time{}, 100)
	require.NoError(t, err)
	return len(recs)
}

// ---- server/discover ------------------------------------------------------

func TestDiscover_AdvertisesOnlyWhatIsImplemented(t *testing.T) {
	native, _, _ := nativeFixture(t)
	hit := false
	up := attribUpstream(t, &hit)
	proxy, _ := attribHandler(t, up.URL, nil)
	for name, h := range map[string]http.Handler{"native": native, "proxy": proxy} {
		rec, out := do(t, h, "/mcp", mcpBody(t, "d-1", wire.MethodDiscover, nil), nil)
		require.Equal(t, http.StatusOK, rec.Code, name)
		res, _ := out["result"].(map[string]any)
		require.NotNil(t, res, "%s: %s", name, rec.Body.String())
		assert.Equal(t, "complete", res["resultType"], name)
		assert.Equal(t, []any{"2026-07-28"}, res["supportedVersions"], name)
		caps, _ := res["capabilities"].(map[string]any)
		assert.Contains(t, caps, "tools", name)
		assert.NotContains(t, caps, "resources", name)
		assert.NotContains(t, caps, "prompts", name)
		assert.NotContains(t, caps, "extensions", "%s: Tasks is not implemented, so it is not advertised", name)
		tc, _ := caps["tools"].(map[string]any)
		assert.NotContains(t, tc, "listChanged", "%s: no subscriptions/listen stream exists", name)
		meta, _ := res["_meta"].(map[string]any)
		si, _ := meta[wire.MetaServerInfo].(map[string]any)
		assert.NotEmpty(t, si["name"], name)
		assert.Equal(t, ServerVersion, si["version"], name)
		assert.Equal(t, "public", res["cacheScope"], name)
		assert.GreaterOrEqual(t, res["ttlMs"].(float64), float64(0), name)
		assert.Equal(t, "d-1", out["id"], name)
	}
	assert.False(t, hit, "discovery is answered locally")
}

// ---- tools/list -------------------------------------------------------------

func TestNativeToolsList_DeterministicWithCacheHintsAndExclusions(t *testing.T) {
	native, _, _ := nativeFixture(t)
	var first []any
	for i := 0; i < 3; i++ {
		rec, out := do(t, native, "/mcp", mcpBody(t, 1, wire.MethodToolsList, nil), nil)
		require.Equal(t, http.StatusOK, rec.Code)
		res := out["result"].(map[string]any)
		list := res["tools"].([]any)
		names := make([]string, 0, len(list))
		for _, tl := range list {
			names = append(names, tl.(map[string]any)["name"].(string))
		}
		assert.Equal(t, []string{"ticket_lookup", "zeta_tool"}, names, "sorted; bad_annotation excluded for its invalid x-mcp-header")
		assert.Equal(t, "complete", res["resultType"])
		assert.Equal(t, float64(listTTLMs), res["ttlMs"])
		assert.Equal(t, "private", res["cacheScope"])
		if first == nil {
			first = list
		} else {
			assert.Equal(t, first, list, "identical across requests")
		}
	}
}

// ---- tools/call: native ------------------------------------------------------

func TestNativeToolsCall_ResultShapeAndHeaderParams(t *testing.T) {
	native, ht, store := nativeFixture(t)
	body := mcpBody(t, 9, wire.MethodToolsCall, map[string]any{"name": "ticket_lookup", "arguments": map[string]any{"ticket_id": "T-1", "region": "eu"}})
	rec, out := do(t, native, "/mcp", body, map[string]string{"Mcp-Param-Ticket": "T-1"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	res := out["result"].(map[string]any)
	assert.Equal(t, "complete", res["resultType"])
	content := res["content"].([]any)
	require.Len(t, content, 1)
	assert.Equal(t, "text", content[0].(map[string]any)["type"])
	assert.Equal(t, map[string]any{"ticket": "ok"}, res["structuredContent"])
	assert.Equal(t, false, res["isError"])
	assert.EqualValues(t, 1, ht.calls.Load())
	assert.Equal(t, 1, countRecords(t, store), "one governed evidence record for the executed call")

	// Integrity failures: every one before execution, none evidenced.
	cases := map[string]map[string]string{
		"param header mismatch":             {"Mcp-Param-Ticket": "T-2"},
		"param header missing":              {},
		"param header invalid chars":        {"Mcp-Param-Ticket": "T\x7f1"},
		"name header smuggles another tool": {"Mcp-Param-Ticket": "T-1", wire.HeaderName: "delete_customer"},
		"method header mismatch":            {"Mcp-Param-Ticket": "T-1", wire.HeaderMethod: "tools/list"},
		"protocol header mismatch":          {"Mcp-Param-Ticket": "T-1", wire.HeaderProtocolVersion: "2025-11-25"},
	}
	for name, hdr := range cases {
		rec, out := do(t, native, "/mcp", body, hdr)
		assert.Equal(t, http.StatusBadRequest, rec.Code, name)
		assert.Equal(t, float64(wire.CodeHeaderMismatch), errCode(out), name)
		assert.EqualValues(t, 1, ht.calls.Load(), "%s: zero additional execution", name)
		assert.Equal(t, 1, countRecords(t, store), "%s: no evidence for a protocol rejection", name)
	}
	// An unrecognized Mcp-Param header is ignored, never used.
	rec, _ = do(t, native, "/mcp", body, map[string]string{"Mcp-Param-Ticket": "T-1", "Mcp-Param-Region": "evil"})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.EqualValues(t, 2, ht.calls.Load())
}

// Metadata cannot select Talon authority: _meta extension keys, clientInfo
// and mirrored headers never change the tenant or agent the evidence is
// attributed to, and a header can never pick a different tool than the body.
func TestMetadataCannotSelectAuthority(t *testing.T) {
	native, ht, store := nativeFixture(t)
	params := map[string]any{
		"_meta": map[string]any{
			wire.MetaProtocolVersion:    wire.ProtocolVersion,
			wire.MetaClientInfo:         map[string]string{"name": "admin", "version": "1"},
			wire.MetaClientCapabilities: map[string]any{},
			"com.example/tenant":        "other-tenant",
			"com.example/agent":         "root",
			"io.dativo.talon/approver":  "lead-1",
		},
		"name":      "ticket_lookup",
		"arguments": map[string]any{"ticket_id": "T-7"},
	}
	rec, _ := do(t, native, "/mcp", mcpBody(t, 1, wire.MethodToolsCall, params), map[string]string{"Mcp-Param-Ticket": "T-7", "X-Talon-Tenant": "other-tenant"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	recs, err := store.List(context.Background(), "default", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.Equal(t, "default", recs[0].TenantID, "tenant comes from Talon auth context only")
	assert.Equal(t, "mcp-client", recs[0].AgentID)
	other, err := store.List(context.Background(), "other-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Empty(t, other)
	assert.EqualValues(t, 1, ht.calls.Load())
}

// ---- tools/call: proxy forwarding ---------------------------------------------

type captured struct {
	hits    atomic.Int64
	headers http.Header
	body    map[string]any
}

func capturingUpstream(t *testing.T, respond func(w http.ResponseWriter, id json.RawMessage)) (*httptest.Server, *captured) {
	t.Helper()
	c := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		c.headers = r.Header.Clone()
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.Unmarshal(req.Params, &c.body)
		respond(w, req.ID)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func jsonResult(result string) func(w http.ResponseWriter, id json.RawMessage) {
	return func(w http.ResponseWriter, id json.RawMessage) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":` + result + `}`))
	}
}

func proxyFixture(t *testing.T, upstreamURL string) (*ProxyHandler, *evidence.Store) {
	t.Helper()
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:       policy.UpstreamConfig{URL: upstreamURL, Vendor: "crm"},
			AllowedTools:   []policy.ToolMapping{{Name: "crm_lookup", UpstreamName: "lookup_v2"}},
			ForbiddenTools: []string{"crm_delete"},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return NewProxyHandler(cfg, engine, store, nil, nil), store
}

func TestProxyForwarding_FreshValidatedUpstreamRequest(t *testing.T) {
	up, cap := capturingUpstream(t, jsonResult(`{"resultType":"complete","content":[{"type":"text","text":"hi"}]}`))
	h, store := proxyFixture(t, up.URL)
	params := map[string]any{
		"_meta": map[string]any{
			wire.MetaProtocolVersion:    wire.ProtocolVersion,
			wire.MetaClientInfo:         map[string]string{"name": "orig-client", "version": "2"},
			wire.MetaClientCapabilities: map[string]any{"elicitation": map[string]any{"form": map[string]any{}}},
			"progressToken":             "pt-1",
			"traceparent":               "00-aaaa-bbbb-01",
		},
		"name":           "crm_lookup",
		"arguments":      map[string]any{"region": "eu-west1", "q": "acme"},
		"requestState":   "opaque-state",
		"inputResponses": map[string]any{"q1": map[string]any{"action": "accept", "content": map[string]any{"x": 1}}},
	}
	rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 42, wire.MethodToolsCall, params), map[string]string{
		"Mcp-Param-Region": "eu-west1",
		"Mcp-Param-Evil":   "forwarded?", // unrecognized: never forwarded
		"Mcp-Session-Id":   "legacy",     // ignored
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.EqualValues(t, 1, cap.hits.Load())

	// Outbound headers are generated from the authorized body, not copied.
	assert.Equal(t, wire.ProtocolVersion, cap.headers.Get(wire.HeaderProtocolVersion))
	assert.Equal(t, wire.MethodToolsCall, cap.headers.Get(wire.HeaderMethod))
	assert.Equal(t, "lookup_v2", cap.headers.Get(wire.HeaderName), "Mcp-Name names the canonical upstream tool")
	assert.Empty(t, cap.headers.Get("Mcp-Param-Region"), "this route declares no mirrored parameters: none generated")
	assert.Empty(t, cap.headers.Get("Mcp-Param-Evil"), "inbound Mcp-Param headers are never forwarded")
	assert.Empty(t, cap.headers.Get("Mcp-Session-Id"))
	assert.Equal(t, "application/json, text/event-stream", cap.headers.Get("Accept"))

	// Outbound body: lossless continuation fields and permitted _meta.
	assert.Equal(t, "lookup_v2", cap.body["name"])
	assert.Equal(t, "opaque-state", cap.body["requestState"])
	assert.NotNil(t, cap.body["inputResponses"])
	meta := cap.body["_meta"].(map[string]any)
	assert.Equal(t, wire.ProtocolVersion, meta[wire.MetaProtocolVersion])
	assert.Equal(t, "talon-mcp-proxy", meta[wire.MetaClientInfo].(map[string]any)["name"], "Talon is the client of the upstream")
	assert.Equal(t, map[string]any{"elicitation": map[string]any{"form": map[string]any{}}}, meta[wire.MetaClientCapabilities], "originating client capabilities are relayed")
	assert.Equal(t, "pt-1", meta["progressToken"])
	assert.Equal(t, "00-aaaa-bbbb-01", meta["traceparent"])

	res := out["result"].(map[string]any)
	assert.Equal(t, "complete", res["resultType"])
	assert.Equal(t, "talon-mcp-proxy", res["_meta"].(map[string]any)[wire.MetaServerInfo].(map[string]any)["name"])
	assert.Equal(t, float64(42), out["id"])
	assert.Equal(t, 1, countRecords(t, store))
}

func TestProxyForwarding_IntegrityFailuresNeverReachUpstream(t *testing.T) {
	up, cap := capturingUpstream(t, jsonResult(`{"content":[]}`))
	h, store := proxyFixture(t, up.URL)
	body := mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{"region": "eu-west1"}})
	cases := map[string]map[string]string{
		"Mcp-Name says forbidden, body allowed": {"Mcp-Param-Region": "eu-west1", wire.HeaderName: "crm_delete"},
		"Mcp-Name says allowed, body forbidden": {"Mcp-Param-Region": "eu-west1", wire.HeaderName: "crm_lookup"},
		"Mcp-Method mismatch":                   {"Mcp-Param-Region": "eu-west1", wire.HeaderMethod: "tools/list"},
		"unsupported version":                   {"Mcp-Param-Region": "eu-west1", wire.HeaderProtocolVersion: "2025-11-25"},
	}
	for name, hdr := range cases {
		b := body
		if name == "Mcp-Name says allowed, body forbidden" {
			b = mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_delete", "arguments": map[string]any{"region": "eu-west1"}})
		}
		rec, out := do(t, h, "/mcp/proxy", b, hdr)
		assert.Equal(t, http.StatusBadRequest, rec.Code, name)
		assert.Equal(t, float64(wire.CodeHeaderMismatch), errCode(out), name)
		e := out["error"].(map[string]any)
		assert.Nil(t, e["data"], "%s: no talon_code on a protocol error", name)
	}
	assert.EqualValues(t, 0, cap.hits.Load(), "zero upstream dispatch for every integrity failure")
	assert.Equal(t, 0, countRecords(t, store), "zero governance evidence for protocol rejections")

	// The same body with agreeing headers but a forbidden tool IS a
	// governance denial: evidenced, still zero upstream.
	rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_delete", "arguments": map[string]any{}}), nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, float64(codeServerError), errCode(out))
	assert.Equal(t, TalonCodeToolForbidden, out["error"].(map[string]any)["data"].(map[string]any)["talon_code"])
	assert.EqualValues(t, 0, cap.hits.Load())
	assert.Equal(t, 1, countRecords(t, store))
}

func TestProxyForwarding_InputRequiredAndSSEPassThrough(t *testing.T) {
	up, cap := capturingUpstream(t, func(w http.ResponseWriter, id json.RawMessage) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n"))
		_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":" + string(id) + ",\"result\":{\"resultType\":\"input_required\",\"inputRequests\":{\"login\":{\"method\":\"elicitation/create\",\"params\":{\"mode\":\"form\",\"message\":\"user?\",\"requestedSchema\":{\"type\":\"object\"}}}},\"requestState\":\"st-9\"}}\n\n"))
	})
	h, _ := proxyFixture(t, up.URL)
	rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 5, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.EqualValues(t, 1, cap.hits.Load())
	res := out["result"].(map[string]any)
	assert.Equal(t, "input_required", res["resultType"], "MRTR interim results pass through losslessly")
	assert.Equal(t, "st-9", res["requestState"])
	assert.NotNil(t, res["inputRequests"].(map[string]any)["login"])
	assert.NotContains(t, res, "ttlMs", "interim results carry no cache hints")
}

func TestProxyToolsList_RebuiltRequestAndCacheHints(t *testing.T) {
	up, cap := capturingUpstream(t, jsonResult(`{"resultType":"complete","tools":[{"name":"lookup_v2","inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}},{"name":"crm_delete","inputSchema":{"type":"object"}},{"name":"broken","inputSchema":{"type":"object","properties":{"n":{"type":"number","x-mcp-header":"N"}}}}],"nextCursor":"c2","ttlMs":120000,"cacheScope":"public"}`))
	h, _ := proxyFixture(t, up.URL)
	rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsList, map[string]any{"cursor": "c1"}), map[string]string{"Mcp-Session-Id": "x"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, wire.MethodToolsList, cap.headers.Get(wire.HeaderMethod))
	assert.Equal(t, wire.ProtocolVersion, cap.headers.Get(wire.HeaderProtocolVersion))
	assert.Empty(t, cap.headers.Get(wire.HeaderName), "tools/list carries no Mcp-Name")
	assert.Equal(t, "c1", cap.body["cursor"], "cursor is rebuilt into the fresh request")
	assert.NotNil(t, cap.body["_meta"].(map[string]any)[wire.MetaClientCapabilities])
	res := out["result"].(map[string]any)
	list := res["tools"].([]any)
	require.Len(t, list, 1, "crm_delete is not in allowed_tools; broken has an invalid x-mcp-header")
	assert.Equal(t, "lookup_v2", list[0].(map[string]any)["name"])
	assert.NotContains(t, rec.Body.String(), "x-mcp-header", "presented definitions carry no annotation this route cannot validate")
	assert.Equal(t, "c2", res["nextCursor"])
	assert.Equal(t, float64(120000), res["ttlMs"], "upstream ttlMs is preserved as a hint")
	assert.Equal(t, "private", res["cacheScope"], "a filtered list is never public")
	assert.Equal(t, "complete", res["resultType"])
}

func TestProxy_NoRedirectFollowing(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, withRuntime := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/setRuntime=%v", status, withRuntime), func(t *testing.T) {
				leaked := atomic.Int64{}
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
				t.Cleanup(target.Close)
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, target.URL, status)
				}))
				t.Cleanup(up.Close)
				h, _ := proxyFixture(t, up.URL)
				if withRuntime {
					h.SetRuntime(ProxyRuntimeConfig{UpstreamTimeout: 5 * time.Second})
				}
				rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, float64(codeServerError), errCode(out), "a redirecting upstream is an upstream error")
				assert.EqualValues(t, 0, leaked.Load(), "the redirect target is never contacted")
			})
		}
	}
}

// Upstream resultType truth table through the proxy: complete continues,
// input_required passes through, missing / task / unknown are honest
// upstream errors with no fabricated result.
func TestProxy_ResultTypeTruthTable(t *testing.T) {
	cases := map[string]struct {
		result string
		ok     bool
		want   string
	}{
		"complete":       {`{"resultType":"complete","content":[]}`, true, "complete"},
		"input_required": {`{"resultType":"input_required","requestState":"s"}`, true, "input_required"},
		"missing":        {`{"content":[]}`, false, "resultType"},
		"task":           {`{"resultType":"task","task":{"taskId":"t1"}}`, false, "task"},
		"unknown":        {`{"resultType":"partial"}`, false, "partial"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			up, _ := capturingUpstream(t, jsonResult(tc.result))
			h, _ := proxyFixture(t, up.URL)
			rec, out := do(t, h, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{}}), nil)
			require.Equal(t, http.StatusOK, rec.Code)
			if tc.ok {
				require.Nil(t, out["error"], rec.Body.String())
				assert.Equal(t, tc.want, out["result"].(map[string]any)["resultType"])
				return
			}
			require.Nil(t, out["result"], "no result is fabricated")
			assert.Equal(t, float64(codeServerError), errCode(out))
			assert.Contains(t, out["error"].(map[string]any)["message"], tc.want)
			assert.Equal(t, TalonCodeUpstreamError, out["error"].(map[string]any)["data"].(map[string]any)["talon_code"])
		})
	}
}

// Drift guard: on every route the mirrored-parameter declaration derived
// from the definition PRESENTED in tools/list is the declaration used for
// inbound validation and outbound generation.
func TestHeaderDeclaration_NeverDrifts(t *testing.T) {
	native, _, _ := nativeFixture(t)
	_, out := do(t, native, "/mcp", mcpBody(t, 1, wire.MethodToolsList, nil), nil)
	listed := out["result"].(map[string]any)["tools"].([]any)
	require.NotEmpty(t, listed)
	for _, tl := range listed {
		m := tl.(map[string]any)
		schema, _ := json.Marshal(m["inputSchema"])
		advertised, err := wire.HeaderParamsFromSchema(schema)
		require.NoError(t, err)
		tool, ok := native.registry.Get(m["name"].(string))
		require.True(t, ok)
		_, validated, err := nativeToolDefinition(tool)
		require.NoError(t, err)
		assert.Equal(t, advertised.Decls(), validated.Decls(), "native %s: advertised == validated", m["name"])
	}

	up, _ := capturingUpstream(t, jsonResult(`{"resultType":"complete","tools":[{"name":"lookup_v2","inputSchema":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}}],"ttlMs":0,"cacheScope":"private"}`))
	proxy, _ := proxyFixture(t, up.URL)
	_, out = do(t, proxy, "/mcp/proxy", mcpBody(t, 1, wire.MethodToolsList, nil), nil)
	for _, tl := range out["result"].(map[string]any)["tools"].([]any) {
		m := tl.(map[string]any)
		schema, _ := json.Marshal(m["inputSchema"])
		advertised, err := wire.HeaderParamsFromSchema(schema)
		require.NoError(t, err)
		validated := proxy.headerDecl("crm_lookup")
		assert.Equal(t, advertised.Decls(), validated.Decls(), "proxy %s: advertised == validated", m["name"])
		assert.True(t, advertised.Empty(), "the proxy presents no mirrored parameters")
	}
	// Consequently an inbound Mcp-Param on the proxy is neither validated
	// nor forwarded: it cannot become a mismatch, and it cannot leak.
	rec, _ := do(t, proxy, "/mcp/proxy", mcpBody(t, 2, wire.MethodToolsCall, map[string]any{"name": "crm_lookup", "arguments": map[string]any{"region": "eu"}}), map[string]string{"Mcp-Param-Region": "us"})
	assert.Equal(t, http.StatusOK, rec.Code)
}
