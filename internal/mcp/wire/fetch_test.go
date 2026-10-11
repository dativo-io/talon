package wire

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listUpstream serves tools/list pages from a script keyed by cursor.
func listUpstream(t *testing.T, pages map[string]string, calls *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		calls.Add(1)
		assert.Equal(t, MethodToolsList, r.Header.Get(HeaderMethod))
		assert.Equal(t, ProtocolVersion, r.Header.Get(HeaderProtocolVersion))
		body, ok := pages[req.Params.Cursor]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":` + body + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testMeta() map[string]json.RawMessage {
	return OutboundMeta(Meta{ClientCapabilities: json.RawMessage("{}")}, Implementation{Name: "t", Version: "1"})
}

func TestFetchToolList_FollowsEveryPage(t *testing.T) {
	var calls atomic.Int64
	srv := listUpstream(t, map[string]string{
		"":   `{"resultType":"complete","tools":[{"name":"a","inputSchema":{"type":"object"}}],"nextCursor":"p2","ttlMs":120000.5,"cacheScope":"public"}`,
		"p2": `{"resultType":"complete","tools":[{"name":"b","inputSchema":{"type":"object"}}],"nextCursor":"p3","ttlMs":5,"cacheScope":"private"}`,
		"p3": `{"resultType":"complete","tools":[],"ttlMs":1,"cacheScope":"public"}`,
	}, &calls)
	list, err := FetchToolList(context.Background(), srv.Client(), srv.URL, json.RawMessage("7"), testMeta())
	require.NoError(t, err)
	assert.Len(t, list.Tools, 2)
	assert.Equal(t, 3, list.Pages)
	assert.EqualValues(t, 3, calls.Load())
	assert.Equal(t, json.Number("1"), list.TTLMs, "the shortest page ttlMs wins, verbatim")
	assert.Equal(t, CacheScopePrivate, list.CacheScope, "one private page makes the logical list private")
}

// A multi-page list is ONE logical list: its freshness is as conservative
// as its least fresh page, whatever the page order.
func TestFetchToolList_ConservativeFreshness(t *testing.T) {
	cases := map[string]struct {
		pages     map[string]string
		wantTTL   json.Number
		wantScope string
	}{
		"shorter later ttl wins": {pages: map[string]string{
			"":   `{"resultType":"complete","tools":[],"nextCursor":"p2","ttlMs":60000,"cacheScope":"public"}`,
			"p2": `{"resultType":"complete","tools":[],"ttlMs":10000,"cacheScope":"public"}`,
		}, wantTTL: "10000", wantScope: CacheScopePublic},
		"shorter earlier ttl kept": {pages: map[string]string{
			"":   `{"resultType":"complete","tools":[],"nextCursor":"p2","ttlMs":10000,"cacheScope":"public"}`,
			"p2": `{"resultType":"complete","tools":[],"ttlMs":60000,"cacheScope":"public"}`,
		}, wantTTL: "10000", wantScope: CacheScopePublic},
		"fraction compared numerically": {pages: map[string]string{
			"":   `{"resultType":"complete","tools":[],"nextCursor":"p2","ttlMs":100.5,"cacheScope":"public"}`,
			"p2": `{"resultType":"complete","tools":[],"ttlMs":100.25,"cacheScope":"public"}`,
		}, wantTTL: "100.25", wantScope: CacheScopePublic},
		"private later page": {pages: map[string]string{
			"":   `{"resultType":"complete","tools":[],"nextCursor":"p2","ttlMs":5,"cacheScope":"public"}`,
			"p2": `{"resultType":"complete","tools":[],"ttlMs":5,"cacheScope":"private"}`,
		}, wantTTL: "5", wantScope: CacheScopePrivate},
		"private earlier page": {pages: map[string]string{
			"":   `{"resultType":"complete","tools":[],"nextCursor":"p2","ttlMs":5,"cacheScope":"private"}`,
			"p2": `{"resultType":"complete","tools":[],"ttlMs":5,"cacheScope":"public"}`,
		}, wantTTL: "5", wantScope: CacheScopePrivate},
		"zero ttl on any page": {pages: map[string]string{
			"":   `{"resultType":"complete","tools":[],"nextCursor":"p2","ttlMs":99999,"cacheScope":"public"}`,
			"p2": `{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"public"}`,
		}, wantTTL: "0", wantScope: CacheScopePublic},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			srv := listUpstream(t, tc.pages, &calls)
			list, err := FetchToolList(context.Background(), srv.Client(), srv.URL, json.RawMessage("1"), testMeta())
			require.NoError(t, err)
			assert.Equal(t, tc.wantTTL, list.TTLMs)
			assert.Equal(t, tc.wantScope, list.CacheScope)
		})
	}
}

func TestFetchToolList_Failures(t *testing.T) {
	cases := map[string]struct {
		pages map[string]string
		kind  string
		is    error
	}{
		"cursor loop": {pages: map[string]string{
			"":   `{"resultType":"complete","tools":[],"nextCursor":"p2","ttlMs":1,"cacheScope":"public"}`,
			"p2": `{"resultType":"complete","tools":[],"nextCursor":"p2","ttlMs":1,"cacheScope":"public"}`,
		}, kind: UpstreamKindProtocol, is: ErrListPagination},
		"missing hints":    {pages: map[string]string{"": `{"resultType":"complete","tools":[]}`}, kind: UpstreamKindProtocol, is: ErrListResultInvalid},
		"wrong resultType": {pages: map[string]string{"": `{"resultType":"task","tools":[],"ttlMs":1,"cacheScope":"public"}`}, kind: UpstreamKindProtocol, is: ErrResultTypeUnsupported},
		"second page bad": {pages: map[string]string{
			"": `{"resultType":"complete","tools":[],"nextCursor":"p2","ttlMs":1,"cacheScope":"public"}`,
		}, kind: UpstreamKindProtocol, is: ErrUpstreamStatus},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			srv := listUpstream(t, tc.pages, &calls)
			_, err := FetchToolList(context.Background(), srv.Client(), srv.URL, json.RawMessage("1"), testMeta())
			require.Error(t, err)
			var ue *UpstreamError
			require.True(t, errors.As(err, &ue))
			assert.Equal(t, tc.kind, ue.Kind)
			assert.True(t, errors.Is(err, tc.is), "%v", err)
		})
	}
}

func TestFetchToolList_PageBound(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// Every page names a fresh cursor: never loops, never ends.
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"resultType":"complete","tools":[],"nextCursor":"c` + string(rune('a'+n%26)) + string(rune('a'+(n/26)%26)) + `","ttlMs":1,"cacheScope":"public"}}`))
	}))
	t.Cleanup(srv.Close)
	_, err := FetchToolList(context.Background(), srv.Client(), srv.URL, json.RawMessage("1"), testMeta())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrListPagination))
	assert.LessOrEqual(t, calls.Load(), int64(MaxListPages))
}

func TestExchange_Classification(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		_, err := Exchange(context.Background(), http.DefaultClient, srv.URL, json.RawMessage("1"), MethodToolsList, EncodeListParams(testMeta(), ""), "", nil)
		var ue *UpstreamError
		require.True(t, errors.As(err, &ue))
		assert.Equal(t, UpstreamKindTransport, ue.Kind)
	})
	t.Run("redirect refused", func(t *testing.T) {
		var leaked atomic.Int64
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { leaked.Add(1) }))
		t.Cleanup(target.Close)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		t.Cleanup(srv.Close)
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		_, err := Exchange(context.Background(), client, srv.URL, json.RawMessage("1"), MethodToolsList, EncodeListParams(testMeta(), ""), "", nil)
		var ue *UpstreamError
		require.True(t, errors.As(err, &ue))
		assert.Equal(t, UpstreamKindProtocol, ue.Kind)
		assert.True(t, errors.Is(err, ErrRedirectRefused))
		assert.EqualValues(t, 0, leaked.Load(), "the redirect target is never contacted")
	})
	t.Run("rpc error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32601,"message":"nope","data":{"x":1}}}`))
		}))
		t.Cleanup(srv.Close)
		_, err := Exchange(context.Background(), srv.Client(), srv.URL, json.RawMessage("1"), MethodToolsList, EncodeListParams(testMeta(), ""), "", nil)
		var ue *UpstreamError
		require.True(t, errors.As(err, &ue))
		assert.Equal(t, UpstreamKindRPC, ue.Kind)
		require.NotNil(t, ue.RPC)
		assert.Equal(t, -32601, ue.RPC.Code)
		assert.JSONEq(t, `{"x":1}`, string(ue.RPC.Data))
	})
	t.Run("id mismatch is protocol", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":99,"result":{"resultType":"complete"}}`))
		}))
		t.Cleanup(srv.Close)
		_, err := Exchange(context.Background(), srv.Client(), srv.URL, json.RawMessage("1"), MethodToolsList, EncodeListParams(testMeta(), ""), "", nil)
		var ue *UpstreamError
		require.True(t, errors.As(err, &ue))
		assert.Equal(t, UpstreamKindProtocol, ue.Kind)
		assert.True(t, errors.Is(err, ErrUpstreamProtocol))
	})
}

func TestParseDiscoverResult(t *testing.T) {
	good := `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"instructions":"hi","ttlMs":3600000,"cacheScope":"public","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"up","version":"2"}}}`
	d, err := ParseDiscoverResult(json.RawMessage(good))
	require.NoError(t, err)
	assert.Equal(t, []string{"2026-07-28"}, d.SupportedVersions)
	assert.JSONEq(t, `{"tools":{}}`, string(d.Capabilities))
	assert.Equal(t, "hi", d.Instructions)
	assert.Equal(t, Implementation{Name: "up", Version: "2"}, d.ServerInfo)
	assert.Equal(t, json.Number("3600000"), d.TTLMs)
	assert.Equal(t, CacheScopePublic, d.CacheScope)

	for name, raw := range map[string]string{
		"not object":           `[]`,
		"missing resultType":   `{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":1,"cacheScope":"public"}`,
		"wrong resultType":     `{"resultType":"input_required","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":1,"cacheScope":"public"}`,
		"empty versions":       `{"resultType":"complete","supportedVersions":[],"capabilities":{},"ttlMs":1,"cacheScope":"public"}`,
		"versions not array":   `{"resultType":"complete","supportedVersions":"2026-07-28","capabilities":{},"ttlMs":1,"cacheScope":"public"}`,
		"missing capabilities": `{"resultType":"complete","supportedVersions":["2026-07-28"],"ttlMs":1,"cacheScope":"public"}`,
		"capabilities array":   `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":[],"ttlMs":1,"cacheScope":"public"}`,
		"missing ttl":          `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}`,
		"string ttl":           `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":"1","cacheScope":"public"}`,
		"bad scope":            `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":1,"cacheScope":"shared"}`,
		"instructions number":  `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":1,"cacheScope":"public","instructions":3}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDiscoverResult(json.RawMessage(raw))
			assert.Error(t, err)
		})
	}
	// serverInfo is informational: a malformed one is ignored, not fatal.
	d, err = ParseDiscoverResult(json.RawMessage(`{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":1,"cacheScope":"public","_meta":{"io.modelcontextprotocol/serverInfo":"x"}}`))
	require.NoError(t, err)
	assert.Equal(t, Implementation{}, d.ServerInfo)
}

// Declarations carried transport-neutrally by a catalog rebuild into the
// SAME header set the schema parser produced: validation and outbound
// generation are identical from either source.
func TestHeaderParamsFromDecls_RoundTrip(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"shard":{"type":"object","properties":{"n":{"type":"integer","x-mcp-header":"Shard"}}},"dry":{"type":"boolean","x-mcp-header":"Dry-Run"}}}`)
	fromSchema, err := HeaderParamsFromSchema(schema)
	require.NoError(t, err)
	rebuilt, err := HeaderParamsFromDecls(fromSchema.Decls())
	require.NoError(t, err)
	assert.Equal(t, fromSchema.Decls(), rebuilt.Decls())
	args := json.RawMessage(`{"region":"eu","shard":{"n":7},"dry":true}`)
	h1, err := OutboundHeaderParams(fromSchema, args)
	require.NoError(t, err)
	h2, err := OutboundHeaderParams(rebuilt, args)
	require.NoError(t, err)
	assert.Equal(t, h1, h2)
	assert.Equal(t, "eu", h1.Get("Mcp-Param-Region"))

	_, err = HeaderParamsFromDecls([]ParamDecl{{Header: "A", Path: []string{"a"}}, {Header: "a", Path: []string{"b"}}})
	assert.Error(t, err, "case-insensitive duplicate")
	_, err = HeaderParamsFromDecls([]ParamDecl{{Header: "bad name", Path: []string{"a"}}})
	assert.Error(t, err)
	_, err = HeaderParamsFromDecls([]ParamDecl{{Header: "A", Path: nil}})
	assert.Error(t, err)
	_, err = HeaderParamsFromDecls([]ParamDecl{{Header: "A", Path: []string{"a"}, Type: "number"}})
	assert.Error(t, err)
}

func TestStripHeaderAnnotations_LosslessNumbers(t *testing.T) {
	out := StripHeaderAnnotations(json.RawMessage(`{"type":"object","properties":{"n":{"type":"integer","maximum":9007199254740993,"x-mcp-header":"N"}}}`))
	assert.Contains(t, string(out), "9007199254740993")
	assert.NotContains(t, string(out), "x-mcp-header")
}

func TestMergeCacheHints(t *testing.T) {
	ttl, scope := MergeCacheHints("5000", CacheScopePublic, "3600000", CacheScopePublic)
	assert.Equal(t, json.Number("5000"), ttl)
	assert.Equal(t, CacheScopePublic, scope)
	ttl, scope = MergeCacheHints("3600000", CacheScopePrivate, "10.25", CacheScopePublic)
	assert.Equal(t, json.Number("10.25"), ttl)
	assert.Equal(t, CacheScopePrivate, scope)
	ttl, _ = MergeCacheHints("1e3", CacheScopePublic, "999.5", CacheScopePublic)
	assert.Equal(t, json.Number("999.5"), ttl, "compared numerically across notations")
}

func TestMetaKeyGrammar(t *testing.T) {
	for _, ok := range []string{"io.modelcontextprotocol/tasks", "com.example/foo", "com.example/foo.bar-baz_1", "a/b", "io.my-vendor.x9/ext"} {
		assert.True(t, ValidExtensionID(ok), ok)
		assert.True(t, ValidMetaKey(ok), ok)
	}
	for _, bad := range []string{"tasks", "/foo", "io..bad/x", "io.bad./x", "-io.x/y", "io.x-/y", "io.x/", "io.x/-y", "io.x/y-", "io.x/y z", "io.x/y\x01", "", "io.x/" + strings.Repeat("y", 300)} {
		assert.False(t, ValidExtensionID(bad), "%q", bad)
	}
	assert.True(t, ValidMetaKey("progressToken"), "an unprefixed name is a valid _meta key")
	assert.False(t, ValidExtensionID("progressToken"), "but not an extension id")
	assert.False(t, ValidMetaKey("-x"))
}
