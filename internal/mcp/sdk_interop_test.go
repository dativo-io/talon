package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
)

// Interoperability with the official MCP Go SDK (pinned v1.8.0, which
// speaks 2026-07-28). The SDK is the counterpart, never Talon's
// implementation: an SDK *server* with an eliciting tool is the upstream
// behind /mcp/proxy, and an SDK *client* drives Talon's routes. This proves
// server/discover, tools/list, tools/call, the Mcp-* headers Talon emits
// (validated by the SDK server) and consumes (emitted by the SDK client),
// resultType handling and an input_required (MRTR) round-trip through the
// proxy.

// sdkUpstream starts an official-SDK Streamable HTTP server with one tool
// that elicits a GitHub login on the first call and completes on the retry.
func sdkUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	calls := &atomic.Int64{}
	srv := sdk.NewServer(&sdk.Implementation{Name: "sdk-upstream", Version: "1.8.0"}, nil)
	srv.AddTool(&sdk.Tool{
		Name:        "ticket_lookup",
		Description: "look up a ticket",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"ticket_id": map[string]any{"type": "string"}}, "required": []any{"ticket_id"}},
	}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		calls.Add(1)
		if len(req.Params.InputResponses) == 0 {
			return &sdk.CallToolResult{
				InputRequests: sdk.InputRequestMap{"login": &sdk.ElicitParams{
					Mode: "form", Message: "GitHub login?",
					RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}, "required": []any{"name"}},
				}},
				RequestState: "state-1",
			}, nil
		}
		login, _ := req.Params.InputResponses["login"].(*sdk.ElicitResult)
		require.NotNil(t, login)
		require.Equal(t, "state-1", req.Params.RequestState, "requestState echoed through the proxy")
		var args map[string]any
		_ = json.Unmarshal(req.Params.Arguments, &args)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ticket " + args["ticket_id"].(string) + " for " + login.Content["name"].(string)}}}, nil
	})
	srv.AddTool(&sdk.Tool{Name: "delete_customer", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		t.Fatal("forbidden tool must never be dispatched")
		return nil, nil
	})
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, &sdk.StreamableHTTPOptions{Stateless: true})
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, calls
}

func sdkClient(t *testing.T, endpoint string) *sdk.ClientSession {
	t.Helper()
	client := sdk.NewClient(&sdk.Implementation{Name: "sdk-client", Version: "1.8.0"}, &sdk.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
			return &sdk.ElicitResult{Action: "accept", Content: map[string]any{"name": "octocat"}}, nil
		},
	})
	session, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{Endpoint: endpoint}, nil)
	require.NoError(t, err, "the official client must connect without any legacy fallback")
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestSDKInterop_ProxyRoute(t *testing.T) {
	up, upstreamCalls := sdkUpstream(t)
	cfg := &policy.ProxyPolicyConfig{
		Agent: policy.ProxyAgentConfig{Name: "vendor-proxy-agent", Type: "mcp_proxy"},
		Proxy: policy.ProxyConfig{
			Upstream:       policy.UpstreamConfig{URL: up.URL, Vendor: "ticketing"},
			AllowedTools:   []policy.ToolMapping{{Name: "ticket_lookup"}},
			ForbiddenTools: []string{"delete_customer"},
		},
	}
	engine, err := policy.NewProxyEngine(context.Background(), cfg)
	require.NoError(t, err)
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	proxy := NewProxyHandler(cfg, engine, store, nil, nil)
	talon := httptest.NewServer(proxy)
	t.Cleanup(talon.Close)

	session := sdkClient(t, talon.URL)
	// server/discover happened inside Connect; its result is what the SDK
	// exposes as the "initialize result" of a modern session.
	disc := session.InitializeResult()
	require.NotNil(t, disc)
	assert.Equal(t, "talon-mcp-proxy", disc.ServerInfo.Name)
	assert.NotNil(t, disc.Capabilities.Tools)

	list, err := session.ListTools(t.Context(), nil)
	require.NoError(t, err)
	names := []string{}
	for _, tl := range list.Tools {
		names = append(names, tl.Name)
	}
	assert.Equal(t, []string{"ticket_lookup"}, names, "forbidden tool filtered, deterministic")

	// tools/call with an MRTR round-trip: the SDK upstream answers
	// input_required, Talon passes it through losslessly, the SDK client
	// fulfils the elicitation and retries with inputResponses+requestState,
	// Talon forwards them, the upstream completes.
	res, err := session.CallTool(t.Context(), &sdk.CallToolParams{Name: "ticket_lookup", Arguments: map[string]any{"ticket_id": "T-1"}})
	require.NoError(t, err)
	require.False(t, res.IsError)
	require.Len(t, res.Content, 1)
	assert.Equal(t, "ticket T-1 for octocat", res.Content[0].(*sdk.TextContent).Text)
	assert.EqualValues(t, 2, upstreamCalls.Load(), "one input_required round-trip plus one completion")

	// Governance still applies on the validated path: a forbidden tool is a
	// Talon denial carried as a JSON-RPC error with the stable code.
	_, err = session.CallTool(t.Context(), &sdk.CallToolParams{Name: "delete_customer", Arguments: map[string]any{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tool not allowed by policy")
	assert.EqualValues(t, 2, upstreamCalls.Load())
}

func TestSDKInterop_NativeRoute(t *testing.T) {
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := &policy.Policy{
		Agent:        policy.AgentConfig{Name: "support-bot", Version: "1.0"},
		VersionTag:   "v1",
		Policies:     policy.PoliciesConfig{},
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"ticket_lookup"}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	ht := &headerTool{name: "ticket_lookup"}
	reg.Register(ht)
	native := NewHandler(reg, engine, store, nil)
	talon := httptest.NewServer(native)
	t.Cleanup(talon.Close)

	session := sdkClient(t, talon.URL)
	assert.Equal(t, "talon", session.InitializeResult().ServerInfo.Name)
	list, err := session.ListTools(t.Context(), nil)
	require.NoError(t, err)
	require.Len(t, list.Tools, 1)
	schema, _ := json.Marshal(list.Tools[0].InputSchema)
	assert.Contains(t, string(schema), "x-mcp-header", "the native route presents its real declaration")

	// The SDK client mirrors the declared x-mcp-header argument into
	// Mcp-Param-Ticket on its own; Talon validates it against the body.
	res, err := session.CallTool(t.Context(), &sdk.CallToolParams{Name: "ticket_lookup", Arguments: map[string]any{"ticket_id": "T-9"}})
	require.NoError(t, err)
	require.False(t, res.IsError)
	assert.EqualValues(t, 1, ht.calls.Load())
	assert.Equal(t, `{"ticket":"ok"}`, res.Content[0].(*sdk.TextContent).Text)
	_ = wire.ProtocolVersion
}
