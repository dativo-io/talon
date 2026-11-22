package action

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

// sdkRefundSource is a real MCP server (the official Go SDK, 2026-07-28)
// with one tool whose behaviour the test chooses, counting every tools/call
// it receives and capturing what Talon sent.
type sdkRefundSource struct {
	srv      *httptest.Server
	calls    atomic.Int64
	lastMeta atomic.Value // map[string]any
	lastIdem atomic.Value // string
	behave   func(*sdk.CallToolRequest) (*sdk.CallToolResult, error)
}

func newSDKRefundSource(t *testing.T, behave func(*sdk.CallToolRequest) (*sdk.CallToolResult, error)) *sdkRefundSource {
	t.Helper()
	s := &sdkRefundSource{behave: behave}
	srv := sdk.NewServer(&sdk.Implementation{Name: "refund-service", Version: "1.0.0"}, nil)
	srv.AddTool(&sdk.Tool{
		Name: "refund.create",
		// Permissive: Talon's catalog owns the schema; the source only counts.
		InputSchema: map[string]any{"type": "object"},
	}, func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		s.calls.Add(1)
		s.lastMeta.Store(map[string]any(req.Params.Meta))
		return s.behave(req)
	})
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, &sdk.StreamableHTTPOptions{Stateless: true})
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(wire.HeaderMethod) == wire.MethodToolsCall {
			s.lastIdem.Store(r.Header.Get("Idempotency-Key"))
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func mcpDefinition(url string) *Definition {
	return &Definition{
		Name: "create_refund", UpstreamName: "refund.create",
		Destination: Destination{Type: DestinationTypeMCP, URL: url},
		Source:      Source{Type: SourceTypeMCP, ID: "refunds", URL: url},
	}
}

func dispatchTo(d *MCPDispatcher, def *Definition) Outcome {
	return d.Dispatch(context.Background(), DispatchRequest{
		Definition: def, Payload: []byte(`{"amount":"30.00","ticket_id":"T-1"}`),
		OperationRef: "op_ref_1", AttemptID: "att_1", IdempotencyKey: "talon-op_ref_1", TenantID: "acme", AgentID: "support-bot",
	})
}

func TestMCPDispatcher_SuccessIsObservedAndCarriesTheIdempotencyIdentity(t *testing.T) {
	src := newSDKRefundSource(t, func(*sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "refund r-1 created"}}}, nil
	})
	out := dispatchTo(NewMCPDispatcher(nil, nil, "test"), mcpDefinition(src.srv.URL))

	assert.Equal(t, AttemptSucceeded, out.Status)
	assert.Equal(t, ResultProvenanceObserved, out.Provenance)
	assert.True(t, out.RequestWritten)
	assert.True(t, out.ResponseObserved)
	assert.NotEmpty(t, out.Ref)
	assert.Contains(t, string(out.Result), "refund r-1 created")
	assert.EqualValues(t, 1, src.calls.Load())
	var relayed map[string]any
	require.NoError(t, json.Unmarshal(out.Result, &relayed))
	rmeta := relayed["_meta"].(map[string]any)
	assert.Equal(t, MCPClientName, rmeta["io.modelcontextprotocol/serverInfo"].(map[string]any)["name"], "the relayed result is the normalized one, not the upstream bytes")
	assert.NotNil(t, rmeta["io.dativo.talon/upstreamServerInfo"], "the upstream identity is kept under its own key")
	meta, _ := src.lastMeta.Load().(map[string]any)
	assert.Equal(t, "talon-op_ref_1", meta[MetaIdempotencyKey], "the operation-scoped idempotency identity travels in _meta")
	assert.Equal(t, "att_1", meta[MetaAttemptID])
	assert.Equal(t, "talon-op_ref_1", src.lastIdem.Load(), "and as the Idempotency-Key header")
}

// A tool that reports an error after the request reached it is UNKNOWN: the
// source may have done part of the work. Never a retryable failure.
func TestMCPDispatcher_ToolErrorAfterDispatchIsUnknown(t *testing.T) {
	src := newSDKRefundSource(t, func(*sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "insufficient funds"}}}, nil
	})
	out := dispatchTo(NewMCPDispatcher(nil, nil, "test"), mcpDefinition(src.srv.URL))
	assert.Equal(t, AttemptUnknown, out.Status)
	assert.Equal(t, ResultProvenanceUnknown, out.Provenance)
	assert.Equal(t, "upstream_tool_error", out.Code)
	assert.True(t, out.RequestWritten)
	assert.EqualValues(t, 1, src.calls.Load())
}

// rawSource answers every tools/call with the reply the test writes, with
// the request's own JSON-RPC id, and counts the calls.
func rawSource(t *testing.T, reply func(w http.ResponseWriter, id json.RawMessage)) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var env struct {
			ID json.RawMessage `json:"id"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &env)
		reply(w, env.ID)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func writeJSON(w http.ResponseWriter, id json.RawMessage, member string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(id) + `,` + member + `}`))
}

func TestMCPDispatcher_UnknownOutcomes(t *testing.T) {
	cases := map[string]struct {
		reply func(w http.ResponseWriter, id json.RawMessage)
		code  string
	}{
		"json-rpc error": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"error":{"code":-32001,"message":"customer cust-77 balance locked","data":{"secret":"x"}}`)
		}, "upstream_jsonrpc_error: code=-32001 category=server_error"},
		"task result": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":{"resultType":"task","task":{"id":"t1"}}`)
		}, "upstream_result_type_unsupported"},
		"input required": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":{"resultType":"input_required","inputRequests":{}}`)
		}, "upstream_input_required_unsupported"},
		"no resultType": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":{"content":[]}`)
		}, "upstream_result_type_unsupported"},
		"wrong id": {func(w http.ResponseWriter, _ json.RawMessage) {
			writeJSON(w, json.RawMessage(`"someone-else"`), `"result":{"resultType":"complete","content":[]}`)
		}, "upstream_response_invalid"},
		"http 500 without body": {func(w http.ResponseWriter, _ json.RawMessage) {
			w.WriteHeader(http.StatusInternalServerError)
		}, "upstream_http_status"},
		"redirect": {func(w http.ResponseWriter, _ json.RawMessage) {
			w.Header().Set("Location", "https://elsewhere.invalid/")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}, "dispatch_redirect_refused"},
		"severed": {func(w http.ResponseWriter, _ json.RawMessage) {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		}, "dispatch_response_lost"},
		// Malformed results after the request was written prove nothing
		// either: never a success, never a safely retryable failure.
		"isError a string": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":{"resultType":"complete","content":[{"type":"text","text":"ok"}],"isError":"false"}`)
		}, "upstream_result_invalid"},
		"isError a number": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":{"resultType":"complete","content":[{"type":"text","text":"ok"}],"isError":0}`)
		}, "upstream_result_invalid"},
		"content missing": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":{"resultType":"complete","isError":false}`)
		}, "upstream_result_invalid"},
		"content block invalid": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":{"resultType":"complete","content":[{"type":"text","text":42}]}`)
		}, "upstream_result_invalid"},
		"structuredContent not an object": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":{"resultType":"complete","content":[],"structuredContent":["refund"]}`)
		}, "upstream_result_invalid"},
		"result not an object": {func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":"done"`)
		}, "upstream_result_invalid"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv, calls := rawSource(t, tc.reply)
			out := dispatchTo(NewMCPDispatcher(nil, nil, "test"), mcpDefinition(srv.URL))
			assert.Equal(t, AttemptUnknown, out.Status)
			assert.Equal(t, ResultProvenanceUnknown, out.Provenance)
			assert.True(t, out.RequestWritten)
			assert.Equal(t, tc.code, out.Code)
			assert.EqualValues(t, 1, calls.Load(), "one request, never followed or repeated")
			assert.NotContains(t, out.Code, "cust-77", "vendor text never becomes the outcome code")
			assert.Empty(t, out.Result, "only a validated success travels back to an adapter")
		})
	}
}

func TestMCPDispatcher_TimeoutAfterSendIsUnknown(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv, calls := rawSource(t, func(http.ResponseWriter, json.RawMessage) { <-release })
	d := NewMCPDispatcher(nil, nil, "test")
	d.Timeout = 200 * time.Millisecond
	out := dispatchTo(d, mcpDefinition(srv.URL))
	assert.Equal(t, AttemptUnknown, out.Status)
	assert.Equal(t, "dispatch_timeout_after_send", out.Code)
	assert.EqualValues(t, 1, calls.Load())
}

type stubSecrets struct {
	value string
	err   error
	gets  atomic.Int64
	who   atomic.Value
}

func (s *stubSecrets) Get(_ context.Context, name, tenantID, agentID string) (*secrets.Secret, error) {
	s.gets.Add(1)
	s.who.Store(name + "|" + tenantID + "|" + agentID)
	if s.err != nil {
		return nil, s.err
	}
	return &secrets.Secret{Name: name, Value: []byte(s.value)}, nil
}

func TestMCPDispatcher_NotDispatchedIsARetryableFailure(t *testing.T) {
	t.Run("credential unavailable", func(t *testing.T) {
		srv, calls := rawSource(t, func(w http.ResponseWriter, id json.RawMessage) {
			writeJSON(w, id, `"result":{"resultType":"complete","content":[]}`)
		})
		def := mcpDefinition(srv.URL)
		def.Source.Auth = &policy.UpstreamAuthConfig{SecretName: "refunds-token"}
		out := dispatchTo(NewMCPDispatcher(nil, &stubSecrets{err: errors.New("acl denied")}, "test"), def)
		assert.Equal(t, AttemptFailed, out.Status)
		assert.Equal(t, ResultProvenanceNotDispatched, out.Provenance)
		assert.Equal(t, "dispatch_credential_unavailable", out.Code)
		assert.False(t, out.RequestWritten)
		assert.Zero(t, calls.Load())
	})
	t.Run("source unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close()
		out := dispatchTo(NewMCPDispatcher(nil, nil, "test"), mcpDefinition(url))
		assert.Equal(t, AttemptFailed, out.Status)
		assert.Equal(t, "dispatch_transport_error", out.Code)
		assert.False(t, out.RequestWritten)
	})
	t.Run("not an mcp destination", func(t *testing.T) {
		def := mcpDefinition("http://127.0.0.1:1")
		def.Destination.Type = DestinationTypeHTTP
		out := dispatchTo(NewMCPDispatcher(nil, nil, "test"), def)
		assert.Equal(t, "dispatch_destination_unsupported", out.Code)
	})
}

func TestMCPDispatcher_CredentialIsReadUnderTheUseCaseIdentity(t *testing.T) {
	var got atomic.Value
	srv, _ := rawSource(t, func(w http.ResponseWriter, id json.RawMessage) {
		writeJSON(w, id, `"result":{"resultType":"complete","content":[]}`)
	})
	wrapped := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("X-Api-Key"))
		r2, _ := http.NewRequestWithContext(r.Context(), r.Method, srv.URL, r.Body)
		r2.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(r2)
		require.NoError(t, err)
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(wrapped.Close)
	raw := ""
	def := mcpDefinition(wrapped.URL)
	def.Source.Auth = &policy.UpstreamAuthConfig{SecretName: "refunds-token", Header: "X-Api-Key", Scheme: &raw}
	sec := &stubSecrets{value: "s3cr3t"}
	out := dispatchTo(NewMCPDispatcher(nil, sec, "test"), def)
	require.Equal(t, AttemptSucceeded, out.Status, out.Code)
	assert.Equal(t, "s3cr3t", got.Load())
	assert.Equal(t, "refunds-token|acme|support-bot", sec.who.Load())
	assert.NotContains(t, string(out.Result), "s3cr3t")
}

func TestDispatchers_RouteByDestinationTypeAndRefuseTheRest(t *testing.T) {
	src := newSDKRefundSource(t, func(*sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok"}}}, nil
	})
	ds := Dispatchers{DestinationTypeMCP: NewMCPDispatcher(nil, nil, "test")}
	assert.True(t, ds.Supports(DestinationTypeMCP))
	assert.False(t, ds.Supports(DestinationTypeHTTP))
	assert.Equal(t, AttemptSucceeded, dispatchTo2(ds, mcpDefinition(src.srv.URL)).Status)
	def := mcpDefinition(src.srv.URL)
	def.Destination.Type = DestinationTypeHTTP
	assert.Equal(t, "dispatch_destination_unsupported", dispatchTo2(ds, def).Code)
	assert.EqualValues(t, 1, src.calls.Load())
}

func dispatchTo2(d Dispatcher, def *Definition) Outcome {
	return d.Dispatch(context.Background(), DispatchRequest{Definition: def, Payload: []byte(`{}`), OperationRef: "r", AttemptID: "a", IdempotencyKey: "k"})
}
