package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestHandler_ToolsList(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	pol := &policy.Policy{Agent: policy.AgentConfig{Name: "test", Version: "1.0"}, VersionTag: "v1", Policies: policy.PoliciesConfig{}}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)

	reg := tools.NewRegistry()
	h := NewHandler(reg, engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1,
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Nil(t, resp.Error)
	assert.Equal(t, "2.0", resp.JSONRPC)
	result, _ := resp.Result.(map[string]interface{})
	require.NotNil(t, result)
	toolList, _ := result["tools"].([]interface{})
	assert.NotNil(t, toolList)
	assert.Len(t, toolList, 0)
}

func TestHandler_ToolsCall_InvalidParams(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	pol := &policy.Policy{Agent: policy.AgentConfig{Name: "test", Version: "1.0"}, VersionTag: "v1", Policies: policy.PoliciesConfig{}}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)

	h := NewHandler(tools.NewRegistry(), engine, store, classifier.MustNewScanner())
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{},
		"id":      2,
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, codeInvalidParams, resp.Error.Code)
}

// stubToolForTest implements tools.Tool for MCP tests.
type stubToolForTest struct {
	name string
}

func (s *stubToolForTest) Name() string                 { return s.name }
func (s *stubToolForTest) Description() string          { return "stub for tests" }
func (s *stubToolForTest) InputSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (s *stubToolForTest) Execute(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
	return json.RawMessage(`{"done":true}`), nil
}

func TestHandler_ToolsCall_Success(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	pol := &policy.Policy{
		Agent:        policy.AgentConfig{Name: "test", Version: "1.0"},
		VersionTag:   "v1",
		Policies:     policy.PoliciesConfig{},
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"echo"}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)

	reg := tools.NewRegistry()
	reg.Register(&stubToolForTest{name: "echo"})
	h := NewHandler(reg, engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "id": 3,
		"params": map[string]interface{}{"name": "echo", "arguments": map[string]interface{}{}},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Nil(t, resp.Error)
	result, _ := resp.Result.(map[string]interface{})
	require.NotNil(t, result)
	_, hasContent := result["content"]
	assert.True(t, hasContent)
}

func TestHandler_ToolsCall_PolicyDenied(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	pol := &policy.Policy{
		Agent:        policy.AgentConfig{Name: "test", Version: "1.0"},
		VersionTag:   "v1",
		Policies:     policy.PoliciesConfig{},
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"only_this"}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	reg.Register(&stubToolForTest{name: "denied_tool"})
	h := NewHandler(reg, engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "id": 4,
		"params": map[string]interface{}{"name": "denied_tool", "arguments": map[string]interface{}{}},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, codeServerError, resp.Error.Code)
}

func TestHandler_ToolsCall_ToolNotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	pol := &policy.Policy{
		Agent:        policy.AgentConfig{Name: "test", Version: "1.0"},
		VersionTag:   "v1",
		Policies:     policy.PoliciesConfig{},
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"missing_tool"}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	h := NewHandler(tools.NewRegistry(), engine, store, classifier.MustNewScanner())

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "id": 5,
		"params": map[string]interface{}{"name": "missing_tool", "arguments": map[string]interface{}{}},
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not found")
}

// piiToolForTest returns a result containing PII, for output classification tests.
type piiToolForTest struct{}

func (p *piiToolForTest) Name() string                 { return "pii_tool" }
func (p *piiToolForTest) Description() string          { return "returns PII" }
func (p *piiToolForTest) InputSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (p *piiToolForTest) Execute(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
	return json.RawMessage(`{"contact":"hans.mueller@example.de"}`), nil
}

func serverToolsCall(t *testing.T, h *Handler, name, arguments string) *jsonrpcResponse {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(requestctx.SetTenantID(req.Context(), "default"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var resp jsonrpcResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	return &resp
}

func latestServerEvidence(t *testing.T, store *evidence.Store) *evidence.Evidence {
	t.Helper()
	records, err := store.List(context.Background(), "default", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.NotEmpty(t, records, "evidence must be recorded for tools/call")
	return &records[0]
}

func newServerHandlerForFlow(t *testing.T, allowedTools []string, extraTools ...tools.Tool) (*Handler, *evidence.Store) {
	t.Helper()
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	pol := &policy.Policy{
		Agent:        policy.AgentConfig{Name: "test", Version: "1.0"},
		VersionTag:   "v1",
		Policies:     policy.PoliciesConfig{},
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: allowedTools},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	reg.Register(&stubToolForTest{name: "echo"})
	for _, tl := range extraTools {
		reg.Register(tl)
	}
	return NewHandler(reg, engine, store, classifier.MustNewScanner()), store
}

func TestHandler_ToolsCall_DataFlowRecordedWithoutPII(t *testing.T) {
	h, store := newServerHandlerForFlow(t, []string{"echo"})
	resp := serverToolsCall(t, h, "echo", `{"q":"weekly summary"}`)
	require.Nil(t, resp.Error)

	ev := latestServerEvidence(t, store)
	require.NotNil(t, ev.DataFlow, "every tools/call must record data flow, classified or not")
	require.Len(t, ev.DataFlow.Items, 1)
	item := ev.DataFlow.Items[0]
	assert.Equal(t, evidence.FlowSourceToolArgs, item.Source)
	assert.Equal(t, evidence.FlowDispositionForwarded, item.Disposition)
	assert.Equal(t, evidence.FlowDestMCPTool, item.Destination.Kind)
	assert.Equal(t, "echo", item.Destination.Name)
	assert.Equal(t, "LOCAL", item.Destination.Region, "embedded tools execute in-process")
	assert.Empty(t, item.EntityTypes)
}

func TestHandler_ToolsCall_DataFlowPIIInArgs(t *testing.T) {
	h, store := newServerHandlerForFlow(t, []string{"echo"})
	resp := serverToolsCall(t, h, "echo", `{"q":"contact hans.mueller@example.de"}`)
	require.Nil(t, resp.Error)

	ev := latestServerEvidence(t, store)
	assert.Contains(t, ev.Classification.PIIDetected, "email")
	require.NotNil(t, ev.DataFlow)
	require.Len(t, ev.DataFlow.Items, 1)
	assert.Contains(t, ev.DataFlow.Items[0].EntityTypes, "email")
	assert.NotEmpty(t, ev.DataFlow.Items[0].ValueDigests, "digests, never raw values")
}

func TestHandler_ToolsCall_DataFlowPIIInResult(t *testing.T) {
	h, store := newServerHandlerForFlow(t, []string{"pii_tool"}, &piiToolForTest{})
	resp := serverToolsCall(t, h, "pii_tool", `{}`)
	require.Nil(t, resp.Error)

	ev := latestServerEvidence(t, store)
	assert.True(t, ev.Classification.OutputPIIDetected)
	require.NotNil(t, ev.DataFlow)
	require.Len(t, ev.DataFlow.Items, 2, "tool_args -> tool plus tool_result -> client")
	result := ev.DataFlow.Items[1]
	assert.Equal(t, evidence.FlowSourceToolResult, result.Source)
	assert.Equal(t, evidence.FlowDispositionSurfaced, result.Disposition)
	assert.Equal(t, evidence.FlowDestClient, result.Destination.Kind)
	assert.Contains(t, result.EntityTypes, "email")
}

func TestHandler_ToolsCall_DataFlowBlockedOnDeny(t *testing.T) {
	h, store := newServerHandlerForFlow(t, []string{"only_this"})
	resp := serverToolsCall(t, h, "echo", `{"q":"x"}`)
	require.NotNil(t, resp.Error)

	ev := latestServerEvidence(t, store)
	require.NotNil(t, ev.DataFlow, "denied calls also record data flow")
	require.Len(t, ev.DataFlow.Items, 1)
	assert.Equal(t, evidence.FlowDispositionBlocked, ev.DataFlow.Items[0].Disposition,
		"blocked disposition: arguments never reached the tool")
}
