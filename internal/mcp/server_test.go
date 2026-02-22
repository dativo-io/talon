package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
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
	h := NewHandler(reg, engine, store)

	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
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

	h := NewHandler(tools.NewRegistry(), engine, store)
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{},
		"id":      2,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
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
