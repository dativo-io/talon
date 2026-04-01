package graphadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_POST_RunStart(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	handler := NewHandler(adapter)

	ev := Event{
		Type:       EventRunStart,
		GraphRunID: "gr_http_1",
		TenantID:   "acme",
		AgentID:    "test-agent",
		RunMeta:    &RunMeta{Framework: "langgraph"},
	}
	body, _ := json.Marshal(ev)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/graph/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var dec Decision
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&dec))
	assert.True(t, dec.Allowed)
	assert.Equal(t, ActionAllow, dec.Action)
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	handler := NewHandler(adapter)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/graph/events", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandler_InvalidJSON(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	handler := NewHandler(adapter)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/graph/events", bytes.NewReader([]byte("not json")))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandler_MissingGraphRunID(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	handler := NewHandler(adapter)

	ev := Event{Type: EventRunStart, TenantID: "acme"}
	body, _ := json.Marshal(ev)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/graph/events", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandler_MissingType(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	handler := NewHandler(adapter)

	ev := Event{GraphRunID: "gr_1", TenantID: "acme"}
	body, _ := json.Marshal(ev)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/graph/events", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandler_DefaultTenantID(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	handler := NewHandler(adapter)

	ev := Event{
		Type:       EventRunStart,
		GraphRunID: "gr_http_2",
		AgentID:    "test-agent",
	}
	body, _ := json.Marshal(ev)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/graph/events", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandler_ToolCallDenied_NoMeta(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	handler := NewHandler(adapter)

	ev := Event{
		Type:       EventToolCall,
		GraphRunID: "gr_http_3",
		TenantID:   "acme",
		AgentID:    "test-agent",
	}
	body, _ := json.Marshal(ev)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/graph/events", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var dec Decision
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&dec))
	assert.False(t, dec.Allowed)
}
