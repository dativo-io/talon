package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHookRegistry_EmptyReturnsTrue(t *testing.T) {
	registry := NewHookRegistry()
	result, err := registry.Execute(context.Background(), HookPrePolicy, &HookData{
		TenantID: "acme",
		AgentID:  "agent",
	})
	require.NoError(t, err)
	assert.True(t, result.Continue)
}

type abortHook struct {
	point HookPoint
}

func (h *abortHook) Point() HookPoint { return h.point }
func (h *abortHook) Execute(_ context.Context, _ *HookData) (*HookResult, error) {
	return &HookResult{Continue: false}, nil
}

func TestHookRegistry_AbortPipeline(t *testing.T) {
	registry := NewHookRegistry()
	registry.Register(&abortHook{point: HookPreLLM})

	result, err := registry.Execute(context.Background(), HookPreLLM, &HookData{
		TenantID: "acme",
	})
	require.NoError(t, err)
	assert.False(t, result.Continue)
}

func TestHookRegistry_MultipleHooksRun(t *testing.T) {
	var count int32
	registry := NewHookRegistry()

	for i := 0; i < 3; i++ {
		registry.Register(&countingHook{point: HookPostEvidence, counter: &count})
	}

	result, err := registry.Execute(context.Background(), HookPostEvidence, &HookData{
		TenantID: "acme",
	})
	require.NoError(t, err)
	assert.True(t, result.Continue)
	assert.Equal(t, int32(3), atomic.LoadInt32(&count))
}

type countingHook struct {
	point   HookPoint
	counter *int32
}

func (h *countingHook) Point() HookPoint { return h.point }
func (h *countingHook) Execute(_ context.Context, _ *HookData) (*HookResult, error) {
	atomic.AddInt32(h.counter, 1)
	return &HookResult{Continue: true}, nil
}

func TestHookRegistry_WrongPointNotTriggered(t *testing.T) {
	var count int32
	registry := NewHookRegistry()
	registry.Register(&countingHook{point: HookPreLLM, counter: &count})

	_, err := registry.Execute(context.Background(), HookPostLLM, &HookData{TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, int32(0), atomic.LoadInt32(&count))
}

func TestWebhookHook_DeliversPayload(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		received = buf

		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, string(HookPostPolicy), r.Header.Get("X-Talon-Hook"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hook := NewWebhookHook(HookPostPolicy, HookConfig{
		Type: "webhook",
		URL:  server.URL,
		On:   "all",
	})

	data := &HookData{
		TenantID:      "acme",
		AgentID:       "sales",
		CorrelationID: "corr_123",
		Stage:         HookPostPolicy,
	}
	result, err := hook.Execute(context.Background(), data)
	require.NoError(t, err)
	assert.True(t, result.Continue)

	var got HookData
	require.NoError(t, json.Unmarshal(received, &got))
	assert.Equal(t, "acme", got.TenantID)
	assert.Equal(t, "sales", got.AgentID)
}

func TestWebhookHook_EmptyURLNoOp(t *testing.T) {
	hook := NewWebhookHook(HookPreLLM, HookConfig{URL: ""})
	result, err := hook.Execute(context.Background(), &HookData{})
	require.NoError(t, err)
	assert.True(t, result.Continue)
}

func TestWebhookHook_UnreachableDoesNotAbort(t *testing.T) {
	hook := NewWebhookHook(HookPreLLM, HookConfig{
		Type: "webhook",
		URL:  "http://127.0.0.1:1", // unreachable port
	})
	result, err := hook.Execute(context.Background(), &HookData{TenantID: "t"})
	require.NoError(t, err)
	assert.True(t, result.Continue)
}

func TestLoadHooksFromConfig(t *testing.T) {
	config := map[string][]HookConfig{
		"post_policy": {
			{Type: "webhook", URL: "http://example.com/hook"},
		},
		"pre_llm": {
			{Type: "webhook", URL: ""},
			{Type: "webhook", URL: "http://example.com/pre"},
		},
		"post_llm": {
			{Type: "unknown", URL: "http://example.com/x"},
		},
	}

	registry := LoadHooksFromConfig(config)
	assert.NotNil(t, registry)

	// post_policy: 1 hook
	assert.Len(t, registry.hooks[HookPostPolicy], 1)
	// pre_llm: 1 hook (empty URL filtered)
	assert.Len(t, registry.hooks[HookPreLLM], 1)
	// post_llm: 0 (unknown type)
	assert.Len(t, registry.hooks[HookPostLLM], 0)
}
