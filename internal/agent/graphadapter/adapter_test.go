package graphadapter

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleEvent_RunStart_NoPolicyEngine(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	ev := &Event{
		Type:       EventRunStart,
		GraphRunID: "gr_test_1",
		TenantID:   "acme",
		AgentID:    "test-agent",
		Timestamp:  time.Now(),
		RunMeta: &RunMeta{
			Framework: "langgraph",
			NodeCount: 3,
			Model:     "gpt-4o",
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
	assert.Equal(t, ActionAllow, dec.Action)
}

func TestHandleEvent_ToolCall_NoPolicy(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	ev := &Event{
		Type:       EventToolCall,
		GraphRunID: "gr_test_2",
		TenantID:   "acme",
		AgentID:    "test-agent",
		Timestamp:  time.Now(),
		ToolMeta: &ToolMeta{
			Name:      "web_search",
			Arguments: map[string]interface{}{"query": "test"},
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestHandleEvent_ToolCall_MissingMeta(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	ev := &Event{
		Type:       EventToolCall,
		GraphRunID: "gr_test_3",
		TenantID:   "acme",
		AgentID:    "test-agent",
		Timestamp:  time.Now(),
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.False(t, dec.Allowed)
	assert.Equal(t, ActionDeny, dec.Action)
	assert.Contains(t, dec.Reasons[0], "tool_meta")
}

func TestHandleEvent_UnknownType(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	ev := &Event{
		Type:       EventType("unknown"),
		GraphRunID: "gr_test_4",
		TenantID:   "acme",
		AgentID:    "test-agent",
		Timestamp:  time.Now(),
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.False(t, dec.Allowed)
	assert.Contains(t, dec.Reasons[0], "unknown event type")
}

func TestHandleEvent_StepStart_NoPolicyEngine(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	ev := &Event{
		Type:       EventStepStart,
		GraphRunID: "gr_test_5",
		TenantID:   "acme",
		AgentID:    "test-agent",
		StepIndex:  1,
		NodeID:     "node_search",
		Timestamp:  time.Now(),
		NodeMeta: &NodeMeta{
			Name:  "search_node",
			Type:  "llm",
			Model: "gpt-4o",
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestHandleEvent_StepEnd_NoEvidence(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	ev := &Event{
		Type:       EventStepEnd,
		GraphRunID: "gr_test_6",
		TenantID:   "acme",
		AgentID:    "test-agent",
		StepIndex:  1,
		Timestamp:  time.Now(),
		Result: &ResultMeta{
			Status:     "completed",
			DurationMS: 500,
			Cost:       0.003,
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestHandleEvent_Retry_NoPolicyEngine(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	ev := &Event{
		Type:       EventRetry,
		GraphRunID: "gr_test_7",
		TenantID:   "acme",
		AgentID:    "test-agent",
		NodeID:     "node_llm",
		Timestamp:  time.Now(),
		Error: &ErrorMeta{
			Message:    "rate limit exceeded",
			Retryable:  true,
			RetryCount: 2,
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestHandleEvent_RunEnd_NoEvidence(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	ev := &Event{
		Type:       EventRunEnd,
		GraphRunID: "gr_test_8",
		TenantID:   "acme",
		AgentID:    "test-agent",
		Cost:       0.05,
		Timestamp:  time.Now(),
		Result: &ResultMeta{
			Status:     "completed",
			DurationMS: 5000,
			Cost:       0.05,
		},
	}

	dec, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.True(t, dec.Allowed)
}

func TestHandleEvent_TimestampDefault(t *testing.T) {
	adapter := NewAdapter(nil, nil, nil)
	ev := &Event{
		Type:       EventRunStart,
		GraphRunID: "gr_test_9",
		TenantID:   "acme",
		AgentID:    "test-agent",
	}

	before := time.Now()
	_, err := adapter.HandleEvent(context.Background(), ev)
	require.NoError(t, err)
	assert.False(t, ev.Timestamp.IsZero())
	assert.True(t, ev.Timestamp.After(before) || ev.Timestamp.Equal(before))
}
