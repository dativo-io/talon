package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
)

type mockTool struct {
	name        string
	description string
	schema      json.RawMessage
	handler     func(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
}

func (t *mockTool) Name() string                 { return t.name }
func (t *mockTool) Description() string          { return t.description }
func (t *mockTool) InputSchema() json.RawMessage { return t.schema }
func (t *mockTool) Execute(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	return t.handler(ctx, params)
}

func TestOpenClawGovernance_E2E(t *testing.T) {
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)

	registry := tools.NewRegistry()
	registry.Register(&mockTool{
		name:        "email_read",
		description: "Read an email",
		schema:      json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}}}`),
		handler: func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(`{"from":"jan.kowalski@gmail.com","subject":"Hello"}`), nil
		},
	})
	registry.Register(&mockTool{
		name:        "email_search",
		description: "Search emails",
		schema:      json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
		handler: func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(`{"results":[]}`), nil
		},
	})
	registry.Register(&mockTool{
		name:        "email_delete",
		description: "Delete an email",
		schema:      json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}}}`),
		handler: func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(`{"deleted":true}`), nil
		},
	})

	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "e2e-governance-agent", Version: "1.0.0"},
		Capabilities: &policy.CapabilitiesConfig{
			AllowedTools:        []string{"email_read", "email_search"},
			DestructivePatterns: policy.DefaultDestructivePatterns,
		},
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"email_read": {
				Arguments: map[string]policy.PIIAction{
					"id": policy.PIIActionAllow,
				},
				Result: policy.PIIActionRedact,
			},
			"email_search": {
				Arguments: map[string]policy.PIIAction{
					"query": policy.PIIActionRedact,
				},
				Result: policy.PIIActionRedact,
			},
			"_default": {
				ArgumentDefault: policy.PIIActionRedact,
				Result:          policy.PIIActionRedact,
			},
		},
		Policies: policy.PoliciesConfig{
			CostLimits: &policy.CostLimitsConfig{PerRequest: 10, Daily: 100, Monthly: 1000},
			RateLimits: &policy.RateLimitsConfig{
				RequestsPerMinute:         100,
				PerAgentRequestsPerMinute: 20,
			},
		},
	}
	pol.ComputeHash([]byte("e2e"))

	ctx := context.Background()
	engine, err := policy.NewEngine(ctx, pol)
	require.NoError(t, err)

	t.Run("allowed_tool_executes_with_result_pii_redacted", func(t *testing.T) {
		tc := llm.ToolCall{ID: "tc_1", Name: "email_read", Arguments: map[string]interface{}{"id": "msg_123"}}
		res := executeE2EToolCall(t, scanner, engine, pol, registry, tc)
		assert.True(t, res.Executed, "allowed tool should execute")
		assert.NotContains(t, res.Content, "jan.kowalski@gmail.com",
			"PII in result should be redacted")
	})

	t.Run("forbidden_tool_denied_by_opa", func(t *testing.T) {
		tc := llm.ToolCall{ID: "tc_2", Name: "email_delete", Arguments: map[string]interface{}{"id": "msg_456"}}
		res := executeE2EToolCall(t, scanner, engine, pol, registry, tc)
		assert.False(t, res.Executed, "email_delete should be denied (not in allowed_tools)")
		assert.Contains(t, res.Content, "not in allowed_tools")
	})

	t.Run("tool_argument_pii_redacted", func(t *testing.T) {
		tc := llm.ToolCall{ID: "tc_3", Name: "email_search", Arguments: map[string]interface{}{"query": "jan.kowalski@gmail.com"}}
		res := executeE2EToolCall(t, scanner, engine, pol, registry, tc)
		assert.True(t, res.Executed, "search tool should execute")
		assert.NotEmpty(t, res.PIIFindings, "PII in query should be detected")
	})

	t.Run("circuit_breaker_opens_on_policy_denials", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 60*time.Second)
		for i := 0; i < 3; i++ {
			cb.RecordPolicyDenial("tenant-e2e", "e2e-governance-agent")
		}
		err := cb.Check("tenant-e2e", "e2e-governance-agent")
		assert.Error(t, err, "circuit should be open after 3 denials")
		assert.Contains(t, err.Error(), "circuit_open")
	})

	t.Run("circuit_breaker_half_open_recovers", func(t *testing.T) {
		cb := NewCircuitBreaker(2, 50*time.Millisecond)
		cb.RecordPolicyDenial("t", "a")
		cb.RecordPolicyDenial("t", "a")
		time.Sleep(60 * time.Millisecond)
		_ = cb.Check("t", "a")
		cb.RecordSuccess("t", "a")
		assert.Equal(t, CircuitClosed, cb.State("t", "a"))
	})

	t.Run("kill_switch_cancels_run", func(t *testing.T) {
		tracker := NewActiveRunTracker()
		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		tracker.Register("tenant-e2e", "corr_e2e_001", cancel)
		ok := tracker.Kill("corr_e2e_001")
		assert.True(t, ok)
		select {
		case <-runCtx.Done():
		default:
			t.Fatal("kill should cancel context")
		}
	})

	t.Run("volume_detection_triggers_review", func(t *testing.T) {
		cfg := &PlanReviewConfig{VolumeThreshold: 100}
		got := RequiresReview("on-demand", 0, 0, false, cfg, "delete 10000 emails")
		assert.True(t, got, "destructive verb + large number should trigger review")
	})

	t.Run("all_evidence_pii_sanitized", func(t *testing.T) {
		text := "email: jan.kowalski@gmail.com"
		sanitized := evidence.SanitizeForEvidence(ctx, text, scanner)
		assert.NotContains(t, sanitized, "jan.kowalski@gmail.com")
	})
}

func executeE2EToolCall(t *testing.T, scanner *classifier.Scanner, engine *policy.Engine, pol *policy.Policy, registry *tools.ToolRegistry, tc llm.ToolCall) ToolCallResult {
	t.Helper()
	r := &Runner{
		classifier:   scanner,
		toolRegistry: registry,
	}
	return r.executeToolCallFull(context.Background(), engine, pol, tc, nil)
}
