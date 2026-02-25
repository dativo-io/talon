package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Gap A (CLOSED): Destructive operation detection via configurable pattern matching.
func TestToolAccess_GapA_DestructiveOpDetection(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		allowedTools []string
		destructive  []string
		toolName     string
		wantAllowed  bool
	}{
		{
			name:         "wildcard allowlist + destructive tool = denied",
			allowedTools: []string{"*"},
			destructive:  DefaultDestructivePatterns,
			toolName:     "email_delete",
			wantAllowed:  false,
		},
		{
			name:         "explicit allowlist with destructive tool = allowed",
			allowedTools: []string{"email_delete", "email_read"},
			destructive:  DefaultDestructivePatterns,
			toolName:     "email_delete",
			wantAllowed:  true,
		},
		{
			name:         "wildcard + non-destructive tool = allowed",
			allowedTools: []string{"*"},
			destructive:  DefaultDestructivePatterns,
			toolName:     "email_read",
			wantAllowed:  true,
		},
		{
			name:         "custom patterns override defaults",
			allowedTools: []string{"*"},
			destructive:  []string{"archive"},
			toolName:     "ticket_archive_permanent",
			wantAllowed:  false,
		},
		{
			name:         "empty destructive_patterns disables detection",
			allowedTools: []string{"*"},
			destructive:  []string{},
			toolName:     "email_delete",
			wantAllowed:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := &Policy{
				Agent: AgentConfig{Name: "test-agent", Version: "1.0.0"},
				Capabilities: &CapabilitiesConfig{
					AllowedTools:        tt.allowedTools,
					DestructivePatterns: tt.destructive,
				},
				Policies: PoliciesConfig{
					CostLimits: &CostLimitsConfig{PerRequest: 10, Daily: 100, Monthly: 1000},
				},
			}
			pol.ComputeHash([]byte("test"))
			engine, err := NewEngine(ctx, pol)
			require.NoError(t, err)

			decision, err := engine.EvaluateToolAccess(ctx, tt.toolName, map[string]interface{}{}, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed,
				"tool %q with allowedTools=%v, destructivePatterns=%v", tt.toolName, tt.allowedTools, tt.destructive)
		})
	}
}

// Gap B (CLOSED): Per-agent rate limit isolation in OPA policy.
func TestRateLimiting_GapB_PerAgentIsolation(t *testing.T) {
	ctx := context.Background()
	pol := &Policy{
		Agent: AgentConfig{Name: "agent-a", Version: "1.0.0"},
		Policies: PoliciesConfig{
			CostLimits: &CostLimitsConfig{PerRequest: 10, Daily: 100, Monthly: 1000},
			RateLimits: &RateLimitsConfig{
				RequestsPerMinute:         100,
				PerAgentRequestsPerMinute: 10,
			},
		},
	}
	pol.ComputeHash([]byte("test"))
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	// Agent A at per-agent limit
	input := map[string]interface{}{
		"cost_estimate":              0.01,
		"requests_last_minute":       5,
		"requests_last_minute_agent": 10,
		"agent_id":                   "agent-a",
	}
	decision, err := engine.Evaluate(ctx, input)
	require.NoError(t, err)
	assert.False(t, decision.Allowed, "agent at per-agent limit should be denied")

	// Agent B same tenant, under per-agent limit
	input["requests_last_minute_agent"] = 5
	input["agent_id"] = "agent-b"
	decision, err = engine.Evaluate(ctx, input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed, "agent under per-agent limit should be allowed")
}

// Gap C (CLOSED): Circuit breaker on repeated policy denials.
func TestRateLimiting_GapC_CircuitBreakerOnRepeatedDenials(t *testing.T) {
	// Circuit breaker is implemented in internal/agent/circuit_breaker.go
	// and tested in internal/agent/circuit_breaker_test.go.
	// This test verifies the OPA policy side remains functional.
	ctx := context.Background()
	pol := &Policy{
		Agent: AgentConfig{Name: "rapid-denier", Version: "1.0.0"},
		Policies: PoliciesConfig{
			CostLimits: &CostLimitsConfig{PerRequest: 10, Daily: 100, Monthly: 1000},
			RateLimits: &RateLimitsConfig{
				RequestsPerMinute: 5,
			},
		},
	}
	pol.ComputeHash([]byte("test"))
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	// Simulate 6 rapid requests (exceeding 5/min limit)
	input := map[string]interface{}{
		"cost_estimate":        0.01,
		"requests_last_minute": 6,
	}
	decision, err := engine.Evaluate(ctx, input)
	require.NoError(t, err)
	assert.False(t, decision.Allowed, "6th request should be denied by rate limit")
	assert.Contains(t, decision.Reasons[0], "Rate limit exceeded")
}
