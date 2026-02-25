package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPolicy() *Policy {
	pol := &Policy{
		Agent: AgentConfig{
			Name:    "test-agent",
			Version: "1.0.0",
		},
		Capabilities: &CapabilitiesConfig{
			AllowedTools:      []string{"sql_query", "file_read"},
			ForbiddenPatterns: []string{".env", "secrets"},
		},
		Secrets: &SecretsConfig{
			Allowed: []SecretACL{
				{Name: "salesforce-api-key", Purpose: "CRM access"},
				{Name: "analytics-db-readonly"},
			},
			Forbidden: []SecretACL{
				{Name: "admin-*"},
			},
		},
		Memory: &MemoryConfig{
			Enabled:             true,
			MaxEntries:          100,
			MaxEntrySizeKB:      10,
			AllowedCategories:   []string{"factual_corrections", "domain_knowledge"},
			ForbiddenCategories: []string{"policy_modifications"},
		},
		Policies: PoliciesConfig{
			CostLimits: &CostLimitsConfig{
				PerRequest: 1.0,
				Daily:      10.0,
				Monthly:    100.0,
			},
			RateLimits: &RateLimitsConfig{
				RequestsPerMinute:    60,
				ConcurrentExecutions: 2,
			},
			TimeRestrictions: &TimeRestrictionsConfig{
				Enabled:  false,
				Weekends: true,
			},
		},
	}
	pol.ComputeHash([]byte("test"))
	return pol
}

func TestNewEngine(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Len(t, engine.prepared, len(allPolicies))
}

func TestEngineCostLimits(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       map[string]interface{}
		wantAllowed bool
		wantReasons int
	}{
		{
			name: "within all limits",
			input: map[string]interface{}{
				"estimated_cost":     0.5,
				"daily_cost_total":   5.0,
				"monthly_cost_total": 50.0,
			},
			wantAllowed: true,
			wantReasons: 0,
		},
		{
			name: "exceeds per-request limit",
			input: map[string]interface{}{
				"estimated_cost":     2.0,
				"daily_cost_total":   0.0,
				"monthly_cost_total": 0.0,
			},
			wantAllowed: false,
			wantReasons: 1,
		},
		{
			name: "exceeds daily limit",
			input: map[string]interface{}{
				"estimated_cost":     0.5,
				"daily_cost_total":   9.8,
				"monthly_cost_total": 50.0,
			},
			wantAllowed: false,
			wantReasons: 1,
		},
		{
			name: "exceeds monthly limit",
			input: map[string]interface{}{
				"estimated_cost":     0.5,
				"daily_cost_total":   5.0,
				"monthly_cost_total": 99.8,
			},
			wantAllowed: false,
			wantReasons: 1,
		},
		{
			name: "exceeds all limits",
			input: map[string]interface{}{
				"estimated_cost":     2.0,
				"daily_cost_total":   9.0,
				"monthly_cost_total": 99.0,
			},
			wantAllowed: false,
			wantReasons: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Evaluate(ctx, tt.input)
			require.NoError(t, err)

			assert.Equal(t, tt.wantAllowed, decision.Allowed)
			assert.Len(t, decision.Reasons, tt.wantReasons)
			if tt.wantAllowed {
				assert.Equal(t, "allow", decision.Action)
			} else {
				assert.Equal(t, "deny", decision.Action)
			}
		})
	}
}

func TestEngineToolAccess(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	tests := []struct {
		name        string
		toolName    string
		params      map[string]interface{}
		wantAllowed bool
	}{
		{
			name:        "allowed tool",
			toolName:    "sql_query",
			params:      map[string]interface{}{},
			wantAllowed: true,
		},
		{
			name:        "disallowed tool",
			toolName:    "shell_exec",
			params:      map[string]interface{}{},
			wantAllowed: false,
		},
		{
			name:     "file_read with forbidden pattern",
			toolName: "file_read",
			params: map[string]interface{}{
				"path": "/config/.env",
			},
			wantAllowed: false,
		},
		{
			name:     "file_read with safe path",
			toolName: "file_read",
			params: map[string]interface{}{
				"path": "/data/sales_report.csv",
			},
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.EvaluateToolAccess(ctx, tt.toolName, tt.params, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
		})
	}
}

func TestEngineToolAccessWithHistory(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	// Pass non-nil tool_history; no Rego rules use it yet, but input must be accepted and rules still apply.
	toolHistory := []map[string]interface{}{
		{"name": "sql_query", "params": map[string]interface{}{"q": "SELECT 1"}, "result_summary": "ok"},
	}
	decision, err := engine.EvaluateToolAccess(ctx, "sql_query", map[string]interface{}{}, toolHistory)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	// Disallowed tool with history still denied
	decision, err = engine.EvaluateToolAccess(ctx, "shell_exec", map[string]interface{}{}, toolHistory)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestEngineLoopContainment(t *testing.T) {
	ctx := context.Background()

	policyWithLimits := newTestPolicy()
	policyWithLimits.Policies.ResourceLimits = &ResourceLimitsConfig{
		MaxIterations:      5,
		MaxToolCallsPerRun: 10,
		MaxCostPerRun:      1.0,
	}
	policyWithLimits.ComputeHash([]byte("test"))

	engineWithLimits, err := NewEngine(ctx, policyWithLimits)
	require.NoError(t, err)

	tests := []struct {
		name        string
		engine      *Engine
		iteration   int
		toolCalls   int
		cost        float64
		wantAllowed bool
	}{
		{
			name:        "max_iterations exceeded",
			engine:      engineWithLimits,
			iteration:   6,
			toolCalls:   0,
			cost:        0,
			wantAllowed: false,
		},
		{
			name:        "max_iterations within",
			engine:      engineWithLimits,
			iteration:   3,
			toolCalls:   0,
			cost:        0,
			wantAllowed: true,
		},
		{
			name:        "max_tool_calls_per_run exceeded",
			engine:      engineWithLimits,
			iteration:   1,
			toolCalls:   15,
			cost:        0,
			wantAllowed: false,
		},
		{
			name:        "max_cost_per_run exceeded",
			engine:      engineWithLimits,
			iteration:   1,
			toolCalls:   0,
			cost:        1.5,
			wantAllowed: false,
		},
		{
			name:        "all within bounds",
			engine:      engineWithLimits,
			iteration:   2,
			toolCalls:   3,
			cost:        0.5,
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := tt.engine.EvaluateLoopContainment(ctx, tt.iteration, tt.toolCalls, tt.cost)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
		})
	}

	// No resource_limits set: should allow (no deny)
	policyNoLimits := newTestPolicy()
	policyNoLimits.Policies.ResourceLimits = nil
	policyNoLimits.ComputeHash([]byte("test"))
	engineNoLimits, err := NewEngine(ctx, policyNoLimits)
	require.NoError(t, err)
	decision, err := engineNoLimits.EvaluateLoopContainment(ctx, 100, 100, 1000.0)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngineSecretAccess(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	tests := []struct {
		name        string
		secretName  string
		wantAllowed bool
	}{
		{
			name:        "allowed secret",
			secretName:  "salesforce-api-key",
			wantAllowed: true,
		},
		{
			name:        "another allowed secret",
			secretName:  "analytics-db-readonly",
			wantAllowed: true,
		},
		{
			name:        "forbidden admin secret via glob",
			secretName:  "admin-master-key",
			wantAllowed: false,
		},
		{
			name:        "unknown secret not in allowed list",
			secretName:  "unknown-secret",
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.EvaluateSecretAccess(ctx, tt.secretName)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
		})
	}
}

func TestEngineMemoryGovernance(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	tests := []struct {
		name             string
		category         string
		contentSizeBytes int
		wantAllowed      bool
	}{
		{
			name:             "allowed category within size",
			category:         "factual_corrections",
			contentSizeBytes: 500,
			wantAllowed:      true,
		},
		{
			name:             "allowed domain_knowledge",
			category:         "domain_knowledge",
			contentSizeBytes: 1000,
			wantAllowed:      true,
		},
		{
			name:             "legacy: tool_approval allowed when domain_knowledge in allowed_categories",
			category:         "tool_approval",
			contentSizeBytes: 500,
			wantAllowed:      true,
		},
		{
			name:             "legacy: cost_decision allowed when domain_knowledge in allowed_categories",
			category:         "cost_decision",
			contentSizeBytes: 500,
			wantAllowed:      true,
		},
		{
			name:             "legacy: user_preferences allowed when domain_knowledge in allowed_categories",
			category:         "user_preferences",
			contentSizeBytes: 500,
			wantAllowed:      true,
		},
		{
			name:             "legacy: procedure_improvements allowed when domain_knowledge in allowed_categories",
			category:         "procedure_improvements",
			contentSizeBytes: 500,
			wantAllowed:      true,
		},
		{
			name:             "forbidden category policy_modifications",
			category:         "policy_modifications",
			contentSizeBytes: 100,
			wantAllowed:      false,
		},
		{
			name:             "hardcoded forbidden prompt_injection",
			category:         "prompt_injection",
			contentSizeBytes: 100,
			wantAllowed:      false,
		},
		{
			name:             "hardcoded forbidden credential_data",
			category:         "credential_data",
			contentSizeBytes: 100,
			wantAllowed:      false,
		},
		{
			name:             "unknown category not in allowed list",
			category:         "random_stuff",
			contentSizeBytes: 100,
			wantAllowed:      false,
		},
		{
			name:             "exceeds max entry size",
			category:         "factual_corrections",
			contentSizeBytes: 11 * 1024, // 11KB > 10KB limit
			wantAllowed:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.EvaluateMemoryWrite(ctx, tt.category, tt.contentSizeBytes)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed, "reasons: %v", decision.Reasons)
		})
	}
}

// TestEngineMemoryGovernance_LegacyOnlyDomainKnowledgeAndPolicyHit ensures that
// policies with only allowed_categories: [domain_knowledge, policy_hit] (no other
// categories) still allow inferred subtypes (tool_approval, cost_decision,
// user_preferences, procedure_improvements, factual_corrections). Without this,
// inferCategoryTypeAndMemType would cause silent memory loss for tool/high-cost/
// keyword-matched runs (regression).
func TestEngineMemoryGovernance_LegacyOnlyDomainKnowledgeAndPolicyHit(t *testing.T) {
	ctx := context.Background()
	legacyPol := &Policy{
		Agent:    AgentConfig{Name: "test", Version: "1.0"},
		Memory:   &MemoryConfig{Enabled: true, MaxEntrySizeKB: 10, AllowedCategories: []string{"domain_knowledge", "policy_hit"}},
		Policies: PoliciesConfig{},
	}
	legacyPol.ComputeHash([]byte("test"))

	engine, err := NewEngine(ctx, legacyPol)
	require.NoError(t, err)

	subtypes := []string{"tool_approval", "cost_decision", "user_preferences", "procedure_improvements", "factual_corrections"}
	for _, cat := range subtypes {
		t.Run(cat, func(t *testing.T) {
			decision, err := engine.EvaluateMemoryWrite(ctx, cat, 500)
			require.NoError(t, err)
			assert.True(t, decision.Allowed, "legacy allowed_categories [domain_knowledge, policy_hit] must allow %q; reasons: %v", cat, decision.Reasons)
		})
	}
}

func TestDataClassificationDefaultsToTier1WhenNoPIIData(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	// No pii_entities in input at all — should default to tier 1, not 0
	tier, err := engine.EvaluateDataClassification(ctx, map[string]interface{}{})
	require.NoError(t, err)
	assert.Equal(t, 1, tier, "missing PII data should default to tier 1 (confidential), not 0 (public)")
}

func TestDataClassificationTier0RequiresExplicitEmptyPII(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	// Explicit empty pii_entities — this is tier 0
	tier, err := engine.EvaluateDataClassification(ctx, map[string]interface{}{
		"pii_entities": []interface{}{},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, tier, "explicitly empty PII should be tier 0")
}

func TestDataClassificationTier2WithSensitivePII(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	tier, err := engine.EvaluateDataClassification(ctx, map[string]interface{}{
		"pii_entities": []interface{}{
			map[string]interface{}{"type": "iban", "value": "DE89370400440532013000"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, tier, "IBAN should trigger tier 2")
}

func TestEngineDecisionHasPolicyVersion(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	decision, err := engine.Evaluate(ctx, map[string]interface{}{
		"estimated_cost":     0.1,
		"daily_cost_total":   0.0,
		"monthly_cost_total": 0.0,
	})
	require.NoError(t, err)
	assert.Contains(t, decision.PolicyVersion, "1.0.0:sha256:")
}

func TestBedrockModelPrefixes(t *testing.T) {
	prefixes := BedrockModelPrefixes()
	require.NotEmpty(t, prefixes)
	assert.Contains(t, prefixes, "anthropic.")
	assert.Contains(t, prefixes, "meta.")
	assert.Contains(t, prefixes, "amazon.")
	assert.Contains(t, prefixes, "cohere.")
	assert.Len(t, prefixes, 7) // known set of Bedrock vendor prefixes
}

func TestEngineEvaluate_RateLimitDeny(t *testing.T) {
	ctx := context.Background()
	pol := newTestPolicy()

	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	// requests_per_minute is 60; sending 60 in input should deny (>= limit)
	decision, err := engine.Evaluate(ctx, map[string]interface{}{
		"tenant_id":             "acme",
		"agent_id":              "test",
		"tier":                  0,
		"estimated_cost":        0.1,
		"daily_cost_total":      0.0,
		"monthly_cost_total":    0.0,
		"requests_last_minute":  60,
		"concurrent_executions": 1,
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.NotEmpty(t, decision.Reasons)
}

// ---------------------------------------------------------------------------
// OpenClaw incident — unit tests (default-deny, context independence, rate limits)
// ---------------------------------------------------------------------------

func newReadonlyInboxPolicy() *Policy {
	pol := &Policy{
		Agent: AgentConfig{
			Name:    "inbox-assistant",
			Version: "1.0.0",
		},
		Capabilities: &CapabilitiesConfig{
			AllowedTools: []string{
				"email_read",
				"email_list",
				"email_search",
				"email_archive",
			},
			ForbiddenPatterns: []string{
				"email_delete",
				"email_bulk_*",
				"email_send",
				"email_forward",
			},
		},
		Policies: PoliciesConfig{
			CostLimits: &CostLimitsConfig{
				PerRequest: 0.10,
				Daily:      5.0,
				Monthly:    50.0,
			},
			RateLimits: &RateLimitsConfig{
				RequestsPerMinute:    20,
				ConcurrentExecutions: 1,
			},
		},
	}
	pol.ComputeHash([]byte("test"))
	return pol
}

func TestEngine_ToolAccess_DestructiveOperationsDeniedByDefault(t *testing.T) {
	ctx := context.Background()
	pol := newReadonlyInboxPolicy()
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	destructiveTools := []string{
		"email_delete",
		"email_bulk_delete",
		"file_delete",
		"user_delete",
		"export_all_data",
		"admin_reset",
		"bulk_archive",
	}

	for _, tool := range destructiveTools {
		t.Run(tool, func(t *testing.T) {
			decision, err := engine.EvaluateToolAccess(ctx, tool, map[string]interface{}{}, nil)
			require.NoError(t, err)
			assert.False(t, decision.Allowed,
				"destructive tool %q should be DENIED by default when not in allowed_tools", tool)
		})
	}
}

func TestEngine_ToolAccess_AllowedOperationsPass(t *testing.T) {
	ctx := context.Background()
	pol := newReadonlyInboxPolicy()
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	allowedTools := []string{
		"email_read",
		"email_list",
		"email_search",
		"email_archive",
	}

	for _, tool := range allowedTools {
		t.Run(tool, func(t *testing.T) {
			decision, err := engine.EvaluateToolAccess(ctx, tool, map[string]interface{}{}, nil)
			require.NoError(t, err)
			assert.True(t, decision.Allowed,
				"read-only tool %q should be ALLOWED", tool)
		})
	}
}

func TestEngine_ContextCompactionCannotBypass(t *testing.T) {
	ctx := context.Background()
	pol := newReadonlyInboxPolicy()
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	decision, err := engine.EvaluateToolAccess(ctx, "email_delete", map[string]interface{}{}, nil)
	require.NoError(t, err)
	assert.False(t, decision.Allowed,
		"email_delete must be denied regardless of what the LLM's context window contains")
}

func TestEngine_CostPolicyContextIndependent(t *testing.T) {
	ctx := context.Background()
	pol := newReadonlyInboxPolicy()
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	decision, err := engine.Evaluate(ctx, map[string]interface{}{
		"estimated_cost":     0.05,
		"daily_cost_total":   0.0,
		"monthly_cost_total": 0.0,
	})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEngine_RateLimitSpeedRunPrevention(t *testing.T) {
	ctx := context.Background()
	pol := newReadonlyInboxPolicy()
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	tests := []struct {
		name               string
		requestsLastMinute int
		wantAllowed        bool
	}{
		{"0 requests - allowed", 0, true},
		{"19 requests - just under limit", 19, true},
		{"20 requests - at limit - denied", 20, false},
		{"50 requests - well over", 50, false},
		{"100 requests - speed run", 100, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Evaluate(ctx, map[string]interface{}{
				"estimated_cost":        0.01,
				"daily_cost_total":      0.0,
				"monthly_cost_total":    0.0,
				"requests_last_minute":  tt.requestsLastMinute,
				"concurrent_executions": 0,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed,
				"at %d requests/min (limit 20), allowed should be %v",
				tt.requestsLastMinute, tt.wantAllowed)
		})
	}
}

func TestEngine_RateLimitConcurrentExecutionsDenied(t *testing.T) {
	ctx := context.Background()
	pol := newReadonlyInboxPolicy()
	engine, err := NewEngine(ctx, pol)
	require.NoError(t, err)

	decision, err := engine.Evaluate(ctx, map[string]interface{}{
		"estimated_cost":        0.01,
		"daily_cost_total":      0.0,
		"monthly_cost_total":    0.0,
		"requests_last_minute":  0,
		"concurrent_executions": 2,
	})
	require.NoError(t, err)
	assert.False(t, decision.Allowed,
		"concurrent_executions 2 > limit 1 should be denied")
}
