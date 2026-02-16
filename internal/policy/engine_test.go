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
			decision, err := engine.EvaluateToolAccess(ctx, tt.toolName, tt.params)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, decision.Allowed)
		})
	}
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
