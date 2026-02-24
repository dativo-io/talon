package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestScanner(t *testing.T) *classifier.Scanner {
	t.Helper()
	s, err := classifier.NewScanner()
	require.NoError(t, err)
	return s
}

func TestApplyToolArgumentPII_AuditMode(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"zendesk_ticket_update": {
				Arguments: map[string]policy.PIIAction{
					"ticket_id": policy.PIIActionAllow,
					"comment":   policy.PIIActionAudit,
				},
			},
		},
	}

	args, _ := json.Marshal(map[string]interface{}{
		"ticket_id": 12345,
		"comment":   "Customer jan.kowalski@gmail.com confirmed the refund to IBAN DE89370400440532013000",
	})

	result := applyToolArgumentPII(ctx, scanner, "zendesk_ticket_update", args, pol)
	require.NotNil(t, result)
	assert.False(t, result.Blocked, "audit mode should not block")
	assert.Nil(t, result.ModifiedArgs, "audit mode should not modify args")
	assert.NotEmpty(t, result.Findings, "should record PII findings")

	foundEmail := false
	for _, f := range result.Findings {
		if f.Field == "comment" && f.Action == "audit" {
			foundEmail = true
			assert.Greater(t, f.PIICount, 0)
		}
	}
	assert.True(t, foundEmail, "should find PII in comment field")
}

func TestApplyToolArgumentPII_RedactMode(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"zendesk_ticket_search": {
				Arguments: map[string]policy.PIIAction{
					"query": policy.PIIActionRedact,
				},
			},
		},
	}

	args, _ := json.Marshal(map[string]interface{}{
		"query": "jan.kowalski@gmail.com",
	})

	result := applyToolArgumentPII(ctx, scanner, "zendesk_ticket_search", args, pol)
	require.NotNil(t, result)
	assert.False(t, result.Blocked)
	assert.NotNil(t, result.ModifiedArgs, "redact mode should modify args")

	var modified map[string]string
	require.NoError(t, json.Unmarshal(result.ModifiedArgs, &modified))
	assert.NotContains(t, modified["query"], "jan.kowalski@gmail.com", "email should be redacted")
	assert.NotEmpty(t, result.Findings)
}

func TestApplyToolArgumentPII_BlockMode(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"sensitive_tool": {
				ArgumentDefault: policy.PIIActionBlock,
			},
		},
	}

	args, _ := json.Marshal(map[string]interface{}{
		"data": "email is user@company.eu",
	})

	result := applyToolArgumentPII(ctx, scanner, "sensitive_tool", args, pol)
	require.NotNil(t, result)
	assert.True(t, result.Blocked, "block mode should block when PII found")
	assert.NotEmpty(t, result.BlockReason)
	assert.NotEmpty(t, result.Findings)
}

func TestApplyToolArgumentPII_AllowMode(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"unrestricted_tool": {
				Arguments: map[string]policy.PIIAction{
					"data": policy.PIIActionAllow,
				},
			},
		},
	}

	args, _ := json.Marshal(map[string]interface{}{
		"data": "jan.kowalski@gmail.com",
	})

	result := applyToolArgumentPII(ctx, scanner, "unrestricted_tool", args, pol)
	require.NotNil(t, result)
	assert.False(t, result.Blocked)
	assert.Nil(t, result.ModifiedArgs, "allow mode should not modify")
	assert.Empty(t, result.Findings, "allow mode skips scanning")
}

func TestApplyToolArgumentPII_DefaultFallback(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"_default": {
				ArgumentDefault: policy.PIIActionRedact,
				Result:          policy.PIIActionRedact,
			},
		},
	}

	args, _ := json.Marshal(map[string]interface{}{
		"query": "jan.kowalski@gmail.com",
	})

	result := applyToolArgumentPII(ctx, scanner, "unknown_tool", args, pol)
	require.NotNil(t, result)
	assert.NotNil(t, result.ModifiedArgs, "_default policy should apply redaction")
	assert.NotEmpty(t, result.Findings)
}

func TestApplyToolArgumentPII_NoToolPolicies(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{}

	args, _ := json.Marshal(map[string]interface{}{
		"data": "jan.kowalski@gmail.com",
	})

	result := applyToolArgumentPII(ctx, scanner, "any_tool", args, pol)
	require.NotNil(t, result)
	assert.Empty(t, result.Findings, "no tool_policies = no scanning")
	assert.Nil(t, result.ModifiedArgs)
}

func TestApplyToolArgumentPII_NonJSONArgs_RedactProducesValidJSON(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"_default": {
				ArgumentDefault: policy.PIIActionRedact,
			},
		},
	}

	// Pass a plain string that isn't a JSON object — triggers the Unmarshal-error fallback.
	rawArgs := json.RawMessage(`"Contact jan.kowalski@gmail.com about IBAN DE89370400440532013000"`)

	result := applyToolArgumentPII(ctx, scanner, "some_tool", rawArgs, pol)
	require.NotNil(t, result)
	assert.False(t, result.Blocked)
	assert.NotNil(t, result.ModifiedArgs, "non-JSON-object args with PII should be redacted")

	// ModifiedArgs must be valid JSON — this was the bug (plain string cast to RawMessage).
	assert.True(t, json.Valid(result.ModifiedArgs),
		"ModifiedArgs must be valid JSON, got: %s", string(result.ModifiedArgs))

	var redactedStr string
	require.NoError(t, json.Unmarshal(result.ModifiedArgs, &redactedStr),
		"ModifiedArgs should unmarshal to a JSON string")
	assert.NotContains(t, redactedStr, "jan.kowalski@gmail.com")
	assert.NotContains(t, redactedStr, "DE89370400440532013000")
}

func TestApplyToolArgumentPII_NonJSONArgs_BlockMode(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"_default": {
				ArgumentDefault: policy.PIIActionBlock,
			},
		},
	}

	rawArgs := json.RawMessage(`"Contact jan.kowalski@gmail.com"`)

	result := applyToolArgumentPII(ctx, scanner, "blocked_tool", rawArgs, pol)
	require.NotNil(t, result)
	assert.True(t, result.Blocked, "block mode should block non-JSON-object args with PII")
	assert.NotEmpty(t, result.BlockReason)
}

func TestApplyToolResultPII_RedactMode(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"zendesk_ticket_search": {
				Result: policy.PIIActionRedact,
			},
		},
	}

	resultContent := `{"tickets":[{"customer":"jan.kowalski@gmail.com","subject":"Refund"}]}`
	redacted, findings := applyToolResultPII(ctx, scanner, "zendesk_ticket_search", resultContent, pol)
	assert.NotContains(t, redacted, "jan.kowalski@gmail.com", "email in result should be redacted")
	assert.NotEmpty(t, findings)
}

func TestApplyToolResultPII_AuditMode(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"crm_tool": {
				Result: policy.PIIActionAudit,
			},
		},
	}

	resultContent := `{"email":"jan.kowalski@gmail.com"}`
	returned, findings := applyToolResultPII(ctx, scanner, "crm_tool", resultContent, pol)
	assert.Equal(t, resultContent, returned, "audit mode should not modify result")
	assert.NotEmpty(t, findings, "should record findings even in audit mode")
}

func TestApplyToolResultPII_AllowMode(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"internal_tool": {
				Result: policy.PIIActionAllow,
			},
		},
	}

	resultContent := `{"email":"jan.kowalski@gmail.com"}`
	returned, findings := applyToolResultPII(ctx, scanner, "internal_tool", resultContent, pol)
	assert.Equal(t, resultContent, returned)
	assert.Empty(t, findings, "allow mode skips scanning")
}

func TestResolveToolPolicy(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		pol      *policy.Policy
		wantNil  bool
	}{
		{
			name:     "exact match",
			toolName: "email_read",
			pol: &policy.Policy{
				ToolPolicies: map[string]policy.ToolPIIPolicy{
					"email_read": {Result: policy.PIIActionAudit},
				},
			},
			wantNil: false,
		},
		{
			name:     "falls back to _default",
			toolName: "unknown_tool",
			pol: &policy.Policy{
				ToolPolicies: map[string]policy.ToolPIIPolicy{
					"_default": {Result: policy.PIIActionRedact},
				},
			},
			wantNil: false,
		},
		{
			name:     "no tool_policies",
			toolName: "any",
			pol:      &policy.Policy{},
			wantNil:  true,
		},
		{
			name:     "nil policy",
			toolName: "any",
			pol:      nil,
			wantNil:  true,
		},
		{
			name:     "no match and no default",
			toolName: "unknown",
			pol: &policy.Policy{
				ToolPolicies: map[string]policy.ToolPIIPolicy{
					"specific_tool": {Result: policy.PIIActionRedact},
				},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := resolveToolPolicy(tt.toolName, tt.pol)
			if tt.wantNil {
				assert.Nil(t, tp)
			} else {
				assert.NotNil(t, tp)
			}
		})
	}
}

func TestEvidenceAlwaysRecordsPIIFindings(t *testing.T) {
	scanner := newTestScanner(t)
	ctx := context.Background()

	pol := &policy.Policy{
		ToolPolicies: map[string]policy.ToolPIIPolicy{
			"audit_tool": {
				Arguments: map[string]policy.PIIAction{
					"comment": policy.PIIActionAudit,
				},
				Result: policy.PIIActionRedact,
			},
		},
	}

	args, _ := json.Marshal(map[string]interface{}{
		"comment": "Contact: jan.kowalski@gmail.com",
	})

	argResult := applyToolArgumentPII(ctx, scanner, "audit_tool", args, pol)
	require.NotEmpty(t, argResult.Findings)

	for _, f := range argResult.Findings {
		assert.NotEmpty(t, f.PIITypes)
		assert.Greater(t, f.PIICount, 0)
		assert.Equal(t, "argument", f.Direction)
	}

	resultContent := `{"data":"DE89370400440532013000"}`
	_, resultFindings := applyToolResultPII(ctx, scanner, "audit_tool", resultContent, pol)
	for _, f := range resultFindings {
		assert.NotEmpty(t, f.PIITypes)
		assert.Equal(t, "result", f.Direction)
	}
}
