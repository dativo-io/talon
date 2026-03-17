package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyToolIntent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		tool           string
		params         []byte
		cfg            *PlanReviewConfig
		wantClass      string
		wantRisk       string
		wantBulk       bool
		wantReview     bool
		wantReasonText string
	}{
		{
			name:           "read only tool",
			tool:           "file_read",
			params:         []byte(`{"path":"docs/runbook.md"}`),
			wantClass:      "read",
			wantRisk:       "low",
			wantBulk:       false,
			wantReview:     false,
			wantReasonText: "classified as read",
		},
		{
			name:           "write tool",
			tool:           "file_write",
			params:         []byte(`{"path":"notes.md","content":"ok"}`),
			wantClass:      "write",
			wantRisk:       "medium",
			wantBulk:       false,
			wantReview:     false,
			wantReasonText: "classified as write",
		},
		{
			name:           "execute tool always review",
			tool:           "shell_execute",
			params:         []byte(`{"command":"ls -la"}`),
			wantClass:      "execute",
			wantRisk:       "high",
			wantBulk:       false,
			wantReview:     true,
			wantReasonText: "human review required",
		},
		{
			name:           "bulk delete critical",
			tool:           "email_delete",
			params:         []byte(`{"count":10000}`),
			wantClass:      "bulk",
			wantRisk:       "critical",
			wantBulk:       true,
			wantReview:     true,
			wantReasonText: "bulk signals detected",
		},
		{
			name:   "plan config threshold triggers bulk review",
			tool:   "record_update",
			params: []byte(`{"items": 150}`),
			cfg: &PlanReviewConfig{
				VolumeThreshold: 100,
			},
			wantClass:      "bulk",
			wantRisk:       "high",
			wantBulk:       true,
			wantReview:     true,
			wantReasonText: "human review required",
		},
		{
			name:           "invalid json ignored for bulk detection",
			tool:           "sql_query",
			params:         []byte(`{not-json`),
			wantClass:      "read",
			wantRisk:       "low",
			wantBulk:       false,
			wantReview:     false,
			wantReasonText: "classified as read",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyToolIntent(tt.tool, tt.params, tt.cfg)
			require.NotNil(t, got)
			assert.Equal(t, tt.wantClass, got.OperationClass)
			assert.Equal(t, tt.wantRisk, got.RiskLevel)
			assert.Equal(t, tt.wantBulk, got.IsBulk)
			assert.Equal(t, tt.wantReview, got.RequiresReview)
			assert.Contains(t, got.Reason, tt.wantReasonText)
		})
	}
}

func TestIntentClassCatalog(t *testing.T) {
	t.Parallel()

	catalog := IntentClassCatalog()
	require.NotEmpty(t, catalog)

	classes := make(map[string]bool, len(catalog))
	for _, entry := range catalog {
		classes[entry.Class] = true
		assert.NotEmpty(t, entry.DefaultRisk)
		assert.NotEmpty(t, entry.Description)
		assert.NotEmpty(t, entry.Examples)
	}

	assert.True(t, classes["read"])
	assert.True(t, classes["write"])
	assert.True(t, classes["delete"])
	assert.True(t, classes["bulk"])
	assert.True(t, classes["execute"])
	assert.True(t, classes["install"])
	assert.True(t, classes["purge"])
}
