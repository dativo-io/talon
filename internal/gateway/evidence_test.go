package gateway

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordGatewayEvidence(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	err = RecordGatewayEvidence(ctx, store, RecordGatewayEvidenceParams{
		CorrelationID:   "corr-1",
		TenantID:        "default",
		CallerName:      "test-caller",
		Team:            "eng",
		Provider:        "openai",
		Model:           "gpt-4o",
		PolicyAllowed:   true,
		InputTier:       1,
		Cost:            0.01,
		InputTokens:     100,
		OutputTokens:    50,
		DurationMS:      200,
		SecretsAccessed: []string{"openai-api-key"},
	})
	require.NoError(t, err)

	// Evidence is stored; verify via CostByAgent (no time filter = all time)
	byAgent, err := store.CostByAgent(ctx, "default", time.Time{}, time.Time{})
	require.NoError(t, err)
	require.NotEmpty(t, byAgent["test-caller"])
	require.Equal(t, 0.01, byAgent["test-caller"])
}

// TestRecordGatewayEvidence_ToolGovernanceRoundTrip ensures tool governance is persisted
// and returned by Get() (same path as "talon audit show"), so the CLI can display it.
func TestRecordGatewayEvidence_ToolGovernanceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	err = RecordGatewayEvidence(ctx, store, RecordGatewayEvidenceParams{
		CorrelationID:  "corr-tools",
		TenantID:       "default",
		CallerName:     "openclaw-main",
		Provider:       "openai",
		Model:          "gpt-4o-mini",
		PolicyAllowed:  true,
		InputTier:      0,
		Cost:           0.001,
		InputTokens:    34,
		OutputTokens:   5,
		DurationMS:     1056,
		ToolsRequested: []string{"search_web", "delete_all_messages"},
		ToolsFiltered:  []string{"delete_all_messages"},
		ToolsForwarded: []string{"search_web"},
	})
	require.NoError(t, err)

	list, err := store.List(ctx, "", "", time.Time{}, time.Time{}, 1)
	require.NoError(t, err)
	require.Len(t, list, 1)
	id := list[0].ID

	ev, err := store.Get(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, ev.ToolGovernance, "Get() must return tool_governance so audit show can display it")
	assert.Equal(t, []string{"search_web", "delete_all_messages"}, ev.ToolGovernance.ToolsRequested)
	assert.Equal(t, []string{"delete_all_messages"}, ev.ToolGovernance.ToolsFiltered)
	assert.Equal(t, []string{"search_web"}, ev.ToolGovernance.ToolsForwarded)
}

func TestEvidenceSanitization(t *testing.T) {
	ctx := context.Background()
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)

	text := "Customer email: jan.kowalski@gmail.com, IBAN: DE89370400440532013000"
	sanitized := evidence.SanitizeForEvidence(ctx, text, scanner)

	assert.NotContains(t, sanitized, "jan.kowalski@gmail.com", "email should be sanitized")
	assert.NotContains(t, sanitized, "DE89370400440532013000", "IBAN should be sanitized")
	assert.NotEmpty(t, sanitized, "sanitized text should not be empty")
}
