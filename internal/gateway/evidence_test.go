package gateway

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
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
