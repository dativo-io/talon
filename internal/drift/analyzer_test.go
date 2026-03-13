package drift

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestAnalyzer_ComputeSignals(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "e.db")
	store, err := evidence.NewStore(dbPath, testutil.TestSigningKey)
	require.NoError(t, err)
	defer store.Close()
	raw, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer raw.Close()
	gen := evidence.NewGenerator(store)
	ctx := context.Background()
	now := time.Now().UTC()

	// Baseline: 7 days of low-cost traffic.
	for i := 1; i <= 7; i++ {
		ev, err := gen.Generate(ctx, evidence.GenerateParams{
			CorrelationID:  fmt.Sprintf("corr_base_%d", i),
			TenantID:       "acme",
			AgentID:        "agent-a",
			InvocationType: "manual",
			PolicyDecision: evidence.PolicyDecision{Allowed: true},
			Classification: evidence.Classification{},
			InputPrompt:    "x",
			OutputResponse: "y",
			Cost:           0.01,
		})
		require.NoError(t, err)
		_, err = raw.ExecContext(ctx, `UPDATE evidence SET timestamp = ? WHERE id = ?`, now.Add(time.Duration(-i*24)*time.Hour), ev.ID)
		require.NoError(t, err)
	}
	// Current day spike.
	_, err = gen.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  "corr_now",
		TenantID:       "acme",
		AgentID:        "agent-a",
		InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{Allowed: false},
		Classification: evidence.Classification{PIIDetected: []string{"email"}},
		InputPrompt:    "x",
		OutputResponse: "y",
		Cost:           1.00,
	})
	require.NoError(t, err)

	a := NewAnalyzer(store)
	rows, err := a.ComputeSignals(ctx, "acme", now)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
}
