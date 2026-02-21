package cmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
)

func TestReportCmd_Flags(t *testing.T) {
	flag := reportCmd.Flags().Lookup("tenant")
	require.NotNil(t, flag)
	assert.Equal(t, "default", flag.DefValue)
}

func TestReportCmd_RunSuccess(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	var buf bytes.Buffer
	reportCmd.SetOut(&buf)
	reportCmd.SetErr(&buf)
	reportCmd.SetArgs(nil)
	rootCmd.SetArgs([]string{"report"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Compliance summary")
	assert.Contains(t, out, "Evidence records today")
	assert.Contains(t, out, "Evidence records (7d)")
	assert.Contains(t, out, "Cost today (EUR)")
	assert.Contains(t, out, "Cost this month (EUR)")
}

// TestReportCmd_EnrichedOutput runs report with pre-populated evidence to cover
// PII summary, error rate, policy denials, and model breakdown.
func TestReportCmd_EnrichedOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	cfg, err := config.Load()
	require.NoError(t, err)
	require.NoError(t, cfg.EnsureDataDir())

	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	gen := evidence.NewGenerator(store)
	ctx := context.Background()

	// Record 1: allowed, PII (email), no error, gpt-4o
	_, err = gen.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  "corr_1",
		TenantID:       "default",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Classification: evidence.Classification{InputTier: 1, PIIDetected: []string{"email"}},
		ModelUsed:      "gpt-4o",
		Cost:           0.001,
		Tokens:         evidence.TokenUsage{Input: 10, Output: 20},
		DurationMS:     100,
		InputPrompt:    "test",
		OutputResponse: "ok",
		Compliance:     evidence.Compliance{},
	})
	require.NoError(t, err)

	// Record 2: denied
	_, err = gen.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  "corr_2",
		TenantID:       "default",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"budget_exceeded"}},
		Classification: evidence.Classification{},
		ModelUsed:      "",
		Cost:           0,
		Tokens:         evidence.TokenUsage{},
		DurationMS:     0,
		InputPrompt:    "test",
		OutputResponse: "",
		Compliance:     evidence.Compliance{},
	})
	require.NoError(t, err)

	// Record 3: error, different model
	_, err = gen.Generate(ctx, evidence.GenerateParams{
		CorrelationID:  "corr_3",
		TenantID:       "default",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Classification: evidence.Classification{},
		ModelUsed:      "gpt-4o-mini",
		Cost:           0.0005,
		Tokens:         evidence.TokenUsage{Input: 5, Output: 10},
		DurationMS:     50,
		Error:          "context deadline exceeded",
		InputPrompt:    "test",
		OutputResponse: "",
		Compliance:     evidence.Compliance{},
	})
	require.NoError(t, err)

	require.NoError(t, store.Close())

	var buf bytes.Buffer
	reportCmd.SetOut(&buf)
	reportCmd.SetErr(&buf)
	reportTenant = "default"
	reportCmd.SetArgs(nil)
	rootCmd.SetArgs([]string{"report", "--tenant", "default"})

	err = rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, "Compliance summary")
	require.Contains(t, out, "Evidence records (7d)")
	// Enriched stats
	require.Contains(t, out, "Policy denials (7d)")
	require.Contains(t, out, "Error rate (7d)")
	require.Contains(t, out, "Records with PII (7d)")
	require.Contains(t, out, "email")
	require.Contains(t, out, "Model breakdown (7d)")
	require.Contains(t, out, "gpt-4o")
	require.Contains(t, out, "gpt-4o-mini")
}
