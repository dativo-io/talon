package evidence

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSigningKey = "test-signing-key-1234567890123456"

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "evidence.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return store
}

func TestStoreAndGet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	gen := NewGenerator(store)
	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_test123",
		TenantID:       "acme",
		AgentID:        "sales-analyst",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{
			Allowed:       true,
			Action:        "allow",
			PolicyVersion: "1.0.0:sha256:abc12345",
		},
		Classification: Classification{
			InputTier:   0,
			PIIDetected: []string{},
		},
		ModelUsed:      "gpt-4",
		CostEUR:        0.0018,
		Tokens:         TokenUsage{Input: 100, Output: 50},
		DurationMS:     250,
		InputPrompt:    "Hello world",
		OutputResponse: "Hi there",
		Compliance: Compliance{
			Frameworks:   []string{"gdpr", "iso-27001"},
			DataLocation: "eu-west-1",
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, ev.ID)
	assert.NotEmpty(t, ev.Signature)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.Equal(t, ev.ID, retrieved.ID)
	assert.Equal(t, "acme", retrieved.TenantID)
	assert.Equal(t, "sales-analyst", retrieved.AgentID)
	assert.Equal(t, "gpt-4", retrieved.Execution.ModelUsed)
}

func TestVerifySignature(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	gen := NewGenerator(store)
	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_verify",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)

	valid, err := store.Verify(ctx, ev.ID)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestListWithFilters(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	// Create records for two tenants
	for _, tenant := range []string{"acme", "globex"} {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_" + tenant,
			TenantID:       tenant,
			AgentID:        "agent",
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			InputPrompt:    "test",
			OutputResponse: "response",
		})
		require.NoError(t, err)
	}

	// List for acme only
	results, err := store.List(ctx, "acme", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "acme", results[0].TenantID)

	// List all
	all, err := store.List(ctx, "", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestListIndex(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_idx",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:      "gpt-4",
		CostEUR:        0.005,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)

	index, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, index, 1)
	assert.True(t, index[0].Allowed)
	assert.Equal(t, "gpt-4", index[0].ModelUsed)
}

func TestTimeline(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	var middleID string
	for i := 0; i < 5; i++ {
		ev, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_tl",
			TenantID:       "acme",
			AgentID:        "agent",
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			InputPrompt:    "test",
			OutputResponse: "response",
		})
		require.NoError(t, err)
		if i == 2 {
			middleID = ev.ID
		}
		// Small sleep to ensure timestamp ordering
		time.Sleep(5 * time.Millisecond)
	}

	timeline, err := store.Timeline(ctx, middleID, 2, 2)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(timeline), 3) // at least: 2 before + target + some after
}

func TestGetNonexistent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	_, err := store.Get(ctx, "ev_does_not_exist")
	assert.Error(t, err)
}

func TestGenerateWithError(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_err",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:      "gpt-4",
		DurationMS:     100,
		Error:          "connection timeout",
		InputPrompt:    "test",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, ev.ID)
	assert.NotEmpty(t, ev.Execution.Error)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.Equal(t, "connection timeout", retrieved.Execution.Error)
}

func TestGenerateWithAttachmentScan(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_att",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: false, Action: "deny"},
		AttachmentScan: &AttachmentScan{
			FilesProcessed:     2,
			InjectionsDetected: 1,
			ActionTaken:        "blocked",
			BlockedFiles:       []string{"malicious.pdf"},
		},
		InputPrompt: "test",
	})
	require.NoError(t, err)
	assert.NotNil(t, ev.AttachmentScan)
	assert.Equal(t, 1, ev.AttachmentScan.InjectionsDetected)
}

func TestVerifyTamperedData(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_tamper",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "test",
	})
	require.NoError(t, err)

	// Tamper with the stored data
	_, err = store.db.ExecContext(ctx,
		`UPDATE evidence SET evidence_json = REPLACE(evidence_json, '"acme"', '"tampered"') WHERE id = ?`, ev.ID)
	require.NoError(t, err)

	valid, err := store.Verify(ctx, ev.ID)
	require.NoError(t, err)
	assert.False(t, valid, "tampered evidence should fail verification")
}

func TestListIndexWithTimeFilter(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	for i := 0; i < 3; i++ {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_tf",
			TenantID:       "acme",
			AgentID:        "agent",
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			InputPrompt:    "test",
		})
		require.NoError(t, err)
	}

	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)
	index, err := store.ListIndex(ctx, "acme", "agent", from, to, 10)
	require.NoError(t, err)
	assert.Len(t, index, 3)

	futureFrom := time.Now().Add(1 * time.Hour)
	futureTo := time.Now().Add(2 * time.Hour)
	empty, err := store.ListIndex(ctx, "acme", "agent", futureFrom, futureTo, 10)
	require.NoError(t, err)
	assert.Len(t, empty, 0)
}

func TestListWithAgentFilter(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	for _, agent := range []string{"sales", "support", "sales"} {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_af",
			TenantID:       "acme",
			AgentID:        agent,
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			InputPrompt:    "test",
		})
		require.NoError(t, err)
	}

	salesOnly, err := store.List(ctx, "acme", "sales", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, salesOnly, 2)

	supportOnly, err := store.List(ctx, "", "support", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, supportOnly, 1)
}

func TestListWithTimeRange(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_tr",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "test",
	})
	require.NoError(t, err)

	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)
	results, err := store.List(ctx, "", "", from, to, 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	// Future range returns empty
	futureFrom := time.Now().Add(1 * time.Hour)
	futureTo := time.Now().Add(2 * time.Hour)
	empty, err := store.List(ctx, "", "", futureFrom, futureTo, 10)
	require.NoError(t, err)
	assert.Len(t, empty, 0)
}

func TestGenerateWithSecretsAndMemory(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:   "corr_sm",
		TenantID:        "acme",
		AgentID:         "agent",
		InvocationType:  "manual",
		PolicyDecision:  PolicyDecision{Allowed: true, Action: "allow"},
		SecretsAccessed: []string{"openai-api-key", "db-password"},
		MemoryWrites: []MemoryWrite{
			{Category: "factual_corrections", EntryID: "mem_001"},
		},
		InputPrompt:    "test",
		OutputResponse: "response",
		ToolsCalled:    []string{"search", "email"},
	})
	require.NoError(t, err)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"openai-api-key", "db-password"}, retrieved.SecretsAccessed)
	assert.Len(t, retrieved.MemoryWrites, 1)
	assert.Equal(t, []string{"search", "email"}, retrieved.Execution.ToolsCalled)
}

func TestVerifyNonexistentEvidence(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Verify(ctx, "ev_nonexistent")
	assert.Error(t, err)
}

func TestNewStoreInvalidSigningKey(t *testing.T) {
	dir := t.TempDir()
	_, err := NewStore(filepath.Join(dir, "ev.db"), "short-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signer")
}

func TestSignerKeyTooShort(t *testing.T) {
	_, err := NewSigner("short")
	assert.Error(t, err)
}

func TestSignAndVerify(t *testing.T) {
	signer, err := NewSigner(testSigningKey)
	require.NoError(t, err)

	data := []byte(`{"test": "data"}`)

	sig, err := signer.Sign(data)
	require.NoError(t, err)
	assert.True(t, signer.Verify(data, sig))
	assert.False(t, signer.Verify([]byte("tampered"), sig))
}

func TestSignerWithHexKey(t *testing.T) {
	// 64 hex chars → 32 bytes (full HMAC key strength); recommended: openssl rand -hex 32
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	signer, err := NewSigner(hexKey)
	require.NoError(t, err)
	data := []byte("payload")
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	assert.True(t, signer.Verify(data, sig))
}

func TestCostTotal(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	// Agent A: 0.01 + 0.02
	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_c1",
		TenantID:       "acme",
		AgentID:        "agent-a",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		CostEUR:        0.01,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_c2",
		TenantID:       "acme",
		AgentID:        "agent-a",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		CostEUR:        0.02,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)
	// Agent B: 0.03
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_c3",
		TenantID:       "acme",
		AgentID:        "agent-b",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		CostEUR:        0.03,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)

	totalAll, err := store.CostTotal(ctx, "acme", "", dayStart, dayEnd)
	require.NoError(t, err)
	assert.InDelta(t, 0.06, totalAll, 0.0001)

	totalA, err := store.CostTotal(ctx, "acme", "agent-a", dayStart, dayEnd)
	require.NoError(t, err)
	assert.InDelta(t, 0.03, totalA, 0.0001)

	totalB, err := store.CostTotal(ctx, "acme", "agent-b", dayStart, dayEnd)
	require.NoError(t, err)
	assert.InDelta(t, 0.03, totalB, 0.0001)
}

func TestCostByAgent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	for _, p := range []struct {
		agent string
		cost  float64
	}{
		{"sales-analyst", 1.5},
		{"support-bot", 0.5},
		{"sales-analyst", 2.0},
	} {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_cba",
			TenantID:       "tenant1",
			AgentID:        p.agent,
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			CostEUR:        p.cost,
			InputPrompt:    "test",
			OutputResponse: "response",
		})
		require.NoError(t, err)
	}

	byAgent, err := store.CostByAgent(ctx, "tenant1", dayStart, dayEnd)
	require.NoError(t, err)
	assert.Len(t, byAgent, 2)
	assert.InDelta(t, 3.5, byAgent["sales-analyst"], 0.0001)
	assert.InDelta(t, 0.5, byAgent["support-bot"], 0.0001)
}

func TestGenerateWithDegradation(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_deg",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:      "gpt-4o-mini",
		OriginalModel:  "gpt-4o",
		Degraded:       true,
		CostEUR:        0.001,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.True(t, retrieved.Execution.Degraded)
	assert.Equal(t, "gpt-4o", retrieved.Execution.OriginalModel)
	assert.Equal(t, "gpt-4o-mini", retrieved.Execution.ModelUsed)
}
