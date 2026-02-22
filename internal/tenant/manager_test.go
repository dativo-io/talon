package tenant

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestManager_ValidateRequest_TenantNotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	m := NewManager([]Tenant{{ID: "acme", RateLimit: 10}}, store)
	err = m.ValidateRequest(context.Background(), "other")
	assert.ErrorIs(t, err, ErrTenantNotFound)
}

func TestManager_ValidateRequest_Allowed(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	m := NewManager([]Tenant{{ID: "acme", DailyBudget: 100, MonthlyBudget: 1000, RateLimit: 100}}, store)
	err = m.ValidateRequest(context.Background(), "acme")
	assert.NoError(t, err)
}

func TestManager_ValidateRequest_NilStore(t *testing.T) {
	m := NewManager([]Tenant{{ID: "acme"}}, nil)
	err := m.ValidateRequest(context.Background(), "acme")
	assert.NoError(t, err)
}

func TestManager_ValidateRequest_BudgetExceeded(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	// Create evidence with cost so that daily budget is exceeded
	ctx := context.Background()
	ev := &evidence.Evidence{
		ID:             "req_1",
		CorrelationID:  "c1",
		Timestamp:      time.Now().UTC(),
		TenantID:       "acme",
		AgentID:        "agent1",
		InvocationType: "test",
		Execution:      evidence.Execution{Cost: 150},
	}
	require.NoError(t, store.Store(ctx, ev))

	m := NewManager([]Tenant{{ID: "acme", DailyBudget: 100, MonthlyBudget: 1000}}, store)
	err = m.ValidateRequest(ctx, "acme")
	assert.ErrorIs(t, err, ErrDailyBudgetExceeded)
}
