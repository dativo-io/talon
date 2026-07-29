package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// Cost-control contract (#144): once-per-crossing threshold evidence, deny
// context, and the org webhook delivered only after the evidence commit.

func newBudgetEventsGateway(t *testing.T, store *evidence.Store, webhookURL string) *Gateway {
	t.Helper()
	return &Gateway{
		config: &GatewayConfig{
			OrganizationPolicy: OrganizationPolicy{CostWebhookURL: webhookURL},
		},
		evidenceStore:   store,
		pricingCurrency: "EUR",
	}
}

func newBudgetEventsStore(t *testing.T) *evidence.Store {
	t.Helper()
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "e.db"), "test-signing-key-1234567890123456")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func budgetTestAgent() *ResolvedIdentity {
	return &ResolvedIdentity{Name: "support-bot", TenantID: "default", Enabled: true}
}

func thresholdRecords(t *testing.T, store *evidence.Store, correlationID string) []*evidence.Evidence {
	t.Helper()
	records, err := store.ListByCorrelationID(context.Background(), correlationID)
	require.NoError(t, err)
	out := make([]*evidence.Evidence, 0, len(records))
	for _, ev := range records {
		if ev.InvocationType == evidence.InvocationTypeBudgetThreshold {
			out = append(out, ev)
		}
	}
	return out
}

// Crossing a warning threshold yields exactly ONE signed record; later
// requests above the same threshold yield none; the next threshold yields its
// own single record (#144 done-when 1).
func TestNoteBudgetThresholds_OncePerCrossing(t *testing.T) {
	store := newBudgetEventsStore(t)
	g := newBudgetEventsGateway(t, store, "")
	agent := budgetTestAgent()
	ctx := context.Background()

	g.noteBudgetThresholds(ctx, agent, "anthropic", "corr-a", "daily", 8.5, 10) // 85%
	recs := thresholdRecords(t, store, "corr-a")
	require.Len(t, recs, 1, "first crossing of 80%% → one signed record")
	cb := recs[0].CostBudget
	require.NotNil(t, cb)
	assert.Equal(t, "daily", cb.Period)
	assert.Equal(t, 10.0, cb.Limit)
	assert.Equal(t, 8.5, cb.Spent)
	assert.Equal(t, 80.0, cb.ThresholdPct)
	assert.Equal(t, evidence.ClassOperatorEvent, evidence.RecordClassOf(recs[0].InvocationType),
		"threshold facts must not count as request traffic")
	assert.True(t, recs[0].PolicyDecision.Allowed)
	assert.True(t, store.VerifyRecord(recs[0]), "threshold record must be signed")

	g.noteBudgetThresholds(ctx, agent, "anthropic", "corr-b", "daily", 8.7, 10) // still ≥80
	assert.Empty(t, thresholdRecords(t, store, "corr-b"), "later requests above the same threshold yield none")

	g.noteBudgetThresholds(ctx, agent, "anthropic", "corr-c", "daily", 9.6, 10) // 96%
	recs = thresholdRecords(t, store, "corr-c")
	require.Len(t, recs, 1, "crossing 95%% fires its own single record")
	assert.Equal(t, 95.0, recs[0].CostBudget.ThresholdPct)
}

// A restart must not duplicate the crossing fact: a fresh gateway (empty
// in-memory fired-set) over the same store rebuilds from evidence.
func TestNoteBudgetThresholds_RestartSafe(t *testing.T) {
	store := newBudgetEventsStore(t)
	ctx := context.Background()
	agent := budgetTestAgent()

	g1 := newBudgetEventsGateway(t, store, "")
	g1.noteBudgetThresholds(ctx, agent, "anthropic", "corr-1", "monthly", 85, 100)
	require.Len(t, thresholdRecords(t, store, "corr-1"), 1)

	g2 := newBudgetEventsGateway(t, store, "") // simulated restart
	g2.noteBudgetThresholds(ctx, agent, "anthropic", "corr-2", "monthly", 86, 100)
	assert.Empty(t, thresholdRecords(t, store, "corr-2"), "restart must not re-record the same window's crossing")
}

// A jump straight past both thresholds records BOTH crossings — each is a
// distinct fact, each exactly once.
func TestNoteBudgetThresholds_DoubleCross(t *testing.T) {
	store := newBudgetEventsStore(t)
	g := newBudgetEventsGateway(t, store, "")
	g.noteBudgetThresholds(context.Background(), budgetTestAgent(), "anthropic", "corr-x", "daily", 9.9, 10)
	recs := thresholdRecords(t, store, "corr-x")
	require.Len(t, recs, 2)
	pcts := []float64{recs[0].CostBudget.ThresholdPct, recs[1].CostBudget.ThresholdPct}
	assert.ElementsMatch(t, []float64{80, 95}, pcts)
}

// Distinct agents and periods track independently (#266 r4 precedent: one
// agent's alert must not suppress another's).
func TestNoteBudgetThresholds_PerAgentPerPeriod(t *testing.T) {
	store := newBudgetEventsStore(t)
	g := newBudgetEventsGateway(t, store, "")
	ctx := context.Background()
	a := &ResolvedIdentity{Name: "agent-a", TenantID: "default", Enabled: true}
	b := &ResolvedIdentity{Name: "agent-b", TenantID: "default", Enabled: true}

	g.noteBudgetThresholds(ctx, a, "anthropic", "corr-a", "daily", 85, 100)
	g.noteBudgetThresholds(ctx, b, "anthropic", "corr-b", "daily", 85, 100)
	g.noteBudgetThresholds(ctx, a, "anthropic", "corr-c", "monthly", 85, 100)

	assert.Len(t, thresholdRecords(t, store, "corr-a"), 1)
	assert.Len(t, thresholdRecords(t, store, "corr-b"), 1, "agent-b's crossing is its own fact")
	assert.Len(t, thresholdRecords(t, store, "corr-c"), 1, "monthly window is independent of daily")
}

// The org webhook fires only AFTER the evidence record committed: the handler
// itself verifies the referenced record is already readable in the store
// (#144 done-when 3).
func TestNoteBudgetThresholds_WebhookAfterEvidenceCommit(t *testing.T) {
	store := newBudgetEventsStore(t)

	var mu sync.Mutex
	var got CostEvent
	var evidenceExisted bool
	var delivered bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev CostEvent
		_ = json.Unmarshal(body, &ev)
		records, err := store.ListByCorrelationID(r.Context(), "corr-wh")
		exists := err == nil
		found := false
		for _, rec := range records {
			if rec.ID == ev.EvidenceID {
				found = true
			}
		}
		mu.Lock()
		got, evidenceExisted, delivered = ev, exists && found, true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	g := newBudgetEventsGateway(t, store, srv.URL) // http://127.0.0.1:… — loopback allowed
	g.noteBudgetThresholds(context.Background(), budgetTestAgent(), "anthropic", "corr-wh", "daily", 8.5, 10)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return delivered
	}, 5*time.Second, 10*time.Millisecond, "webhook must be delivered")
	mu.Lock()
	defer mu.Unlock()
	assert.True(t, evidenceExisted, "the webhook must reference an ALREADY-COMMITTED evidence record")
	assert.Equal(t, "budget_threshold", got.Event)
	assert.Equal(t, "support-bot", got.Agent)
	assert.Equal(t, "daily", got.Period)
	assert.Equal(t, 80.0, got.ThresholdPct)
	assert.Equal(t, 10.0, got.Limit)
	assert.Equal(t, "EUR", got.Currency)
	assert.NotEmpty(t, got.EvidenceID)
}

func TestBudgetWindowStart(t *testing.T) {
	at := time.Date(2026, 7, 28, 15, 4, 5, 0, time.FixedZone("CEST", 2*3600))
	assert.Equal(t, time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC), budgetWindowStart("daily", at))
	assert.Equal(t, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), budgetWindowStart("monthly", at))
}

func TestCostBudgetDetail(t *testing.T) {
	daily := costBudgetDetail([]string{"budget_exceeded: request would exceed agent daily cost limit (10)"}, 9.8, 50, 10, 200, 0.5)
	require.NotNil(t, daily)
	assert.Equal(t, &evidence.CostBudget{Period: "daily", Limit: 10, Spent: 9.8, Estimate: 0.5}, daily)

	monthly := costBudgetDetail([]string{"budget_exceeded: request would exceed organization monthly cost limit (200)"}, 9.8, 199.9, 10, 200, 0.5)
	require.NotNil(t, monthly)
	assert.Equal(t, "monthly", monthly.Period)
	assert.Equal(t, 200.0, monthly.Limit)
	assert.Equal(t, 199.9, monthly.Spent)

	assert.Nil(t, costBudgetDetail([]string{"PII block"}, 1, 2, 3, 4, 5), "non-budget denials carry no cost context")
	assert.Nil(t, costBudgetDetail(nil, 1, 2, 3, 4, 5))
}

func TestCostDenyReasonCode(t *testing.T) {
	assert.Equal(t, "budget_exceeded", costDenyReasonCode([]string{"budget_exceeded: daily"}))
	assert.Equal(t, "session_budget_exceeded", costDenyReasonCode([]string{"session_budget_exceeded: spend"}))
	assert.Empty(t, costDenyReasonCode([]string{"PII block"}), "non-cost denials are not cost events")
	assert.Empty(t, costDenyReasonCode(nil))
}
