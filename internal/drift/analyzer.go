package drift

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

type Signal struct {
	Name     string  `json:"name"`
	ZScore   float64 `json:"z_score"`
	Current  float64 `json:"current"`
	Baseline float64 `json:"baseline"`
	Alert    bool    `json:"alert"`
}

type AgentDrift struct {
	TenantID string   `json:"tenant_id"`
	AgentID  string   `json:"agent_id"`
	Signals  []Signal `json:"signals"`
}

type Analyzer struct {
	store *evidence.Store
}

func NewAnalyzer(store *evidence.Store) *Analyzer {
	return &Analyzer{store: store}
}

func (a *Analyzer) ComputeSignals(ctx context.Context, tenantID string, now time.Time) ([]AgentDrift, error) {
	if a.store == nil {
		return nil, fmt.Errorf("evidence store is nil")
	}
	currentFrom := now.Add(-24 * time.Hour)
	baselineFrom := now.Add(-8 * 24 * time.Hour)
	baselineTo := now.Add(-24 * time.Hour)

	current, err := a.store.List(ctx, tenantID, "", currentFrom, now, 200000)
	if err != nil {
		return nil, fmt.Errorf("listing current evidence: %w", err)
	}
	baseline, err := a.store.List(ctx, tenantID, "", baselineFrom, baselineTo, 200000)
	if err != nil {
		return nil, fmt.Errorf("listing baseline evidence: %w", err)
	}

	curAgg := aggregateByAgent(current)
	baseAgg := aggregateByAgent(baseline)

	out := []AgentDrift{}
	for agentID, c := range curAgg {
		b := baseAgg[agentID]
		costZ := zscore(c.cost, b.cost)
		denyRateCur := ratio(float64(c.denied), float64(c.total))
		denyRateBase := ratio(float64(b.denied), float64(b.total))
		denyZ := zscore(denyRateCur, denyRateBase)
		piiRateCur := ratio(float64(c.pii), float64(c.total))
		piiRateBase := ratio(float64(b.pii), float64(b.total))
		piiZ := zscore(piiRateCur, piiRateBase)
		out = append(out, AgentDrift{
			TenantID: tenantID,
			AgentID:  agentID,
			Signals: []Signal{
				{Name: "cost_anomaly", ZScore: costZ, Current: c.cost, Baseline: b.cost, Alert: math.Abs(costZ) >= 2.0},
				{Name: "denial_rate_spike", ZScore: denyZ, Current: denyRateCur, Baseline: denyRateBase, Alert: math.Abs(denyZ) >= 2.0},
				{Name: "pii_rate_change", ZScore: piiZ, Current: piiRateCur, Baseline: piiRateBase, Alert: math.Abs(piiZ) >= 2.0},
			},
		})
	}
	return out, nil
}

type agg struct {
	total  int
	denied int
	pii    int
	cost   float64
}

func aggregateByAgent(list []evidence.Evidence) map[string]agg {
	out := map[string]agg{}
	for i := range list {
		ev := list[i]
		a := out[ev.AgentID]
		a.total++
		if !ev.PolicyDecision.Allowed {
			a.denied++
		}
		if len(ev.Classification.PIIDetected) > 0 {
			a.pii++
		}
		a.cost += ev.Execution.Cost
		out[ev.AgentID] = a
	}
	return out
}

func ratio(n, d float64) float64 {
	if d <= 0 {
		return 0
	}
	return n / d
}

func zscore(current, baseline float64) float64 {
	// Lightweight z-like score for MVP: normalize by half-baseline floor.
	den := math.Max(0.01, math.Abs(baseline)*0.5)
	return (current - baseline) / den
}
