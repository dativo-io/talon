package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
)

// BudgetWarnThresholds are the warning thresholds of the cost-control
// contract (#144), in ascending order. Crossing each one yields exactly one
// signed budget_threshold evidence record per budget window. Exported so
// `talon costs` states the same thresholds enforcement fires on.
var BudgetWarnThresholds = []float64{80, 95}

// CostEvent is the payload POSTed to the organization cost webhook (#144),
// strictly after the signed evidence record it references has committed.
type CostEvent struct {
	Event         string    `json:"event"` // budget_threshold | budget_denied
	TenantID      string    `json:"tenant_id"`
	Agent         string    `json:"agent"`
	Period        string    `json:"period,omitempty"` // daily | monthly
	ThresholdPct  float64   `json:"threshold_pct,omitempty"`
	Limit         float64   `json:"limit,omitempty"`
	Spent         float64   `json:"spent,omitempty"`
	EstimatedCost float64   `json:"estimated_cost,omitempty"`
	Currency      string    `json:"currency,omitempty"`
	ReasonCode    string    `json:"reason_code,omitempty"` // budget_exceeded | session_budget_exceeded
	EvidenceID    string    `json:"evidence_id"`
	Timestamp     time.Time `json:"timestamp"`
}

// budgetWindowStart returns the UTC start of the budget window a spend total
// is accumulated over — the same UTC day/month windows enforcement uses
// (agentCostTotals, #216).
func budgetWindowStart(period string, now time.Time) time.Time {
	now = now.UTC()
	if period == "monthly" {
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

func budgetEventKey(tenantID, agentName, period string, threshold float64, windowStart time.Time) string {
	return tenantID + "|" + agentName + "|" + period + "|" +
		strconv.FormatFloat(threshold, 'f', -1, 64) + "|" + windowStart.Format("2006-01-02")
}

// noteBudgetThresholds implements the once-per-crossing contract (#144) for
// one budget period: for every warning threshold the window's spend has
// reached, write ONE signed budget_threshold evidence record, then emit the
// OTel alert metric and the organization cost webhook as projections of that
// committed fact. Subsequent requests in the same window above the same
// threshold write nothing. The in-memory fired-set is claimed under lock
// before any I/O (concurrent requests race to one winner) and is rebuilt
// lazily from the evidence store after a restart (HasBudgetThresholdEvent).
// A failed evidence write releases the claim so a later request retries —
// the metric and webhook never fire without a committed record.
func (g *Gateway) noteBudgetThresholds(ctx context.Context, agent *ResolvedIdentity, provider, correlationID, period string, spent, cap float64) {
	if cap <= 0 {
		return
	}
	pct := (spent / cap) * 100
	now := time.Now()
	windowStart := budgetWindowStart(period, now)
	for _, threshold := range BudgetWarnThresholds {
		if pct < threshold {
			break
		}
		key := budgetEventKey(agent.TenantID, agent.Name, period, threshold, windowStart)
		if !g.claimBudgetEvent(key) {
			continue
		}
		exists, err := g.evidenceStore.HasBudgetThresholdEvent(ctx, agent.TenantID, agent.Name, period, threshold, windowStart)
		if err != nil {
			// Store read failed: release so a later request re-checks. Firing
			// blind could duplicate the crossing fact after a restart.
			g.releaseBudgetEvent(key)
			log.Warn().Err(err).Str("agent", agent.Name).Str("period", period).Msg("budget_threshold_lookup_failed")
			continue
		}
		if exists {
			continue // already recorded this window (pre-restart)
		}
		ev, err := RecordGatewayEvidence(ctx, g.evidenceStore, RecordGatewayEvidenceParams{
			CorrelationID:  correlationID,
			TenantID:       agent.TenantID,
			AgentName:      agent.Name,
			Team:           agent.Team,
			Provider:       provider,
			PolicyAllowed:  true,
			PolicyVersion:  agent.PolicyDigest,
			PolicyDigests:  g.policyDigests(agent, provider),
			Currency:       g.pricingCurrency,
			InvocationType: evidence.InvocationTypeBudgetThreshold,
			CostBudget: &evidence.CostBudget{
				Period:       period,
				Limit:        cap,
				Spent:        spent,
				ThresholdPct: threshold,
			},
		})
		if err != nil {
			g.releaseBudgetEvent(key)
			log.Warn().Err(err).Str("agent", agent.Name).Str("period", period).Msg("budget_threshold_evidence_failed")
			continue
		}
		// Projections of the committed fact — strictly after the store write.
		RecordBudgetAlert(ctx, agent.TenantID, threshold)
		g.postCostEvent(CostEvent{
			Event:        "budget_threshold",
			TenantID:     agent.TenantID,
			Agent:        agent.Name,
			Period:       period,
			ThresholdPct: threshold,
			Limit:        cap,
			Spent:        spent,
			Currency:     g.pricingCurrency,
			EvidenceID:   ev.ID,
			Timestamp:    ev.Timestamp.UTC(),
		})
		log.Info().
			Str("agent", agent.Name).
			Str("period", period).
			Float64("threshold_pct", threshold).
			Str("evidence_id", ev.ID).
			Msg("budget_threshold_crossed")
	}
}

// claimBudgetEvent marks a (tenant, agent, period, threshold, window) key as
// fired, returning false when it was already claimed. Claiming happens before
// any I/O so concurrent requests race to exactly one winner.
func (g *Gateway) claimBudgetEvent(key string) bool {
	g.budgetEventMu.Lock()
	defer g.budgetEventMu.Unlock()
	if g.budgetEventFired == nil {
		g.budgetEventFired = make(map[string]bool)
	}
	if g.budgetEventFired[key] {
		return false
	}
	g.budgetEventFired[key] = true
	return true
}

func (g *Gateway) releaseBudgetEvent(key string) {
	g.budgetEventMu.Lock()
	defer g.budgetEventMu.Unlock()
	delete(g.budgetEventFired, key)
}

// costBudgetDetail extracts the structured budget-window context when an
// agent/org budget deny fired, from the same numbers the policy decision saw.
// Nil when no budget_exceeded reason is present. Limit is the BINDING cap for
// the denied period — the tightest of agent and org, which is by construction
// the cap the deny fired on.
func costBudgetDetail(reasons []string, dailyCost, monthlyCost, dailyCap, monthlyCap, estimatedCost float64) *evidence.CostBudget {
	for _, r := range reasons {
		if !strings.HasPrefix(r, "budget_exceeded:") {
			continue
		}
		period, spent, limit := "daily", dailyCost, dailyCap
		if strings.Contains(r, "monthly") {
			period, spent, limit = "monthly", monthlyCost, monthlyCap
		}
		return &evidence.CostBudget{
			Period:   period,
			Limit:    limit,
			Spent:    spent,
			Estimate: estimatedCost,
		}
	}
	return nil
}

// costDenyReasonCode returns the machine code of the first cost-control deny
// reason ("budget_exceeded" or "session_budget_exceeded"), or "" when the
// denial was not cost-driven — only cost denials go to the cost webhook.
func costDenyReasonCode(reasons []string) string {
	for _, r := range reasons {
		switch {
		case strings.HasPrefix(r, "budget_exceeded:"):
			return "budget_exceeded"
		case strings.HasPrefix(r, "session_budget_exceeded:"):
			return "session_budget_exceeded"
		}
	}
	return ""
}

// postCostEvent delivers a cost event to the organization webhook, if one is
// configured. Callers invoke it only AFTER the referenced evidence record
// committed; delivery itself is asynchronous and best-effort — failure is
// logged, evidence remains the truth (#144).
func (g *Gateway) postCostEvent(ev CostEvent) {
	url := g.config.OrganizationPolicy.CostWebhookURL
	if url == "" {
		return
	}
	go deliverCostEvent(url, ev)
}

// deliverCostEvent POSTs one event with a bounded timeout. The URL was
// validated at config load (Validate) and is re-checked here as
// defense-in-depth against a config object built without Validate.
func deliverCostEvent(url string, ev CostEvent) {
	if !policy.AllowedWebhookURL(url) {
		log.Warn().Str("url", url).Msg("cost_webhook_url_rejected")
		return
	}
	body, err := json.Marshal(ev)
	if err != nil {
		log.Warn().Err(err).Msg("cost_webhook_marshal_failed")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Warn().Err(err).Str("url", url).Msg("cost_webhook_request_failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// URL validated by policy.AllowedWebhookURL (HTTPS or HTTP loopback only).
	resp, err := (&http.Client{}).Do(req) // #nosec G704
	if err != nil {
		log.Warn().Err(err).Str("url", url).Str("event", ev.Event).Msg("cost_webhook_post_failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Warn().Int("status", resp.StatusCode).Str("url", url).Str("event", ev.Event).Msg("cost_webhook_non_2xx")
	}
}
