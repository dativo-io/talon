package fleet

import (
	"context"
	"sort"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

// EvidenceSource is the read surface Project needs from the evidence store.
// Declaring it as an interface (rather than *evidence.Store) lets unit tests
// drive Project with in-memory fakes and keeps the projection honest about
// exactly which queries it depends on.
type EvidenceSource interface {
	AgentTrafficStats(ctx context.Context, tenantID string, from, to time.Time) (map[string]evidence.TrafficStats, error)
	FallbackCountsByAgent(ctx context.Context, tenantID string, from, to time.Time) (map[string]int, error)
	CostByAgent(ctx context.Context, tenantID string, from, to time.Time) (map[string]float64, error)
	AgentsSummary(ctx context.Context, from, to time.Time, tenantID string) ([]evidence.AgentSummary, error)
	LastRequestByAgent(ctx context.Context, tenantID string, from, to time.Time) (map[string]time.Time, error)
}

// SessionSource is the read surface Project needs from the session store.
type SessionSource interface {
	FailedSessionCountsByAgent(ctx context.Context, tenantID string, since time.Time) (map[string]int, error)
}

// Project turns per-agent identity/config inputs (AgentStatus) into
// attention-queue rows. This is the ONE code path both the server's
// /v1/agents/fleet handler and the `talon agents` CLI use, so the dashboard and
// the CLI can never compute health, budget, or session state independently
// (#270 parity criterion). It performs all time-window math here and hands
// pre-windowed Signals to the pure Evaluate, so health decisions stay
// table-testable and identical across surfaces.
//
// Never-valid files are NOT passed in as AgentStatus (they have no trustworthy
// identity); they surface as FleetIssues rendered separately by the caller.
func Project(ctx context.Context, ev EvidenceSource, ss SessionSource, agents []AgentStatus, th Thresholds, now time.Time) ([]AgentRow, error) {
	now = now.UTC()
	qTenant := queryTenant(agents)

	// Rolling windows for the runtime signals, and UTC budget periods matching
	// the cost surfaces exactly (costs.go:141-145).
	denialFrom := now.Add(-th.DenialWindow)
	fallbackFrom := now.Add(-th.FallbackWindow)
	failedSince := now.Add(-th.FailedSessionWindow)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	traffic, err := ev.AgentTrafficStats(ctx, qTenant, denialFrom, now)
	if err != nil {
		return nil, err
	}
	fallbacks, err := ev.FallbackCountsByAgent(ctx, qTenant, fallbackFrom, now)
	if err != nil {
		return nil, err
	}
	dayCost, err := ev.CostByAgent(ctx, qTenant, dayStart, now)
	if err != nil {
		return nil, err
	}
	monthSummary, err := ev.AgentsSummary(ctx, monthStart, monthEnd, qTenant)
	if err != nil {
		return nil, err
	}
	// LastRun is the most recent REQUEST-class timestamp, all-time (no month
	// boundary), so an operator event never becomes the last-run and an agent
	// whose last request predates this month still shows one (#270 review P2).
	lastRun, err := ev.LastRequestByAgent(ctx, qTenant, time.Time{}, now)
	if err != nil {
		return nil, err
	}
	failed, err := ss.FailedSessionCountsByAgent(ctx, qTenant, failedSince)
	if err != nil {
		return nil, err
	}

	// Month-to-date cost per agent comes from the summary query.
	monthCost := make(map[string]float64, len(monthSummary))
	for _, a := range monthSummary {
		monthCost[a.AgentID] = a.CostEUR
	}

	rows := make([]AgentRow, 0, len(agents))
	for i := range agents {
		a := &agents[i]
		state := StateEnabled
		if !a.Enabled {
			state = StateStopped
		}
		sig := Signals{
			Requests:       traffic[a.Name].Requests,
			Denied:         traffic[a.Name].Denied,
			Fallbacks:      fallbacks[a.Name],
			FailedSessions: failed[a.Name],
			ConfigRejected: a.ConfigRejected,
			PolicyDenyAll:  a.PolicyDenyAll,
			Budgets: []BudgetPeriod{
				{Name: "daily", Spend: dayCost[a.Name], Cap: a.DailyCap},
				{Name: "monthly", Spend: monthCost[a.Name], Cap: a.MonthlyCap},
			},
		}
		health, causes := Evaluate(state, sig, th, a.Currency)
		rows = append(rows, AgentRow{
			Name:           a.Name,
			TenantID:       a.TenantID,
			State:          state,
			Health:         health,
			Why:            WhyString(causes),
			Causes:         causes,
			SpendMonth:     monthCost[a.Name],
			MonthlyCap:     a.MonthlyCap,
			SpendDay:       dayCost[a.Name],
			DailyCap:       a.DailyCap,
			Currency:       a.Currency,
			Requests:       sig.Requests,
			Denied:         sig.Denied,
			Fallbacks:      sig.Fallbacks,
			FailedSessions: sig.FailedSessions,
			LastRun:        lastRun[a.Name],
			ConfigPath:     a.ConfigPath,
			PolicyDigest:   a.PolicyDigest,
			ConfigError:    a.ConfigError,
		})
	}
	sortRows(rows)
	return rows, nil
}

// queryTenant scopes the store reads: when every agent shares one tenant, that
// tenant (tightening the query and honoring tenant isolation for the HTTP
// tenant-scoped path); when agents span tenants (the local admin view), the
// empty string spans all tenants. Cross-tenant attribution is unambiguous
// because discovery fails closed on duplicate agent names, so agent_id is unique
// across the fleet.
func queryTenant(agents []AgentStatus) string {
	tenant := ""
	for i := range agents {
		if i == 0 {
			tenant = agents[i].TenantID
			continue
		}
		if agents[i].TenantID != tenant {
			return ""
		}
	}
	return tenant
}

// healthRank orders rows for the attention queue: the most actionable first.
// BLOCKED (broken) and NEEDS ATTENTION (degraded) precede STOPPED (intentionally
// off by an operator) and HEALTHY. This is the QUEUE order — distinct from the
// health-value resolution priority in Evaluate (where STOPPED outranks NEEDS
// ATTENTION for deciding a single agent's one health value): a disabled agent is
// low-urgency to surface, but its resolved health is still STOPPED.
func healthRank(h Health) int {
	switch h {
	case HealthBlocked:
		return 0
	case HealthNeedsAttention:
		return 1
	case HealthStopped:
		return 2
	default: // HealthHealthy
		return 3
	}
}

// sortRows orders by attention rank, then name — stable so equal-rank rows keep
// a deterministic (alphabetical) order across surfaces for parity.
func sortRows(rows []AgentRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := healthRank(rows[i].Health), healthRank(rows[j].Health)
		if ri != rj {
			return ri < rj
		}
		return rows[i].Name < rows[j].Name
	})
}
