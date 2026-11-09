// Package costs is the shared cost-report projection behind `talon costs` and
// the operations console (#535). It owns the calendar windows, the payload
// shape and the budget-status vocabulary; the SQL aggregations stay in
// internal/evidence and the effective-cap resolution stays with its callers
// (the CLI's server-first tri-state resolver, or a runtime probe). No caller
// may re-derive any number this package produces.
//
// Semantics are those `talon costs` has always had: UTC calendar day
// [00:00, +24h), UTC calendar month, and a 7-day window that ends with today;
// every amount is in the active pricing table's currency and sums
// execution.cost over every record class in scope (denied and unpriced records
// contribute 0, never a fabricated price).
package costs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Window is one evaluation of the calendar windows at Now, all UTC.
type Window struct {
	Now        time.Time
	DayStart   time.Time // today 00:00 UTC
	DayEnd     time.Time // tomorrow 00:00 UTC (exclusive)
	MonthStart time.Time
	MonthEnd   time.Time // first day of next month (exclusive)
	WeekStart  time.Time // DayStart - 6 days: the 7-day window is [WeekStart, DayEnd)
}

// WindowAt computes the windows `talon costs` uses for a given instant.
func WindowAt(now time.Time) Window {
	now = now.UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return Window{
		Now:        now,
		DayStart:   dayStart,
		DayEnd:     dayStart.Add(24 * time.Hour),
		MonthStart: monthStart,
		MonthEnd:   monthStart.AddDate(0, 1, 0),
		WeekStart:  dayStart.AddDate(0, 0, -6),
	}
}

// Breakdown selects which view of the tenant's spend the report carries. The
// views mirror the `talon costs` flags one-to-one.
type Breakdown string

const (
	// BreakdownAgents is the default tenant view: per-agent spend, tenant
	// budgets and cache usage.
	BreakdownAgents Breakdown = "agents"
	// BreakdownModel is `--by-model`: per-model spend for the tenant or one agent.
	BreakdownModel Breakdown = "model"
	// BreakdownProvider is `--by-provider`.
	BreakdownProvider Breakdown = "provider"
	// BreakdownTeam is `--by-team`: per-team spend for the whole tenant (the
	// evidence team field; records without one are "unassigned"). An agent
	// filter does not apply to this view.
	BreakdownTeam Breakdown = "team"
)

// Scope is what the report describes. An AgentID narrows the agents view to
// one agent (spend totals plus that agent's budgets, no cache figures), as
// `talon costs --agent` does.
type Scope struct {
	TenantID  string
	AgentID   string
	Breakdown Breakdown
}

// Source is the evidence-store surface the report reads. *evidence.Store
// satisfies it.
type Source interface {
	CostTotal(ctx context.Context, tenantID, agentID string, from, to time.Time) (float64, error)
	CostByAgent(ctx context.Context, tenantID string, from, to time.Time) (map[string]float64, error)
	CostByModel(ctx context.Context, tenantID, agentID string, from, to time.Time) (map[string]float64, error)
	CostByProvider(ctx context.Context, tenantID, agentID string, from, to time.Time) (map[string]float64, error)
	CostByTeam(ctx context.Context, tenantID string, from, to time.Time) (map[string]float64, error)
	CacheSavings(ctx context.Context, tenantID string, from, to time.Time) (hits int64, costSaved float64, err error)
	CountInRange(ctx context.Context, tenantID, agentID string, from, to time.Time) (int, error)
	CountUnpriced(ctx context.Context, tenantID, agentID string, from, to time.Time) (int, error)
	CurrenciesInRange(ctx context.Context, tenantID, agentID string, from, to time.Time) (map[string]int, error)
}

// BudgetResolver supplies the effective daily/monthly caps for a scope. The
// used amounts are passed in so a resolver that already knows the caps can
// return the usage without re-querying; a resolver that answers from a running
// server may return the server's own used figures verbatim (the CLI does).
// A nil daily or monthly result means "no cap known for this scope"; it is
// reported as such, never as 0.
type BudgetResolver interface {
	Resolve(ctx context.Context, tenantID, agentID string, dailyUsed, monthlyUsed float64) (daily, monthly *BudgetUsage, err error)
}

// Report is the `talon costs --json` contract. Field names keep their legacy
// _eur suffix for consumer compatibility; Currency is the authoritative unit
// of every amount (#216). The *_month_eur maps are additive (#535): the month
// breakdown the text output always printed next to the day breakdown.
type Report struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id,omitempty"`
	Currency string `json:"currency"`
	// Window bounds, so a consumer never has to guess the day/month/7d edges.
	Window WindowBounds `json:"window"`

	TodayEUR     float64 `json:"today_eur"`
	MonthEUR     float64 `json:"month_eur"`
	SevenDaysEUR float64 `json:"seven_days_eur"`

	ByAgentEUR         map[string]float64 `json:"by_agent_eur,omitempty"`
	ByAgentMonthEUR    map[string]float64 `json:"by_agent_month_eur,omitempty"`
	ByModelEUR         map[string]float64 `json:"by_model_eur,omitempty"`
	ByModelMonthEUR    map[string]float64 `json:"by_model_month_eur,omitempty"`
	ByProviderEUR      map[string]float64 `json:"by_provider_eur,omitempty"`
	ByProviderMonthEUR map[string]float64 `json:"by_provider_month_eur,omitempty"`
	ByTeamEUR          map[string]float64 `json:"by_team_eur,omitempty"`
	ByTeamMonthEUR     map[string]float64 `json:"by_team_month_eur,omitempty"`

	DailyBudget   *BudgetUsage `json:"daily_budget,omitempty"`
	MonthlyBudget *BudgetUsage `json:"monthly_budget,omitempty"`

	CacheSevenDays *CacheUsage `json:"cache_7d,omitempty"`
	// CacheMonth covers the UTC calendar month. Its JSON name predates the
	// calendar-month definition and is kept for compatibility.
	CacheMonth *CacheUsage `json:"cache_30d,omitempty"`

	// Currencies counts the priced records per amount window ("day",
	// "seven_days", "month") and per stamped currency ("" = written before
	// the currency field; rendered as the table currency, the unit the
	// shipped tables always used). A window whose priced records are not all
	// in Currency, because they span several currencies or because the one
	// recorded currency is not the configured one, is NOT a sum of comparable
	// values: its fields are still computed as they always were, but listed in
	// UnavailableFields with a warning, so no consumer presents them as a
	// total (#535 review rounds 3 and 4).
	Currencies map[string]map[string]int `json:"currencies,omitempty"`

	// UnpricedRecords counts allowed model calls in the calendar month whose
	// cost was not derived from a pricing-table price (pricing_known absent
	// or false). When positive, every amount above understates real spend by
	// an unknown figure; consumers show the count next to the amounts
	// instead of presenting them as complete.
	UnpricedRecords int `json:"unpriced_records"`

	// Warnings lists secondary queries that failed (7-day total, cache,
	// tenant totals). The affected figure is left at 0 as it always was; the
	// warning says so instead of letting the 0 pass for a measurement.
	Warnings []string `json:"warnings,omitempty"`
	// UnavailableFields names the JSON fields whose value is NOT a
	// measurement because of a warning above (machine-readable form of the
	// same fact): a consumer renders them as unavailable, never as 0.
	UnavailableFields []string `json:"unavailable_fields,omitempty"`
}

// WindowBounds is the Window as it appears in the report (RFC 3339, UTC).
type WindowBounds struct {
	DayStart   time.Time `json:"day_start"`
	DayEnd     time.Time `json:"day_end"`
	MonthStart time.Time `json:"month_start"`
	MonthEnd   time.Time `json:"month_end"`
	WeekStart  time.Time `json:"week_start"`
	WeekEnd    time.Time `json:"week_end"`
}

// BudgetUsage is one period's spend against its effective cap. Source names
// where the cap came from (agent_effective_cap, policy_cost_limits,
// server_<budget_source>, ...).
type BudgetUsage struct {
	UsedEUR  float64 `json:"used_eur"`
	LimitEUR float64 `json:"limit_eur"`
	Percent  float64 `json:"percent"`
	Source   string  `json:"source"`
	// StatusWord is the operator vocabulary (OK/WARNING/CRITICAL/BLOCKED)
	// serialized so no consumer re-derives it from Percent.
	StatusWord string `json:"status"`
}

// Status maps utilization to the operator status vocabulary of the
// cost-control contract (#144): WARNING and CRITICAL correspond one-to-one to
// the gateway's BudgetWarnThresholds evidence events; BLOCKED means new
// requests whose estimate exceeds the remaining headroom are denied before
// the provider is called.
func (b BudgetUsage) Status() string { return StatusWord(b.Percent) }

// StatusWord is Status for a bare utilization percentage.
func StatusWord(pct float64) string {
	switch {
	case pct >= 100:
		return "BLOCKED"
	case pct >= 95:
		return "CRITICAL"
	case pct >= 80:
		return "WARNING"
	default:
		return "OK"
	}
}

// NewBudgetUsage builds a BudgetUsage; a non-positive limit means no cap and
// yields nil.
func NewBudgetUsage(used, limit float64, source string) *BudgetUsage {
	if limit <= 0 {
		return nil
	}
	pct := 100 * used / limit
	return &BudgetUsage{UsedEUR: used, LimitEUR: limit, Percent: pct, Source: source, StatusWord: StatusWord(pct)}
}

// CacheUsage is cache-hit accounting over a window: hits and saved cost from
// cache-hit records, hit rate against every record of the tenant in the window.
type CacheUsage struct {
	Hits      int64   `json:"hits"`
	SavedEUR  float64 `json:"saved_eur"`
	HitRate   float64 `json:"hit_rate_percent"`
	TotalSeen int     `json:"total_seen"`
}

// Build produces the report for scope at window w. currency is the active
// pricing table's ISO-4217 code. budgets may be nil (no caps reported).
func Build(ctx context.Context, src Source, scope Scope, w Window, currency string, budgets BudgetResolver) (*Report, error) {
	if scope.TenantID == "" {
		scope.TenantID = "default"
	}
	if scope.Breakdown == "" {
		scope.Breakdown = BreakdownAgents
	}
	r := &Report{
		TenantID: scope.TenantID,
		AgentID:  scope.AgentID,
		Currency: currency,
		Window: WindowBounds{
			DayStart: w.DayStart, DayEnd: w.DayEnd,
			MonthStart: w.MonthStart, MonthEnd: w.MonthEnd,
			WeekStart: w.WeekStart, WeekEnd: w.DayEnd,
		},
	}
	var err error
	switch scope.Breakdown {
	case BreakdownModel, BreakdownProvider, BreakdownTeam:
		err = buildBreakdown(ctx, src, scope, w, r)
	case BreakdownAgents:
		err = buildAgents(ctx, src, scope, w, budgets, r)
	default:
		err = fmt.Errorf("unknown cost breakdown %q", scope.Breakdown)
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// weekTotal fills seven_days_eur; a failure is a warning on the report, the
// figure stays 0 as it always did in the CLI, and the warning says so.
func weekTotal(ctx context.Context, src Source, tenant, agent string, w Window, r *Report) {
	v, err := src.CostTotal(ctx, tenant, agent, w.WeekStart, w.DayEnd)
	if err != nil {
		r.markUnavailable("seven_days_eur", err)
		return
	}
	r.SevenDaysEUR = v
}

// buildBreakdown fills the model, provider or team view: a day map, a month
// map, their sums as the day/month totals, and the 7-day total.
func buildBreakdown(ctx context.Context, src Source, scope Scope, w Window, r *Report) error {
	tenant, agent := scope.TenantID, scope.AgentID
	var (
		daily, monthly map[string]float64
		err            error
		label          string
	)
	switch scope.Breakdown {
	case BreakdownModel:
		label = "model"
		if daily, err = src.CostByModel(ctx, tenant, agent, w.DayStart, w.DayEnd); err == nil {
			monthly, err = src.CostByModel(ctx, tenant, agent, w.MonthStart, w.MonthEnd)
		}
	case BreakdownProvider:
		label = "provider"
		if daily, err = src.CostByProvider(ctx, tenant, agent, w.DayStart, w.DayEnd); err == nil {
			monthly, err = src.CostByProvider(ctx, tenant, agent, w.MonthStart, w.MonthEnd)
		}
	case BreakdownTeam:
		// Team spend is a tenant-wide view: the store aggregation has no
		// agent dimension, so the agent filter does not apply and is not
		// echoed back.
		label, agent, r.AgentID = "team", "", ""
		if daily, err = src.CostByTeam(ctx, tenant, w.DayStart, w.DayEnd); err == nil {
			monthly, err = src.CostByTeam(ctx, tenant, w.MonthStart, w.MonthEnd)
		}
	}
	if err != nil {
		if daily == nil {
			return fmt.Errorf("cost by %s (daily): %w", label, err)
		}
		return fmt.Errorf("cost by %s (monthly): %w", label, err)
	}
	r.TodayEUR, r.MonthEUR = sumValues(daily), sumValues(monthly)
	weekTotal(ctx, src, tenant, agent, w, r)
	unpriced(ctx, src, tenant, agent, w, r)
	currencies(ctx, src, tenant, agent, w, r)
	switch scope.Breakdown {
	case BreakdownModel:
		r.ByModelEUR, r.ByModelMonthEUR = daily, monthly
	case BreakdownProvider:
		r.ByProviderEUR, r.ByProviderMonthEUR = daily, monthly
	case BreakdownTeam:
		r.ByTeamEUR, r.ByTeamMonthEUR = daily, monthly
	}
	return nil
}

// buildAgents fills the default view: one agent's totals and budgets, or the
// tenant's per-agent maps, totals, budgets and cache figures.
func buildAgents(ctx context.Context, src Source, scope Scope, w Window, budgets BudgetResolver, r *Report) error {
	tenant, agent := scope.TenantID, scope.AgentID
	if agent != "" {
		daily, err := src.CostTotal(ctx, tenant, agent, w.DayStart, w.DayEnd)
		if err != nil {
			return fmt.Errorf("cost total daily: %w", err)
		}
		monthly, err := src.CostTotal(ctx, tenant, agent, w.MonthStart, w.MonthEnd)
		if err != nil {
			return fmt.Errorf("cost total monthly: %w", err)
		}
		r.TodayEUR, r.MonthEUR = daily, monthly
		weekTotal(ctx, src, tenant, agent, w, r)
		unpriced(ctx, src, tenant, agent, w, r)
		currencies(ctx, src, tenant, agent, w, r)
		return resolveBudgets(ctx, budgets, tenant, agent, r)
	}

	byAgentDaily, err := src.CostByAgent(ctx, tenant, w.DayStart, w.DayEnd)
	if err != nil {
		return fmt.Errorf("cost by agent (daily): %w", err)
	}
	byAgentMonthly, err := src.CostByAgent(ctx, tenant, w.MonthStart, w.MonthEnd)
	if err != nil {
		return fmt.Errorf("cost by agent (monthly): %w", err)
	}
	r.ByAgentEUR, r.ByAgentMonthEUR = byAgentDaily, byAgentMonthly
	if r.TodayEUR, err = src.CostTotal(ctx, tenant, "", w.DayStart, w.DayEnd); err != nil {
		r.markUnavailable("today_eur", err)
	}
	if r.MonthEUR, err = src.CostTotal(ctx, tenant, "", w.MonthStart, w.MonthEnd); err != nil {
		r.markUnavailable("month_eur", err)
	}
	weekTotal(ctx, src, tenant, "", w, r)
	unpriced(ctx, src, tenant, "", w, r)
	currencies(ctx, src, tenant, "", w, r)
	if err := resolveBudgets(ctx, budgets, tenant, "", r); err != nil {
		return err
	}
	r.CacheSevenDays, r.CacheMonth = cacheUsage(ctx, src, tenant, w, r)
	return nil
}

// markUnavailable records that field holds no measurement.
func (r *Report) markUnavailable(field string, err error) {
	r.Warnings = append(r.Warnings, field+" unavailable: "+err.Error())
	r.UnavailableFields = append(r.UnavailableFields, field)
}

// unpriced fills UnpricedRecords for the calendar month in scope.
func unpriced(ctx context.Context, src Source, tenant, agent string, w Window, r *Report) {
	n, err := src.CountUnpriced(ctx, tenant, agent, w.MonthStart, w.MonthEnd)
	if err != nil {
		r.markUnavailable("unpriced_records", err)
		return
	}
	r.UnpricedRecords = n
}

// amountWindow is one time window over which the report adds execution.cost,
// with the report fields that hold that sum.
type amountWindow struct {
	name     string
	from, to time.Time
	fields   []string
}

// amountWindows lists the three windows of a Window. seven_days spans two
// calendar months around a month boundary, so it is checked on its own
// bounds, never inferred from the month.
func amountWindows(w Window) []amountWindow {
	return []amountWindow{
		{"day", w.DayStart, w.DayEnd, []string{"today_eur", "by_agent_eur", "by_model_eur", "by_provider_eur", "by_team_eur"}},
		{"seven_days", w.WeekStart, w.DayEnd, []string{"seven_days_eur"}},
		{"month", w.MonthStart, w.MonthEnd, []string{"month_eur", "by_agent_month_eur", "by_model_month_eur", "by_provider_month_eur", "by_team_month_eur"}},
	}
}

// currencies fills Currencies per amount window and marks the fields of
// every window whose priced records are not all in r.Currency, or whose
// currencies could not be read, as not a measurement: adding euros to dollars is not a total, and a sum of dollars
// labelled "EUR" is not one either (#535 review rounds 3 and 4). Unstamped
// records count as r.Currency, the unit the shipped tables always used.
// It reports whether every window is comparable.
func currencies(ctx context.Context, src Source, tenant, agent string, w Window, r *Report) bool {
	comparable := true
	for _, win := range amountWindows(w) {
		counts, err := src.CurrenciesInRange(ctx, tenant, agent, win.from, win.to)
		if err != nil {
			// Fail closed: a total whose unit could not be validated is not a
			// measurement either, and no budget utilization is derived from it
			// (#535 review round 5).
			r.markUnavailable("currencies."+win.name, err)
			r.Warnings = append(r.Warnings, win.name+" window: currency of the priced records could not be validated; amounts are not reported as sums in "+r.Currency)
			r.UnavailableFields = append(r.UnavailableFields, win.fields...)
			comparable = false
			continue
		}
		if len(counts) > 0 {
			if r.Currencies == nil {
				r.Currencies = map[string]map[string]int{}
			}
			r.Currencies[win.name] = counts
		}
		var foreign []string
		for cur := range counts {
			if cur != "" && cur != r.Currency && !containsString(foreign, cur) {
				foreign = append(foreign, cur)
			}
		}
		if len(foreign) == 0 {
			continue
		}
		comparable = false
		sort.Strings(foreign)
		r.Warnings = append(r.Warnings, win.name+" window: priced records in "+strings.Join(foreign, ", ")+" are not sums in "+r.Currency+"; see currencies."+win.name)
		r.UnavailableFields = append(r.UnavailableFields, win.fields...)
	}
	return comparable
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// resolveBudgets derives utilization from TodayEUR and MonthEUR. When either
// is not a measurement in r.Currency (see currencies), no utilization or
// status word is derived from it: a percentage or BLOCKED computed from
// incomparable amounts would be presented as fact (#535 review round 4).
func resolveBudgets(ctx context.Context, budgets BudgetResolver, tenant, agent string, r *Report) error {
	if budgets == nil {
		return nil
	}
	if containsString(r.UnavailableFields, "today_eur") || containsString(r.UnavailableFields, "month_eur") {
		r.Warnings = append(r.Warnings, "budget utilization not computed: the summed amounts are not comparable in "+r.Currency)
		r.UnavailableFields = append(r.UnavailableFields, "daily_budget", "monthly_budget")
		return nil
	}
	daily, monthly, err := budgets.Resolve(ctx, tenant, agent, r.TodayEUR, r.MonthEUR)
	if err != nil {
		return err
	}
	r.DailyBudget, r.MonthlyBudget = daily, monthly
	return nil
}

// cacheUsage computes the 7-day and calendar-month cache figures. A failed
// savings query leaves that period nil (as the CLI always did) and records a
// warning; a failed count leaves TotalSeen at 0 with a warning.
func cacheUsage(ctx context.Context, src Source, tenant string, w Window, r *Report) (sevenDays, month *CacheUsage) {
	one := func(label string, from, to time.Time) *CacheUsage {
		hits, saved, err := src.CacheSavings(ctx, tenant, from, to)
		if err != nil {
			r.markUnavailable(label, err)
			return nil
		}
		total, err := src.CountInRange(ctx, tenant, "", from, to)
		if err != nil {
			r.markUnavailable(label+".total_seen", err)
		}
		return &CacheUsage{Hits: hits, SavedEUR: saved, HitRate: percentage(int(hits), total), TotalSeen: total}
	}
	sevenDays = one("cache_7d", w.WeekStart, w.DayEnd)
	if sevenDays == nil {
		return nil, nil
	}
	return sevenDays, one("cache_30d", w.MonthStart, w.MonthEnd)
}

func percentage(hits, total int) float64 {
	if total <= 0 {
		return 0
	}
	return 100 * float64(hits) / float64(total)
}

func sumValues(m map[string]float64) float64 {
	total := 0.0
	for _, v := range m {
		total += v
	}
	return total
}
