package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/pricing"
)

var (
	costsAgent        string
	costsTenant       string
	costsByModel      bool
	costsByProvider   bool
	costsByTeam       bool
	costsSession      string
	costsJSON         bool
	costsExportFmt    string
	costsExportFrom   string
	costsExportTo     string
	costsExportTenant string
	costsExportAgent  string
	costsExportOutput string
	costsExportLimit  int
)

var costsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export cost evidence rows",
	RunE:  costsExport,
}

type costsPayload struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id,omitempty"`
	// Currency is the ISO-4217 unit of every amount in this payload, from the
	// active pricing table (#216). Field names keep their legacy _eur suffix
	// for consumer compatibility; Currency is the authoritative unit.
	Currency       string             `json:"currency"`
	TodayEUR       float64            `json:"today_eur"`
	MonthEUR       float64            `json:"month_eur"`
	SevenDaysEUR   float64            `json:"seven_days_eur"`
	ByAgentEUR     map[string]float64 `json:"by_agent_eur,omitempty"`
	ByModelEUR     map[string]float64 `json:"by_model_eur,omitempty"`
	ByProviderEUR  map[string]float64 `json:"by_provider_eur,omitempty"`
	ByTeamEUR      map[string]float64 `json:"by_team_eur,omitempty"`
	DailyBudget    *budgetUsage       `json:"daily_budget,omitempty"`
	MonthlyBudget  *budgetUsage       `json:"monthly_budget,omitempty"`
	CacheSevenDays *cacheUsage        `json:"cache_7d,omitempty"`
	CacheMonth     *cacheUsage        `json:"cache_30d,omitempty"`
}

type budgetUsage struct {
	UsedEUR  float64 `json:"used_eur"`
	LimitEUR float64 `json:"limit_eur"`
	Percent  float64 `json:"percent"`
	Source   string  `json:"source"`
}

type cacheUsage struct {
	Hits      int64   `json:"hits"`
	SavedEUR  float64 `json:"saved_eur"`
	HitRate   float64 `json:"hit_rate_percent"`
	TotalSeen int     `json:"total_seen"`
}

var costsCmd = &cobra.Command{
	Use:   "costs",
	Short: "Show cost and budget usage",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, span := tracer.Start(cmd.Context(), "costs")
		defer span.End()

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
		if err != nil {
			return fmt.Errorf("opening evidence store: %w", err)
		}
		defer store.Close()

		costCurrency := loadPricingTable(cfg, "").CurrencyCode()

		tenantID := costsTenant
		if tenantID == "" {
			tenantID = "default"
		}

		if costsSession != "" {
			sessionOut := cmd.OutOrStdout()
			records, err := store.ListBySessionID(ctx, costsSession)
			if err != nil {
				return fmt.Errorf("querying session %s: %w", costsSession, err)
			}
			// Scope by the tenant the user actually passed — NOT the "default"
			// fallback used by the calendar rollups below. Defaulting here
			// silently emptied the summary for any session owned by another
			// tenant (bit the coding-agents demo, tenant "demo").
			records = scopeSessionRecords(records, costsTenant, costsAgent)
			sum := evidence.BuildSessionSummary(costsSession, records)
			if costsJSON {
				enc := json.NewEncoder(sessionOut)
				enc.SetIndent("", "  ")
				return enc.Encode(sum)
			}
			renderSessionSummary(sessionOut, sum)
			return nil
		}

		now := time.Now().UTC()
		dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		dayEnd := dayStart.Add(24 * time.Hour)
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		monthEnd := monthStart.AddDate(0, 1, 0)
		weekStart := dayStart.AddDate(0, 0, -6)

		out := cmd.OutOrStdout()

		if costsByModel {
			byModelDaily, err := store.CostByModel(ctx, tenantID, costsAgent, dayStart, dayEnd)
			if err != nil {
				return fmt.Errorf("cost by model (daily): %w", err)
			}
			byModelMonthly, err := store.CostByModel(ctx, tenantID, costsAgent, monthStart, monthEnd)
			if err != nil {
				return fmt.Errorf("cost by model (monthly): %w", err)
			}
			weekTotal, _ := store.CostTotal(ctx, tenantID, costsAgent, weekStart, dayEnd)
			if costsJSON {
				return writeCostsJSON(out, costCurrency, costsPayload{
					TenantID:     tenantID,
					AgentID:      costsAgent,
					TodayEUR:     sumValues(byModelDaily),
					MonthEUR:     sumValues(byModelMonthly),
					SevenDaysEUR: weekTotal,
					ByModelEUR:   byModelDaily,
				})
			}
			renderCostByModel(out, costCurrency, tenantID, costsAgent, byModelDaily, byModelMonthly)
			// Optional: 7d trend (same agent filter when --agent is set)
			fmt.Fprintf(out, "  7d total: %s\n", formatMoney(costCurrency, weekTotal))
			return nil
		}
		if costsByProvider {
			byProviderDaily, err := store.CostByProvider(ctx, tenantID, costsAgent, dayStart, dayEnd)
			if err != nil {
				return fmt.Errorf("cost by provider (daily): %w", err)
			}
			byProviderMonthly, err := store.CostByProvider(ctx, tenantID, costsAgent, monthStart, monthEnd)
			if err != nil {
				return fmt.Errorf("cost by provider (monthly): %w", err)
			}
			weekTotal, _ := store.CostTotal(ctx, tenantID, costsAgent, weekStart, dayEnd)
			if costsJSON {
				return writeCostsJSON(out, costCurrency, costsPayload{
					TenantID:      tenantID,
					AgentID:       costsAgent,
					TodayEUR:      sumValues(byProviderDaily),
					MonthEUR:      sumValues(byProviderMonthly),
					SevenDaysEUR:  weekTotal,
					ByProviderEUR: byProviderDaily,
				})
			}
			renderCostByProvider(out, costCurrency, tenantID, costsAgent, byProviderDaily, byProviderMonthly)
			fmt.Fprintf(out, "  7d total: %s\n", formatMoney(costCurrency, weekTotal))
			return nil
		}
		if costsByTeam {
			byTeamDaily, err := store.CostByTeam(ctx, tenantID, dayStart, dayEnd)
			if err != nil {
				return fmt.Errorf("cost by team (daily): %w", err)
			}
			byTeamMonthly, err := store.CostByTeam(ctx, tenantID, monthStart, monthEnd)
			if err != nil {
				return fmt.Errorf("cost by team (monthly): %w", err)
			}
			if costsJSON {
				weekTotal, _ := store.CostTotal(ctx, tenantID, "", weekStart, dayEnd)
				return writeCostsJSON(out, costCurrency, costsPayload{
					TenantID:     tenantID,
					TodayEUR:     sumValues(byTeamDaily),
					MonthEUR:     sumValues(byTeamMonthly),
					SevenDaysEUR: weekTotal,
					ByTeamEUR:    byTeamDaily,
				})
			}
			renderCostByTeam(out, costCurrency, tenantID, byTeamDaily, byTeamMonthly)
			return nil
		}

		if costsAgent != "" {
			daily, err := store.CostTotal(ctx, tenantID, costsAgent, dayStart, dayEnd)
			if err != nil {
				return fmt.Errorf("cost total daily: %w", err)
			}
			monthly, err := store.CostTotal(ctx, tenantID, costsAgent, monthStart, monthEnd)
			if err != nil {
				return fmt.Errorf("cost total monthly: %w", err)
			}
			dailyBudget, monthlyBudget := resolveBudgetUsage(ctx, cfg, tenantID, costsAgent, daily, monthly)
			if costsJSON {
				weekTotal, _ := store.CostTotal(ctx, tenantID, costsAgent, weekStart, dayEnd)
				return writeCostsJSON(out, costCurrency, costsPayload{
					TenantID:      tenantID,
					AgentID:       costsAgent,
					TodayEUR:      daily,
					MonthEUR:      monthly,
					SevenDaysEUR:  weekTotal,
					DailyBudget:   dailyBudget,
					MonthlyBudget: monthlyBudget,
				})
			}
			renderCostReportSingleAgent(out, costCurrency, tenantID, costsAgent, daily, monthly)
			weekTotal, _ := store.CostTotal(ctx, tenantID, costsAgent, weekStart, dayEnd)
			fmt.Fprintf(out, "  7d total: %s\n", formatMoney(costCurrency, weekTotal))
			printBudgetUtilization(out, costCurrency, dailyBudget, monthlyBudget)
			return nil
		}

		byAgentDaily, err := store.CostByAgent(ctx, tenantID, dayStart, dayEnd)
		if err != nil {
			return fmt.Errorf("cost by agent (daily): %w", err)
		}
		byAgentMonthly, err := store.CostByAgent(ctx, tenantID, monthStart, monthEnd)
		if err != nil {
			return fmt.Errorf("cost by agent (monthly): %w", err)
		}
		dailyTotal, _ := store.CostTotal(ctx, tenantID, "", dayStart, dayEnd)
		monthlyTotal, _ := store.CostTotal(ctx, tenantID, "", monthStart, monthEnd)
		weekTotal, _ := store.CostTotal(ctx, tenantID, "", weekStart, dayEnd)
		dailyBudget, monthlyBudget := resolveBudgetUsage(ctx, cfg, tenantID, "", dailyTotal, monthlyTotal)
		cache7d, cache30d := getCacheUsage(ctx, store, tenantID, weekStart, dayEnd, monthStart, monthEnd)
		if costsJSON {
			return writeCostsJSON(out, costCurrency, costsPayload{
				TenantID:       tenantID,
				TodayEUR:       dailyTotal,
				MonthEUR:       monthlyTotal,
				SevenDaysEUR:   weekTotal,
				ByAgentEUR:     byAgentDaily,
				DailyBudget:    dailyBudget,
				MonthlyBudget:  monthlyBudget,
				CacheSevenDays: cache7d,
				CacheMonth:     cache30d,
			})
		}
		renderCostReportAllAgents(out, costCurrency, tenantID, byAgentDaily, byAgentMonthly)
		fmt.Fprintf(out, "  7d total: %s\n", formatMoney(costCurrency, weekTotal))
		printBudgetUtilization(out, costCurrency, dailyBudget, monthlyBudget)
		printCacheSavings(out, costCurrency, cache7d, cache30d)
		return nil
	},
}

func printCacheSavings(w io.Writer, currency string, cache7d, cache30d *cacheUsage) {
	if cache7d != nil && (cache7d.Hits > 0 || cache7d.SavedEUR > 0) {
		fmt.Fprintf(w, "  Cache (7d):   %d requests from cache, %s saved, %.1f%% hit rate\n", cache7d.Hits, formatMoney(currency, cache7d.SavedEUR), cache7d.HitRate)
	}
	if cache30d != nil && (cache30d.Hits > 0 || cache30d.SavedEUR > 0) {
		fmt.Fprintf(w, "  Cache (30d):  %d requests from cache, %s saved, %.1f%% hit rate\n", cache30d.Hits, formatMoney(currency, cache30d.SavedEUR), cache30d.HitRate)
	}
}

func printBudgetUtilization(w io.Writer, currency string, dailyBudget, monthlyBudget *budgetUsage) {
	if dailyBudget != nil && dailyBudget.LimitEUR > 0 {
		fmt.Fprintf(w, "  Daily budget:   %.1f%% (%s / %s)\n", dailyBudget.Percent, formatMoney(currency, dailyBudget.UsedEUR), pricing.FormatAmount(currency, fmt.Sprintf("%.2f", dailyBudget.LimitEUR)))
	}
	if monthlyBudget != nil && monthlyBudget.LimitEUR > 0 {
		fmt.Fprintf(w, "  Monthly budget: %.1f%% (%s / %s)\n", monthlyBudget.Percent, formatMoney(currency, monthlyBudget.UsedEUR), pricing.FormatAmount(currency, fmt.Sprintf("%.2f", monthlyBudget.LimitEUR)))
	}
}

func resolveBudgetUsage(
	ctx context.Context,
	cfg *config.Config,
	tenantID, agentID string,
	daily, monthly float64,
) (dailyBudget *budgetUsage, monthlyBudget *budgetUsage) {
	if agentID != "" {
		if dailyLimit, monthlyLimit, ok := loadAgentEffectiveCaps(ctx, cfg, tenantID, agentID); ok {
			return toBudgetUsage(daily, dailyLimit, "agent_effective_cap"), toBudgetUsage(monthly, monthlyLimit, "agent_effective_cap")
		}
	}
	pol, err := policy.LoadPolicy(ctx, cfg.DefaultPolicy, false, ".")
	if err != nil || pol == nil || pol.Policies.CostLimits == nil {
		return nil, nil
	}
	cl := pol.Policies.CostLimits
	return toBudgetUsage(daily, cl.Daily, "policy_cost_limits"), toBudgetUsage(monthly, cl.Monthly, "policy_cost_limits")
}

// loadAgentEffectiveCaps reports the agent's effective daily/monthly caps via
// the SAME computation enforcement uses: organization baseline → the agent's
// one override (ResolveEffectivePolicy). `talon costs` must never disagree
// with what runtime gated on (#216, #266). Caps are provider-independent, so
// the destination constraints are empty.
func loadAgentEffectiveCaps(ctx context.Context, cfg *config.Config, tenantID, agentID string) (dailyLimit float64, monthlyLimit float64, ok bool) {
	path := strings.TrimSpace(os.Getenv("TALON_GATEWAY_CONFIG"))
	if path == "" {
		path = "talon.config.yaml"
	}
	gwCfg, err := gateway.LoadGatewayConfig(path)
	if err != nil {
		return 0, 0, false
	}
	pol, err := policy.LoadPolicy(ctx, cfg.DefaultPolicy, false, ".")
	if err != nil || pol == nil {
		return 0, 0, false
	}
	la := LoadedAgentFromPolicy(pol, cfg.DefaultPolicy)
	agentTenant := la.TenantID
	if agentTenant == "" {
		agentTenant = "default"
	}
	if la.Name != agentID || agentTenant != tenantID {
		return 0, 0, false
	}
	eff := gateway.ResolveEffectivePolicy(gwCfg.OrganizationPolicy, gateway.ProviderConfig{}, la.Override)
	// Binding caps: an org ceiling (constraints.max_*) tighter than the
	// agent's own cap is what enforcement gates on (#287).
	daily, monthly := eff.BindingDailyCap(), eff.BindingMonthlyCap()
	return daily, monthly, daily > 0 || monthly > 0
}

func toBudgetUsage(used, limit float64, source string) *budgetUsage {
	if limit <= 0 {
		return nil
	}
	return &budgetUsage{
		UsedEUR:  used,
		LimitEUR: limit,
		Percent:  100 * used / limit,
		Source:   source,
	}
}

func getCacheUsage(
	ctx context.Context,
	store *evidence.Store,
	tenantID string,
	weekStart, dayEnd, monthStart, monthEnd time.Time,
) (sevenDays *cacheUsage, month *cacheUsage) {
	hits7d, saved7d, err := store.CacheSavings(ctx, tenantID, weekStart, dayEnd)
	if err != nil {
		return nil, nil
	}
	total7d, _ := store.CountInRange(ctx, tenantID, "", weekStart, dayEnd)
	sevenDays = &cacheUsage{
		Hits:      hits7d,
		SavedEUR:  saved7d,
		HitRate:   percentage(int(hits7d), total7d),
		TotalSeen: total7d,
	}
	hits30d, saved30d, err := store.CacheSavings(ctx, tenantID, monthStart, monthEnd)
	if err != nil {
		return sevenDays, nil
	}
	total30d, _ := store.CountInRange(ctx, tenantID, "", monthStart, monthEnd)
	month = &cacheUsage{
		Hits:      hits30d,
		SavedEUR:  saved30d,
		HitRate:   percentage(int(hits30d), total30d),
		TotalSeen: total30d,
	}
	return sevenDays, month
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

func writeCostsJSON(w io.Writer, currency string, payload costsPayload) error {
	payload.Currency = currency
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("encoding costs json: %w", err)
	}
	return nil
}

func costsExport(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
	defer cancel()

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	from, to, err := parseAuditDateRange(costsExportFrom, costsExportTo)
	if err != nil {
		return err
	}
	agentID := strings.TrimSpace(costsExportAgent)
	tenantID := strings.TrimSpace(costsExportTenant)
	if tenantID == "" {
		tenantID = "default"
	}
	limit := costsExportLimit
	if limit <= 0 {
		limit = 10000
	}
	list, err := store.List(ctx, tenantID, agentID, from, to, limit)
	if err != nil {
		return fmt.Errorf("querying evidence: %w", err)
	}
	records := toExportRecords(list)

	out, cleanup, err := resolveExportOutput(cmd, costsExportOutput)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	switch costsExportFmt {
	case "csv":
		return renderCostsExportCSV(out, records)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(records)
	default:
		return fmt.Errorf("unsupported --format %q; use csv or json", costsExportFmt)
	}
}

func renderCostsExportCSV(w io.Writer, records []evidence.ExportRecord) error {
	writer := csv.NewWriter(w)
	header := []string{
		"evidence_id", "tenant_id", "agent_id", "timestamp", "model", "provider",
		"cost", "currency", "input_tokens", "output_tokens", "policy_decision", "policy_reason",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for i := range records {
		rec := &records[i]
		decision := rec.PolicyAction
		if decision == "" {
			if rec.Allowed {
				decision = "allow"
			} else {
				decision = "deny"
			}
		}
		row := []string{
			rec.ID,
			rec.TenantID,
			rec.AgentID,
			rec.Timestamp.Format(time.RFC3339),
			rec.ModelUsed,
			rec.Provider,
			formatCostNumeric(rec.Cost),
			exportCurrency(rec.Currency),
			strconv.Itoa(rec.InputTokens),
			strconv.Itoa(rec.OutputTokens),
			decision,
			rec.PolicyReasonsCSV(),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

// renderCostReportSingleAgent writes single-agent cost output to w (testable).
func renderCostReportSingleAgent(w io.Writer, currency, tenantID, agentID string, daily, monthly float64) {
	fmt.Fprintf(w, "Tenant: %s | Agent: %s\n", tenantID, agentID)
	fmt.Fprintf(w, "  Today:   %s\n", formatMoney(currency, daily))
	fmt.Fprintf(w, "  Month:   %s\n", formatMoney(currency, monthly))
}

// renderCostByModel writes per-model cost table to w. If agentID is non-empty, the header shows tenant and agent.
//
//nolint:dupl // similar to renderCostReportAllAgents but for model grouping; keeping separate for clarity
func renderCostByModel(w io.Writer, currency, tenantID, agentID string, byModelDaily, byModelMonthly map[string]float64) {
	models := make(map[string]bool)
	for m := range byModelDaily {
		models[m] = true
	}
	for m := range byModelMonthly {
		models[m] = true
	}
	var list []string
	for m := range models {
		list = append(list, m)
	}
	sort.Strings(list)
	if agentID != "" {
		fmt.Fprintf(w, "Tenant: %s | Agent: %s (by model)\n", tenantID, agentID)
	} else {
		fmt.Fprintf(w, "Tenant: %s (by model)\n", tenantID)
	}
	fmt.Fprintf(w, "%-32s %14s %14s\n", "Model", "Today", "Month")
	fmt.Fprintf(w, "%-32s %14s %14s\n", "-----", "-----", "-----")
	var dailyTotal, monthlyTotal float64
	for _, model := range list {
		d := byModelDaily[model]
		m := byModelMonthly[model]
		dailyTotal += d
		monthlyTotal += m
		fmt.Fprintf(w, "%-32s %14s %14s\n", model, formatMoney(currency, d), formatMoney(currency, m))
	}
	if len(list) > 0 {
		fmt.Fprintf(w, "%-32s %14s %14s\n", "-----", "-----", "-----")
	}
	fmt.Fprintf(w, "%-32s %14s %14s\n", "Total", formatMoney(currency, dailyTotal), formatMoney(currency, monthlyTotal))
}

// renderCostByProvider writes per-provider cost table to w.
//
//nolint:dupl // parallel to model/team renderers by design for readability in CLI output
func renderCostByProvider(w io.Writer, currency, tenantID, agentID string, byProviderDaily, byProviderMonthly map[string]float64) {
	providers := make(map[string]bool)
	for p := range byProviderDaily {
		providers[p] = true
	}
	for p := range byProviderMonthly {
		providers[p] = true
	}
	var list []string
	for p := range providers {
		list = append(list, p)
	}
	sort.Strings(list)
	if agentID != "" {
		fmt.Fprintf(w, "Tenant: %s | Agent: %s (by provider)\n", tenantID, agentID)
	} else {
		fmt.Fprintf(w, "Tenant: %s (by provider)\n", tenantID)
	}
	fmt.Fprintf(w, "%-20s %14s %14s\n", "Provider", "Today", "Month")
	fmt.Fprintf(w, "%-20s %14s %14s\n", "--------", "-----", "-----")
	var dailyTotal, monthlyTotal float64
	for _, provider := range list {
		d := byProviderDaily[provider]
		m := byProviderMonthly[provider]
		dailyTotal += d
		monthlyTotal += m
		fmt.Fprintf(w, "%-20s %14s %14s\n", provider, formatMoney(currency, d), formatMoney(currency, m))
	}
	if len(list) > 0 {
		fmt.Fprintf(w, "%-20s %14s %14s\n", "--------", "-----", "-----")
	}
	fmt.Fprintf(w, "%-20s %14s %14s\n", "Total", formatMoney(currency, dailyTotal), formatMoney(currency, monthlyTotal))
}

// renderCostByTeam writes per-team cost table to w (testable).
//
//nolint:dupl // similar to renderCostByModel but for team grouping; keeping separate for clarity
func renderCostByTeam(w io.Writer, currency, tenantID string, byTeamDaily, byTeamMonthly map[string]float64) {
	teams := make(map[string]bool)
	for t := range byTeamDaily {
		teams[t] = true
	}
	for t := range byTeamMonthly {
		teams[t] = true
	}
	var list []string
	for t := range teams {
		list = append(list, t)
	}
	sort.Strings(list)
	fmt.Fprintf(w, "Tenant: %s (by team)\n", tenantID)
	fmt.Fprintf(w, "%-32s %14s %14s\n", "Team", "Today", "Month")
	fmt.Fprintf(w, "%-32s %14s %14s\n", "-----", "-----", "-----")
	var dailyTotal, monthlyTotal float64
	for _, team := range list {
		d := byTeamDaily[team]
		m := byTeamMonthly[team]
		dailyTotal += d
		monthlyTotal += m
		fmt.Fprintf(w, "%-32s %14s %14s\n", team, formatMoney(currency, d), formatMoney(currency, m))
	}
	if len(list) > 0 {
		fmt.Fprintf(w, "%-32s %14s %14s\n", "-----", "-----", "-----")
	}
	fmt.Fprintf(w, "%-32s %14s %14s\n", "Total", formatMoney(currency, dailyTotal), formatMoney(currency, monthlyTotal))
}

// renderCostReportAllAgents writes per-agent cost table to w (testable).
//
//nolint:dupl // similar to renderCostByModel but for agent grouping; keeping separate for clarity
func renderCostReportAllAgents(w io.Writer, currency, tenantID string, byAgentDaily, byAgentMonthly map[string]float64) {
	agents := make(map[string]bool)
	for a := range byAgentDaily {
		agents[a] = true
	}
	for a := range byAgentMonthly {
		agents[a] = true
	}
	var list []string
	for a := range agents {
		list = append(list, a)
	}
	sort.Strings(list)
	fmt.Fprintf(w, "Tenant: %s\n", tenantID)
	fmt.Fprintf(w, "%-24s %14s %14s\n", "Agent", "Today", "Month")
	fmt.Fprintf(w, "%-24s %14s %14s\n", "----", "-----", "-----")
	var dailyTotal, monthlyTotal float64
	for _, agentID := range list {
		d := byAgentDaily[agentID]
		m := byAgentMonthly[agentID]
		dailyTotal += d
		monthlyTotal += m
		fmt.Fprintf(w, "%-24s %14s %14s\n", agentID, formatMoney(currency, d), formatMoney(currency, m))
	}
	if len(list) > 0 {
		fmt.Fprintf(w, "%-24s %14s %14s\n", "----", "-----", "-----")
	}
	fmt.Fprintf(w, "%-24s %14s %14s\n", "Total", formatMoney(currency, dailyTotal), formatMoney(currency, monthlyTotal))
}

func init() {
	rootCmd.AddCommand(costsCmd)
	costsCmd.AddCommand(costsExportCmd)
	costsCmd.Flags().StringVar(&costsAgent, "agent", "", "filter by agent name")
	costsCmd.Flags().StringVar(&costsTenant, "tenant", "", "tenant ID (default: default)")
	costsCmd.Flags().BoolVar(&costsByModel, "by-model", false, "group output by model")
	costsCmd.Flags().BoolVar(&costsByProvider, "by-provider", false, "group output by provider")
	costsCmd.Flags().BoolVar(&costsByTeam, "by-team", false, "group output by agent team")
	costsCmd.Flags().StringVar(&costsSession, "session", "", "show a per-session cost rollup (session_id)")
	costsCmd.Flags().BoolVar(&costsJSON, "json", false, "output results as JSON")
	costsExportCmd.Flags().StringVar(&costsExportFmt, "format", "csv", "output format: csv or json")
	costsExportCmd.Flags().StringVar(&costsExportFrom, "from", "", "start date (YYYY-MM-DD)")
	costsExportCmd.Flags().StringVar(&costsExportTo, "to", "", "end date (YYYY-MM-DD)")
	costsExportCmd.Flags().StringVar(&costsExportTenant, "tenant", "", "tenant ID (default: default)")
	costsExportCmd.Flags().StringVar(&costsExportAgent, "agent", "", "filter by agent name")
	costsExportCmd.Flags().StringVar(&costsExportOutput, "output", "", "write to file instead of stdout")
	costsExportCmd.Flags().IntVar(&costsExportLimit, "limit", 10000, "maximum records to export")
}
