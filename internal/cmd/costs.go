package cmd

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
)

var (
	costsAgent   string
	costsTenant  string
	costsByModel bool
)

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

		tenantID := costsTenant
		if tenantID == "" {
			tenantID = "default"
		}

		now := time.Now().UTC()
		dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		dayEnd := dayStart.Add(24 * time.Hour)
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		monthEnd := monthStart.AddDate(0, 1, 0)
		weekStart := dayStart.AddDate(0, 0, -6)

		out := cmd.OutOrStdout()

		if costsByModel {
			byModelDaily, err := store.CostByModel(ctx, tenantID, dayStart, dayEnd)
			if err != nil {
				return fmt.Errorf("cost by model (daily): %w", err)
			}
			byModelMonthly, err := store.CostByModel(ctx, tenantID, monthStart, monthEnd)
			if err != nil {
				return fmt.Errorf("cost by model (monthly): %w", err)
			}
			renderCostByModel(out, tenantID, byModelDaily, byModelMonthly)
			// Optional: 7d trend
			weekTotal, _ := store.CostTotal(ctx, tenantID, "", weekStart, dayEnd)
			fmt.Fprintf(out, "  7d total: €%s\n", formatCost(weekTotal))
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
			renderCostReportSingleAgent(out, tenantID, costsAgent, daily, monthly)
			weekTotal, _ := store.CostTotal(ctx, tenantID, costsAgent, weekStart, dayEnd)
			fmt.Fprintf(out, "  7d total: €%s\n", formatCost(weekTotal))
			printBudgetUtilization(out, ctx, cfg, tenantID, daily, monthly)
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
		renderCostReportAllAgents(out, tenantID, byAgentDaily, byAgentMonthly)
		dailyTotal, _ := store.CostTotal(ctx, tenantID, "", dayStart, dayEnd)
		monthlyTotal, _ := store.CostTotal(ctx, tenantID, "", monthStart, monthEnd)
		weekTotal, _ := store.CostTotal(ctx, tenantID, "", weekStart, dayEnd)
		fmt.Fprintf(out, "  7d total: €%s\n", formatCost(weekTotal))
		printBudgetUtilization(out, ctx, cfg, tenantID, dailyTotal, monthlyTotal)
		return nil
	},
}

func printBudgetUtilization(w io.Writer, ctx context.Context, cfg *config.Config, tenantID string, daily, monthly float64) {
	pol, err := policy.LoadPolicy(ctx, cfg.DefaultPolicy, false)
	if err != nil || pol == nil || pol.Policies.CostLimits == nil {
		return
	}
	cl := pol.Policies.CostLimits
	if cl.Daily > 0 {
		pct := 0.0
		if cl.Daily > 0 {
			pct = 100 * daily / cl.Daily
		}
		fmt.Fprintf(w, "  Daily budget:   %.1f%% (€%s / €%.2f)\n", pct, formatCost(daily), cl.Daily)
	}
	if cl.Monthly > 0 {
		pct := 0.0
		if cl.Monthly > 0 {
			pct = 100 * monthly / cl.Monthly
		}
		fmt.Fprintf(w, "  Monthly budget: %.1f%% (€%s / €%.2f)\n", pct, formatCost(monthly), cl.Monthly)
	}
}

// renderCostReportSingleAgent writes single-agent cost output to w (testable).
func renderCostReportSingleAgent(w io.Writer, tenantID, agentID string, daily, monthly float64) {
	fmt.Fprintf(w, "Tenant: %s | Agent: %s\n", tenantID, agentID)
	fmt.Fprintf(w, "  Today:   €%s\n", formatCost(daily))
	fmt.Fprintf(w, "  Month:   €%s\n", formatCost(monthly))
}

// renderCostByModel writes per-model cost table to w.
//
//nolint:dupl // similar to renderCostReportAllAgents but for model grouping; keeping separate for clarity
func renderCostByModel(w io.Writer, tenantID string, byModelDaily, byModelMonthly map[string]float64) {
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
	fmt.Fprintf(w, "Tenant: %s (by model)\n", tenantID)
	fmt.Fprintf(w, "%-32s %14s %14s\n", "Model", "Today", "Month")
	fmt.Fprintf(w, "%-32s %14s %14s\n", "-----", "-----", "-----")
	var dailyTotal, monthlyTotal float64
	for _, model := range list {
		d := byModelDaily[model]
		m := byModelMonthly[model]
		dailyTotal += d
		monthlyTotal += m
		fmt.Fprintf(w, "%-32s €%13s €%13s\n", model, formatCost(d), formatCost(m))
	}
	if len(list) > 0 {
		fmt.Fprintf(w, "%-32s %14s %14s\n", "-----", "-----", "-----")
	}
	fmt.Fprintf(w, "%-32s €%13s €%13s\n", "Total", formatCost(dailyTotal), formatCost(monthlyTotal))
}

// renderCostReportAllAgents writes per-agent cost table to w (testable).
//
//nolint:dupl // similar to renderCostByModel but for agent grouping; keeping separate for clarity
func renderCostReportAllAgents(w io.Writer, tenantID string, byAgentDaily, byAgentMonthly map[string]float64) {
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
		fmt.Fprintf(w, "%-24s €%13s €%13s\n", agentID, formatCost(d), formatCost(m))
	}
	if len(list) > 0 {
		fmt.Fprintf(w, "%-24s %14s %14s\n", "----", "-----", "-----")
	}
	fmt.Fprintf(w, "%-24s €%13s €%13s\n", "Total", formatCost(dailyTotal), formatCost(monthlyTotal))
}

func init() {
	rootCmd.AddCommand(costsCmd)
	costsCmd.Flags().StringVar(&costsAgent, "agent", "", "filter by agent name")
	costsCmd.Flags().StringVar(&costsTenant, "tenant", "", "tenant ID (default: default)")
	costsCmd.Flags().BoolVar(&costsByModel, "by-model", false, "group output by model")
}
