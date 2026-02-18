package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
)

var (
	costsAgent  string
	costsTenant string
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

		if costsAgent != "" {
			daily, err := store.CostTotal(ctx, tenantID, costsAgent, dayStart, dayEnd)
			if err != nil {
				return fmt.Errorf("cost total daily: %w", err)
			}
			monthly, err := store.CostTotal(ctx, tenantID, costsAgent, monthStart, monthEnd)
			if err != nil {
				return fmt.Errorf("cost total monthly: %w", err)
			}
			renderCostReportSingleAgent(os.Stdout, tenantID, costsAgent, daily, monthly)
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
		renderCostReportAllAgents(os.Stdout, tenantID, byAgentDaily, byAgentMonthly)
		return nil
	},
}

// renderCostReportSingleAgent writes single-agent cost output to w (testable).
func renderCostReportSingleAgent(w io.Writer, tenantID, agentID string, daily, monthly float64) {
	fmt.Fprintf(w, "Tenant: %s | Agent: %s\n", tenantID, agentID)
	fmt.Fprintf(w, "  Today:   €%.4f\n", daily)
	fmt.Fprintf(w, "  Month:   €%.4f\n", monthly)
}

// renderCostReportAllAgents writes per-agent cost table to w (testable).
func renderCostReportAllAgents(w io.Writer, tenantID string, byAgentDaily, byAgentMonthly map[string]float64) {
	var dailyTotal, monthlyTotal float64
	agents := make(map[string]bool)
	for a := range byAgentDaily {
		agents[a] = true
	}
	for a := range byAgentMonthly {
		agents[a] = true
	}
	fmt.Fprintf(w, "Tenant: %s\n", tenantID)
	fmt.Fprintf(w, "%-24s %12s %12s\n", "Agent", "Today", "Month")
	fmt.Fprintf(w, "%-24s %12s %12s\n", "----", "-----", "-----")
	for agentID := range agents {
		d := byAgentDaily[agentID]
		m := byAgentMonthly[agentID]
		dailyTotal += d
		monthlyTotal += m
		fmt.Fprintf(w, "%-24s €%11.4f €%11.4f\n", agentID, d, m)
	}
	fmt.Fprintf(w, "%-24s %12s %12s\n", "----", "-----", "-----")
	fmt.Fprintf(w, "%-24s €%11.4f €%11.4f\n", "Total", dailyTotal, monthlyTotal)
}

func init() {
	rootCmd.AddCommand(costsCmd)
	costsCmd.Flags().StringVar(&costsAgent, "agent", "", "filter by agent name")
	costsCmd.Flags().StringVar(&costsTenant, "tenant", "", "tenant ID (default: default)")
}
