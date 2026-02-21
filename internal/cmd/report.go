package cmd

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
)

var reportTenant string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Print a compliance summary (evidence count, cost, period)",
	Long:  "Summarizes evidence records and spend for the default tenant — useful for SMB compliance reviews.",
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportTenant, "tenant", "default", "Tenant ID to summarize")
	rootCmd.AddCommand(reportCmd)
}

//nolint:gocyclo // report aggregates multiple evidence dimensions in one pass
func runReport(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	todayEnd := todayStart.Add(24 * time.Hour)
	weekStart := todayStart.AddDate(0, 0, -6) // 7-day window
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)

	countToday, _ := store.CountInRange(ctx, reportTenant, "", todayStart, todayEnd)
	countWeek, _ := store.CountInRange(ctx, reportTenant, "", weekStart, todayEnd)
	costToday, _ := store.CostTotal(ctx, reportTenant, "", todayStart, todayEnd)
	costMonth, _ := store.CostTotal(ctx, reportTenant, "", monthStart, monthEnd)

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Compliance summary — tenant %s\n", reportTenant)
	fmt.Fprintf(out, "  Evidence records today:  %d\n", countToday)
	fmt.Fprintf(out, "  Evidence records (7d):   %d\n", countWeek)
	fmt.Fprintf(out, "  Cost today (EUR):        %.4f\n", costToday)
	fmt.Fprintf(out, "  Cost this month (EUR):   %.4f\n", costMonth)

	// Enriched stats over 7-day window
	list, err := store.List(ctx, reportTenant, "", weekStart, todayEnd, 10000)
	if err == nil && len(list) > 0 {
		var denied, withError, withPII int
		piiTypes := make(map[string]int)
		modelCount := make(map[string]int)
		for i := range list {
			ev := &list[i]
			if !ev.PolicyDecision.Allowed {
				denied++
			}
			if ev.Execution.Error != "" {
				withError++
			}
			if len(ev.Classification.PIIDetected) > 0 {
				withPII++
				for _, t := range ev.Classification.PIIDetected {
					piiTypes[t]++
				}
			}
			if ev.Execution.ModelUsed != "" {
				modelCount[ev.Execution.ModelUsed]++
			}
		}
		total := len(list)
		fmt.Fprintf(out, "  Policy denials (7d):     %d (%.1f%%)\n", denied, pct(denied, total))
		fmt.Fprintf(out, "  Error rate (7d):         %d / %d (%.1f%%)\n", withError, total, pct(withError, total))
		if withPII > 0 {
			fmt.Fprintf(out, "  Records with PII (7d):   %d\n", withPII)
			var types []string
			for t := range piiTypes {
				types = append(types, t)
			}
			sort.Strings(types)
			for _, t := range types {
				fmt.Fprintf(out, "    - %s: %d\n", t, piiTypes[t])
			}
		}
		if len(modelCount) > 0 {
			fmt.Fprintf(out, "  Model breakdown (7d):\n")
			var models []string
			for m := range modelCount {
				models = append(models, m)
			}
			sort.Strings(models)
			for _, m := range models {
				fmt.Fprintf(out, "    - %s: %d\n", m, modelCount[m])
			}
		}
	}

	fmt.Fprintln(out)
	return nil
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}
