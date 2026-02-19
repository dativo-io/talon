package cmd

import (
	"context"
	"fmt"
	"os"
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
	weekStart := todayStart.AddDate(0, 0, -7)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)

	countToday, _ := store.CountInRange(ctx, reportTenant, "", todayStart, todayEnd)
	countWeek, _ := store.CountInRange(ctx, reportTenant, "", weekStart, todayEnd)
	costToday, _ := store.CostTotal(ctx, reportTenant, "", todayStart, todayEnd)
	costMonth, _ := store.CostTotal(ctx, reportTenant, "", monthStart, monthEnd)

	fmt.Fprintf(os.Stdout, "Compliance summary — tenant %s\n", reportTenant)
	fmt.Fprintf(os.Stdout, "  Evidence records today:  %d\n", countToday)
	fmt.Fprintf(os.Stdout, "  Evidence records (7d):   %d\n", countWeek)
	fmt.Fprintf(os.Stdout, "  Cost today (EUR):        %.4f\n", costToday)
	fmt.Fprintf(os.Stdout, "  Cost this month (EUR):   %.4f\n", costMonth)
	fmt.Fprintln(os.Stdout)
	return nil
}
