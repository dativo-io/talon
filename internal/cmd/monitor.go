package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/drift"
)

var monitorTenant string

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Show drift signals derived from evidence",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
		defer cancel()
		store, err := openEvidenceStore()
		if err != nil {
			return fmt.Errorf("initializing evidence store: %w", err)
		}
		defer store.Close()
		a := drift.NewAnalyzer(store)
		now := time.Now().UTC()
		rows, err := a.ComputeSignals(ctx, monitorTenant, now)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Agent Drift Signals (24h vs previous 7d)")
		fmt.Fprintln(cmd.OutOrStdout(), "AGENT\tSIGNAL\tCURRENT\tBASELINE\tZSCORE\tALERT")
		for _, r := range rows {
			for _, s := range r.Signals {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%.4f\t%.4f\t%.2f\t%t\n",
					r.AgentID, s.Name, s.Current, s.Baseline, s.ZScore, s.Alert)
			}
		}
		return nil
	},
}

func init() {
	monitorCmd.Flags().StringVar(&monitorTenant, "tenant", "", "Tenant ID filter")
	rootCmd.AddCommand(monitorCmd)
}
