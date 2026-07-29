package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/scoring"
)

var (
	agentsTenant string
	agentsID     string
)

// agentsCmd is only DECLARED here. The agents ROOT behavior — the attention
// queue (`talon agents`), `agents show`, and the --url/--tenant/--json flags —
// is implemented in agents_root.go (wired onto this command in its init). Two
// independent readers have concluded from this file alone that
// `talon agents --url` doesn't exist (#380); it does — read agents_root.go
// before drawing conclusions about the root command.
var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Agent analytics commands",
}

var agentsScoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Compute governance maturity score for an agent",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
		defer cancel()
		store, err := openEvidenceStore()
		if err != nil {
			return err
		}
		defer store.Close()
		from := time.Now().UTC().Add(-30 * 24 * time.Hour)
		list, err := store.List(ctx, agentsTenant, agentsID, from, time.Now().UTC(), 200000)
		if err != nil {
			return err
		}
		s := scoring.Compute(list, agentsID)
		fmt.Fprintf(cmd.OutOrStdout(), "Agent: %s\nScore: %.2f\nLevel: %s\n", s.AgentID, s.Score, s.Level)
		return nil
	},
}

func init() {
	agentsScoreCmd.Flags().StringVar(&agentsTenant, "tenant", "default", "Tenant ID")
	agentsScoreCmd.Flags().StringVar(&agentsID, "agent", "default", "Agent ID")
	agentsCmd.AddCommand(agentsScoreCmd)
	rootCmd.AddCommand(agentsCmd)
}
