package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	talonprompt "github.com/dativo-io/talon/internal/prompt"
)

var (
	promptTenant string
	promptAgent  string
	promptLimit  int
)

var promptCmd = &cobra.Command{
	Use:   "prompt",
	Short: "Prompt version history",
}

var promptHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Show stored prompt versions for an agent",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		store, err := talonprompt.NewStore(cfg.EvidenceDBPath())
		if err != nil {
			return err
		}
		defer store.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		list, err := store.List(ctx, promptTenant, promptAgent, promptLimit)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "HASH\tFIRST_SEEN\tCONTENT_PREVIEW")
		for _, v := range list {
			preview := v.Content
			if len(preview) > 64 {
				preview = preview[:64] + "..."
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", v.Hash, v.FirstSeen.Format(time.RFC3339), preview)
		}
		return nil
	},
}

func init() {
	promptHistoryCmd.Flags().StringVar(&promptTenant, "tenant", "default", "Tenant ID")
	promptHistoryCmd.Flags().StringVar(&promptAgent, "agent", "default", "Agent ID")
	promptHistoryCmd.Flags().IntVar(&promptLimit, "limit", 20, "Max prompt versions to show")
	promptCmd.AddCommand(promptHistoryCmd)
	rootCmd.AddCommand(promptCmd)
}
