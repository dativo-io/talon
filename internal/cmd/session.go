package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	talonsession "github.com/dativo-io/talon/internal/session"
)

var (
	sessTenant string
	sessStatus string
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage sessions (workflow grouping)",
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List sessions",
	RunE:  sessionList,
}

var sessionShowCmd = &cobra.Command{
	Use:   "show [session-id]",
	Short: "Show session details",
	Args:  cobra.ExactArgs(1),
	RunE:  sessionShow,
}

func init() {
	sessionListCmd.Flags().StringVar(&sessTenant, "tenant", "default", "Tenant ID")
	sessionListCmd.Flags().StringVar(&sessStatus, "status", "", "Filter by status")
	sessionCmd.AddCommand(sessionListCmd, sessionShowCmd)
	rootCmd.AddCommand(sessionCmd)
}

func sessionList(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	store, err := talonsession.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return fmt.Errorf("opening session store: %w", err)
	}
	defer store.Close()

	sessions, err := store.ListByTenant(context.Background(), sessTenant, talonsession.Status(sessStatus))
	if err != nil {
		return fmt.Errorf("listing sessions: %w", err)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tAGENT\tCOST\tTOKENS\tCREATED")
	for _, s := range sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.4f\t%d\t%s\n",
			s.ID, s.Status, s.AgentID, s.TotalCost, s.TotalTokens, s.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	tw.Flush()
	return nil
}

func sessionShow(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	store, err := talonsession.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return fmt.Errorf("opening session store: %w", err)
	}
	defer store.Close()

	sess, err := store.Get(context.Background(), args[0])
	if err != nil {
		return fmt.Errorf("getting session %s: %w", args[0], err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(sess)
}
