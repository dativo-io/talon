package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
)

var (
	auditTenant string
	auditAgent  string
	auditLimit  int
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Query and export audit trail (evidence)",
}

var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List evidence records",
	RunE:  auditList,
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify [evidence-id]",
	Short: "Verify HMAC signature of an evidence record",
	Args:  cobra.ExactArgs(1),
	RunE:  auditVerify,
}

func init() {
	auditListCmd.Flags().StringVar(&auditTenant, "tenant", "", "Filter by tenant ID")
	auditListCmd.Flags().StringVar(&auditAgent, "agent", "", "Filter by agent ID")
	auditListCmd.Flags().IntVar(&auditLimit, "limit", 20, "Maximum records to show")

	auditCmd.AddCommand(auditListCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	rootCmd.AddCommand(auditCmd)
}

func openEvidenceStore() (*evidence.Store, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}

	return evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
}

func auditList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	index, err := store.ListIndex(ctx, auditTenant, auditAgent, time.Time{}, time.Time{}, auditLimit)
	if err != nil {
		return fmt.Errorf("querying evidence: %w", err)
	}

	if len(index) == 0 {
		fmt.Println("No evidence records found.")
		return nil
	}

	fmt.Printf("Evidence Records (showing %d):\n\n", len(index))
	for i := range index {
		entry := &index[i]
		status := "\u2713"
		if !entry.Allowed {
			status = "\u2717"
		}
		errorMark := ""
		if entry.HasError {
			errorMark = " [ERROR]"
		}
		fmt.Printf("  %s %s | %s | %s/%s | %s | \u20ac%.4f | %dms%s\n",
			status,
			entry.ID,
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.TenantID,
			entry.AgentID,
			entry.ModelUsed,
			entry.CostEUR,
			entry.DurationMS,
			errorMark,
		)
	}

	return nil
}

func auditVerify(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	evidenceID := args[0]

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	valid, err := store.Verify(ctx, evidenceID)
	if err != nil {
		return fmt.Errorf("verifying evidence: %w", err)
	}

	if valid {
		fmt.Printf("\u2713 Evidence %s: signature VALID (HMAC-SHA256 intact)\n", evidenceID)
	} else {
		fmt.Printf("\u2717 Evidence %s: signature INVALID (possible tampering)\n", evidenceID)
		return fmt.Errorf("signature verification failed for %s", evidenceID)
	}

	return nil
}
