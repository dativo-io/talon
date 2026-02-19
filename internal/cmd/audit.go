package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
)

var (
	auditTenant    string
	auditAgent     string
	auditLimit     int
	auditExportFmt string
	auditFrom      string
	auditTo        string
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

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export evidence records as CSV or JSON for compliance",
	RunE:  auditExport,
}

func init() {
	auditListCmd.Flags().StringVar(&auditTenant, "tenant", "", "Filter by tenant ID")
	auditListCmd.Flags().StringVar(&auditAgent, "agent", "", "Filter by agent ID")
	auditListCmd.Flags().IntVar(&auditLimit, "limit", 20, "Maximum records to show")

	auditExportCmd.Flags().StringVar(&auditExportFmt, "format", "csv", "Output format: csv or json")
	auditExportCmd.Flags().StringVar(&auditFrom, "from", "", "Start date (YYYY-MM-DD)")
	auditExportCmd.Flags().StringVar(&auditTo, "to", "", "End date (YYYY-MM-DD)")
	auditExportCmd.Flags().StringVar(&auditTenant, "tenant", "", "Filter by tenant ID")
	auditExportCmd.Flags().StringVar(&auditAgent, "agent", "", "Filter by agent ID")
	auditExportCmd.Flags().IntVar(&auditLimit, "limit", 10000, "Maximum records to export")

	auditCmd.AddCommand(auditListCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	auditCmd.AddCommand(auditExportCmd)
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
	renderAuditList(os.Stdout, index)
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
	renderVerifyResult(os.Stdout, evidenceID, valid)
	if !valid {
		return fmt.Errorf("signature verification failed for %s", evidenceID)
	}
	return nil
}

func auditExport(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
	defer cancel()

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	var from, to time.Time
	if auditFrom != "" {
		var errParse error
		from, errParse = time.ParseInLocation("2006-01-02", auditFrom, time.UTC)
		if errParse != nil {
			return fmt.Errorf("invalid --from: %w", errParse)
		}
	}
	if auditTo != "" {
		var errParse error
		to, errParse = time.ParseInLocation("2006-01-02", auditTo, time.UTC)
		if errParse != nil {
			return fmt.Errorf("invalid --to: %w", errParse)
		}
		if !to.IsZero() {
			to = to.Add(24 * time.Hour)
		}
	}

	index, err := store.ListIndex(ctx, auditTenant, auditAgent, from, to, auditLimit)
	if err != nil {
		return fmt.Errorf("querying evidence: %w", err)
	}

	switch auditExportFmt {
	case "csv":
		return renderAuditExportCSV(os.Stdout, index)
	case "json":
		return renderAuditExportJSON(os.Stdout, index)
	default:
		return fmt.Errorf("unsupported --format %q; use csv or json", auditExportFmt)
	}
}

func renderAuditExportCSV(w io.Writer, index []evidence.Index) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()
	header := []string{"id", "timestamp", "tenant_id", "agent_id", "invocation_type", "allowed", "cost_eur", "model_used", "duration_ms", "has_error"}
	if err := writer.Write(header); err != nil {
		return err
	}
	for i := range index {
		row := []string{
			index[i].ID,
			index[i].Timestamp.Format(time.RFC3339),
			index[i].TenantID,
			index[i].AgentID,
			index[i].InvocationType,
			strconv.FormatBool(index[i].Allowed),
			strconv.FormatFloat(index[i].CostEUR, 'f', 4, 64),
			index[i].ModelUsed,
			strconv.FormatInt(index[i].DurationMS, 10),
			strconv.FormatBool(index[i].HasError),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func renderAuditExportJSON(w io.Writer, index []evidence.Index) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(index)
}

// renderAuditList writes evidence index lines to w (testable).
func renderAuditList(w io.Writer, index []evidence.Index) {
	fmt.Fprintf(w, "Evidence Records (showing %d):\n\n", len(index))
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
		fmt.Fprintf(w, "  %s %s | %s | %s/%s | %s | \u20ac%.4f | %dms%s\n",
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
}

// renderVerifyResult writes verify outcome to w (testable).
func renderVerifyResult(w io.Writer, evidenceID string, valid bool) {
	if valid {
		fmt.Fprintf(w, "\u2713 Evidence %s: signature VALID (HMAC-SHA256 intact)\n", evidenceID)
	} else {
		fmt.Fprintf(w, "\u2717 Evidence %s: signature INVALID (possible tampering)\n", evidenceID)
	}
}
