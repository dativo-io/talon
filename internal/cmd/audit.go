package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
)

var (
	auditTenant         string
	auditAgent          string
	auditLimit          int // list: max records to show
	auditExportLimit    int // export: max records to export
	auditExportFmt      string
	auditFrom           string
	auditTo             string
	auditCaller         string
	auditViolationsOnly bool
	auditOutputFile     string
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

var auditShowCmd = &cobra.Command{
	Use:   "show [evidence-id]",
	Short: "Show full evidence record (HMAC-verified); with no ID, shows latest",
	Args:  cobra.MaximumNArgs(1),
	RunE:  auditShow,
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify [evidence-id]",
	Short: "Verify HMAC signature of an evidence record",
	Args:  cobra.ExactArgs(1),
	RunE:  auditVerify,
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export evidence records as CSV, JSON, or NDJSON for compliance",
	RunE:  auditExport,
}

func init() {
	auditListCmd.Flags().StringVar(&auditTenant, "tenant", "", "Filter by tenant ID")
	auditListCmd.Flags().StringVar(&auditAgent, "agent", "", "Filter by agent ID")
	auditListCmd.Flags().IntVar(&auditLimit, "limit", 20, "Maximum records to show")

	auditExportCmd.Flags().StringVar(&auditExportFmt, "format", "csv", "Output format: csv, json, or ndjson")
	auditExportCmd.Flags().StringVar(&auditFrom, "from", "", "Start date (YYYY-MM-DD)")
	auditExportCmd.Flags().StringVar(&auditTo, "to", "", "End date (YYYY-MM-DD)")
	auditExportCmd.Flags().StringVar(&auditTenant, "tenant", "", "Filter by tenant ID")
	auditExportCmd.Flags().StringVar(&auditAgent, "agent", "", "Filter by agent ID")
	auditExportCmd.Flags().StringVar(&auditCaller, "caller", "", "Filter by caller name (alias for --agent in gateway context)")
	auditExportCmd.Flags().BoolVar(&auditViolationsOnly, "violations-only", false, "Only export records with policy violations or shadow violations")
	auditExportCmd.Flags().StringVar(&auditOutputFile, "output", "", "Write to file instead of stdout")
	auditExportCmd.Flags().IntVar(&auditExportLimit, "limit", 10000, "Maximum records to export")

	auditCmd.AddCommand(auditListCmd)
	auditCmd.AddCommand(auditShowCmd)
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

	index, err := store.ListIndex(ctx, auditTenant, auditAgent, time.Time{}, time.Time{}, auditLimit, "")
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

func auditShow(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	var evidenceID string
	if len(args) > 0 {
		evidenceID = args[0]
	} else {
		index, err := store.ListIndex(ctx, "", "", time.Time{}, time.Time{}, 1, "")
		if err != nil {
			return fmt.Errorf("listing evidence: %w", err)
		}
		if len(index) == 0 {
			fmt.Println("No evidence records found.")
			return nil
		}
		evidenceID = index[0].ID
		fmt.Fprintf(os.Stderr, "Showing latest: %s\n", evidenceID)
	}

	ev, err := store.Get(ctx, evidenceID)
	if err != nil {
		return fmt.Errorf("fetching evidence: %w", err)
	}
	valid := store.VerifyRecord(ev)
	renderAuditShow(os.Stdout, ev, valid)
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

	ev, err := store.Get(ctx, evidenceID)
	if err != nil {
		return fmt.Errorf("verifying evidence: %w", err)
	}
	valid := store.VerifyRecord(ev)
	renderVerifyResult(os.Stdout, evidenceID, valid, ev)
	if !valid {
		return fmt.Errorf("signature verification failed for %s", evidenceID)
	}
	return nil
}

func auditExport(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
	defer cancel()

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	from, to, err := parseAuditDateRange(auditFrom, auditTo)
	if err != nil {
		return err
	}
	agentFilter := resolveAgentFilter(auditAgent, auditCaller)

	list, err := store.List(ctx, auditTenant, agentFilter, from, to, auditExportLimit)
	if err != nil {
		return fmt.Errorf("querying evidence: %w", err)
	}
	records := filterExportRecords(list, auditViolationsOnly)

	out, cleanup, err := resolveExportOutput(cmd, auditOutputFile)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	switch auditExportFmt {
	case "csv":
		return renderAuditExportCSV(out, records)
	case "json":
		return renderAuditExportJSONWrapped(out, records)
	case "ndjson":
		return renderAuditExportNDJSON(out, records)
	default:
		return fmt.Errorf("unsupported --format %q; use csv, json, or ndjson", auditExportFmt)
	}
}

func parseAuditDateRange(fromStr, toStr string) (from, to time.Time, err error) {
	if fromStr != "" {
		from, err = time.ParseInLocation("2006-01-02", fromStr, time.UTC)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid --from: %w", err)
		}
	}
	if toStr != "" {
		to, err = time.ParseInLocation("2006-01-02", toStr, time.UTC)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid --to: %w", err)
		}
		if !to.IsZero() {
			to = to.Add(24 * time.Hour)
		}
	}
	return from, to, nil
}

func resolveAgentFilter(agent, caller string) string {
	if agent != "" {
		return agent
	}
	return caller
}

func filterExportRecords(list []evidence.Evidence, violationsOnly bool) []evidence.ExportRecord {
	records := make([]evidence.ExportRecord, 0, len(list))
	for i := range list {
		rec := evidence.ToExportRecord(&list[i])
		if violationsOnly && !rec.ObservationModeOverride && rec.Allowed {
			continue
		}
		records = append(records, rec)
	}
	return records
}

func resolveExportOutput(cmd *cobra.Command, outputFile string) (io.Writer, func(), error) {
	if outputFile == "" {
		return cmd.OutOrStdout(), nil, nil
	}
	f, err := os.Create(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("creating output file: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

func renderAuditExportCSV(w io.Writer, records []evidence.ExportRecord) error {
	writer := csv.NewWriter(w)
	header := []string{
		"id", "timestamp", "tenant_id", "agent_id", "invocation_type", "allowed", "cost", "model_used", "duration_ms", "has_error",
		"input_tier", "output_tier", "pii_detected", "pii_redacted", "policy_reasons", "tools_called", "input_hash", "output_hash",
		"observation_mode_override", "shadow_violation_types",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for i := range records {
		r := &records[i]
		row := []string{
			r.ID,
			r.Timestamp.Format(time.RFC3339),
			r.TenantID,
			r.AgentID,
			r.InvocationType,
			strconv.FormatBool(r.Allowed),
			formatCostNumeric(r.Cost),
			r.ModelUsed,
			strconv.FormatInt(r.DurationMS, 10),
			strconv.FormatBool(r.HasError),
			strconv.Itoa(r.InputTier),
			strconv.Itoa(r.OutputTier),
			r.PIIDetectedCSV(),
			strconv.FormatBool(r.PIIRedacted),
			r.PolicyReasonsCSV(),
			r.ToolsCalledCSV(),
			r.InputHash,
			r.OutputHash,
			strconv.FormatBool(r.ObservationModeOverride),
			r.ShadowViolationTypesCSV(),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func renderAuditExportJSONWrapped(w io.Writer, records []evidence.ExportRecord) error {
	envelope := evidence.ExportEnvelope{
		ExportMetadata: evidence.ExportMetadata{
			GeneratedAt:  time.Now().UTC(),
			TalonVersion: resolvedVersion(),
			Filter: evidence.ExportFilter{
				From:   auditFrom,
				To:     auditTo,
				Tenant: auditTenant,
				Agent:  auditAgent,
				Caller: auditCaller,
			},
			TotalRecords: len(records),
		},
		Records: records,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

func renderAuditExportNDJSON(w io.Writer, records []evidence.ExportRecord) error {
	enc := json.NewEncoder(w)
	for i := range records {
		if err := enc.Encode(&records[i]); err != nil {
			return fmt.Errorf("encoding record %s: %w", records[i].ID, err)
		}
	}
	return nil
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
		fmt.Fprintf(w, "  %s %s | %s | %s/%s | %s | €%s | %dms%s\n",
			status,
			entry.ID,
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.TenantID,
			entry.AgentID,
			entry.ModelUsed,
			formatCost(entry.Cost),
			entry.DurationMS,
			errorMark,
		)
	}
}

// renderVerifyResult writes verify outcome and optional compact summary to w (testable).
func renderVerifyResult(w io.Writer, evidenceID string, valid bool, ev *evidence.Evidence) {
	if valid {
		fmt.Fprintf(w, "\u2713 Evidence %s: signature VALID (HMAC-SHA256 intact)\n", evidenceID)
	} else {
		fmt.Fprintf(w, "\u2717 Evidence %s: signature INVALID — record may have been tampered\n", evidenceID)
		if ev != nil {
			fmt.Fprintln(w, "(record contents shown for reference only — do not trust)")
		}
	}
	if ev != nil {
		piiStr := strings.Join(ev.Classification.PIIDetected, ", ")
		if piiStr == "" {
			piiStr = "(none)"
		}
		policyStatus := "ALLOWED"
		if !ev.PolicyDecision.Allowed {
			policyStatus = "DENIED"
		}
		fmt.Fprintf(w, "%s | %s/%s | %s | €%s | %dms\n",
			ev.Timestamp.Format(time.RFC3339),
			ev.TenantID,
			ev.AgentID,
			ev.Execution.ModelUsed,
			formatCost(ev.Execution.Cost),
			ev.Execution.DurationMS,
		)
		fmt.Fprintf(w, "Policy: %s | Tier: %d→%d | PII: %s | Redacted: %t\n",
			policyStatus,
			ev.Classification.InputTier,
			ev.Classification.OutputTier,
			piiStr,
			ev.Classification.PIIRedacted,
		)
	}
}

// renderAuditShow writes a full evidence record (Layer 3) to w. HMAC status is shown prominently.
func renderAuditShow(w io.Writer, ev *evidence.Evidence, valid bool) {
	const sep = "─────────────────────────────────────────────────────"
	fmt.Fprintf(w, "Evidence: %s\n", ev.ID)
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "Timestamp:       %s\n", ev.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, "Tenant / Agent:  %s / %s\n", ev.TenantID, ev.AgentID)
	fmt.Fprintf(w, "Invocation:      %s\n", ev.InvocationType)
	if valid {
		fmt.Fprintf(w, "HMAC Signature:  ✓ VALID\n")
	} else {
		fmt.Fprintf(w, "HMAC Signature:  ✗ INVALID (tampered)\n")
	}
	fmt.Fprintln(w, "Policy Decision")
	fmt.Fprintf(w, "Allowed:       %t\n", ev.PolicyDecision.Allowed)
	fmt.Fprintf(w, "Action:        %s\n", ev.PolicyDecision.Action)
	if ev.PolicyDecision.PolicyVersion != "" {
		fmt.Fprintf(w, "Policy Ver:    %s\n", ev.PolicyDecision.PolicyVersion)
	}
	if !ev.PolicyDecision.Allowed && len(ev.PolicyDecision.Reasons) > 0 {
		for _, r := range ev.PolicyDecision.Reasons {
			fmt.Fprintf(w, "  Reason:      %s\n", r)
		}
	}
	fmt.Fprintln(w, "Classification")
	fmt.Fprintf(w, "Input Tier:    %d\n", ev.Classification.InputTier)
	fmt.Fprintf(w, "Output Tier:   %d\n", ev.Classification.OutputTier)
	piiStr := strings.Join(ev.Classification.PIIDetected, ", ")
	if piiStr == "" {
		piiStr = "(none)"
	}
	fmt.Fprintf(w, "PII Detected:  %s\n", piiStr)
	fmt.Fprintf(w, "PII Redacted:  %t\n", ev.Classification.PIIRedacted)
	fmt.Fprintln(w, "Execution")
	fmt.Fprintf(w, "Model:         %s\n", ev.Execution.ModelUsed)
	fmt.Fprintf(w, "Cost:          €%s\n", formatCost(ev.Execution.Cost))
	fmt.Fprintf(w, "Duration:      %dms\n", ev.Execution.DurationMS)
	fmt.Fprintf(w, "Tokens:        in=%d out=%d\n", ev.Execution.Tokens.Input, ev.Execution.Tokens.Output)
	toolsStr := strings.Join(ev.Execution.ToolsCalled, ", ")
	if toolsStr == "" {
		toolsStr = "(none)"
	}
	fmt.Fprintf(w, "Tools Called:  %s\n", toolsStr)
	if ev.ToolGovernance != nil {
		fmt.Fprintln(w, "Tool Governance (gateway)")
		req := strings.Join(ev.ToolGovernance.ToolsRequested, ", ")
		if req == "" {
			req = "(none)"
		}
		filt := strings.Join(ev.ToolGovernance.ToolsFiltered, ", ")
		if filt == "" {
			filt = "(none)"
		}
		fwd := strings.Join(ev.ToolGovernance.ToolsForwarded, ", ")
		if fwd == "" {
			fwd = "(none)"
		}
		fmt.Fprintf(w, "  Requested:  %s\n", req)
		fmt.Fprintf(w, "  Filtered:   %s\n", filt)
		fmt.Fprintf(w, "  Forwarded:  %s\n", fwd)
	}
	if ev.Execution.MemoryTokens > 0 {
		fmt.Fprintf(w, "Memory Tokens: %d (injected into prompt)\n", ev.Execution.MemoryTokens)
	}
	if len(ev.MemoryReads) > 0 {
		fmt.Fprintln(w, "Memory Reads (injected into prompt)")
		for _, r := range ev.MemoryReads {
			fmt.Fprintf(w, "  Entry: %s  TrustScore: %d\n", r.EntryID, r.TrustScore)
		}
	}
	fmt.Fprintln(w, "Audit Trail")
	fmt.Fprintf(w, "Input Hash:    %s\n", ev.AuditTrail.InputHash)
	fmt.Fprintf(w, "Output Hash:   %s\n", ev.AuditTrail.OutputHash)
	fmt.Fprintln(w, "Compliance")
	fmt.Fprintf(w, "Frameworks:    %s\n", strings.Join(ev.Compliance.Frameworks, ", "))
	fmt.Fprintf(w, "Data Residency: %s\n", ev.Compliance.DataLocation)
	fmt.Fprintln(w, sep)
}
