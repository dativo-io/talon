package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
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
	auditViolationsOnly bool
	auditOutputFile     string
	auditVerifyFile     string
	auditVerifyFailover bool
	auditSession        string
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
	Short: "Verify HMAC signature of an evidence record (--failover: semantic fallback-chain verification)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  auditVerify,
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export evidence records as CSV, JSON, NDJSON, signed JSON, signed NDJSON, or HTML",
	RunE:  auditExport,
}

func init() {
	auditListCmd.Flags().StringVar(&auditTenant, "tenant", "", "Filter by tenant ID")
	auditListCmd.Flags().StringVar(&auditAgent, "agent", "", "Filter by agent ID")
	auditListCmd.Flags().IntVar(&auditLimit, "limit", 20, "Maximum records to show")
	auditListCmd.Flags().StringVar(&auditSession, "session", "", "Show a per-session summary and the session's records (session_id)")

	auditVerifyCmd.Flags().StringVar(&auditVerifyFile, "file", "", "Verify all records from a signed export file")
	auditVerifyCmd.Flags().StringVar(&auditSession, "session", "", "Verify every record in a session (session_id)")
	auditVerifyCmd.Flags().BoolVar(&auditVerifyFailover, "failover", false, "Verify provider fallback chains: with a correlation ID argument verifies that chain; without, verifies all failover evidence")
	auditExportCmd.Flags().StringVar(&auditExportFmt, "format", "csv", "Output format: csv, json, ndjson, signed-json, signed-ndjson, or html")
	auditExportCmd.Flags().StringVar(&auditFrom, "from", "", "Start date (YYYY-MM-DD)")
	auditExportCmd.Flags().StringVar(&auditTo, "to", "", "End date (YYYY-MM-DD)")
	auditExportCmd.Flags().StringVar(&auditTenant, "tenant", "", "Filter by tenant ID")
	auditExportCmd.Flags().StringVar(&auditAgent, "agent", "", "Filter by agent ID")
	auditExportCmd.Flags().BoolVar(&auditViolationsOnly, "violations-only", false, "Only export records with policy violations or shadow violations")
	auditExportCmd.Flags().StringVar(&auditOutputFile, "output", "", "Write to file instead of stdout")
	auditExportCmd.Flags().IntVar(&auditExportLimit, "limit", 10000, "Maximum records to export")
	auditExportCmd.Flags().StringVar(&auditSession, "session", "", "Export only records for this session (session_id)")

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

	if auditSession != "" {
		records, err := fetchSessionRecords(ctx, store, auditSession, auditTenant, auditAgent)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			fmt.Printf("No evidence records found for session %s.\n", auditSession)
			return nil
		}
		renderSessionSummary(os.Stdout, evidence.BuildSessionSummary(auditSession, records))
		fmt.Fprintln(os.Stdout)
		renderSessionRecords(os.Stdout, records)
		return nil
	}

	index, err := store.ListIndex(ctx, auditTenant, auditAgent, time.Time{}, time.Time{}, auditLimit, "", "", "")
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
		index, err := store.ListIndex(ctx, "", "", time.Time{}, time.Time{}, 1, "", "", "")
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

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	if auditVerifyFailover {
		if auditVerifyFile != "" {
			return fmt.Errorf("use either --failover or --file, not both")
		}
		return auditVerifyFailoverChains(ctx, store, args)
	}

	if auditSession != "" {
		if auditVerifyFile != "" || len(args) > 0 {
			return fmt.Errorf("use either --session, --file, or an evidence ID, not more than one")
		}
		return auditVerifySession(ctx, store, auditSession)
	}

	if auditVerifyFile != "" {
		if len(args) > 0 {
			return fmt.Errorf("use either evidence ID or --file, not both")
		}
		return auditVerifyFromFile(store, auditVerifyFile)
	}
	if len(args) == 0 {
		return fmt.Errorf("evidence id is required when --file is not provided")
	}
	evidenceID := args[0]

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

// auditVerifyFromFile verifies every record in a signed export file and returns
// a non-nil error if any record fails.
func auditVerifyFromFile(store *evidence.Store, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading verify file: %w", err)
	}
	report, verifyErr := store.VerifyExport(data)
	renderVerifyFileReport(os.Stdout, path, report)
	if report.HasFailures() {
		if verifyErr != nil {
			return fmt.Errorf("file verification failed: %w", verifyErr)
		}
		return fmt.Errorf("file verification failed")
	}
	if verifyErr != nil {
		return fmt.Errorf("verifying file: %w", verifyErr)
	}
	return nil
}

// auditVerifyFailoverChains runs the semantic failover verifier: with an
// argument, over that correlation ID; without, over all correlation IDs that
// carry failover evidence. Non-zero exit when any chain is invalid or
// insufficient.
func auditVerifyFailoverChains(ctx context.Context, store *evidence.Store, args []string) error {
	var correlationIDs []string
	if len(args) > 0 {
		correlationIDs = []string{args[0]}
	} else {
		ids, err := store.ListFailoverCorrelationIDs(ctx, 1000)
		if err != nil {
			return fmt.Errorf("listing failover evidence: %w", err)
		}
		correlationIDs = ids
	}
	if len(correlationIDs) == 0 {
		fmt.Fprintln(os.Stdout, "No failover evidence found.")
		return nil
	}
	failed := 0
	checked := 0
	for _, id := range correlationIDs {
		finding, err := store.VerifyFailoverChain(ctx, id)
		if err != nil {
			return fmt.Errorf("verifying failover chain %s: %w", id, err)
		}
		if finding == nil {
			continue
		}
		checked++
		renderFailoverFinding(os.Stdout, finding)
		if !finding.OK() {
			failed++
		}
	}
	fmt.Fprintf(os.Stdout, "\nFailover chains checked: %d, failed: %d\n", checked, failed)
	if failed > 0 {
		return fmt.Errorf("%d failover chain(s) failed verification", failed)
	}
	return nil
}

func renderFailoverFinding(w io.Writer, f *evidence.FailoverFinding) {
	status := "PASS"
	if !f.OK() {
		status = "FAIL"
	}
	fmt.Fprintf(w, "[%s] %s  verdict=%s  records=%s\n", status, f.CorrelationID, f.Verdict, strings.Join(f.EvidenceIDs, ","))
	for _, d := range f.Details {
		fmt.Fprintf(w, "       - %s\n", d)
	}
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
	agentFilter := auditAgent

	var list []evidence.Evidence
	if auditSession != "" {
		records, ferr := fetchSessionRecords(ctx, store, auditSession, auditTenant, agentFilter)
		if ferr != nil {
			return ferr
		}
		list = derefEvidence(records)
	} else {
		list, err = store.List(ctx, auditTenant, agentFilter, from, to, auditExportLimit)
		if err != nil {
			return fmt.Errorf("querying evidence: %w", err)
		}
	}
	filteredEvidence := filterEvidenceForExport(list, auditViolationsOnly)
	records := toExportRecords(filteredEvidence)

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
	case "signed-json":
		return renderAuditExportSignedJSON(out, filteredEvidence)
	case "signed-ndjson":
		return renderAuditExportSignedNDJSON(out, filteredEvidence)
	case "html":
		return renderAuditExportHTML(out, records)
	default:
		return fmt.Errorf("unsupported --format %q; use csv, json, ndjson, signed-json, signed-ndjson, or html", auditExportFmt)
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

func filterEvidenceForExport(list []evidence.Evidence, violationsOnly bool) []evidence.Evidence {
	if !violationsOnly {
		return append([]evidence.Evidence(nil), list...)
	}
	filtered := make([]evidence.Evidence, 0, len(list))
	for i := range list {
		ev := list[i]
		if !ev.ObservationModeOverride && ev.PolicyDecision.Allowed {
			continue
		}
		filtered = append(filtered, ev)
	}
	return filtered
}

// fetchSessionRecords loads a session's evidence (newest first) and applies
// caller-scoping: records whose tenant/agent do not match the (optional)
// filters are dropped so one caller cannot read another caller's session.
func fetchSessionRecords(ctx context.Context, store *evidence.Store, sessionID, tenant, agent string) ([]*evidence.Evidence, error) {
	records, err := store.ListBySessionID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("querying session %s: %w", sessionID, err)
	}
	return scopeSessionRecords(records, tenant, agent), nil
}

// scopeSessionRecords drops records that do not match the tenant/agent filters.
// Empty filters match everything.
func scopeSessionRecords(records []*evidence.Evidence, tenant, agent string) []*evidence.Evidence {
	if tenant == "" && agent == "" {
		return records
	}
	out := make([]*evidence.Evidence, 0, len(records))
	for _, ev := range records {
		if tenant != "" && ev.TenantID != tenant {
			continue
		}
		if agent != "" && ev.AgentID != agent {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// derefEvidence copies a slice of evidence pointers into values (the shape the
// export path expects).
func derefEvidence(records []*evidence.Evidence) []evidence.Evidence {
	out := make([]evidence.Evidence, 0, len(records))
	for _, ev := range records {
		if ev != nil {
			out = append(out, *ev)
		}
	}
	return out
}

// auditVerifySession verifies the HMAC signature of every record in a session
// and prints a per-record + aggregate report. Returns a non-nil error (non-zero
// exit) if any record fails or the session is empty.
func auditVerifySession(ctx context.Context, store *evidence.Store, sessionID string) error {
	records, err := fetchSessionRecords(ctx, store, sessionID, auditTenant, auditAgent)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return fmt.Errorf("no evidence records found for session %s", sessionID)
	}
	invalid := 0
	for _, ev := range records {
		valid := store.VerifyRecord(ev)
		mark := "✓"
		if !valid {
			mark = "✗"
			invalid++
		}
		fmt.Fprintf(os.Stdout, "  %s %s | %s | %s\n", mark, ev.ID,
			ev.Timestamp.Format("2006-01-02 15:04:05"), formatMoney(ev.Execution.Currency, ev.Execution.Cost))
	}
	fmt.Fprintf(os.Stdout, "\nSession %s: %d record(s), %d valid, %d invalid\n",
		sessionID, len(records), len(records)-invalid, invalid)
	if invalid > 0 {
		return fmt.Errorf("%d record(s) in session %s failed signature verification", invalid, sessionID)
	}
	return nil
}

// renderSessionSummary prints the caller-scoped session rollup produced by
// evidence.BuildSessionSummary.
func renderSessionSummary(w io.Writer, sum evidence.SessionSummary) {
	fmt.Fprintf(w, "Session %s\n", sum.SessionID)
	if sum.RecordCount == 0 {
		fmt.Fprintln(w, "  (no records)")
		return
	}
	fmt.Fprintf(w, "  Tenant:    %s\n", sum.TenantID)
	if len(sum.AgentIDs) > 0 {
		fmt.Fprintf(w, "  Agent:     %s\n", strings.Join(sum.AgentIDs, ", "))
	}
	if sum.Client != "" || sum.SessionSource != "" {
		fmt.Fprintf(w, "  Source:    %s (%s)\n", sum.Client, sum.SessionSource)
	}
	fmt.Fprintf(w, "  Window:    %s → %s\n",
		sum.FirstSeen.Format(time.RFC3339), sum.LastSeen.Format(time.RFC3339))
	fmt.Fprintf(w, "  Requests:  %d (%d allowed, %d denied, %d error)\n",
		sum.RecordCount, sum.Allowed, sum.Denied, sum.Errors)
	if len(sum.Providers) > 0 {
		fmt.Fprintf(w, "  Providers: %s\n", strings.Join(sum.Providers, ", "))
	}
	if len(sum.Models) > 0 {
		fmt.Fprintf(w, "  Models:    %s\n", strings.Join(sum.Models, ", "))
	}
	fmt.Fprintf(w, "  Tokens:    in %d / out %d / cache-read %d / cache-write %d\n",
		sum.InputTokens, sum.OutputTokens, sum.CacheReadTokens, sum.CacheWriteTokens)
	fmt.Fprintf(w, "  Cost:      %s\n", formatMoney(sum.Currency, sum.TotalCost))
	if sessionHasAgentBreakdown(sum) {
		fmt.Fprintln(w, "\n  Per-agent:")
		for i := range sum.Subagents {
			a := &sum.Subagents[i]
			id := a.AgentID
			if id == "" {
				id = "(unattributed)"
			}
			parent := ""
			if a.ParentAgentID != "" {
				parent = " ←" + a.ParentAgentID
			}
			fmt.Fprintf(w, "    %-24s%s  %d req  %s  (in %d / out %d)\n",
				id, parent, a.RecordCount, formatMoney(sum.Currency, a.TotalCost), a.InputTokens, a.OutputTokens)
		}
	}
}

// sessionHasAgentBreakdown reports whether the per-agent table adds information
// beyond the session totals (more than one agent, or a single named subagent).
func sessionHasAgentBreakdown(sum evidence.SessionSummary) bool {
	if len(sum.Subagents) > 1 {
		return true
	}
	return len(sum.Subagents) == 1 && sum.Subagents[0].AgentID != "" &&
		(len(sum.AgentIDs) != 1 || sum.Subagents[0].AgentID != sum.AgentIDs[0])
}

// renderSessionRecords prints a compact per-record line list for a session
// (newest first, as returned by ListBySessionID).
func renderSessionRecords(w io.Writer, records []*evidence.Evidence) {
	fmt.Fprintf(w, "Records (%d, newest first):\n", len(records))
	for _, ev := range records {
		status := "✓"
		if !ev.PolicyDecision.Allowed {
			status = "✗"
		}
		errMark := ""
		if ev.Execution.Error != "" {
			errMark = " [ERROR]"
		}
		agent := ""
		if ev.Orchestration != nil && ev.Orchestration.AgentID != "" {
			agent = " | agent=" + ev.Orchestration.AgentID
		}
		fmt.Fprintf(w, "  %s %s | %s | %s | %s | %dms%s%s\n",
			status, ev.ID, ev.Timestamp.Format("2006-01-02 15:04:05"),
			ev.Execution.ModelUsed, formatMoney(ev.Execution.Currency, ev.Execution.Cost),
			ev.Execution.DurationMS, agent, errMark)
	}
}

func toExportRecords(list []evidence.Evidence) []evidence.ExportRecord {
	records := make([]evidence.ExportRecord, 0, len(list))
	for i := range list {
		records = append(records, evidence.ToExportRecord(&list[i]))
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
		"id", "session_id", "timestamp", "tenant_id", "agent_id", "invocation_type", "allowed", "policy_action", "cost", "model_used", "provider", "input_tokens", "output_tokens", "duration_ms", "has_error",
		"input_tier", "output_tier", "pii_detected", "pii_redacted", "policy_reasons", "tools_called", "input_hash", "output_hash",
		"observation_mode_override", "shadow_violation_types",
		"cache_hit", "cache_entry_id", "cost_saved",
		"upstream_auth_mode", "upstream_key_source", "upstream_key_fingerprint", "gateway_annotations",
		"primary_explanation_code", "primary_explanation_reason", "primary_version_identity",
		"flow_destinations", "flow_regions", "flow_entity_types",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for i := range records {
		r := &records[i]
		row := []string{
			r.ID,
			r.SessionID,
			r.Timestamp.Format(time.RFC3339),
			r.TenantID,
			r.AgentID,
			r.InvocationType,
			strconv.FormatBool(r.Allowed),
			r.PolicyAction,
			formatCostNumeric(r.Cost),
			r.ModelUsed,
			r.Provider,
			strconv.Itoa(r.InputTokens),
			strconv.Itoa(r.OutputTokens),
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
			strconv.FormatBool(r.CacheHit),
			r.CacheEntryID,
			formatCostNumeric(r.CostSaved),
			r.UpstreamAuthMode,
			r.UpstreamKeySource,
			r.UpstreamKeyFingerprint,
			r.GatewayAnnotationsCSV(),
			r.PrimaryExplanationCode,
			r.PrimaryExplanationReason,
			r.PrimaryVersionIdentity,
			r.FlowDestinationsCSV(),
			r.FlowRegionsCSV(),
			r.FlowEntityTypesCSV(),
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
			},
			TotalRecords: len(records),
		},
		Records: records,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

func renderAuditExportSignedJSON(w io.Writer, records []evidence.Evidence) error {
	envelope := evidence.SignedExportEnvelope{
		ExportMetadata: evidence.ExportMetadata{
			GeneratedAt:  time.Now().UTC(),
			TalonVersion: resolvedVersion(),
			Filter: evidence.ExportFilter{
				From:   auditFrom,
				To:     auditTo,
				Tenant: auditTenant,
				Agent:  auditAgent,
			},
			TotalRecords: len(records),
			Algorithm:    evidence.SignedExportAlgorithm,
			Signed:       true,
		},
		Records: records,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

func renderAuditExportSignedNDJSON(w io.Writer, records []evidence.Evidence) error {
	enc := json.NewEncoder(w)
	for i := range records {
		if err := enc.Encode(&records[i]); err != nil {
			return fmt.Errorf("encoding record %s: %w", records[i].ID, err)
		}
	}
	return nil
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

func renderAuditExportHTML(w io.Writer, records []evidence.ExportRecord) error {
	const exportTpl = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Talon Audit Export</title>
  <style>
    body{font-family:ui-sans-serif,-apple-system,Segoe UI,sans-serif;margin:24px;color:#111}
    table{border-collapse:collapse;width:100%}
    th,td{border:1px solid #ddd;padding:8px;font-size:13px}
    th{background:#f4f4f4}
    code{background:#f5f5f5;padding:1px 4px;border-radius:3px}
    .meta{color:#555}
  </style>
</head>
<body>
  <h1>Talon Audit Export</h1>
  <p class="meta">Generated: {{ .Generated }} | Records: {{ .RecordCount }}</p>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Timestamp</th>
        <th>Tenant</th>
        <th>Agent</th>
        <th>Allowed</th>
        <th>Cost(EUR)</th>
        <th>Model</th>
        <th>Duration(ms)</th>
      </tr>
    </thead>
    <tbody>
      {{- range .Rows }}
      <tr>
        <td><code>{{ .ID }}</code></td>
        <td>{{ .Timestamp }}</td>
        <td>{{ .TenantID }}</td>
        <td>{{ .AgentID }}</td>
        <td>{{ .Allowed }}</td>
        <td>{{ .Cost }}</td>
        <td>{{ .ModelUsed }}</td>
        <td>{{ .DurationMS }}</td>
      </tr>
      {{- end }}
    </tbody>
  </table>
</body>
</html>`

	type row struct {
		ID         string
		Timestamp  string
		TenantID   string
		AgentID    string
		Allowed    bool
		Cost       string
		ModelUsed  string
		DurationMS int64
	}
	type viewData struct {
		Generated   string
		RecordCount int
		Rows        []row
	}

	rows := make([]row, 0, len(records))
	for i := range records {
		r := records[i]
		rows = append(rows, row{
			ID:         r.ID,
			Timestamp:  r.Timestamp.Format(time.RFC3339),
			TenantID:   r.TenantID,
			AgentID:    r.AgentID,
			Allowed:    r.Allowed,
			Cost:       formatCostNumeric(r.Cost),
			ModelUsed:  r.ModelUsed,
			DurationMS: r.DurationMS,
		})
	}

	tpl, err := template.New("audit_export").Parse(exportTpl)
	if err != nil {
		return fmt.Errorf("parsing audit export html template: %w", err)
	}

	data := viewData{
		Generated:   time.Now().UTC().Format(time.RFC3339),
		RecordCount: len(records),
		Rows:        rows,
	}
	if err := tpl.Execute(w, data); err != nil {
		return fmt.Errorf("rendering audit export html: %w", err)
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
		cacheMark := ""
		if entry.CacheHit {
			cacheMark = " [CACHE]"
		}
		explanationMark := ""
		if entry.PrimaryExplanationCode != "" {
			explanationMark = " [" + entry.PrimaryExplanationCode + "]"
		}
		fmt.Fprintf(w, "  %s %s | %s | %s/%s | %s | %s | %dms%s%s%s\n",
			status,
			entry.ID,
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.TenantID,
			entry.AgentID,
			entry.ModelUsed,
			formatMoney(entry.Currency, entry.Cost),
			entry.DurationMS,
			errorMark,
			cacheMark,
			explanationMark,
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
		fmt.Fprintf(w, "%s | %s/%s | %s | %s | %dms\n",
			ev.Timestamp.Format(time.RFC3339),
			ev.TenantID,
			ev.AgentID,
			ev.Execution.ModelUsed,
			formatMoney(ev.Execution.Currency, ev.Execution.Cost),
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

func renderVerifyFileReport(w io.Writer, path string, report evidence.FileVerifyReport) {
	fmt.Fprintf(w, "File: %s\n", path)
	fmt.Fprintf(w, "Total records: %d\n", report.Total)
	fmt.Fprintf(w, "Valid records: %d\n", report.Valid)
	fmt.Fprintf(w, "Invalid records: %d\n", report.Invalid)
	fmt.Fprintf(w, "Missing signature: %d\n", report.MissingSignature)
	fmt.Fprintf(w, "Could not parse: %d\n", report.Unparseable)
	fmt.Fprintf(w, "Unsupported: %d\n", report.Unsupported)
	if report.Hint != "" {
		fmt.Fprintf(w, "Hint: %s\n", report.Hint)
	}
	if len(report.Records) == 0 {
		return
	}
	fmt.Fprintln(w, "Record results:")
	for i := range report.Records {
		rec := report.Records[i]
		id := rec.ID
		if id == "" {
			id = "(unknown)"
		}
		detail := rec.Detail
		if detail == "" {
			detail = "-"
		}
		fmt.Fprintf(w, "  - %s: %s (%s)\n", id, rec.Status, detail)
	}
}

// renderAuditShow writes a full evidence record (Layer 3) to w. HMAC status is shown prominently.
//
//nolint:gocyclo // display logic for all evidence fields including cache, tool gov, memory
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
	// Input-path redaction only: the gateway/runner records whether the request
	// was masked before egress (InputPIIRedacted). There is no output-redaction
	// flag, so we do not print a misleading output= value (#307).
	fmt.Fprintf(w, "PII Redacted:  input=%t\n", ev.Classification.InputPIIRedacted)
	fmt.Fprintln(w, "Execution")
	fmt.Fprintf(w, "Model:         %s\n", ev.Execution.ModelUsed)
	fmt.Fprintf(w, "Cost:          %s\n", formatMoney(ev.Execution.Currency, ev.Execution.Cost))
	fmt.Fprintf(w, "Duration:      %dms\n", ev.Execution.DurationMS)
	tokensLine := fmt.Sprintf("in=%d out=%d", ev.Execution.Tokens.Input, ev.Execution.Tokens.Output)
	if ev.Execution.Tokens.CacheRead > 0 || ev.Execution.Tokens.CacheWrite > 0 {
		tokensLine += fmt.Sprintf(" cache_read=%d cache_write=%d",
			ev.Execution.Tokens.CacheRead, ev.Execution.Tokens.CacheWrite)
	}
	fmt.Fprintf(w, "Tokens:        %s\n", tokensLine)
	if ev.Execution.PricingBasis != "" {
		fmt.Fprintf(w, "Pricing Basis: %s\n", ev.Execution.PricingBasis)
	}
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
	if rd := ev.RoutingDecision; rd != nil && (rd.SelectedProvider != "" || len(rd.RejectedCandidates) > 0) {
		fmt.Fprintln(w, "Routing Decision (sovereignty-aware)")
		if rd.SelectedProvider != "" {
			fmt.Fprintf(w, "  Selected:   %s / %s\n", rd.SelectedProvider, rd.SelectedModel)
		}
		// Group by provider so a provider rejected under several policy rules
		// prints once with its reasons as sub-bullets — a single provider was
		// refused, not dispatched twice. Preserve first-seen provider order.
		order := make([]string, 0, len(rd.RejectedCandidates))
		reasons := make(map[string][]string)
		for _, rc := range rd.RejectedCandidates {
			if _, seen := reasons[rc.ProviderID]; !seen {
				order = append(order, rc.ProviderID)
			}
			reasons[rc.ProviderID] = append(reasons[rc.ProviderID], rc.Reason)
		}
		for _, provider := range order {
			rs := reasons[provider]
			if len(rs) == 1 {
				fmt.Fprintf(w, "  Rejected:   %s (%s)\n", provider, rs[0])
				continue
			}
			fmt.Fprintf(w, "  Rejected:   %s\n", provider)
			for _, r := range rs {
				fmt.Fprintf(w, "                • %s\n", r)
			}
		}
	}
	if ev.UpstreamAuthMode != "" || ev.UpstreamKeySource != "" || ev.UpstreamKeyFingerprint != "" {
		fmt.Fprintln(w, "Upstream Auth")
		fmt.Fprintf(w, "  Mode:        %s\n", ev.UpstreamAuthMode)
		fmt.Fprintf(w, "  Key Source:  %s\n", ev.UpstreamKeySource)
		fmt.Fprintf(w, "  Key FP:      %s\n", ev.UpstreamKeyFingerprint)
	}
	if len(ev.GatewayAnnotations) > 0 {
		fmt.Fprintf(w, "Gateway Annotations: %s\n", strings.Join(ev.GatewayAnnotations, ", "))
	}
	if o := ev.Orchestration; o != nil {
		fmt.Fprintln(w, "Orchestration (client-asserted)")
		if o.AgentID != "" {
			fmt.Fprintf(w, "  Agent:       %s\n", o.AgentID)
		}
		if o.ParentAgentID != "" {
			fmt.Fprintf(w, "  Parent:      %s\n", o.ParentAgentID)
		}
		if o.Client != "" {
			fmt.Fprintf(w, "  Client:      %s\n", o.Client)
		}
		fmt.Fprintf(w, "  Session Src: %s\n", o.SessionSource)
		fmt.Fprintf(w, "  Provenance:  %s\n", o.Provenance)
	}
	if ev.CacheHit {
		fmt.Fprintln(w, "Cache")
		fmt.Fprintf(w, "  Hit:         true\n")
		fmt.Fprintf(w, "  Entry ID:    %s\n", ev.CacheEntryID)
		fmt.Fprintf(w, "  Similarity:  %.2f\n", ev.CacheSimilarity)
		fmt.Fprintf(w, "  Cost Saved:  %s\n", formatMoney(ev.Execution.Currency, ev.CostSaved))
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
	if ev.DataFlow != nil && len(ev.DataFlow.Items) > 0 {
		fmt.Fprintln(w, "Data Flow")
		if ev.DataFlow.Detector != "" {
			fmt.Fprintf(w, "  Detector:    %s\n", ev.DataFlow.Detector)
		}
		for i := range ev.DataFlow.Items {
			item := &ev.DataFlow.Items[i]
			dest := item.Destination.Kind + ":" + item.Destination.Name
			if item.Destination.Model != "" {
				dest += " model=" + item.Destination.Model
			}
			if item.Destination.Region != "" {
				dest += " region=" + item.Destination.Region
			}
			types := strings.Join(item.EntityTypes, ", ")
			if types == "" {
				types = "no classified data"
			}
			fmt.Fprintf(w, "  %s -> %s | %s | tier %d | %s\n",
				item.Source, dest, item.Disposition, item.Tier, types)
		}
	}
	fmt.Fprintln(w, "Audit Trail")
	fmt.Fprintf(w, "Input Hash:    %s\n", ev.AuditTrail.InputHash)
	fmt.Fprintf(w, "Output Hash:   %s\n", ev.AuditTrail.OutputHash)
	fmt.Fprintln(w, "Compliance")
	fmt.Fprintf(w, "Frameworks:    %s\n", strings.Join(ev.Compliance.Frameworks, ", "))
	fmt.Fprintf(w, "Data Residency: %s\n", ev.Compliance.DataLocation)
	if len(ev.Explanations) > 0 {
		fmt.Fprintln(w, "Explanations")
		for i := range ev.Explanations {
			ex := ev.Explanations[i]
			fmt.Fprintf(w, "  [%d] %s | %s | %s\n", i+1, ex.Code, ex.Decision, ex.Reason)
			if ex.Stage != "" {
				fmt.Fprintf(w, "      Stage: %s\n", ex.Stage)
			}
			if ex.Trigger != "" {
				fmt.Fprintf(w, "      Trigger: %s\n", ex.Trigger)
			}
			if ex.Fix != "" {
				fmt.Fprintf(w, "      Fix: %s\n", ex.Fix)
			}
			if ex.PolicyRef != "" {
				fmt.Fprintf(w, "      Policy Ref: %s\n", ex.PolicyRef)
			}
			if ex.VersionIdentity != "" {
				fmt.Fprintf(w, "      Version: %s\n", ex.VersionIdentity)
			}
		}
	}
	fmt.Fprintln(w, sep)
}
