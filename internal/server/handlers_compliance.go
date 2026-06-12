package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/compliance"
	"github.com/dativo-io/talon/internal/evidence"
)

// complianceEvidenceQueryLimit caps the evidence records loaded for one
// document generation. Mirrors the cap used by the compliance CLI.
const complianceEvidenceQueryLimit = 200000

// complianceScope is the parsed, validated query scope shared by all
// /v1/compliance/* handlers. These routes are admin-only, so tenant/agent are
// plain filters: empty means all (same semantics as the compliance CLI).
type complianceScope struct {
	TenantID string
	AgentID  string
	From     time.Time
	To       time.Time
	FromStr  string // display form, YYYY-MM-DD
	ToStr    string
	Format   string // "html" or "json"
}

// parseComplianceScope extracts tenant/agent/date/format query parameters.
// Dates use YYYY-MM-DD (UTC) like the CLI; the end date is inclusive.
func parseComplianceScope(r *http.Request) (complianceScope, error) {
	q := r.URL.Query()
	scope := complianceScope{
		TenantID: strings.TrimSpace(q.Get("tenant")),
		AgentID:  strings.TrimSpace(q.Get("agent")),
		FromStr:  strings.TrimSpace(q.Get("from")),
		ToStr:    strings.TrimSpace(q.Get("to")),
		Format:   strings.ToLower(strings.TrimSpace(q.Get("format"))),
	}
	if scope.Format == "" {
		scope.Format = "html"
	}
	if scope.Format != "html" && scope.Format != "json" {
		return scope, fmt.Errorf("unsupported format %q; use html or json", scope.Format)
	}
	if scope.FromStr != "" {
		from, err := time.ParseInLocation("2006-01-02", scope.FromStr, time.UTC)
		if err != nil {
			return scope, fmt.Errorf("invalid from date (use YYYY-MM-DD): %w", err)
		}
		scope.From = from
	}
	if scope.ToStr != "" {
		to, err := time.ParseInLocation("2006-01-02", scope.ToStr, time.UTC)
		if err != nil {
			return scope, fmt.Errorf("invalid to date (use YYYY-MM-DD): %w", err)
		}
		scope.To = to.Add(24 * time.Hour) // inclusive end date
	}
	return scope, nil
}

// complianceDeclarations resolves declared facts via the configured loader.
// Without a loader the zero value is used: generators render flagged
// placeholder sections, never errors.
func (s *Server) complianceDeclarations(ctx context.Context) compliance.Declarations {
	if s.declarationsLoader == nil {
		return compliance.Declarations{}
	}
	return s.declarationsLoader(ctx)
}

// listComplianceEvidence queries evidence for one document generation.
func (s *Server) listComplianceEvidence(ctx context.Context, scope complianceScope) ([]evidence.Evidence, error) {
	if s.evidenceStore == nil {
		return nil, nil
	}
	return s.evidenceStore.List(ctx, scope.TenantID, scope.AgentID, scope.From, scope.To, complianceEvidenceQueryLimit)
}

// frameworkCoverage is the per-framework summary in the coverage response.
type frameworkCoverage struct {
	Framework      string                      `json:"framework"`
	EvidenceCount  int                         `json:"evidence_count"`
	DeniedCount    int                         `json:"denied_count"`
	PIIRecordCount int                         `json:"pii_record_count"`
	TotalCostEUR   float64                     `json:"total_cost_eur"`
	Controls       []compliance.ControlMapping `json:"controls"`
}

// handleComplianceCoverage returns per-framework control coverage for the
// dashboard compliance mode: built-in control mappings, evidence counts per
// framework, and declaration warnings for the auditor exports.
func (s *Server) handleComplianceCoverage(w http.ResponseWriter, r *http.Request) {
	scope, err := parseComplianceScope(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	list, err := s.listComplianceEvidence(r.Context(), scope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	// Distinct frameworks in first-appearance order of the built-in mappings.
	var order []string
	seen := map[string]bool{}
	for _, m := range compliance.DefaultMappings() {
		if !seen[m.Framework] {
			seen[m.Framework] = true
			order = append(order, m.Framework)
		}
	}
	frameworks := make([]frameworkCoverage, 0, len(order))
	for _, fw := range order {
		rep := compliance.BuildReport(fw, scope.TenantID, scope.AgentID, scope.FromStr, scope.ToStr, list)
		controls := rep.Mappings
		if controls == nil {
			controls = []compliance.ControlMapping{}
		}
		frameworks = append(frameworks, frameworkCoverage{
			Framework:      fw,
			EvidenceCount:  rep.EvidenceCount,
			DeniedCount:    rep.DeniedCount,
			PIIRecordCount: rep.PIIRecordCount,
			TotalCostEUR:   rep.TotalCostEUR,
			Controls:       controls,
		})
	}

	decl := s.complianceDeclarations(r.Context())
	ropaWarnings := decl.ValidateForRoPA()
	if ropaWarnings == nil {
		ropaWarnings = []string{}
	}
	annexWarnings := decl.ValidateForAnnexIV()
	if annexWarnings == nil {
		annexWarnings = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"generated_at":         time.Now().UTC().Format(time.RFC3339),
		"tenant_id":            scope.TenantID,
		"agent_id":             scope.AgentID,
		"from":                 scope.FromStr,
		"to":                   scope.ToStr,
		"evidence_count_total": len(list),
		"frameworks":           frameworks,
		"declaration_warnings": map[string][]string{
			"ropa":     ropaWarnings,
			"annex_iv": annexWarnings,
		},
		"claim_note": compliance.ClaimNoteFor("GDPR, EU AI Act, NIS2, DORA and ISO 27001 controls"),
	})
}

// auditorDocumentGenerator builds one auditor document from declarations,
// evidence, and the request scope.
type auditorDocumentGenerator func(ctx context.Context, decl compliance.Declarations, list []evidence.Evidence, scope complianceScope) (compliance.Document, error)

// handleComplianceRoPA serves a GDPR Art. 30 Record of Processing Activities
// as a one-click download (supporting records, not a legal filing).
func (s *Server) handleComplianceRoPA(w http.ResponseWriter, r *http.Request) {
	s.serveAuditorDocument(w, r, "ropa", "talon-ropa",
		func(ctx context.Context, decl compliance.Declarations, list []evidence.Evidence, scope complianceScope) (compliance.Document, error) {
			return compliance.GenerateRoPA(ctx, decl, list, compliance.RoPAOptions{
				TenantID: scope.TenantID,
				AgentID:  scope.AgentID,
				From:     scope.FromStr,
				To:       scope.ToStr,
			})
		})
}

// handleComplianceAnnexIV serves an EU AI Act Annex IV technical-documentation
// pack as a one-click download (supporting records, not a legal filing).
func (s *Server) handleComplianceAnnexIV(w http.ResponseWriter, r *http.Request) {
	s.serveAuditorDocument(w, r, "annex_iv", "talon-annex-iv",
		func(ctx context.Context, decl compliance.Declarations, list []evidence.Evidence, scope complianceScope) (compliance.Document, error) {
			return compliance.GenerateAnnexIV(ctx, decl, list, compliance.AnnexIVOptions{
				TenantID: scope.TenantID,
				AgentID:  scope.AgentID,
				From:     scope.FromStr,
				To:       scope.ToStr,
			})
		})
}

// serveAuditorDocument is the shared handler body for the RoPA and Annex IV
// endpoints: parse scope, load declarations, query evidence, generate, render,
// and record control-plane evidence for the export itself.
func (s *Server) serveAuditorDocument(w http.ResponseWriter, r *http.Request, kind, filename string, generate auditorDocumentGenerator) {
	scope, err := parseComplianceScope(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	list, err := s.listComplianceEvidence(r.Context(), scope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	decl := s.complianceDeclarations(r.Context())
	doc, err := generate(r.Context(), decl, list, scope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	var out []byte
	switch scope.Format {
	case "json":
		out, err = compliance.RenderDocumentJSON(doc)
	default:
		out, err = compliance.RenderDocumentHTML(doc)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	s.recordControlPlaneAction(r.Context(), scope.TenantID, "compliance_export_"+kind, "admin_api",
		exportDetail(scope, len(list)))
	writeComplianceAttachment(w, scope.Format, filename, out)
}

// handleComplianceReport serves the framework-mapped compliance report
// (control mappings + evidence aggregates) as a one-click download.
func (s *Server) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	scope, err := parseComplianceScope(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	framework := strings.TrimSpace(r.URL.Query().Get("framework"))
	list, err := s.listComplianceEvidence(r.Context(), scope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	report := compliance.BuildReport(framework, scope.TenantID, scope.AgentID, scope.FromStr, scope.ToStr, list)
	var out []byte
	switch scope.Format {
	case "json":
		out, err = compliance.RenderJSON(report)
	default:
		out, err = compliance.RenderHTML(report)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	s.recordControlPlaneAction(r.Context(), scope.TenantID, "compliance_export_report", "admin_api",
		exportDetail(scope, report.EvidenceCount))
	writeComplianceAttachment(w, scope.Format, "talon-compliance-report", out)
}

func exportDetail(scope complianceScope, evidenceCount int) string {
	detail := fmt.Sprintf("format=%s evidence_count=%d", scope.Format, evidenceCount)
	if scope.AgentID != "" {
		detail += " agent=" + scope.AgentID
	}
	if scope.FromStr != "" || scope.ToStr != "" {
		detail += fmt.Sprintf(" range=%s..%s", scope.FromStr, scope.ToStr)
	}
	return detail
}

func writeComplianceAttachment(w http.ResponseWriter, format, filename string, out []byte) {
	ext := "html"
	contentType := "text/html; charset=utf-8"
	if format == "json" {
		ext = "json"
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename+"."+ext))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: document produced by compliance.RenderDocumentHTML/RenderHTML, which html-escapes all dynamic values (covered by golden tests); JSON variant is json.Marshal output
	_, _ = w.Write(out)
}
