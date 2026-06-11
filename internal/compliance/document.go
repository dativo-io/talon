package compliance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"time"
)

// Document is the generic auditor-document model shared by the RoPA and
// Annex IV generators (and future report types). It renders to JSON
// (machine-checkable) and HTML (print-to-PDF-ready) via RenderDocumentJSON
// and RenderDocumentHTML.
//
// Every document carries a claims-discipline note: Talon emits supporting
// records for auditor review, never a compliance determination.
type Document struct {
	Title       string          `json:"title"`
	Subtitle    string          `json:"subtitle,omitempty"`
	GeneratedAt time.Time       `json:"generated_at"`
	Framework   string          `json:"framework"` // e.g. "gdpr", "eu-ai-act"
	Article     string          `json:"article"`   // e.g. "Art. 30", "Annex IV"
	TenantID    string          `json:"tenant_id,omitempty"`
	AgentID     string          `json:"agent_id,omitempty"`
	Warnings    []string        `json:"warnings,omitempty"` // missing-declaration warnings
	Sections    []DocSection    `json:"sections"`
	Linkage     EvidenceLinkage `json:"evidence_linkage"`
	ClaimNote   string          `json:"claim_note"`
}

// DocSection is one titled section of an auditor document. Missing marks a
// section whose declared facts are absent; renderers flag it prominently so
// the operator knows exactly what to fill in.
type DocSection struct {
	Heading string    `json:"heading"`
	Body    string    `json:"body,omitempty"`
	Table   *DocTable `json:"table,omitempty"`
	Missing bool      `json:"missing,omitempty"`
}

// DocTable is a simple header+rows table inside a section.
type DocTable struct {
	Headers []string   `json:"headers"`
	Rows    [][]string `json:"rows"`
}

// EvidenceLinkage ties a document back to the signed evidence records it was
// generated from, including the offline verification command.
type EvidenceLinkage struct {
	EvidenceCount     int      `json:"evidence_count"`
	From              string   `json:"from,omitempty"`
	To                string   `json:"to,omitempty"`
	SampleEvidenceIDs []string `json:"sample_evidence_ids,omitempty"`
	VerifyCommand     string   `json:"verify_command,omitempty"`
	SignedExportRef   string   `json:"signed_export_ref,omitempty"`
}

// MissingDeclarationText is rendered as the body of a section whose declared
// facts are absent.
const MissingDeclarationText = "DECLARATION MISSING — this section requires declared facts. " +
	"Set the fields listed in the document warnings (talon.config.yaml `compliance.controller` " +
	"or agent.talon.yaml `compliance.declarations`) and regenerate."

// ClaimNoteFor returns the mandatory claims-discipline footer for a document
// supporting the given framework articles. Wording follows the project rule:
// supporting records, never a compliance determination.
func ClaimNoteFor(articles string) string {
	return fmt.Sprintf("This document contains supporting records and control descriptions for %s, "+
		"generated from HMAC-signed runtime evidence and operator-declared facts. "+
		"It is not a completed legal filing, a certification, or a compliance determination. "+
		"Review with your DPO or counsel. See LIMITATIONS.md.", articles)
}

// RenderDocumentJSON renders a document as indented JSON.
func RenderDocumentJSON(doc Document) ([]byte, error) {
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("rendering document JSON: %w", err)
	}
	return out, nil
}

const documentHTMLTemplate = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>
body { font-family: ui-sans-serif, -apple-system, "Segoe UI", sans-serif; margin: 32px auto; max-width: 900px; color: #111; line-height: 1.45; }
h1 { margin: 0 0 4px; font-size: 26px; }
h2 { margin: 28px 0 8px; font-size: 18px; border-bottom: 1px solid #d9d9d9; padding-bottom: 4px; }
.subtitle { color: #444; margin: 0 0 16px; }
.meta { color: #555; font-size: 13px; margin: 0 0 24px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0 18px; }
th, td { border: 1px solid #d9d9d9; padding: 7px 9px; text-align: left; font-size: 13px; vertical-align: top; }
th { background: #f4f4f4; }
code { background: #f5f5f5; padding: 1px 4px; border-radius: 4px; font-size: 12px; }
.missing { border: 2px dashed #c0392b; background: #fdf3f2; padding: 10px 14px; border-radius: 6px; color: #7b241c; font-size: 14px; }
.warnings { border: 1px solid #e6c200; background: #fdf9e7; padding: 10px 14px; border-radius: 6px; font-size: 13px; margin: 0 0 20px; }
.warnings ul { margin: 6px 0 0 18px; padding: 0; }
.linkage { background: #f4f7f4; border: 1px solid #cfe0cf; padding: 12px 16px; border-radius: 6px; font-size: 13px; margin: 28px 0 0; }
.claim { color: #555; font-size: 12px; border-top: 1px solid #d9d9d9; margin-top: 32px; padding-top: 12px; }
@media print { body { margin: 12mm; } .warnings { display: none; } }
</style></head><body>
<h1>{{.Title}}</h1>
{{if .Subtitle}}<p class="subtitle">{{.Subtitle}}</p>{{end}}
<p class="meta">Generated: {{.GeneratedAt.UTC.Format "2006-01-02 15:04:05 UTC"}} | Framework: <b>{{.Framework}}</b> | Scope: <b>{{.Article}}</b>{{if .TenantID}} | Tenant: <b>{{.TenantID}}</b>{{end}}{{if .AgentID}} | Agent: <b>{{.AgentID}}</b>{{end}}</p>
{{if .Warnings}}<div class="warnings"><b>Declarations to complete before auditor handoff:</b><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul></div>{{end}}
{{range .Sections}}<h2>{{.Heading}}</h2>
{{if .Missing}}<p class="missing">{{.Body}}</p>{{else}}{{if .Body}}<p>{{.Body}}</p>{{end}}{{end}}
{{if .Table}}<table><thead><tr>{{range .Table.Headers}}<th>{{.}}</th>{{end}}</tr></thead><tbody>
{{range .Table.Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>{{end}}
</tbody></table>{{end}}
{{end}}<div class="linkage"><b>Evidence linkage.</b> Built from {{.Linkage.EvidenceCount}} signed evidence record(s){{if .Linkage.From}} from {{.Linkage.From}}{{end}}{{if .Linkage.To}} to {{.Linkage.To}}{{end}}.
{{if .Linkage.SampleEvidenceIDs}}Sample IDs: {{range $i, $id := .Linkage.SampleEvidenceIDs}}{{if $i}}, {{end}}<code>{{$id}}</code>{{end}}.{{end}}
{{if .Linkage.VerifyCommand}}Verify offline: <code>{{.Linkage.VerifyCommand}}</code>.{{end}}
{{if .Linkage.SignedExportRef}}Signed export: <code>{{.Linkage.SignedExportRef}}</code>.{{end}}</div>
<p class="claim">{{.ClaimNote}}</p>
</body></html>`

var documentTemplate = template.Must(template.New("auditor-document").Parse(documentHTMLTemplate))

// RenderDocumentHTML renders a document as a standalone, print-to-PDF-ready
// HTML page. All user-supplied strings are HTML-escaped by html/template.
func RenderDocumentHTML(doc Document) ([]byte, error) {
	var buf bytes.Buffer
	if err := documentTemplate.Execute(&buf, doc); err != nil {
		return nil, fmt.Errorf("rendering document HTML: %w", err)
	}
	return buf.Bytes(), nil
}
