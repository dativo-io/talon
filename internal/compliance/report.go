package compliance

import (
	"bytes"
	"encoding/json"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

type Report struct {
	GeneratedAt       time.Time        `json:"generated_at"`
	Framework         string           `json:"framework"`
	TenantID          string           `json:"tenant_id,omitempty"`
	AgentID           string           `json:"agent_id,omitempty"`
	From              string           `json:"from,omitempty"`
	To                string           `json:"to,omitempty"`
	EvidenceCount     int              `json:"evidence_count"`
	DeniedCount       int              `json:"denied_count"`
	PIIRecordCount    int              `json:"pii_record_count"`
	TotalCostEUR      float64          `json:"total_cost_eur"`
	Mappings          []ControlMapping `json:"mappings"`
	SampleEvidenceIDs []string         `json:"sample_evidence_ids"`
}

func BuildReport(framework, tenantID, agentID, from, to string, list []evidence.Evidence) Report {
	r := Report{
		GeneratedAt: time.Now().UTC(),
		Framework:   strings.ToLower(framework),
		TenantID:    tenantID,
		AgentID:     agentID,
		From:        from,
		To:          to,
	}
	allMappings := DefaultMappings()
	for _, m := range allMappings {
		if framework == "" || strings.EqualFold(m.Framework, framework) {
			r.Mappings = append(r.Mappings, m)
		}
	}
	for i := range list {
		ev := &list[i]
		if framework != "" && !containsFramework(ev.Compliance.Frameworks, framework) {
			continue
		}
		r.EvidenceCount++
		if !ev.PolicyDecision.Allowed {
			r.DeniedCount++
		}
		if len(ev.Classification.PIIDetected) > 0 {
			r.PIIRecordCount++
		}
		r.TotalCostEUR += ev.Execution.Cost
		if len(r.SampleEvidenceIDs) < 20 {
			r.SampleEvidenceIDs = append(r.SampleEvidenceIDs, ev.ID)
		}
	}
	sort.Strings(r.SampleEvidenceIDs)
	return r
}

func RenderJSON(report Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

func RenderHTML(report Report) ([]byte, error) {
	const tpl = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Talon Compliance Report</title>
<style>
body { font-family: ui-sans-serif, -apple-system, "Segoe UI", sans-serif; margin: 24px; color: #111; }
h1, h2 { margin: 0 0 10px; }
.meta { margin: 0 0 20px; color: #444; }
table { border-collapse: collapse; width: 100%; margin: 12px 0 24px; }
th, td { border: 1px solid #d9d9d9; padding: 8px; text-align: left; font-size: 14px; vertical-align: top; }
th { background: #f4f4f4; }
.cards { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 10px; margin: 16px 0; }
.card { border: 1px solid #d9d9d9; padding: 10px; border-radius: 8px; }
.label { color: #555; font-size: 12px; }
.value { font-size: 20px; font-weight: 700; }
code { background: #f5f5f5; padding: 1px 4px; border-radius: 4px; }
</style></head><body>
<h1>Talon Compliance Report</h1>
<p class="meta">Generated: {{.GeneratedAt}} | Framework: <b>{{if .Framework}}{{.Framework}}{{else}}all{{end}}</b> | Tenant: <b>{{if .TenantID}}{{.TenantID}}{{else}}all{{end}}</b> | Agent: <b>{{if .AgentID}}{{.AgentID}}{{else}}all{{end}}</b></p>
<div class="cards">
  <div class="card"><div class="label">Evidence Records</div><div class="value">{{.EvidenceCount}}</div></div>
  <div class="card"><div class="label">Policy Denials</div><div class="value">{{.DeniedCount}}</div></div>
  <div class="card"><div class="label">PII Records</div><div class="value">{{.PIIRecordCount}}</div></div>
  <div class="card"><div class="label">Total Cost (EUR)</div><div class="value">{{printf "%.4f" .TotalCostEUR}}</div></div>
</div>
<h2>Control Mappings</h2>
<table><thead><tr><th>Framework</th><th>Article</th><th>Control</th><th>Source</th></tr></thead><tbody>
{{range .Mappings}}<tr><td>{{.Framework}}</td><td>{{.Article}}</td><td>{{.Control}}</td><td><code>{{.Source}}</code></td></tr>{{end}}
</tbody></table>
<h2>Sample Evidence IDs</h2>
<table><thead><tr><th>ID</th></tr></thead><tbody>
{{range .SampleEvidenceIDs}}<tr><td><code>{{.}}</code></td></tr>{{end}}
</tbody></table>
</body></html>`
	t, err := template.New("compliance").Parse(tpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, report); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func containsFramework(list []string, fw string) bool {
	for _, v := range list {
		if strings.EqualFold(v, fw) {
			return true
		}
	}
	return false
}
