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
	// DataDestinations aggregates data-flow evidence per destination —
	// supports evidence for GDPR Art. 30 records of processing (recipients)
	// and EU AI Act Art. 13 transparency. Empty for evidence recorded before
	// data-flow tracking was introduced.
	DataDestinations []DestinationSummary `json:"data_destinations,omitempty"`
}

// DestinationSummary aggregates classified-data flows to one destination.
type DestinationSummary struct {
	Kind        string   `json:"kind"`             // llm_provider | mcp_tool | client | cache
	Name        string   `json:"name"`             // e.g. "openai"
	Region      string   `json:"region,omitempty"` // "EU" | "US" | "LOCAL" | "unknown"
	RecordCount int      `json:"record_count"`     // evidence records with flows to this destination
	EntityTypes []string `json:"entity_types,omitempty"`
	// RedactedEntityTypes are the entity types that were redacted before
	// every flow to this destination: the type was detected, but the raw
	// values never reached the recipient. Always a subset of EntityTypes.
	RedactedEntityTypes []string `json:"redacted_entity_types,omitempty"`
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
	agg := newDestinationAggregator()
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
		agg.addRecord(ev.DataFlow)
	}
	r.DataDestinations = agg.summaries()
	sort.Strings(r.SampleEvidenceIDs)
	return r
}

// destinationAggregator collapses data-flow items across evidence records
// into one summary per (kind, name, region) destination.
type destinationAggregator struct {
	byKey map[string]*destinationAgg
}

type destinationAgg struct {
	kind, name, region string
	recordCount        int
	entityTypes        map[string]struct{}
	// unredactedTypes: entity types that reached this destination unredacted
	// in at least one flow. Types in entityTypes but not here were always
	// redacted before egress.
	unredactedTypes map[string]struct{}
}

func newDestinationAggregator() *destinationAggregator {
	return &destinationAggregator{byKey: make(map[string]*destinationAgg)}
}

// addRecord folds one evidence record's data flow into the aggregate.
// Each destination counts at most once per record. Blocked items are skipped:
// the data never reached the destination, so listing it as a recipient
// (GDPR Art. 30(1)(d)) or transfer (Art. 30(1)(e)) would overstate.
func (a *destinationAggregator) addRecord(df *evidence.DataFlow) {
	if df == nil {
		return
	}
	seenInRecord := make(map[string]struct{})
	for i := range df.Items {
		item := &df.Items[i]
		if item.Disposition == evidence.FlowDispositionBlocked {
			continue
		}
		d := item.Destination
		key := d.Kind + "\x1f" + d.Name + "\x1f" + d.Region
		agg, ok := a.byKey[key]
		if !ok {
			agg = &destinationAgg{
				kind: d.Kind, name: d.Name, region: d.Region,
				entityTypes:     map[string]struct{}{},
				unredactedTypes: map[string]struct{}{},
			}
			a.byKey[key] = agg
		}
		if _, dup := seenInRecord[key]; !dup {
			seenInRecord[key] = struct{}{}
			agg.recordCount++
		}
		for _, t := range item.EntityTypes {
			agg.entityTypes[t] = struct{}{}
			if item.Disposition != evidence.FlowDispositionRedacted {
				agg.unredactedTypes[t] = struct{}{}
			}
		}
	}
}

// summaries returns deterministic, sorted destination summaries.
func (a *destinationAggregator) summaries() []DestinationSummary {
	out := make([]DestinationSummary, 0, len(a.byKey))
	for _, agg := range a.byKey {
		types := make([]string, 0, len(agg.entityTypes))
		var redacted []string
		for t := range agg.entityTypes {
			types = append(types, t)
			if _, raw := agg.unredactedTypes[t]; !raw {
				redacted = append(redacted, t)
			}
		}
		sort.Strings(types)
		sort.Strings(redacted)
		out = append(out, DestinationSummary{
			Kind:                agg.kind,
			Name:                agg.name,
			Region:              agg.region,
			RecordCount:         agg.recordCount,
			EntityTypes:         types,
			RedactedEntityTypes: redacted,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Region < out[j].Region
	})
	if len(out) == 0 {
		return nil
	}
	return out
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
{{if .DataDestinations}}<h2>Data Destinations</h2>
<p class="meta">Where classified data was sent (from signed data-flow evidence) — supports evidence for GDPR Art. 30 records of processing and EU AI Act Art. 13 transparency.</p>
<table><thead><tr><th>Kind</th><th>Destination</th><th>Region</th><th>Records</th><th>Entity Types</th></tr></thead><tbody>
{{range .DataDestinations}}<tr><td>{{.Kind}}</td><td><code>{{.Name}}</code></td><td>{{.Region}}</td><td>{{.RecordCount}}</td><td>{{range $i, $t := .EntityTypes}}{{if $i}}, {{end}}<code>{{$t}}</code>{{end}}</td></tr>{{end}}
</tbody></table>
{{end}}<h2>Sample Evidence IDs</h2>
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
