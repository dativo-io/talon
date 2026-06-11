package compliance

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/dativo-io/talon/internal/evidence"
	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/compliance")

// RoPAOptions scopes a RoPA export and carries presentation inputs.
type RoPAOptions struct {
	TenantID string
	AgentID  string
	From     string // display only; filtering happens at the store query
	To       string
	// VerifyCommand overrides the default offline verification command shown
	// in the evidence linkage.
	VerifyCommand string
	// SignedExportRef names the signed evidence export that accompanies the
	// document, when one is produced alongside it.
	SignedExportRef string
	// Now overrides the generation timestamp (used by tests and golden
	// regeneration for deterministic output). Zero means time.Now().
	Now time.Time
}

// maxSampleEvidenceIDs caps the evidence IDs listed in the linkage section.
const maxSampleEvidenceIDs = 10

// GenerateRoPA builds a GDPR Art. 30(1)-shaped Record of Processing
// Activities document from declared facts and signed runtime evidence.
//
// Declared facts (controller, purposes, retention) come from operator and
// agent configuration; runtime facts (personal-data categories observed,
// recipients, third-country transfers) come from the evidence records.
// Missing declarations produce warnings and flagged sections, never errors:
// the export must work out of the box and tell the DPO what to fill in.
func GenerateRoPA(ctx context.Context, decl Declarations, list []evidence.Evidence, opts RoPAOptions) (Document, error) {
	_, span := tracer.Start(ctx, "compliance.generate_ropa")
	defer span.End()
	span.SetAttributes(
		attribute.String("tenant_id", opts.TenantID),
		attribute.String("agent_id", opts.AgentID),
		attribute.Int("evidence_count", len(list)),
	)

	agg := newDestinationAggregator()
	activities := map[string]*activityAgg{}
	observedPII := map[string]struct{}{}
	var sampleIDs []string

	for i := range list {
		ev := &list[i]
		agg.addRecord(ev.DataFlow)
		for _, p := range ev.Classification.PIIDetected {
			observedPII[p] = struct{}{}
		}
		if ev.DataFlow != nil {
			for j := range ev.DataFlow.Items {
				for _, et := range ev.DataFlow.Items[j].EntityTypes {
					observedPII[et] = struct{}{}
				}
			}
		}
		key := ev.TenantID + "\x1f" + ev.AgentID
		act, ok := activities[key]
		if !ok {
			act = &activityAgg{tenantID: ev.TenantID, agentID: ev.AgentID, first: ev.Timestamp, last: ev.Timestamp}
			activities[key] = act
		}
		act.records++
		if ev.Timestamp.Before(act.first) {
			act.first = ev.Timestamp
		}
		if ev.Timestamp.After(act.last) {
			act.last = ev.Timestamp
		}
		if len(sampleIDs) < maxSampleEvidenceIDs {
			sampleIDs = append(sampleIDs, ev.ID)
		}
	}
	sort.Strings(sampleIDs)
	destinations := agg.summaries()
	warnings := decl.ValidateForRoPA()
	span.SetAttributes(attribute.Int("declaration_warnings", len(warnings)))

	generatedAt := opts.Now
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	doc := Document{
		Title:       "Record of Processing Activities",
		Subtitle:    "AI traffic governed by Dativo Talon — generated from signed runtime evidence and declared facts",
		GeneratedAt: generatedAt,
		Framework:   "gdpr",
		Article:     "Art. 30",
		TenantID:    opts.TenantID,
		AgentID:     opts.AgentID,
		Warnings:    warnings,
		ClaimNote:   ClaimNoteFor("GDPR Art. 30"),
		Linkage: EvidenceLinkage{
			EvidenceCount:     len(list),
			From:              opts.From,
			To:                opts.To,
			SampleEvidenceIDs: sampleIDs,
			VerifyCommand:     verifyCommand(opts),
			SignedExportRef:   opts.SignedExportRef,
		},
	}

	doc.Sections = append(doc.Sections,
		controllerSection(decl.Controller),
		activitiesSection(activities),
		purposesSection(decl.Processing),
		categoriesSection(decl.Processing, observedPII),
		recipientsSection(destinations),
		transfersSection(destinations),
		retentionSection(decl.Processing),
		measuresSection(decl.Processing),
	)
	return doc, nil
}

type activityAgg struct {
	tenantID, agentID string
	records           int
	first, last       time.Time
}

func verifyCommand(opts RoPAOptions) string {
	if opts.VerifyCommand != "" {
		return opts.VerifyCommand
	}
	if opts.SignedExportRef != "" {
		return "talon audit verify --file " + opts.SignedExportRef
	}
	return "talon audit verify <evidence-id>"
}

func controllerSection(c ControllerDeclarations) DocSection {
	if c.Name == "" {
		return DocSection{Heading: "1. Controller (Art. 30(1)(a))", Body: MissingDeclarationText, Missing: true}
	}
	rows := [][]string{{"Controller", c.Name}}
	if c.Contact != "" {
		rows = append(rows, []string{"Contact", c.Contact})
	}
	if c.DPOContact != "" {
		rows = append(rows, []string{"Data Protection Officer", c.DPOContact})
	}
	if c.Address != "" {
		rows = append(rows, []string{"Address", c.Address})
	}
	if c.Representative != "" {
		rows = append(rows, []string{"EU Representative (Art. 27)", c.Representative})
	}
	return DocSection{
		Heading: "1. Controller (Art. 30(1)(a))",
		Table:   &DocTable{Headers: []string{"Field", "Value"}, Rows: rows},
	}
}

func activitiesSection(activities map[string]*activityAgg) DocSection {
	if len(activities) == 0 {
		return DocSection{
			Heading: "2. Processing activities observed",
			Body:    "No evidence records were found in the selected scope. Run governed traffic through Talon or widen the date range, then regenerate.",
		}
	}
	keys := make([]string, 0, len(activities))
	for k := range activities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		a := activities[k]
		rows = append(rows, []string{
			a.tenantID,
			a.agentID,
			strconv.Itoa(a.records),
			a.first.UTC().Format("2006-01-02"),
			a.last.UTC().Format("2006-01-02"),
		})
	}
	return DocSection{
		Heading: "2. Processing activities observed",
		Body:    "Each row is one governed caller (tenant, agent) observed in the signed evidence store for the selected scope.",
		Table:   &DocTable{Headers: []string{"Tenant", "Agent", "Evidence records", "First seen", "Last seen"}, Rows: rows},
	}
}

func purposesSection(p ProcessingDeclarations) DocSection {
	heading := "3. Purposes of processing (Art. 30(1)(b))"
	if len(p.Purposes) == 0 {
		return DocSection{Heading: heading, Body: MissingDeclarationText, Missing: true}
	}
	body := strings.Join(p.Purposes, "; ")
	if p.LegalBasis != "" {
		body += fmt.Sprintf(" — declared lawful basis (Art. 6): %s", p.LegalBasis)
	}
	return DocSection{Heading: heading, Body: body}
}

func categoriesSection(p ProcessingDeclarations, observedPII map[string]struct{}) DocSection {
	heading := "4. Categories of data subjects and personal data (Art. 30(1)(c))"
	var rows [][]string
	if len(p.DataSubjectCategories) > 0 {
		rows = append(rows, []string{"Data subjects (declared)", strings.Join(p.DataSubjectCategories, ", ")})
	}
	if len(p.PersonalDataCategories) > 0 {
		rows = append(rows, []string{"Personal data (declared)", strings.Join(p.PersonalDataCategories, ", ")})
	}
	observed := make([]string, 0, len(observedPII))
	for t := range observedPII {
		observed = append(observed, t)
	}
	sort.Strings(observed)
	if len(observed) > 0 {
		rows = append(rows, []string{"Personal data identifiers observed in evidence", strings.Join(observed, ", ")})
	}
	if len(rows) == 0 {
		return DocSection{Heading: heading, Body: MissingDeclarationText, Missing: true}
	}
	return DocSection{
		Heading: heading,
		Body:    "Declared categories come from agent configuration; observed identifiers come from PII detection recorded in signed evidence.",
		Table:   &DocTable{Headers: []string{"Category", "Values"}, Rows: rows},
	}
}

func recipientsSection(destinations []DestinationSummary) DocSection {
	heading := "5. Categories of recipients (Art. 30(1)(d))"
	if len(destinations) == 0 {
		return DocSection{
			Heading: heading,
			Body: "No data flows were recorded in the selected scope. Destinations appear here once " +
				"governed traffic passes through Talon and data-flow evidence is captured.",
		}
	}
	rows := make([][]string, 0, len(destinations))
	for _, d := range destinations {
		rows = append(rows, []string{d.Name, d.Kind, d.Region, strconv.Itoa(d.RecordCount), strings.Join(d.EntityTypes, ", ")})
	}
	return DocSection{
		Heading: heading,
		Body:    "Destinations that received request or response data, aggregated from signed data-flow evidence.",
		Table:   &DocTable{Headers: []string{"Recipient", "Kind", "Region", "Evidence records", "Identifier types"}, Rows: rows},
	}
}

// euRegions are destination regions not considered third-country transfers.
var euRegions = map[string]struct{}{"EU": {}, "LOCAL": {}}

func transfersSection(destinations []DestinationSummary) DocSection {
	heading := "6. Transfers to third countries (Art. 30(1)(e))"
	// Absence of data-flow evidence is not a "no transfers" finding: say so
	// explicitly instead of implying transfers were assessed.
	if len(destinations) == 0 {
		return DocSection{
			Heading: heading,
			Body: "No data-flow evidence was recorded in the selected scope, so third-country transfers " +
				"cannot be assessed yet. Transfers appear here once data-flow evidence is captured for " +
				"governed requests.",
		}
	}
	var rows [][]string
	unknown := 0
	for _, d := range destinations {
		region := strings.ToUpper(d.Region)
		if _, eu := euRegions[region]; eu || d.Region == "" {
			continue
		}
		if strings.EqualFold(d.Region, evidence.FlowRegionUnknown) {
			unknown++
		}
		rows = append(rows, []string{d.Name, d.Kind, d.Region, strconv.Itoa(d.RecordCount)})
	}
	if len(rows) == 0 {
		return DocSection{
			Heading: heading,
			Body: "Data flows were recorded in the selected scope and all destinations were within " +
				"EU/LOCAL regions; no third-country transfers were observed.",
		}
	}
	body := "Destinations outside EU/LOCAL regions observed in data-flow evidence. Document the transfer mechanism (e.g. SCCs, adequacy decision) for each with your DPO."
	if unknown > 0 {
		body += fmt.Sprintf(" %d destination(s) have an unresolved region (\"unknown\") — set gateway.providers.<name>.region and regenerate.", unknown)
	}
	return DocSection{
		Heading: heading,
		Body:    body,
		Table:   &DocTable{Headers: []string{"Destination", "Kind", "Region", "Evidence records"}, Rows: rows},
	}
}

func retentionSection(p ProcessingDeclarations) DocSection {
	heading := "7. Envisaged erasure time limits (Art. 30(1)(f))"
	if p.RetentionPeriod == "" {
		return DocSection{Heading: heading, Body: MissingDeclarationText, Missing: true}
	}
	return DocSection{Heading: heading, Body: p.RetentionPeriod}
}

func measuresSection(p ProcessingDeclarations) DocSection {
	rows := [][]string{
		{"Evidence integrity", "HMAC-SHA256 signed evidence records; offline verification via talon audit verify", "internal/evidence"},
		{"Secrets protection", "AES-256-GCM encrypted vault with per-agent ACLs; every access audited", "internal/secrets"},
		{"PII detection", "EU identifier patterns scanned on input and output; redaction/block per policy", "internal/classifier"},
		{"Data residency controls", "Tier-based routing and egress rules restricting destinations by region", "internal/llm, internal/gateway"},
		{"Tenant isolation", "Per-tenant state, budgets, rate limits, and evidence scoping", "internal/tenant"},
	}
	for _, m := range DefaultMappings() {
		if strings.EqualFold(m.Framework, "gdpr") {
			rows = append(rows, []string{"Mapped control: GDPR " + m.Article, m.Control, m.Source})
		}
	}
	if p.Safeguards != "" {
		rows = append(rows, []string{"Organisational safeguards (declared)", p.Safeguards, "agent.talon.yaml"})
	}
	return DocSection{
		Heading: "8. Technical and organisational security measures (Art. 30(1)(g), Art. 32)",
		Body: "Technical controls applied by Talon to the processing described above. Organisational measures " +
			"beyond Talon (access policies, training, vendor DPAs) should be documented separately; see the " +
			"declared safeguards field.",
		Table: &DocTable{Headers: []string{"Control", "Description", "Source"}, Rows: rows},
	}
}
