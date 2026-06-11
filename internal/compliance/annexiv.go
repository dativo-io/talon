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
)

// AnnexIVOptions scopes an Annex IV technical-documentation export.
type AnnexIVOptions struct {
	TenantID string
	AgentID  string
	From     string // display only; filtering happens at the store query
	To       string
	// VerifyCommand overrides the default offline verification command.
	VerifyCommand string
	// SignedExportRef names the signed evidence export accompanying the pack.
	SignedExportRef string
	// Now overrides the generation timestamp (tests, golden regeneration).
	Now time.Time
}

// GenerateAnnexIV builds an EU AI Act Annex IV-shaped technical-documentation
// pack from declared facts and signed runtime evidence.
//
// Section numbering follows Annex IV items where Talon holds relevant
// records (1: general description; 3: monitoring, functioning and control;
// 5: risk management; 6: lifecycle changes; 9: post-market monitoring).
// Items Talon cannot document (e.g. development process of the underlying
// model, performance metrics, declaration of conformity) are listed for the
// operator to complete — Talon is a deployment-governance layer, not the
// model provider.
func GenerateAnnexIV(ctx context.Context, decl Declarations, list []evidence.Evidence, opts AnnexIVOptions) (Document, error) {
	_, span := tracer.Start(ctx, "compliance.generate_annex_iv")
	defer span.End()
	span.SetAttributes(
		attribute.String("tenant_id", opts.TenantID),
		attribute.String("agent_id", opts.AgentID),
		attribute.Int("evidence_count", len(list)),
	)

	stats := collectAnnexIVStats(list)
	warnings := decl.ValidateForAnnexIV()
	span.SetAttributes(attribute.Int("declaration_warnings", len(warnings)))

	generatedAt := opts.Now
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	doc := Document{
		Title:       "EU AI Act Annex IV — Technical Documentation Pack",
		Subtitle:    "Deployment-governance records produced by Dativo Talon from signed runtime evidence and declared facts",
		GeneratedAt: generatedAt,
		Framework:   "eu-ai-act",
		Article:     "Annex IV",
		TenantID:    opts.TenantID,
		AgentID:     opts.AgentID,
		Warnings:    warnings,
		ClaimNote:   ClaimNoteFor("EU AI Act Annex IV technical documentation"),
		Linkage: EvidenceLinkage{
			EvidenceCount:     len(list),
			From:              opts.From,
			To:                opts.To,
			SampleEvidenceIDs: stats.sampleIDs,
			VerifyCommand:     annexIVVerifyCommand(opts),
			SignedExportRef:   opts.SignedExportRef,
		},
	}

	doc.Sections = append(doc.Sections,
		annexGeneralSection(decl.System, stats),
		annexMonitoringSection(decl.System, stats),
		annexRiskSection(stats),
		annexLifecycleSection(stats),
		annexPostMarketSection(stats),
		annexOperatorItemsSection(),
	)
	return doc, nil
}

func annexIVVerifyCommand(opts AnnexIVOptions) string {
	if opts.VerifyCommand != "" {
		return opts.VerifyCommand
	}
	if opts.SignedExportRef != "" {
		return "talon audit verify --file " + opts.SignedExportRef
	}
	return "talon audit verify <evidence-id>"
}

// annexIVStats aggregates the runtime facts the Annex IV sections cite.
type annexIVStats struct {
	sampleIDs      []string
	total          int
	denied         int
	piiRecords     int
	degraded       int
	planReviews    int
	memoryWrites   int
	shadowRecords  int
	denialReasons  map[string]int
	models         map[string]int // model -> record count
	providers      map[string]int // destination name (llm_provider flows) -> count
	regions        map[string]int
	first, last    time.Time
	egressDecided  int
	routingDecided int
}

func collectAnnexIVStats(list []evidence.Evidence) annexIVStats {
	s := annexIVStats{
		denialReasons: map[string]int{},
		models:        map[string]int{},
		providers:     map[string]int{},
		regions:       map[string]int{},
	}
	for i := range list {
		s.add(&list[i])
	}
	sort.Strings(s.sampleIDs)
	return s
}

// add folds one evidence record into the aggregate.
func (s *annexIVStats) add(ev *evidence.Evidence) {
	s.total++
	if len(s.sampleIDs) < maxSampleEvidenceIDs {
		s.sampleIDs = append(s.sampleIDs, ev.ID)
	}
	if s.first.IsZero() || ev.Timestamp.Before(s.first) {
		s.first = ev.Timestamp
	}
	if ev.Timestamp.After(s.last) {
		s.last = ev.Timestamp
	}
	s.addDecisions(ev)
	s.addExecution(ev)
	s.addDataFlow(ev.DataFlow)
}

// addDecisions counts policy, oversight, routing, and egress outcomes.
func (s *annexIVStats) addDecisions(ev *evidence.Evidence) {
	if !ev.PolicyDecision.Allowed {
		s.denied++
		for _, r := range ev.PolicyDecision.Reasons {
			s.denialReasons[r]++
		}
	}
	if ev.PlanReview != nil {
		s.planReviews++
	}
	if len(ev.ShadowViolations) > 0 {
		s.shadowRecords++
	}
	if ev.EgressDecision != nil {
		s.egressDecided++
	}
	if ev.RoutingDecision != nil {
		s.routingDecided++
	}
}

// addExecution counts classification, model, and memory facts.
func (s *annexIVStats) addExecution(ev *evidence.Evidence) {
	if len(ev.Classification.PIIDetected) > 0 {
		s.piiRecords++
	}
	if ev.Execution.Degraded {
		s.degraded++
	}
	if ev.Execution.ModelUsed != "" {
		s.models[ev.Execution.ModelUsed]++
	}
	s.memoryWrites += len(ev.MemoryWrites)
}

// addDataFlow counts destination providers and regions from flow items.
func (s *annexIVStats) addDataFlow(flow *evidence.DataFlow) {
	if flow == nil {
		return
	}
	for j := range flow.Items {
		dest := flow.Items[j].Destination
		if dest.Kind == "llm_provider" && dest.Name != "" {
			s.providers[dest.Name]++
		}
		if dest.Region != "" {
			s.regions[dest.Region]++
		}
	}
}

func sortedCountRows(m map[string]int) [][]string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, []string{k, strconv.Itoa(m[k])})
	}
	return rows
}

func annexGeneralSection(sys SystemDeclarations, stats annexIVStats) DocSection {
	heading := "1. General description of the AI system (Annex IV s.1)"
	if sys.SystemDescription == "" && sys.IntendedPurpose == "" {
		return DocSection{Heading: heading, Body: MissingDeclarationText, Missing: true}
	}
	rows := [][]string{}
	if sys.SystemDescription != "" {
		rows = append(rows, []string{"System description (declared)", sys.SystemDescription})
	}
	if sys.IntendedPurpose != "" {
		rows = append(rows, []string{"Intended purpose (declared)", sys.IntendedPurpose})
	}
	if len(stats.models) > 0 {
		models := make([]string, 0, len(stats.models))
		for m := range stats.models {
			models = append(models, m)
		}
		sort.Strings(models)
		rows = append(rows, []string{"Models observed in evidence", strings.Join(models, ", ")})
	}
	if len(stats.providers) > 0 {
		providers := make([]string, 0, len(stats.providers))
		for p := range stats.providers {
			providers = append(providers, p)
		}
		sort.Strings(providers)
		rows = append(rows, []string{"LLM providers observed in evidence", strings.Join(providers, ", ")})
	}
	return DocSection{
		Heading: heading,
		Body:    "Declared description of the system and the models/providers actually observed in signed runtime evidence for the selected scope.",
		Table:   &DocTable{Headers: []string{"Item", "Value"}, Rows: rows},
	}
}

func annexMonitoringSection(sys SystemDeclarations, stats annexIVStats) DocSection {
	heading := "3. Monitoring, functioning and control (Annex IV s.3, Art. 14 human oversight)"
	rows := [][]string{
		{"Signed evidence records in scope", strconv.Itoa(stats.total)},
		{"Policy denials enforced", strconv.Itoa(stats.denied)},
		{"Records with PII detected", strconv.Itoa(stats.piiRecords)},
		{"Plan-review (human oversight) events", strconv.Itoa(stats.planReviews)},
		{"Cost-degradation fallbacks", strconv.Itoa(stats.degraded)},
	}
	if stats.routingDecided > 0 {
		rows = append(rows, []string{"Records with routing decisions (data sovereignty)", strconv.Itoa(stats.routingDecided)})
	}
	if stats.egressDecided > 0 {
		rows = append(rows, []string{"Records with egress decisions (destination control)", strconv.Itoa(stats.egressDecided)})
	}
	body := "Every governed request produces an HMAC-signed evidence record (policy decision, classification, model, cost, duration) " +
		"exported via OpenTelemetry. Operators monitor via the dashboard and metrics endpoints; plan-review gates require human " +
		"approval before agent tool execution where configured."
	if sys.OversightDescription != "" {
		body += " Declared oversight arrangements: " + sys.OversightDescription
	}
	section := DocSection{
		Heading: heading,
		Body:    body,
		Table:   &DocTable{Headers: []string{"Runtime control indicator", "Count"}, Rows: rows},
	}
	if sys.OversightDescription == "" {
		// Oversight is a declared fact; flag without hiding the runtime indicators.
		section.Body += " NOTE: no oversight declaration set — see document warnings."
	}
	return section
}

func annexRiskSection(stats annexIVStats) DocSection {
	rows := [][]string{
		{"Policy-as-code enforcement", "Every request evaluated against .talon.yaml policy via embedded OPA before execution"},
		{"PII detection and redaction", "EU identifier patterns scanned on input and output; redact/block per policy"},
		{"Prompt-injection prevention", "Attachment content sandboxed in isolation delimiters; instruction patterns scanned"},
		{"Cost controls", "Per-request, daily, and monthly budgets enforced per tenant"},
		{"Data-residency routing", "Tier-based routing and egress rules restricting destinations by region"},
		{"Memory governance", "Agent learnings constrained by category allowlists, PII scanning, and audit records"},
	}
	body := "Risk-management controls Talon applies at deployment time (EU AI Act Art. 9 support). " +
		"Enforcement outcomes for the selected scope are quantified in section 3."
	if len(stats.denialReasons) > 0 {
		reasonRows := sortedCountRows(stats.denialReasons)
		return DocSection{
			Heading: "5. Risk management system (Annex IV s.5, Art. 9)",
			Body:    body + " Denial reasons recorded in evidence:",
			Table: &DocTable{
				Headers: []string{"Control / denial reason", "Description / count"},
				Rows:    append(rows, reasonRows...),
			},
		}
	}
	return DocSection{
		Heading: "5. Risk management system (Annex IV s.5, Art. 9)",
		Body:    body,
		Table:   &DocTable{Headers: []string{"Control", "Description"}, Rows: rows},
	}
}

func annexLifecycleSection(stats annexIVStats) DocSection {
	body := "Policy files carry a canonical version hash recorded in every evidence record (policy_version), making policy " +
		"changes traceable across the system lifecycle. Governed agent memory writes are individually audited."
	rows := [][]string{
		{"Audited memory writes in scope", strconv.Itoa(stats.memoryWrites)},
		{"Shadow-mode records (controls evaluated, not enforced)", strconv.Itoa(stats.shadowRecords)},
	}
	return DocSection{
		Heading: "6. Changes through the lifecycle (Annex IV s.6)",
		Body:    body,
		Table:   &DocTable{Headers: []string{"Lifecycle indicator", "Count"}, Rows: rows},
	}
}

func annexPostMarketSection(stats annexIVStats) DocSection {
	body := "Talon's evidence store provides continuous post-deployment records: every governed request is signed at write " +
		"time and retained per the configured retention policy, supporting the post-market monitoring plan (Art. 72)."
	if stats.total > 0 {
		body += fmt.Sprintf(" Scope covered: %d records from %s to %s.",
			stats.total, stats.first.UTC().Format("2006-01-02"), stats.last.UTC().Format("2006-01-02"))
	}
	return DocSection{
		Heading: "9. Post-market monitoring (Annex IV s.9, Art. 72)",
		Body:    body,
	}
}

func annexOperatorItemsSection() DocSection {
	return DocSection{
		Heading: "Items to complete outside Talon",
		Body: "Talon governs deployment and produces runtime records; it is not the model provider. The following Annex IV " +
			"items must be completed by your organisation and/or the model provider, and attached to this pack.",
		Table: &DocTable{
			Headers: []string{"Annex IV item", "Owner"},
			Rows: [][]string{
				{"2. Development process of the underlying model(s)", "Model provider documentation"},
				{"4. Appropriateness of performance metrics", "Deployer + model provider"},
				{"7. Harmonised standards applied", "Deployer"},
				{"8. EU declaration of conformity", "Deployer"},
			},
		},
	}
}
