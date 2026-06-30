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

// SovereigntyPostureConfig carries declared operator/gateway facts for the
// posture report. Runtime observations come from signed evidence.
type SovereigntyPostureConfig struct {
	DataSovereigntyMode string
	DeploymentMode      string
	AirGapEgressGuard   bool
	AllowedEgressHosts  []string
	GatewayProviders    []SovereigntyGatewayProvider
	LLMProviders        []SovereigntyLLMProvider
	// GatewayConfigError, when non-empty, records that a declared gateway config
	// could not be loaded. The gateway section renders this distinctly so an
	// empty provider list is never misread as "no providers configured".
	GatewayConfigError string
}

// SovereigntyGatewayProvider is one configured gateway upstream.
type SovereigntyGatewayProvider struct {
	Name    string
	Region  string
	Enabled bool
	// Posture is allowed, excluded (declared under eu_strict), or disabled.
	Posture string
}

// SovereigntyLLMProvider is one registry provider evaluated under the
// configured data sovereignty mode.
type SovereigntyLLMProvider struct {
	ID      string
	Allowed bool
	Reason  string
	// Status is allowed, not_allowed, or excluded_declared.
	Status string
}

// SovereigntyPostureOptions scopes the export and carries presentation inputs.
type SovereigntyPostureOptions struct {
	TenantID        string
	AgentID         string
	From            string
	To              string
	SignedExportRef string
	Now             time.Time
}

type sovereigntyStats struct {
	policyDenials      int
	egressDenials      int
	egressAllows       int
	routingRejections  int
	egressDenyByReason map[string]int
	routingRejectByID  map[string]int
}

// GenerateSovereigntyPosture builds a sovereignty posture report from declared
// configuration and signed runtime evidence (#133). The report is intended for
// security teams and auditors reviewing in-region / air-gap posture — not a
// compliance determination.
func GenerateSovereigntyPosture(
	ctx context.Context,
	cfg SovereigntyPostureConfig,
	list []evidence.Evidence,
	opts SovereigntyPostureOptions,
) (Document, error) {
	_, span := tracer.Start(ctx, "compliance.generate_sovereignty_posture")
	defer span.End()
	span.SetAttributes(
		attribute.String("tenant_id", opts.TenantID),
		attribute.String("agent_id", opts.AgentID),
		attribute.Int("evidence_count", len(list)),
	)

	stats := aggregateSovereigntyStats(list)
	agg := newDestinationAggregator()
	var sampleIDs []string
	for i := range list {
		ev := &list[i]
		agg.addRecord(ev.DataFlow)
		if len(sampleIDs) < maxSampleEvidenceIDs {
			sampleIDs = append(sampleIDs, ev.ID)
		}
	}
	sort.Strings(sampleIDs)
	destinations := agg.summaries()

	generatedAt := opts.Now
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	mode := cfg.DataSovereigntyMode
	if mode == "" {
		mode = "global"
	}
	deploy := cfg.DeploymentMode
	if deploy == "" {
		deploy = "standard"
	}

	warnings := sovereigntyWarnings(cfg, destinations, stats)

	doc := Document{
		Title:       "Sovereignty Posture Report",
		Subtitle:    "Configured EU/in-region controls and observed egress — generated from signed runtime evidence",
		GeneratedAt: generatedAt,
		Framework:   "sovereignty",
		Article:     "Posture",
		TenantID:    opts.TenantID,
		AgentID:     opts.AgentID,
		Warnings:    warnings,
		ClaimNote:   ClaimNoteFor("data-residency and egress governance"),
		Linkage: EvidenceLinkage{
			EvidenceCount:     len(list),
			From:              opts.From,
			To:                opts.To,
			SampleEvidenceIDs: sampleIDs,
			VerifyCommand:     sovereigntyVerifyCommand(opts),
			SignedExportRef:   opts.SignedExportRef,
		},
		Sections: []DocSection{
			sovereigntyConfigSection(cfg, mode, deploy),
			sovereigntyLLMProvidersSection(cfg),
			sovereigntyGatewaySection(cfg),
			sovereigntyObservedDestinationsSection(destinations),
			sovereigntyDenialsSection(stats),
		},
	}
	return doc, nil
}

func sovereigntyVerifyCommand(opts SovereigntyPostureOptions) string {
	if opts.SignedExportRef != "" {
		return "talon audit verify --file " + opts.SignedExportRef
	}
	return "talon audit verify"
}

func sovereigntyWarnings(cfg SovereigntyPostureConfig, destinations []DestinationSummary, stats sovereigntyStats) []string {
	var warnings []string
	if cfg.DataSovereigntyMode == "" {
		warnings = append(warnings, "llm.routing.data_sovereignty_mode is not set — routing defaults to global in this report")
	}
	for _, d := range destinations {
		if strings.EqualFold(d.Region, "US") || strings.EqualFold(d.Region, "CN") {
			warnings = append(warnings, fmt.Sprintf("observed egress to non-EU region %q via %s (%s)", d.Region, d.Name, d.Kind))
		}
	}
	for _, p := range cfg.LLMProviders {
		if p.Status == "excluded_declared" {
			warnings = append(warnings, fmt.Sprintf("declared provider %q excluded under %s", p.ID, cfg.DataSovereigntyMode))
		}
	}
	for _, p := range cfg.GatewayProviders {
		if p.Posture == "excluded" {
			warnings = append(warnings, fmt.Sprintf("declared gateway provider %q excluded under %s", p.Name, cfg.DataSovereigntyMode))
		}
	}
	if stats.egressDenials > 0 && cfg.DataSovereigntyMode != "eu_strict" {
		warnings = append(warnings, "egress denials observed while data_sovereignty_mode is not eu_strict — align routing and egress policy")
	}
	return warnings
}

func sovereigntyConfigSection(cfg SovereigntyPostureConfig, mode, deploy string) DocSection {
	body := fmt.Sprintf(
		"Data sovereignty routing mode: %s\nDeployment mode: %s\nTransport egress guard: %s",
		mode, deploy, boolLabel(cfg.AirGapEgressGuard),
	)
	if len(cfg.AllowedEgressHosts) > 0 {
		body += "\nAdditional allowed egress hosts: " + strings.Join(cfg.AllowedEgressHosts, ", ")
	}
	return DocSection{Heading: "1. Configured sovereignty posture", Body: body}
}

func sovereigntyLLMProvidersSection(cfg SovereigntyPostureConfig) DocSection {
	if len(cfg.LLMProviders) == 0 {
		return DocSection{
			Heading: "2. LLM providers (registry evaluation)",
			Body:    "No provider registry entries evaluated.",
		}
	}
	rows := make([][]string, 0, len(cfg.LLMProviders))
	for _, p := range cfg.LLMProviders {
		status := p.Status
		if status == "" {
			status = "not_allowed"
			if p.Allowed {
				status = "allowed"
			}
		}
		rows = append(rows, []string{p.ID, status, p.Reason})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return DocSection{
		Heading: "2. LLM providers (registry evaluation)",
		Body:    "Providers evaluated under the configured data_sovereignty_mode using routing.rego.",
		Table:   &DocTable{Headers: []string{"Provider", "Status", "Reason"}, Rows: rows},
	}
}

func sovereigntyGatewaySection(cfg SovereigntyPostureConfig) DocSection {
	if cfg.GatewayConfigError != "" {
		return DocSection{
			Heading: "3. Gateway upstream providers",
			Body: "Gateway config could not be loaded: " + cfg.GatewayConfigError +
				"\nProvider rows are unavailable for this report. This is NOT a statement that no gateway providers are configured — resolve the gateway config and regenerate.",
		}
	}
	if len(cfg.GatewayProviders) == 0 {
		return DocSection{
			Heading: "3. Gateway upstream providers",
			Body:    "No gateway providers configured.",
		}
	}
	rows := make([][]string, 0, len(cfg.GatewayProviders))
	for _, p := range cfg.GatewayProviders {
		posture := p.Posture
		if posture == "" {
			posture = "allowed"
			if !p.Enabled {
				posture = "disabled"
			}
		}
		rows = append(rows, []string{p.Name, p.Region, boolLabel(p.Enabled), posture})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return DocSection{
		Heading: "3. Gateway upstream providers",
		Table:   &DocTable{Headers: []string{"Provider", "Region", "Enabled", "Posture"}, Rows: rows},
	}
}

func sovereigntyObservedDestinationsSection(destinations []DestinationSummary) DocSection {
	if len(destinations) == 0 {
		return DocSection{
			Heading: "4. Observed egress destinations (runtime)",
			Body:    "No forwarded data-flow destinations in the selected evidence window.",
		}
	}
	rows := make([][]string, 0, len(destinations))
	for _, d := range destinations {
		rows = append(rows, []string{d.Kind, d.Name, d.Region, strconv.Itoa(d.RecordCount)})
	}
	return DocSection{
		Heading: "4. Observed egress destinations (runtime)",
		Body:    "Aggregated from signed data_flow evidence (blocked flows excluded).",
		Table:   &DocTable{Headers: []string{"Kind", "Name", "Region", "Records"}, Rows: rows},
	}
}

func sovereigntyDenialsSection(stats sovereigntyStats) DocSection {
	rows := [][]string{
		{"Policy denials (any reason)", strconv.Itoa(stats.policyDenials)},
		{"Egress denials", strconv.Itoa(stats.egressDenials)},
		{"Egress allows (control executed)", strconv.Itoa(stats.egressAllows)},
		{"Routing rejections (candidates)", strconv.Itoa(stats.routingRejections)},
	}
	for reason, n := range stats.egressDenyByReason {
		rows = append(rows, []string{"Egress deny: " + reason, strconv.Itoa(n)})
	}
	for id, n := range stats.routingRejectByID {
		rows = append(rows, []string{"Routing reject: " + id, strconv.Itoa(n)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return DocSection{
		Heading: "5. Policy and egress denials (runtime)",
		Body:    "Counts from signed evidence in the selected window.",
		Table:   &DocTable{Headers: []string{"Control", "Count"}, Rows: rows},
	}
}

func aggregateSovereigntyStats(list []evidence.Evidence) sovereigntyStats {
	s := sovereigntyStats{
		egressDenyByReason: make(map[string]int),
		routingRejectByID:  make(map[string]int),
	}
	for i := range list {
		ev := &list[i]
		if !ev.PolicyDecision.Allowed {
			s.policyDenials++
		}
		if ev.EgressDecision != nil {
			switch ev.EgressDecision.Decision {
			case "deny":
				s.egressDenials++
				reason := ev.EgressDecision.Reason
				if reason == "" {
					reason = "unspecified"
				}
				s.egressDenyByReason[reason]++
			case "allow":
				s.egressAllows++
			}
		}
		if ev.RoutingDecision != nil {
			s.routingRejections += len(ev.RoutingDecision.RejectedCandidates)
			for _, rc := range ev.RoutingDecision.RejectedCandidates {
				id := rc.ProviderID
				if id == "" {
					id = "unknown"
				}
				s.routingRejectByID[id]++
			}
		}
	}
	return s
}

func boolLabel(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
