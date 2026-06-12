package cmd

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/compliance"
	"github.com/dativo-io/talon/internal/pack"
	"github.com/dativo-io/talon/internal/policy"
)

// normalizeComplianceSelection parses a --compliance flag value ("gdpr,nis2" or
// "all") into a validated, deduplicated list of overlay names.
func normalizeComplianceSelection(raw string) ([]string, error) {
	valid := make(map[string]bool)
	for _, name := range pack.ComplianceOverlayNames() {
		valid[name] = true
	}
	var names []string
	seen := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(strings.ToLower(part))
		if name == "" {
			continue
		}
		if name == "all" {
			for _, n := range pack.ComplianceOverlayNames() {
				if !seen[n] {
					seen[n] = true
					names = append(names, n)
				}
			}
			continue
		}
		if !valid[name] {
			return nil, fmt.Errorf("unsupported compliance pack %q; use one of: %s, all",
				name, strings.Join(pack.ComplianceOverlayNames(), ", "))
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names, nil
}

// complianceOverlayLabel returns a human-readable wizard label for an overlay name.
func complianceOverlayLabel(name string) string {
	switch name {
	case "gdpr":
		return "GDPR — PII redaction, EU routing, processing records (supports Art. 5(1)(c), 30, 32, 44-50)"
	case "nis2":
		return "NIS2 — rate limits, time restrictions, 2y audit retention (supports Art. 21)"
	case "dora":
		return "DORA — strict PII blocking, cost limits, 5y retention (supports Art. 6, 11)"
	case "eu-ai-act":
		return "EU AI Act — full audit trail, human oversight via plan review (supports Art. 9, 11, 13, 14)"
	default:
		return name
	}
}

// applyComplianceOverlaysToPolicy merges the named compliance overlays onto base
// in place. Used by the wizard and scripted init paths (the --pack path merges
// from the written file via applyComplianceOverlays).
func applyComplianceOverlaysToPolicy(base *policy.Policy, names []string) error {
	for _, name := range names {
		overlayContent, err := pack.ReadComplianceOverlay(name)
		if err != nil {
			return fmt.Errorf("reading compliance overlay %q: %w", name, err)
		}
		var overlay policy.Policy
		if err := yaml.Unmarshal(overlayContent, &overlay); err != nil {
			return fmt.Errorf("parsing overlay %q: %w", name, err)
		}
		mergeComplianceOverlay(base, &overlay)
	}
	return nil
}

// complianceAnnotationBlock builds the YAML comment block written into generated
// agent policies when compliance packs are applied. Every line is derived from
// compliance.DefaultMappings(), so each annotated article links to a real,
// shipping control (claims discipline: supporting evidence, never "compliant").
func complianceAnnotationBlock(packs []string) string {
	if len(packs) == 0 {
		return ""
	}
	frameworks := make(map[string]bool)
	for _, p := range packs {
		frameworks[p] = true
	}
	var b strings.Builder
	b.WriteString("#\n")
	b.WriteString("# Compliance packs applied: " + strings.Join(packs, ", ") + "\n")
	b.WriteString("# These settings provide supporting controls and evidence for the articles below.\n")
	b.WriteString("# They do not, by themselves, make you compliant. See docs/guides/policy-packs.md.\n")
	for _, m := range compliance.DefaultMappings() {
		if frameworks[m.Framework] {
			fmt.Fprintf(&b, "#   supports: %s %s — %s (%s)\n", m.Framework, m.Article, m.Source, m.Control)
		}
	}
	return b.String()
}
