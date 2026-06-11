// Command auditorpackgen writes examples/auditor-pack artifacts without Docker.
// Invoked by scripts/generate-auditor-pack.sh when the demo stack is unavailable.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dativo-io/talon/internal/compliance"
	"github.com/dativo-io/talon/internal/evidence"
)

const testSigningKey = "01234567890123456789012345678901"

func main() {
	outDir := flag.String("out", "examples/auditor-pack", "output directory")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal("mkdir out: %v", err)
	}

	dir, err := os.MkdirTemp("", "talon-auditor-pack-*")
	if err != nil {
		fatal("temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testSigningKey)
	if err != nil {
		fatal("evidence store: %v", err)
	}
	defer store.Close()

	gen := evidence.NewGenerator(store)
	ctx := context.Background()

	scenarios := []evidence.GenerateParams{
		{
			CorrelationID: "corr_demo_eu_summary", TenantID: "default", AgentID: "gateway",
			InvocationType: "gateway",
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", Reasons: []string{"within budget"}},
			InputPrompt:    "What are the key trends in European AI regulation?",
			OutputResponse: "Summary of EU AI Act and GDPR interplay for deployers.",
			Cost:           0.003,
		},
		{
			CorrelationID: "corr_demo_pii_email", TenantID: "default", AgentID: "gateway",
			InvocationType: "gateway",
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Classification: evidence.Classification{PIIDetected: []string{"email"}, InputTier: 1},
			InputPrompt:    "My email is jan@example.com, help me reset my password",
			OutputResponse: "Password reset steps (synthetic demo).",
			Cost:           0.002,
		},
		{
			CorrelationID: "corr_demo_pii_iban", TenantID: "default", AgentID: "gateway",
			InvocationType: "gateway",
			PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"pii policy"}},
			Classification: evidence.Classification{PIIDetected: []string{"iban"}, InputTier: 2},
			InputPrompt:    "Process payment to IBAN DE89370400440532013000",
			OutputResponse: "",
			Cost:           0,
		},
	}

	var records []evidence.Evidence
	for i := range scenarios {
		ev, err := gen.Generate(ctx, scenarios[i])
		if err != nil {
			fatal("generate: %v", err)
		}
		records = append(records, *ev)
	}

	envelope := evidence.SignedExportEnvelope{
		ExportMetadata: evidence.ExportMetadata{
			GeneratedAt:  time.Now().UTC(),
			TalonVersion: "auditorpackgen",
			TotalRecords: len(records),
			Algorithm:    evidence.SignedExportAlgorithm,
			Signed:       true,
		},
		Records: records,
	}
	evPath := filepath.Join(*outDir, "evidence.signed.json")
	f, err := os.Create(evPath)
	if err != nil {
		fatal("create evidence: %v", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		fatal("encode evidence: %v", err)
	}
	f.Close()

	report := compliance.BuildReport("", "default", "", "", "", records)
	html, err := compliance.RenderHTML(report)
	if err != nil {
		fatal("html report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "compliance-report.html"), html, 0o600); err != nil {
		fatal("write html: %v", err)
	}
	jsonReport, err := compliance.RenderJSON(report)
	if err != nil {
		fatal("json report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "compliance-report.json"), jsonReport, 0o600); err != nil {
		fatal("write json: %v", err)
	}

	// GDPR Art. 30 RoPA: declared demo facts merged with the synthetic evidence.
	ropaDoc, err := compliance.GenerateRoPA(ctx, demoDeclarations(), records, compliance.RoPAOptions{
		TenantID:        "default",
		SignedExportRef: "evidence.signed.json",
	})
	if err != nil {
		fatal("generate ropa: %v", err)
	}
	writeDocument(*outDir, "ropa", ropaDoc)

	// EU AI Act Annex IV technical-documentation pack.
	annexDoc, err := compliance.GenerateAnnexIV(ctx, demoDeclarations(), records, compliance.AnnexIVOptions{
		TenantID:        "default",
		SignedExportRef: "evidence.signed.json",
	})
	if err != nil {
		fatal("generate annex-iv: %v", err)
	}
	writeDocument(*outDir, "annex-iv", annexDoc)

	manifest := map[string]interface{}{
		"generated_at":          time.Now().UTC().Format(time.RFC3339),
		"source":                "scripts/auditorpackgen (offline; no docker-compose)",
		"record_count_estimate": len(records),
		"files": map[string]string{
			"evidence_signed":        "evidence.signed.json",
			"compliance_report_html": "compliance-report.html",
			"compliance_report_json": "compliance-report.json",
			"ropa_html":              "ropa.html",
			"ropa_json":              "ropa.json",
			"annex_iv_html":          "annex-iv.html",
			"annex_iv_json":          "annex-iv.json",
		},
		"verify_commands": []string{
			"TALON_SIGNING_KEY=" + testSigningKey + " talon audit verify --file examples/auditor-pack/evidence.signed.json",
			"open examples/auditor-pack/ropa.html",
			"open examples/auditor-pack/annex-iv.html",
		},
		"claim_note":               "Supporting controls and evidence for auditor review — not a completed legal filing. See LIMITATIONS.md.",
		"offline_signing_key_note": "Offline pack uses a fixed demo key; docker-compose regeneration uses the stack vault key.",
		"declared_facts_note":      "RoPA/Annex IV declarations use Example GmbH fields (see docs/guides/ropa-declarations.md); production exports read them from talon.config.yaml and agent.talon.yaml.",
	}
	mb, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(*outDir, "manifest.json"), mb, 0o600); err != nil {
		fatal("manifest: %v", err)
	}

	fmt.Printf("Wrote auditor pack to %s (%d records)\n", *outDir, len(records))
}

// writeDocument renders an auditor document as <base>.html and <base>.json
// in outDir, exiting via fatal on any error.
func writeDocument(outDir, base string, doc compliance.Document) {
	html, err := compliance.RenderDocumentHTML(doc)
	if err != nil {
		fatal("%s html: %v", base, err)
	}
	if err := os.WriteFile(filepath.Join(outDir, base+".html"), html, 0o600); err != nil {
		fatal("write %s html: %v", base, err)
	}
	jsonOut, err := compliance.RenderDocumentJSON(doc)
	if err != nil {
		fatal("%s json: %v", base, err)
	}
	if err := os.WriteFile(filepath.Join(outDir, base+".json"), jsonOut, 0o600); err != nil {
		fatal("write %s json: %v", base, err)
	}
}

// demoDeclarations are synthetic declared facts for the sample pack —
// what an operator would put in talon.config.yaml and agent.talon.yaml.
func demoDeclarations() compliance.Declarations {
	return compliance.Declarations{
		Controller: compliance.ControllerDeclarations{
			Name:       "Example GmbH",
			Contact:    "privacy@example.eu",
			DPOContact: "dpo@example.eu",
			Address:    "Examplestr. 1, 10115 Berlin, Germany",
		},
		Processing: compliance.ProcessingDeclarations{
			Purposes: []string{
				"customer support ticket triage",
				"internal AI assistance",
			},
			DataSubjectCategories: []string{"customers", "employees"},
			PersonalDataCategories: []string{
				"contact details",
				"payment identifiers",
				"support ticket content",
			},
			RetentionPeriod: "90 days after ticket closure",
			Safeguards:      "Role-based access; vendor DPAs on file; signed evidence retained for audit review",
			LegalBasis:      "contract (Art. 6(1)(b))",
		},
		System: compliance.SystemDeclarations{
			SystemDescription:    "Gateway-governed LLM assistant for customer support ticket triage and internal AI assistance",
			IntendedPurpose:      "Summarize and route inbound support tickets; assist employees with internal knowledge queries",
			OversightDescription: "Support lead reviews flagged tickets; role-based access controls; plan-review gate for tool use where configured",
		},
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "auditorpackgen: "+format+"\n", args...)
	os.Exit(1)
}
