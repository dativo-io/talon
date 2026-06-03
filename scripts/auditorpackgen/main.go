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

	manifest := map[string]interface{}{
		"generated_at":          time.Now().UTC().Format(time.RFC3339),
		"source":                "scripts/auditorpackgen (offline; no docker-compose)",
		"record_count_estimate": len(records),
		"files": map[string]string{
			"evidence_signed":        "evidence.signed.json",
			"compliance_report_html": "compliance-report.html",
			"compliance_report_json": "compliance-report.json",
		},
		"verify_commands": []string{
			"TALON_SIGNING_KEY=" + testSigningKey + " talon audit verify --file examples/auditor-pack/evidence.signed.json",
		},
		"claim_note":               "Supporting controls and evidence for auditor review — not a completed legal filing. See LIMITATIONS.md.",
		"offline_signing_key_note": "Offline pack uses a fixed demo key; docker-compose regeneration uses the stack vault key.",
	}
	mb, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(*outDir, "manifest.json"), mb, 0o600); err != nil {
		fatal("manifest: %v", err)
	}

	fmt.Printf("Wrote auditor pack to %s (%d records)\n", *outDir, len(records))
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "auditorpackgen: "+format+"\n", args...)
	os.Exit(1)
}
