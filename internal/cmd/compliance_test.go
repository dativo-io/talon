package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/compliance"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
)

func TestComplianceCmd_HasSubcommands(t *testing.T) {
	expected := []string{"report", "ropa", "annex-iv", "sovereignty"}
	registered := make(map[string]bool)
	for _, c := range complianceCmd.Commands() {
		registered[c.Name()] = true
	}
	for _, name := range expected {
		assert.True(t, registered[name], "compliance subcommand %q should be registered", name)
	}
}

func TestComplianceRopaCmd_Flags(t *testing.T) {
	for _, name := range []string{"format", "tenant", "agent", "from", "to", "output", "policy"} {
		flag := complianceRopaCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "compliance ropa flag %q should be registered", name)
	}
	assert.Equal(t, "html", complianceRopaCmd.Flags().Lookup("format").DefValue)
}

func seedComplianceEvidence(t *testing.T) {
	t.Helper()
	cfg, err := config.Load()
	require.NoError(t, err)
	require.NoError(t, cfg.EnsureDataDir())

	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	defer store.Close()

	gen := evidence.NewGenerator(store)
	ctx := context.Background()
	params := []evidence.GenerateParams{
		{
			CorrelationID: "corr_ropa_1", TenantID: "default", AgentID: "support-agent",
			InvocationType: "gateway",
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Classification: evidence.Classification{PIIDetected: []string{"email"}, InputTier: 1},
			Cost:           0.002,
		},
		{
			CorrelationID: "corr_ropa_2", TenantID: "default", AgentID: "support-agent",
			InvocationType: "gateway",
			PolicyDecision: evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"pii policy"}},
			Classification: evidence.Classification{PIIDetected: []string{"iban"}, InputTier: 2},
		},
	}
	for i := range params {
		_, err := gen.Generate(ctx, params[i])
		require.NoError(t, err)
	}
}

func writeDeclaredPolicy(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "agent.talon.yaml")
	content := `
agent:
  name: support-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 10.0
compliance:
  frameworks: [gdpr]
  declarations:
    processing:
      purposes: ["customer support triage"]
      data_subject_categories: ["customers"]
      retention_period: "90 days"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestComplianceRopa_EndToEndJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	seedComplianceEvidence(t)
	policyPath := writeDeclaredPolicy(t, dir)

	outPath := filepath.Join(dir, "ropa.json")
	var errBuf bytes.Buffer
	rootCmd.SetErr(&errBuf)
	rootCmd.SetArgs([]string{
		"compliance", "ropa",
		"--format", "json",
		"--policy", policyPath,
		"--from", "2020-01-01",
		"--output", outPath,
	})
	t.Cleanup(func() {
		rootCmd.SetErr(nil)
		complianceFormat, complianceOutput, compliancePolicyFile, complianceFrom = "html", "", "", ""
	})

	require.NoError(t, rootCmd.Execute())

	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var doc compliance.Document
	require.NoError(t, json.Unmarshal(raw, &doc))

	assert.Equal(t, "Record of Processing Activities", doc.Title)
	assert.Equal(t, "gdpr", doc.Framework)
	assert.Equal(t, 2, doc.Linkage.EvidenceCount)
	assert.Len(t, doc.Sections, 8)
	assert.Contains(t, doc.ClaimNote, "not a completed legal filing")

	// Declared facts from the policy file made it into the document.
	purposes := findSection(t, doc, "3. Purposes of processing (Art. 30(1)(b))")
	assert.False(t, purposes.Missing)
	assert.Contains(t, purposes.Body, "customer support triage")

	// Controller is not declared (no talon.config.yaml compliance block):
	// the command still succeeds and flags the gap.
	controller := findSection(t, doc, "1. Controller (Art. 30(1)(a))")
	assert.True(t, controller.Missing)
	assert.NotEmpty(t, doc.Warnings)
	assert.Contains(t, errBuf.String(), "WARNING:", "warnings are echoed to stderr")

	// Observed PII identifiers from evidence are merged in.
	categories := findSection(t, doc, "4. Categories of data subjects and personal data (Art. 30(1)(c))")
	require.NotNil(t, categories.Table)
	foundObserved := false
	for _, row := range categories.Table.Rows {
		if row[0] == "Personal data identifiers observed in evidence" {
			foundObserved = true
			assert.Equal(t, "email, iban", row[1])
		}
	}
	assert.True(t, foundObserved)
}

func TestComplianceRopa_HTMLContainsClaimNote(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	seedComplianceEvidence(t)

	outPath := filepath.Join(dir, "ropa.html")
	rootCmd.SetErr(&bytes.Buffer{})
	rootCmd.SetArgs([]string{"compliance", "ropa", "--format", "html", "--from", "2020-01-01", "--output", outPath})
	t.Cleanup(func() {
		rootCmd.SetErr(nil)
		complianceFormat, complianceOutput, complianceFrom = "html", "", ""
	})

	require.NoError(t, rootCmd.Execute())

	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	html := string(raw)
	assert.Contains(t, html, "Record of Processing Activities")
	assert.Contains(t, html, "DECLARATION MISSING", "undeclared sections are flagged in HTML")
	assert.Contains(t, html, "not a completed legal filing")
}

func TestComplianceAnnexIVCmd_Flags(t *testing.T) {
	for _, name := range []string{"format", "tenant", "agent", "from", "to", "output", "policy"} {
		flag := complianceAnnexIVCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "compliance annex-iv flag %q should be registered", name)
	}
}

func TestComplianceAnnexIV_EndToEndJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	seedComplianceEvidence(t)

	policyPath := filepath.Join(dir, "agent.talon.yaml")
	content := `
agent:
  name: support-agent
  version: 1.0.0
policies:
  cost_limits:
    daily: 10.0
compliance:
  frameworks: [eu-ai-act]
  declarations:
    system:
      system_description: "LLM assistant for support ticket triage"
      intended_purpose: "Summarize and route inbound support tickets"
      oversight_description: "Support lead reviews flagged tickets daily"
`
	require.NoError(t, os.WriteFile(policyPath, []byte(content), 0o644))

	outPath := filepath.Join(dir, "annexiv.json")
	var errBuf bytes.Buffer
	rootCmd.SetErr(&errBuf)
	rootCmd.SetArgs([]string{
		"compliance", "annex-iv",
		"--format", "json",
		"--policy", policyPath,
		"--from", "2020-01-01",
		"--output", outPath,
	})
	t.Cleanup(func() {
		rootCmd.SetErr(nil)
		complianceFormat, complianceOutput, compliancePolicyFile, complianceFrom = "html", "", "", ""
	})

	require.NoError(t, rootCmd.Execute())

	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var doc compliance.Document
	require.NoError(t, json.Unmarshal(raw, &doc))

	assert.Equal(t, "EU AI Act Annex IV — Technical Documentation Pack", doc.Title)
	assert.Equal(t, "eu-ai-act", doc.Framework)
	assert.Equal(t, 2, doc.Linkage.EvidenceCount)
	assert.Len(t, doc.Sections, 6)
	assert.Empty(t, doc.Warnings, "all system declarations are set")
	assert.Contains(t, doc.ClaimNote, "not a completed legal filing")

	general := findSection(t, doc, "1. General description of the AI system (Annex IV s.1)")
	assert.False(t, general.Missing)

	operator := findSection(t, doc, "Items to complete outside Talon")
	require.NotNil(t, operator.Table)
	assert.Len(t, operator.Table.Rows, 4)
}

// TestComplianceSovereignty_MergesGatewaySovereignty verifies that a
// sovereignty block declared in --gateway-config (air_gap) is merged into the
// operator config and reflected as the effective eu_strict mode in the report.
// This is the same class of bug fixed in #185 for serve/doctor.
func TestComplianceSovereignty_MergesGatewaySovereignty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	seedComplianceEvidence(t)

	gwPath := filepath.Join(dir, "gw.airgap.yaml")
	gwYAML := `sovereignty:
  deployment_mode: air_gap
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "shadow"
  providers:
    ollama:
      enabled: true
      base_url: "http://127.0.0.1:11434"
      region: "LOCAL"
      secret_name: "ollama-api-key"
  callers:
    - name: "local"
      tenant_key: "k-local"
      tenant_id: "default"
  default_policy:
    default_pii_action: "warn"
`
	require.NoError(t, os.WriteFile(gwPath, []byte(gwYAML), 0o600))

	outPath := filepath.Join(dir, "sov.json")
	rootCmd.SetErr(&bytes.Buffer{})
	rootCmd.SetArgs([]string{
		"compliance", "sovereignty",
		"--format", "json",
		"--gateway-config", gwPath,
		"--from", "2020-01-01",
		"--output", outPath,
	})
	t.Cleanup(func() {
		rootCmd.SetErr(nil)
		complianceFormat, complianceFrom, complianceGatewayConfig, complianceOutput = "html", "", "", ""
	})

	require.NoError(t, rootCmd.Execute())

	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var doc compliance.Document
	require.NoError(t, json.Unmarshal(raw, &doc))

	assert.Equal(t, "Sovereignty Posture Report", doc.Title)
	cfgSection := findSection(t, doc, "1. Configured sovereignty posture")
	assert.Contains(t, cfgSection.Body, "eu_strict", "gateway air_gap should resolve to effective eu_strict routing mode")
	assert.Contains(t, cfgSection.Body, "air_gap", "deployment mode should reflect gateway-declared air_gap")

	// Gateway providers were loaded (no GatewayConfigError path).
	gw := findSection(t, doc, "3. Gateway upstream providers")
	require.NotNil(t, gw.Table)
}

func TestComplianceSovereignty_ExcludedDeclaredProvider(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("OPENAI_API_KEY", "sk-test")
	seedComplianceEvidence(t)

	gwPath := filepath.Join(dir, "gw.mixed.yaml")
	gwYAML := `sovereignty:
  mode: eu_strict
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  mode: "shadow"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      region: "US"
      secret_name: "openai-api-key"
    ollama:
      enabled: true
      base_url: "http://127.0.0.1:11434"
      region: "LOCAL"
      secret_name: "ollama-api-key"
  callers:
    - name: "local"
      tenant_key: "k-local"
      tenant_id: "default"
  default_policy:
    default_pii_action: "warn"
`
	require.NoError(t, os.WriteFile(gwPath, []byte(gwYAML), 0o600))

	outPath := filepath.Join(dir, "sov.json")
	rootCmd.SetErr(&bytes.Buffer{})
	rootCmd.SetArgs([]string{
		"compliance", "sovereignty",
		"--format", "json",
		"--gateway-config", gwPath,
		"--from", "2020-01-01",
		"--output", outPath,
	})
	t.Cleanup(func() {
		rootCmd.SetErr(nil)
		complianceFormat, complianceFrom, complianceGatewayConfig, complianceOutput = "html", "", "", ""
	})

	require.NoError(t, rootCmd.Execute())

	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var doc compliance.Document
	require.NoError(t, json.Unmarshal(raw, &doc))

	foundExcluded := false
	for _, w := range doc.Warnings {
		if strings.Contains(w, "excluded") && strings.Contains(w, "openai") {
			foundExcluded = true
		}
	}
	assert.True(t, foundExcluded, "warnings should mention excluded openai")

	gwSection := findSection(t, doc, "3. Gateway upstream providers")
	require.NotNil(t, gwSection.Table)
	for _, row := range gwSection.Table.Rows {
		if row[0] == "openai" {
			assert.Equal(t, "excluded", row[3])
		}
	}
}

// TestComplianceSovereignty_ExplicitInvalidGatewayConfigFails verifies that an
// explicitly provided --gateway-config that cannot be loaded is a hard error,
// not a report rendering "No gateway providers configured."
func TestComplianceSovereignty_ExplicitInvalidGatewayConfigFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	seedComplianceEvidence(t)

	badGw := filepath.Join(dir, "bad.gateway.yaml")
	require.NoError(t, os.WriteFile(badGw, []byte("gateway: [this is not valid\n"), 0o600))

	rootCmd.SetErr(&bytes.Buffer{})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{
		"compliance", "sovereignty",
		"--format", "json",
		"--gateway-config", badGw,
		"--from", "2020-01-01",
	})
	t.Cleanup(func() {
		rootCmd.SetErr(nil)
		rootCmd.SetOut(nil)
		complianceFormat, complianceFrom, complianceGatewayConfig = "html", "", ""
	})

	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway config")
}

func TestComplianceRopa_RejectsUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	rootCmd.SetErr(&bytes.Buffer{})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{"compliance", "ropa", "--format", "pdf"})
	t.Cleanup(func() {
		rootCmd.SetErr(nil)
		rootCmd.SetOut(nil)
		complianceFormat = "html"
	})

	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported --format")
}

func findSection(t *testing.T, doc compliance.Document, heading string) compliance.DocSection {
	t.Helper()
	for _, s := range doc.Sections {
		if s.Heading == heading {
			return s
		}
	}
	t.Fatalf("section %q not found", heading)
	return compliance.DocSection{}
}
