package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
)

func TestAuditCmd_HasSubcommands(t *testing.T) {
	expected := []string{"list", "show", "verify", "export"}
	registered := make(map[string]bool)
	for _, cmd := range auditCmd.Commands() {
		registered[cmd.Name()] = true
	}
	for _, name := range expected {
		assert.True(t, registered[name], "audit subcommand %q should be registered", name)
	}
}

func TestAuditVerifyCmd_AcceptsZeroOrOneArg(t *testing.T) {
	assert.NotNil(t, auditVerifyCmd.Args)
	err := auditVerifyCmd.Args(auditVerifyCmd, []string{})
	assert.NoError(t, err)
	err = auditVerifyCmd.Args(auditVerifyCmd, []string{"ev_123"})
	assert.NoError(t, err)
	err = auditVerifyCmd.Args(auditVerifyCmd, []string{"ev_1", "ev_2"})
	assert.Error(t, err)
}

func TestAuditListCmd_Flags(t *testing.T) {
	flags := []string{"tenant", "agent", "limit"}
	for _, name := range flags {
		flag := auditListCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "audit list flag %q should be registered", name)
	}
}

func TestAuditListCmd_LimitDefault(t *testing.T) {
	flag := auditListCmd.Flags().Lookup("limit")
	require.NotNil(t, flag)
	assert.Equal(t, "20", flag.DefValue)
}

func TestOpenEvidenceStore_DefaultKey(t *testing.T) {
	home, _ := os.UserHomeDir()
	talonDir := filepath.Join(home, ".talon")
	_ = os.MkdirAll(talonDir, 0o755)

	store, err := openEvidenceStore()
	require.NoError(t, err)
	defer store.Close()
}

func TestOpenEvidenceStore_CustomKey(t *testing.T) {
	home, _ := os.UserHomeDir()
	talonDir := filepath.Join(home, ".talon")
	_ = os.MkdirAll(talonDir, 0o755)

	t.Setenv("TALON_SIGNING_KEY", "custom-key-for-evidence-signing!")
	store, err := openEvidenceStore()
	require.NoError(t, err)
	defer store.Close()
}

func TestRenderAuditList(t *testing.T) {
	var buf bytes.Buffer
	ts := time.Date(2025, 2, 18, 10, 0, 0, 0, time.UTC)
	index := []evidence.Index{
		{ID: "ev_1", Timestamp: ts, TenantID: "acme", AgentID: "agent", ModelUsed: "gpt-4", Cost: 0.01, DurationMS: 100, Allowed: true, HasError: false},
		{ID: "ev_2", Timestamp: ts, TenantID: "acme", AgentID: "agent", ModelUsed: "gpt-4", Cost: 0.02, DurationMS: 200, Allowed: false, HasError: true},
	}
	renderAuditList(&buf, index)
	out := buf.String()
	assert.Contains(t, out, "Evidence Records (showing 2)")
	assert.Contains(t, out, "ev_1")
	assert.Contains(t, out, "ev_2")
	assert.Contains(t, out, "acme")
	assert.Contains(t, out, "0.0100")
	assert.Contains(t, out, "0.0200")
}

func TestRenderVerifyResult(t *testing.T) {
	var bufValid, bufInvalid bytes.Buffer
	renderVerifyResult(&bufValid, "ev_abc", true, nil)
	renderVerifyResult(&bufInvalid, "ev_xyz", false, nil)
	assert.Contains(t, bufValid.String(), "VALID")
	assert.Contains(t, bufValid.String(), "ev_abc")
	assert.Contains(t, bufInvalid.String(), "INVALID")
	assert.Contains(t, bufInvalid.String(), "ev_xyz")
}

func TestRenderAuditExportCSV(t *testing.T) {
	var buf bytes.Buffer
	ts := time.Date(2025, 2, 18, 10, 0, 0, 0, time.UTC)
	records := []evidence.ExportRecord{
		{ID: "ev_1", Timestamp: ts, TenantID: "acme", AgentID: "agent", InvocationType: "manual", Allowed: true, Cost: 0.01, ModelUsed: "gpt-4", DurationMS: 100, HasError: false, InputTier: 1, OutputTier: 0, PIIDetected: []string{"EMAIL_ADDRESS"}, PIIRedacted: true},
	}
	err := renderAuditExportCSV(&buf, records)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "id,session_id,timestamp,tenant_id")
	assert.Contains(t, out, "ev_1")
	assert.Contains(t, out, "acme")
	assert.Contains(t, out, "true")
	assert.Contains(t, out, "0.0100")
	assert.Contains(t, out, "input_tier,output_tier,pii_detected,pii_redacted")
	assert.Contains(t, out, "primary_explanation_code,primary_explanation_reason,primary_version_identity")
	assert.Contains(t, out, "EMAIL_ADDRESS")
}

func TestRenderAuditExportJSON(t *testing.T) {
	var buf bytes.Buffer
	ts := time.Date(2025, 2, 18, 10, 0, 0, 0, time.UTC)
	records := []evidence.ExportRecord{
		{ID: "ev_2", Timestamp: ts, TenantID: "default", AgentID: "runner", InvocationType: "scheduled", Allowed: false, Cost: 0, ModelUsed: "", DurationMS: 0, HasError: true, PIIDetected: []string{"PHONE_NUMBER"}},
	}
	err := renderAuditExportJSONWrapped(&buf, records)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "ev_2")
	assert.Contains(t, out, "default")
	assert.Contains(t, out, "scheduled")
	assert.Contains(t, out, "false")
	assert.Contains(t, out, "pii_detected")
	assert.Contains(t, out, "PHONE_NUMBER")
	assert.Contains(t, out, "export_metadata")
	assert.Contains(t, out, "total_records")
}

func TestRenderAuditExportHTML_EscapesUserControlledFields(t *testing.T) {
	var buf bytes.Buffer
	ts := time.Date(2025, 2, 18, 10, 0, 0, 0, time.UTC)
	records := []evidence.ExportRecord{
		{
			ID:         "ev_1",
			Timestamp:  ts,
			TenantID:   `<script>alert("tenant")</script>`,
			AgentID:    `<img src=x onerror=alert("agent")>`,
			ModelUsed:  `<svg onload=alert("model")>`,
			Allowed:    true,
			Cost:       0.01,
			DurationMS: 100,
		},
	}

	err := renderAuditExportHTML(&buf, records)
	require.NoError(t, err)
	out := buf.String()

	assert.NotContains(t, out, `<script>alert("tenant")</script>`)
	assert.NotContains(t, out, `<img src=x onerror=alert("agent")>`)
	assert.NotContains(t, out, `<svg onload=alert("model")>`)

	assert.Contains(t, out, `&lt;script&gt;alert(&#34;tenant&#34;)&lt;/script&gt;`)
	assert.Contains(t, out, `&lt;img src=x onerror=alert(&#34;agent&#34;)&gt;`)
	assert.Contains(t, out, `&lt;svg onload=alert(&#34;model&#34;)&gt;`)
}

func TestAuditListCmd_RunSuccess(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	rootCmd.SetArgs([]string{"audit", "list"})
	err := rootCmd.Execute()
	require.NoError(t, err)
}

func TestAuditExportCmd_RunSuccess(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	rootCmd.SetArgs([]string{"audit", "export", "--format", "csv"})
	err := rootCmd.Execute()
	require.NoError(t, err)
}

func TestAuditExportCmd_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	rootCmd.SetArgs([]string{"audit", "export", "--format", "json"})
	err := rootCmd.Execute()
	require.NoError(t, err)
}

func TestRenderAuditShow_PIIDetected(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		ID:        "req_9d838d88",
		Timestamp: time.Date(2026, 2, 21, 11, 28, 45, 0, time.FixedZone("CET", 3600)),
		TenantID:  "default", AgentID: "slack-support-bot", InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: "abc123"},
		Classification: evidence.Classification{InputTier: 2, OutputTier: 0, PIIDetected: []string{"EMAIL_ADDRESS", "PHONE_NUMBER"}, PIIRedacted: true, InputPIIRedacted: true},
		Execution:      evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.0001, DurationMS: 909, Tokens: evidence.TokenUsage{Input: 45, Output: 32}, ToolsCalled: []string{}},
		AuditTrail:     evidence.AuditTrail{InputHash: "sha256:a3f9", OutputHash: "sha256:b2c1"},
		Compliance:     evidence.Compliance{Frameworks: []string{"gdpr", "iso27001"}, DataLocation: "eu-only"},
	}
	renderAuditShow(&buf, ev, true)
	out := buf.String()
	assert.Contains(t, out, "Evidence: req_9d838d88")
	assert.Contains(t, out, "✓ VALID")
	assert.Contains(t, out, "EMAIL_ADDRESS")
	assert.Contains(t, out, "PHONE_NUMBER")
	assert.Contains(t, out, "PII Redacted:  input=true output=true")
}

func TestRenderAuditShow_PINone(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		ID:        "req_nopii",
		Timestamp: time.Now(),
		TenantID:  "default", AgentID: "bot", InvocationType: "manual",
		Classification: evidence.Classification{InputTier: 0, OutputTier: 0, PIIDetected: nil, PIIRedacted: false},
		Execution:      evidence.Execution{ModelUsed: "gpt-4o", Cost: 0},
		AuditTrail:     evidence.AuditTrail{},
		Compliance:     evidence.Compliance{},
	}
	renderAuditShow(&buf, ev, true)
	out := buf.String()
	assert.Contains(t, out, "PII Detected:  (none)")
}

func TestRenderAuditShow_DataFlow(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		ID:        "req_flow",
		Timestamp: time.Now(),
		TenantID:  "default", AgentID: "bot", InvocationType: "manual",
		Classification: evidence.Classification{},
		Execution:      evidence.Execution{ModelUsed: "gpt-4o-mini"},
		AuditTrail:     evidence.AuditTrail{},
		Compliance:     evidence.Compliance{},
		DataFlow: &evidence.DataFlow{
			Detector: "talon-classifier",
			Items: []evidence.DataFlowItem{
				{
					Source:      evidence.FlowSourcePrompt,
					Disposition: evidence.FlowDispositionRedacted,
					Tier:        2,
					EntityTypes: []string{"email"},
					Destination: evidence.FlowDestination{
						Kind: evidence.FlowDestLLMProvider, Name: "openai",
						Model: "gpt-4o-mini", Region: "US",
					},
				},
				{
					Source:      evidence.FlowSourcePrompt,
					Disposition: evidence.FlowDispositionForwarded,
					Destination: evidence.FlowDestination{
						Kind: evidence.FlowDestLLMProvider, Name: "mistral", Region: "EU",
					},
				},
			},
		},
	}
	renderAuditShow(&buf, ev, true)
	out := buf.String()
	assert.Contains(t, out, "Data Flow")
	assert.Contains(t, out, "Detector:    talon-classifier")
	assert.Contains(t, out, "prompt -> llm_provider:openai model=gpt-4o-mini region=US | redacted | tier 2 | email")
	assert.Contains(t, out, "prompt -> llm_provider:mistral region=EU | forwarded | tier 0 | no classified data")
}

func TestRenderAuditShow_RoutingDecision(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		ID:        "req_route",
		Timestamp: time.Now(),
		TenantID:  "default", AgentID: "bot", InvocationType: "manual",
		Classification: evidence.Classification{},
		Execution:      evidence.Execution{ModelUsed: "llama3.2"},
		AuditTrail:     evidence.AuditTrail{},
		Compliance:     evidence.Compliance{},
		RoutingDecision: &evidence.RoutingDecision{
			SelectedProvider: "ollama",
			SelectedModel:    "llama3.2",
			RejectedCandidates: []evidence.RejectedCandidate{
				{ProviderID: "openai", Reason: "confidential tier requires LOCAL provider only"},
			},
		},
	}
	renderAuditShow(&buf, ev, true)
	out := buf.String()
	assert.Contains(t, out, "Routing Decision (sovereignty-aware)")
	assert.Contains(t, out, "Selected:   ollama / llama3.2")
	assert.Contains(t, out, "Rejected:   openai (confidential tier requires LOCAL provider only)")
}

// When ONE provider is rejected under several policy rules, it must render once
// with its reasons as sub-bullets — not repeated as if dispatched twice.
func TestRenderAuditShow_RoutingDecision_GroupsReasonsPerProvider(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		ID:        "req_route_multi",
		Timestamp: time.Now(),
		TenantID:  "default", AgentID: "bot", InvocationType: "manual",
		Classification: evidence.Classification{},
		Execution:      evidence.Execution{ModelUsed: "llama3.2"},
		AuditTrail:     evidence.AuditTrail{},
		Compliance:     evidence.Compliance{},
		RoutingDecision: &evidence.RoutingDecision{
			SelectedProvider: "ollama",
			SelectedModel:    "llama3.2",
			RejectedCandidates: []evidence.RejectedCandidate{
				{ProviderID: "openai", Reason: "confidential tier blocks cloud providers"},
				{ProviderID: "openai", Reason: "confidential tier requires LOCAL provider only"},
			},
		},
	}
	renderAuditShow(&buf, ev, true)
	out := buf.String()
	// openai appears once as a header, then each reason as a sub-bullet.
	assert.Equal(t, 1, strings.Count(out, "Rejected:   openai"), "one provider header, not one per reason")
	assert.Contains(t, out, "• confidential tier blocks cloud providers")
	assert.Contains(t, out, "• confidential tier requires LOCAL provider only")
	// The old flattened "openai (reason)" form must NOT appear for the grouped case.
	assert.NotContains(t, out, "Rejected:   openai (confidential tier blocks cloud providers)")
}

func TestRenderAuditShow_NoRoutingDecision_SectionOmitted(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		ID: "req_noroute", Timestamp: time.Now(),
		TenantID: "default", AgentID: "bot", InvocationType: "manual",
		Classification: evidence.Classification{},
		Execution:      evidence.Execution{ModelUsed: "gpt-4o-mini"},
		AuditTrail:     evidence.AuditTrail{}, Compliance: evidence.Compliance{},
	}
	renderAuditShow(&buf, ev, true)
	assert.NotContains(t, buf.String(), "Routing Decision")
}

func TestRenderAuditShow_NoDataFlow_SectionOmitted(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		ID:        "req_noflow",
		Timestamp: time.Now(),
		TenantID:  "default", AgentID: "bot", InvocationType: "manual",
		Classification: evidence.Classification{},
		Execution:      evidence.Execution{},
		AuditTrail:     evidence.AuditTrail{},
		Compliance:     evidence.Compliance{},
	}
	renderAuditShow(&buf, ev, true)
	assert.NotContains(t, buf.String(), "Data Flow")
}

func TestRenderAuditShow_InvalidSignature(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		ID:        "req_tampered",
		Timestamp: time.Now(),
		TenantID:  "default", AgentID: "bot", InvocationType: "manual",
		Classification: evidence.Classification{},
		Execution:      evidence.Execution{},
		AuditTrail:     evidence.AuditTrail{},
		Compliance:     evidence.Compliance{},
	}
	renderAuditShow(&buf, ev, false)
	out := buf.String()
	assert.Contains(t, out, "✗ INVALID")
	assert.Contains(t, out, "tampered")
}

func TestRenderAuditShow_ExplanationStage(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		ID:             "req_stage",
		Timestamp:      time.Now(),
		TenantID:       "default",
		AgentID:        "bot",
		InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{
			Allowed: false,
			Action:  "deny",
		},
		Execution:  evidence.Execution{},
		AuditTrail: evidence.AuditTrail{},
		Compliance: evidence.Compliance{},
		Explanations: []explanation.Item{{
			Code:     explanation.CodePolicyDeniedTool,
			Decision: explanation.DecisionDeny,
			Stage:    "tool_execution",
			Reason:   "Request blocked by tool access policy.",
		}},
	}

	renderAuditShow(&buf, ev, true)
	out := buf.String()
	assert.Contains(t, out, "Stage: tool_execution")
}

func TestRenderVerifyResult_WithSummary(t *testing.T) {
	var buf bytes.Buffer
	ev := &evidence.Evidence{
		Timestamp: time.Date(2026, 2, 21, 11, 28, 45, 0, time.FixedZone("CET", 3600)),
		TenantID:  "default", AgentID: "slack-support-bot",
		PolicyDecision: evidence.PolicyDecision{Allowed: true},
		Classification: evidence.Classification{InputTier: 2, OutputTier: 0, PIIDetected: []string{"EMAIL_ADDRESS"}, PIIRedacted: true},
		Execution:      evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.0000, DurationMS: 909},
	}
	renderVerifyResult(&buf, "req_9d838d88", true, ev)
	out := buf.String()
	assert.Contains(t, out, "VALID")
	assert.Contains(t, out, "default/slack-support-bot")
	assert.Contains(t, out, "gpt-4o-mini")
	assert.Contains(t, out, "Tier: 2→0")
	assert.Contains(t, out, "PII: EMAIL_ADDRESS")
	assert.Contains(t, out, "Redacted: true")
}

func TestAuditShowCmd_NotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	rootCmd.SetArgs([]string{"audit", "show", "req_nonexistent_12345"})
	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetching evidence")
	assert.Contains(t, err.Error(), "not found")
}

func TestAuditShowCmd_AcceptsZeroOrOneArg(t *testing.T) {
	// show [evidence-id]: 0 or 1 arg allowed
	errZero := auditShowCmd.Args(auditShowCmd, []string{})
	assert.NoError(t, errZero)
	errOne := auditShowCmd.Args(auditShowCmd, []string{"ev_123"})
	assert.NoError(t, errOne)
	errTwo := auditShowCmd.Args(auditShowCmd, []string{"ev_1", "ev_2"})
	assert.Error(t, errTwo)
}

func TestAuditShowCmd_ZeroArgs_EmptyStore_PrintsNoRecords(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	// audit show writes via fmt.Println(os.Stdout), so redirect process stdout
	oldOut := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = oldOut }()

	rootCmd.SetArgs([]string{"audit", "show"})
	done := make(chan struct{})
	var out []byte
	go func() {
		defer close(done)
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out = buf.Bytes()
	}()

	err = rootCmd.Execute()
	require.NoError(t, err)
	w.Close()
	<-done
	assert.Contains(t, string(out), "No evidence records found.")
}

func TestAuditExportSignedJSON_IncludesSignatures(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", "test-signing-key-1234567890123456")

	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), "test-signing-key-1234567890123456")
	require.NoError(t, err)
	defer store.Close()
	gen := evidence.NewGenerator(store)
	_, err = gen.Generate(context.Background(), evidence.GenerateParams{
		CorrelationID:  "corr_signed_export",
		TenantID:       "default",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "hello",
		OutputResponse: "world",
	})
	require.NoError(t, err)

	outPath := filepath.Join(dir, "signed.json")
	rootCmd.SetArgs([]string{"audit", "export", "--format", "signed-json", "--output", outPath})
	require.NoError(t, rootCmd.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "\"signed\": true")
	assert.Contains(t, string(data), "\"algorithm\": \"HMAC-SHA256\"")

	var envelope evidence.SignedExportEnvelope
	require.NoError(t, json.Unmarshal(data, &envelope))
	require.Len(t, envelope.Records, 1)
	assert.NotEmpty(t, envelope.Records[0].Signature)
}

func TestAuditVerifyFile_SucceedsForValidSignedExport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", "test-signing-key-1234567890123456")

	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), "test-signing-key-1234567890123456")
	require.NoError(t, err)
	defer store.Close()
	gen := evidence.NewGenerator(store)
	_, err = gen.Generate(context.Background(), evidence.GenerateParams{
		CorrelationID:  "corr_verify_file_ok",
		TenantID:       "default",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "hello",
		OutputResponse: "world",
	})
	require.NoError(t, err)

	outPath := filepath.Join(dir, "signed.json")
	rootCmd.SetArgs([]string{"audit", "export", "--format", "signed-json", "--output", outPath})
	require.NoError(t, rootCmd.Execute())

	rootCmd.SetArgs([]string{"audit", "verify", "--file", outPath})
	err = rootCmd.Execute()
	require.NoError(t, err)
}

func TestAuditVerifyFile_FailsForTamperedSignedExport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", "test-signing-key-1234567890123456")

	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), "test-signing-key-1234567890123456")
	require.NoError(t, err)
	defer store.Close()
	gen := evidence.NewGenerator(store)
	_, err = gen.Generate(context.Background(), evidence.GenerateParams{
		CorrelationID:  "corr_verify_file_bad",
		TenantID:       "default",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "hello",
		OutputResponse: "world",
	})
	require.NoError(t, err)

	outPath := filepath.Join(dir, "signed.json")
	rootCmd.SetArgs([]string{"audit", "export", "--format", "signed-json", "--output", outPath})
	require.NoError(t, rootCmd.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	tampered := strings.Replace(string(data), "\"tenant_id\": \"default\"", "\"tenant_id\": \"tampered\"", 1)
	require.NoError(t, os.WriteFile(outPath, []byte(tampered), 0o644))

	rootCmd.SetArgs([]string{"audit", "verify", "--file", outPath})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file verification failed")
}

func sessTestRecord(id, session, tenant, caller, model string, cost float64, allowed bool, orch *evidence.OrchestrationContext) *evidence.Evidence {
	return &evidence.Evidence{
		ID:             id,
		SessionID:      session,
		TenantID:       tenant,
		AgentID:        caller,
		Timestamp:      time.Date(2026, 7, 5, 10, 0, 0, 0, time.UTC),
		PolicyDecision: evidence.PolicyDecision{Allowed: allowed},
		Execution:      evidence.Execution{ModelUsed: model, Cost: cost, Tokens: evidence.TokenUsage{Input: 100, Output: 20}},
		Orchestration:  orch,
	}
}

func TestScopeSessionRecords(t *testing.T) {
	records := []*evidence.Evidence{
		sessTestRecord("a", "s", "acme", "callerA", "m", 0.01, true, nil),
		sessTestRecord("b", "s", "acme", "callerB", "m", 0.01, true, nil),
		sessTestRecord("c", "s", "other", "callerA", "m", 0.01, true, nil),
	}
	// No filters → all pass through.
	assert.Len(t, scopeSessionRecords(records, "", ""), 3)
	// Tenant filter.
	assert.Len(t, scopeSessionRecords(records, "acme", ""), 2)
	// Agent filter.
	assert.Len(t, scopeSessionRecords(records, "", "callerA"), 2)
	// Combined.
	got := scopeSessionRecords(records, "acme", "callerA")
	require.Len(t, got, 1)
	assert.Equal(t, "a", got[0].ID)
}

func TestRenderSessionSummary_WithAgentBreakdown(t *testing.T) {
	orchGen := &evidence.OrchestrationContext{AgentID: "generator", Client: "claude-code", SessionSource: "client_asserted"}
	orchJudge := &evidence.OrchestrationContext{AgentID: "judge", ParentAgentID: "generator", Client: "claude-code", SessionSource: "client_asserted"}
	records := []*evidence.Evidence{
		sessTestRecord("a", "sess-x", "acme", "orch", "claude-opus-4-8", 0.20, true, orchGen),
		sessTestRecord("b", "sess-x", "acme", "orch", "claude-haiku-4-5", 0.02, true, orchJudge),
	}
	var buf bytes.Buffer
	renderSessionSummary(&buf, evidence.BuildSessionSummary("sess-x", records))
	out := buf.String()
	assert.Contains(t, out, "Session sess-x")
	assert.Contains(t, out, "claude-code (client_asserted)")
	assert.Contains(t, out, "Per-agent:")
	assert.Contains(t, out, "generator")
	assert.Contains(t, out, "judge")
	assert.Contains(t, out, "←generator")
}

func TestRenderSessionSummary_SingleCallerNoBreakdown(t *testing.T) {
	records := []*evidence.Evidence{
		sessTestRecord("a", "sess-y", "acme", "cli", "m", 0.10, true, nil),
	}
	var buf bytes.Buffer
	renderSessionSummary(&buf, evidence.BuildSessionSummary("sess-y", records))
	out := buf.String()
	assert.Contains(t, out, "Session sess-y")
	// Single caller-keyed agent equal to the only caller → no per-agent table.
	assert.NotContains(t, out, "Per-agent:")
}

func TestRenderSessionRecords(t *testing.T) {
	orch := &evidence.OrchestrationContext{AgentID: "generator"}
	records := []*evidence.Evidence{
		sessTestRecord("ev_1", "s", "acme", "orch", "claude-opus-4-8", 0.10, true, orch),
		sessTestRecord("ev_2", "s", "acme", "orch", "claude-opus-4-8", 0.00, false, nil),
	}
	records[1].Execution.Error = "boom"
	var buf bytes.Buffer
	renderSessionRecords(&buf, records)
	out := buf.String()
	assert.Contains(t, out, "Records (2, newest first)")
	assert.Contains(t, out, "ev_1")
	assert.Contains(t, out, "agent=generator")
	assert.Contains(t, out, "[ERROR]")
}

// resetAuditCostFlags clears the package-global flag variables that cobra binds
// across Execute() calls, so session-flag tests neither inherit nor leak state.
func resetAuditCostFlags() {
	auditSession = ""
	auditVerifyFile = ""
	auditVerifyFailover = false
	auditTenant = ""
	auditAgent = ""
	auditCaller = ""
	costsSession = ""
	costsJSON = false
	costsAgent = ""
	costsCaller = ""
	costsTenant = ""
}

func TestAuditListCmd_SessionScoped(t *testing.T) {
	resetAuditCostFlags()
	t.Cleanup(resetAuditCostFlags)
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", "test-signing-key-1234567890123456")

	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), "test-signing-key-1234567890123456")
	require.NoError(t, err)
	gen := evidence.NewGenerator(store)
	for _, p := range []evidence.GenerateParams{
		{CorrelationID: "c1", SessionID: "sess-A", TenantID: "default", AgentID: "coder", InvocationType: "gateway", ModelUsed: "claude-sonnet-5", Cost: 0.10, PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"}, InputPrompt: "a", OutputResponse: "b"},
		{CorrelationID: "c2", SessionID: "sess-A", TenantID: "default", AgentID: "coder", InvocationType: "gateway", ModelUsed: "claude-sonnet-5", Cost: 0.05, PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"}, InputPrompt: "a", OutputResponse: "b"},
		{CorrelationID: "c3", SessionID: "sess-B", TenantID: "default", AgentID: "coder", InvocationType: "gateway", ModelUsed: "claude-sonnet-5", Cost: 0.99, PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"}, InputPrompt: "a", OutputResponse: "b"},
	} {
		_, err := gen.Generate(context.Background(), p)
		require.NoError(t, err)
	}
	store.Close()

	// audit list --session sess-A → summary + only its 2 records, not sess-B.
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"audit", "list", "--session", "sess-A"})
	// list writes summary to os.Stdout; capture via the render path instead.
	// Re-open store and drive the shared function directly for a hermetic check.
	store2, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), "test-signing-key-1234567890123456")
	require.NoError(t, err)
	defer store2.Close()
	recs, err := store2.ListBySessionID(context.Background(), "sess-A")
	require.NoError(t, err)
	require.Len(t, recs, 2, "session scoping must return only sess-A records")
	sum := evidence.BuildSessionSummary("sess-A", recs)
	assert.InDelta(t, 0.15, sum.TotalCost, 1e-9)
	assert.Equal(t, 2, sum.RecordCount)

	// costs --session sess-B --json → single record, cost 0.99.
	var cbuf bytes.Buffer
	rootCmd.SetOut(&cbuf)
	rootCmd.SetArgs([]string{"costs", "--session", "sess-B", "--json"})
	require.NoError(t, rootCmd.Execute())
	var payload evidence.SessionSummary
	require.NoError(t, json.Unmarshal(cbuf.Bytes(), &payload))
	assert.Equal(t, "sess-B", payload.SessionID)
	assert.Equal(t, 1, payload.RecordCount)
	assert.InDelta(t, 0.99, payload.TotalCost, 1e-9)
}

func TestAuditVerifyCmd_Session(t *testing.T) {
	resetAuditCostFlags()
	t.Cleanup(resetAuditCostFlags)
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", "test-signing-key-1234567890123456")

	store, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), "test-signing-key-1234567890123456")
	require.NoError(t, err)
	gen := evidence.NewGenerator(store)
	_, err = gen.Generate(context.Background(), evidence.GenerateParams{
		CorrelationID: "cv1", SessionID: "sess-V", TenantID: "default", AgentID: "coder",
		InvocationType: "gateway", PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt: "a", OutputResponse: "b",
	})
	require.NoError(t, err)
	store.Close()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"audit", "verify", "--session", "sess-V"})
	require.NoError(t, rootCmd.Execute())
}

func TestAuditVerifyCmd_SessionAndFileMutuallyExclusive(t *testing.T) {
	resetAuditCostFlags()
	t.Cleanup(resetAuditCostFlags)
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)
	t.Setenv("TALON_SIGNING_KEY", "test-signing-key-1234567890123456")
	rootCmd.SetArgs([]string{"audit", "verify", "--session", "s", "--file", "x.json"})
	err := rootCmd.Execute()
	require.Error(t, err)
}
