package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
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

func TestAuditVerifyCmd_RequiresOneArg(t *testing.T) {
	assert.NotNil(t, auditVerifyCmd.Args)
	err := auditVerifyCmd.Args(auditVerifyCmd, []string{})
	assert.Error(t, err)
	err = auditVerifyCmd.Args(auditVerifyCmd, []string{"ev_123"})
	assert.NoError(t, err)
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
	assert.Contains(t, out, "id,timestamp,tenant_id")
	assert.Contains(t, out, "ev_1")
	assert.Contains(t, out, "acme")
	assert.Contains(t, out, "true")
	assert.Contains(t, out, "0.0100")
	assert.Contains(t, out, "input_tier,output_tier,pii_detected,pii_redacted")
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
		Classification: evidence.Classification{InputTier: 2, OutputTier: 0, PIIDetected: []string{"EMAIL_ADDRESS", "PHONE_NUMBER"}, PIIRedacted: true},
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
	assert.Contains(t, out, "PII Redacted:  true")
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
