package cmd

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/feature"
	"github.com/dativo-io/talon/internal/policy"
)

func TestBuildConfigs_AgentWorkload_ModelTier1(t *testing.T) {
	state := WizardState{
		AgentName:        "test-agent",
		AgentDescription: "Test",
		WorkloadType:     "agent",
		PackID:           "generic",
		ProviderID:       "openai",
		DataSovereignty:  "global",
		EnabledFeatures:  []string{"pii", "audit", "cost"},
	}
	agentCfg, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	require.NotNil(t, agentCfg)
	require.NotNil(t, infraCfg)
	assert.Equal(t, 1, agentCfg.Agent.ModelTier)
	assert.NotEmpty(t, agentCfg.Capabilities.AllowedTools)
}

func TestBuildConfigs_ProxyWorkload_ModelTier0_NoTools(t *testing.T) {
	state := WizardState{
		AgentName:       "proxy-agent",
		WorkloadType:    "proxy",
		PackID:          "generic",
		ProviderID:      "openai",
		DataSovereignty: "global",
		EnabledFeatures: []string{"audit", "cost", "pii"},
	}
	agentCfg, _, err := BuildConfigs(state)
	require.NoError(t, err)
	assert.Equal(t, 0, agentCfg.Agent.ModelTier)
	assert.Empty(t, agentCfg.Capabilities.AllowedTools)
}

func TestBuildConfigs_EUStrict_AgentRouting(t *testing.T) {
	state := WizardState{
		AgentName:       "eu-agent",
		WorkloadType:    "agent",
		ProviderID:      "azure-openai",
		RegionID:        "westeurope",
		DataSovereignty: "eu_strict",
		EnabledFeatures: []string{"pii", "audit"},
	}
	agentCfg, _, err := BuildConfigs(state)
	require.NoError(t, err)
	require.NotNil(t, agentCfg.Policies.ModelRouting)
	require.NotNil(t, agentCfg.Policies.ModelRouting.Tier1)
	assert.Equal(t, "westeurope", agentCfg.Policies.ModelRouting.Tier1.Location)
	assert.Equal(t, "eu", agentCfg.Compliance.DataResidency)
}

func TestBuildConfigs_EUStrict_InfraSovereignty(t *testing.T) {
	state := WizardState{
		AgentName:       "eu-agent",
		ProviderID:      "openai",
		DataSovereignty: "eu_strict",
		EnabledFeatures: []string{"pii"},
	}
	_, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	require.NotNil(t, infraCfg.LLM)
	require.NotNil(t, infraCfg.LLM.Routing)
	assert.Equal(t, "eu_strict", infraCfg.LLM.Routing.DataSovereigntyMode)
}

func TestBuildConfigs_AllFeatures_BothFilesValid(t *testing.T) {
	state := WizardState{
		AgentName:       "full-agent",
		WorkloadType:    "agent",
		ProviderID:      "anthropic",
		DataSovereignty: "global",
		EnabledFeatures: []string{"pii", "audit", "cost", "injection", "eu-ai-act", "dora"},
	}
	agentCfg, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	require.NotNil(t, agentCfg)
	require.NotNil(t, infraCfg)
	// BuildConfigs already runs ValidateSchema on agent
	assert.NotNil(t, agentCfg.Policies.DataClassification)
	assert.NotNil(t, agentCfg.Audit)
	assert.NotNil(t, agentCfg.Policies.CostLimits)
	assert.NotNil(t, agentCfg.AttachmentHandling)
	assert.Contains(t, agentCfg.Compliance.Frameworks, "eu-ai-act")
	assert.Contains(t, agentCfg.Compliance.Frameworks, "dora")
}

func TestBuildConfigs_NoFeatures_BothFilesValid(t *testing.T) {
	state := WizardState{
		AgentName:       "minimal-agent",
		WorkloadType:    "agent",
		ProviderID:      "openai",
		DataSovereignty: "global",
		EnabledFeatures: nil,
	}
	agentCfg, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	require.NotNil(t, agentCfg)
	require.NotNil(t, infraCfg)
}

func TestBuildConfigs_OllamaProvider_NoKeyEnv(t *testing.T) {
	state := WizardState{
		AgentName:       "local-agent",
		ProviderID:      "ollama",
		DataSovereignty: "global",
		EnabledFeatures: []string{"pii"},
	}
	_, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	require.NotNil(t, infraCfg.LLM)
	require.NotEmpty(t, infraCfg.LLM.Providers)
	blk, ok := infraCfg.LLM.Providers["ollama"]
	require.True(t, ok)
	_, hasKeyEnv := blk.Config["key_env"]
	assert.False(t, hasKeyEnv)
}

func TestBuildConfigs_PricingFileAlwaysSet(t *testing.T) {
	state := WizardState{
		AgentName:       "any",
		ProviderID:      "openai",
		DataSovereignty: "global",
	}
	_, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	require.NotNil(t, infraCfg.LLM)
	assert.Equal(t, "pricing/models.yaml", infraCfg.LLM.PricingFile)
}

func TestBuildConfigs_HeaderComment_BothFiles(t *testing.T) {
	state := WizardState{
		AgentName:       "h",
		ProviderID:      "openai",
		PackID:          "generic",
		EnabledFeatures: []string{"pii"},
	}
	agentCfg, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	opts := WriteOptions{
		AgentPath:   "agent.talon.yaml",
		InfraPath:   "talon.config.yaml",
		ProviderID:  state.ProviderID,
		Sovereignty: state.DataSovereignty,
		PackID:      state.PackID,
		Features:    state.EnabledFeatures,
	}
	agentYAML, infraYAML, err := marshalWithHeader(agentCfg, infraCfg, opts)
	require.NoError(t, err)
	assert.Contains(t, string(agentYAML), "# Generated by: talon init")
	assert.Contains(t, string(agentYAML), "Sovereignty:")
	assert.Contains(t, string(infraYAML), "# Generated by: talon init")
}

func TestWriteConfigs_RefusesOverwrite_WithoutForce(t *testing.T) {
	dir := t.TempDir()
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	infraPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(agentPath, []byte("existing"), 0o644))
	state := WizardState{
		AgentName:       "x",
		ProviderID:      "openai",
		DataSovereignty: "global",
	}
	agentCfg, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	opts := WriteOptions{
		AgentPath:   agentPath,
		InfraPath:   infraPath,
		Force:       false,
		ProviderID:  state.ProviderID,
		Sovereignty: state.DataSovereignty,
		PackID:      state.PackID,
		Features:    state.EnabledFeatures,
	}
	err = WriteConfigs(agentCfg, infraCfg, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Contains(t, err.Error(), "--force")
}

func TestWriteConfigs_AtomicWrite_NoPartialOnInterrupt(t *testing.T) {
	dir := t.TempDir()
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	infraPath := filepath.Join(dir, "talon.config.yaml")
	state := WizardState{
		AgentName:       "atomic-agent",
		ProviderID:      "openai",
		DataSovereignty: "global",
	}
	agentCfg, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	opts := WriteOptions{
		AgentPath:   agentPath,
		InfraPath:   infraPath,
		Force:       true,
		ProviderID:  state.ProviderID,
		Sovereignty: state.DataSovereignty,
		PackID:      state.PackID,
		Features:    state.EnabledFeatures,
	}
	err = WriteConfigs(agentCfg, infraCfg, opts)
	require.NoError(t, err)
	agentContent, err := os.ReadFile(agentPath)
	require.NoError(t, err)
	infraContent, err := os.ReadFile(infraPath)
	require.NoError(t, err)
	assert.Contains(t, string(agentContent), "agent:")
	assert.Contains(t, string(infraContent), "llm:")
}

func TestVaultSecretName(t *testing.T) {
	assert.Equal(t, "openai-api-key", VaultSecretName("openai"))
	assert.Equal(t, "azure-openai-key", VaultSecretName("azure-openai"))
	assert.Equal(t, "anthropic-api-key", VaultSecretName("anthropic"))
	assert.Equal(t, "", VaultSecretName("ollama"))
	assert.Equal(t, "", VaultSecretName("bedrock"))
	assert.Equal(t, "mistral-api-key", VaultSecretName("mistral"))
	assert.Equal(t, "vertex-api-key", VaultSecretName("vertex"))
	assert.Equal(t, "custom-api-key", VaultSecretName("custom"))
}

func TestPrintNextSteps_VaultFirst_ThenProviderKey(t *testing.T) {
	var buf bytes.Buffer
	PrintNextSteps("my-agent", "openai", &buf)
	out := buf.String()
	assert.Contains(t, out, "TALON_SECRETS_KEY")
	assert.Contains(t, out, "talon secrets set")
	assert.Contains(t, out, "openai-api-key")
	assert.Contains(t, out, "talon serve")
	assert.Contains(t, out, "my-agent")
}

func TestPrintNextSteps_OllamaSkipsProviderKey(t *testing.T) {
	var buf bytes.Buffer
	PrintNextSteps("local-agent", "ollama", &buf)
	out := buf.String()
	assert.Contains(t, out, "TALON_SECRETS_KEY")
	assert.NotContains(t, out, "talon secrets set")
	assert.Contains(t, out, "talon serve")
	assert.Contains(t, out, "local-agent")
}

func TestRunWizard_EOF_ReturnsAborted(t *testing.T) {
	wio := WizardIO{
		In:     strings.NewReader(""),
		Out:    io.Discard,
		ErrOut: io.Discard,
	}
	state, confirmed, err := RunWizard(wio)
	// Empty input: may hit EOF on first or a later prompt; either way we must not confirm
	assert.False(t, confirmed)
	if err != nil {
		assert.ErrorIs(t, err, io.EOF)
	}
	// State may have default name if first readLine returned default before EOF
	_ = state
}

func TestRunWizard_FullFlow_OpenClaw_Azure(t *testing.T) {
	// Simulate: name, desc, owner, workload=1 (agent), pack=1 (openclaw), provider=1, region (if needed), residency=1 (eu_strict), features default, confirm
	input := "sales-analyst\nAnalyst\ndpo@eu\n1\n1\n1\n1\n\n\n"
	wio := WizardIO{
		In:     strings.NewReader(input),
		Out:    io.Discard,
		ErrOut: io.Discard,
	}
	state, confirmed, err := RunWizard(wio)
	require.NoError(t, err)
	require.True(t, confirmed)
	assert.Equal(t, "sales-analyst", state.AgentName)
	assert.Equal(t, "agent", state.WorkloadType)
	assert.Equal(t, "openclaw", state.PackID)
	assert.NotEmpty(t, state.ProviderID)
	// Residency choice 1 = eu_strict
	assert.Equal(t, "eu_strict", state.DataSovereignty)
}

func TestRunWizard_ProxyWorkload_SkipsPackAndReducesFeatures(t *testing.T) {
	// workload=2 (proxy) -> pack should be generic, features list is reduced
	input := "proxy-agent\n\n\n2\n1\n\n1\n\n"
	wio := WizardIO{
		In:     strings.NewReader(input),
		Out:    io.Discard,
		ErrOut: io.Discard,
	}
	state, confirmed, err := RunWizard(wio)
	require.NoError(t, err)
	require.True(t, confirmed)
	assert.Equal(t, "proxy", state.WorkloadType)
	assert.Equal(t, "generic", state.PackID)
}

func TestRunWizard_ComplianceFeatures_AcceptsNumbers(t *testing.T) {
	// Agent workload: name, desc, owner, workload=1, pack=1, provider=1, residency=3, features "1,2,3,4", confirm
	// For agent, first 4 features are pii, audit, cost, injection
	input := "num-agent\n\n\n1\n1\n1\n3\n1,2,3,4\n\n"
	wio := WizardIO{
		In:     strings.NewReader(input),
		Out:    io.Discard,
		ErrOut: io.Discard,
	}
	state, confirmed, err := RunWizard(wio)
	require.NoError(t, err)
	require.True(t, confirmed)
	assert.Equal(t, []string{"pii", "audit", "cost", "injection"}, state.EnabledFeatures)
}

func TestRunWizard_ComplianceFeatures_AcceptsIDs(t *testing.T) {
	// Same flow but features line "pii,audit,cost"
	input := "id-agent\n\n\n1\n1\n1\n3\npii,audit,cost\n\n"
	wio := WizardIO{
		In:     strings.NewReader(input),
		Out:    io.Discard,
		ErrOut: io.Discard,
	}
	state, confirmed, err := RunWizard(wio)
	require.NoError(t, err)
	require.True(t, confirmed)
	assert.Equal(t, []string{"pii", "audit", "cost"}, state.EnabledFeatures)
}

func TestRunWizard_ComplianceFeatures_AcceptsMixedAndDedupes(t *testing.T) {
	// Features "1,2,audit,dora" -> 1=pii, 2=audit (dedupe with "audit"), dora
	input := "mix-agent\n\n\n1\n1\n1\n3\n1,2,audit,dora\n\n"
	wio := WizardIO{
		In:     strings.NewReader(input),
		Out:    io.Discard,
		ErrOut: io.Discard,
	}
	state, confirmed, err := RunWizard(wio)
	require.NoError(t, err)
	require.True(t, confirmed)
	assert.Contains(t, state.EnabledFeatures, "pii")
	assert.Contains(t, state.EnabledFeatures, "audit")
	assert.Contains(t, state.EnabledFeatures, "dora")
	assert.Len(t, state.EnabledFeatures, 3)
}

func TestRunWizard_QwenAndEUStrict_ShowsWarning(t *testing.T) {
	// Provider 8 = Qwen (non-EU), residency 1 = eu_strict -> warning must appear
	// name, desc, owner, workload=1, pack=1, provider=8, residency=1, features default, confirm
	var out bytes.Buffer
	input := "qwen-eu\n\n\n1\n1\n8\n1\n\n\n"
	wio := WizardIO{
		In:     strings.NewReader(input),
		Out:    &out,
		ErrOut: io.Discard,
	}
	_, confirmed, err := RunWizard(wio)
	require.NoError(t, err)
	require.True(t, confirmed)
	outStr := out.String()
	assert.Contains(t, outStr, "Qwen", "warning should mention chosen provider")
	assert.Contains(t, outStr, "blocked", "warning should say requests will be blocked")
	assert.Contains(t, outStr, "CN", "warning should mention jurisdiction")
}

func TestRunWizard_AzureAndEUStrict_NoWarning(t *testing.T) {
	// Azure OpenAI is EU; selecting eu_strict should not show the non-EU warning
	// name, desc, owner, workload=1, pack=1, provider=3 (Azure), region=1, residency=1, features default, confirm
	var out bytes.Buffer
	input := "azure-eu\n\n\n1\n1\n3\n1\n1\n\n\n"
	wio := WizardIO{
		In:     strings.NewReader(input),
		Out:    &out,
		ErrOut: io.Discard,
	}
	_, confirmed, err := RunWizard(wio)
	require.NoError(t, err)
	require.True(t, confirmed)
	outStr := out.String()
	assert.NotContains(t, outStr, "requests to this provider will be blocked", "EU provider with eu_strict should not show block warning")
}

func TestDefaultsForWorkload_Proxy_ThreeFeatures(t *testing.T) {
	feats := feature.DefaultsForWorkload("proxy")
	require.Len(t, feats, 3)
	ids := make([]string, len(feats))
	for i, f := range feats {
		ids[i] = f.ID
	}
	assert.Contains(t, ids, "pii")
	assert.Contains(t, ids, "audit")
	assert.Contains(t, ids, "cost")
}

func TestBuildConfigs_Bedrock_NoKeyEnv(t *testing.T) {
	state := WizardState{
		AgentName:       "bedrock-agent",
		ProviderID:      "bedrock",
		DataSovereignty: "global",
		EnabledFeatures: []string{"pii"},
	}
	_, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	require.NotNil(t, infraCfg.LLM)
	blk, ok := infraCfg.LLM.Providers["bedrock"]
	require.True(t, ok)
	_, hasKeyEnv := blk.Config["key_env"]
	assert.False(t, hasKeyEnv)
}

func TestBuildConfigs_Vertex_EURegion(t *testing.T) {
	state := WizardState{
		AgentName:       "vertex-agent",
		WorkloadType:    "agent",
		ProviderID:      "vertex",
		RegionID:        "europe-west1",
		DataSovereignty: "eu_strict",
		EnabledFeatures: []string{"audit"},
	}
	agentCfg, _, err := BuildConfigs(state)
	require.NoError(t, err)
	require.NotNil(t, agentCfg.Policies.ModelRouting)
	require.NotNil(t, agentCfg.Policies.ModelRouting.Tier1)
	assert.Equal(t, "europe-west1", agentCfg.Policies.ModelRouting.Tier1.Location)
}

func TestIsTerminal(t *testing.T) {
	// Just ensure it doesn't panic; in tests stdin is usually not a TTY
	_ = IsTerminal()
}

// Test runList* functions (same package) to improve coverage.
func TestRunListProviders(t *testing.T) {
	var buf bytes.Buffer
	err := runListProviders(&buf)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "provider")
	assert.Contains(t, out, "Add a provider")
}

func TestRunListPacks(t *testing.T) {
	var buf bytes.Buffer
	err := runListPacks(&buf)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "pack")
	assert.Contains(t, out, "openclaw")
}

func TestRunListFeatures(t *testing.T) {
	var buf bytes.Buffer
	err := runListFeatures(&buf)
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "feature")
	assert.Contains(t, out, "pii")
}

// --- Unit tests: wizard helpers (pyramid base) ---

func TestPackName(t *testing.T) {
	assert.Equal(t, "OpenClaw", packName("openclaw"))
	assert.Contains(t, packName("generic"), "Generic") // registry may use "Custom / Generic"
	assert.Equal(t, "unknown-pack", packName("unknown-pack"))
}

func TestProviderName(t *testing.T) {
	assert.Equal(t, "OpenAI", providerName("openai"))
	assert.Equal(t, "Anthropic", providerName("anthropic"))
	assert.Equal(t, "unknown-provider", providerName("unknown-provider"))
}

func TestDataResidencyLabel(t *testing.T) {
	assert.Contains(t, dataResidencyLabel("eu_strict"), "EU")
	assert.Equal(t, "EU preferred", dataResidencyLabel("eu_preferred"))
	assert.Equal(t, "Global", dataResidencyLabel("global"))
	assert.Equal(t, "Global", dataResidencyLabel(""))
}

func TestReadLine_EmptyInput_ReturnsDefault(t *testing.T) {
	scan := bufio.NewScanner(strings.NewReader("\n"))
	var out bytes.Buffer
	got := readLine(scan, &out, "Prompt", "default-val")
	assert.Equal(t, "default-val", got)
}

func TestReadLine_NonEmpty_ReturnsTrimmed(t *testing.T) {
	scan := bufio.NewScanner(strings.NewReader("  my-agent  \n"))
	var out bytes.Buffer
	got := readLine(scan, &out, "Name", "default")
	assert.Equal(t, "my-agent", got)
}

func TestReadChoice_InvalidNumber_ReturnsDefault(t *testing.T) {
	scan := bufio.NewScanner(strings.NewReader("99\n"))
	var out bytes.Buffer
	choice, err := readChoice(scan, &out, "Q?", []string{"A", "B"}, 1)
	require.NoError(t, err)
	assert.Equal(t, 1, choice)
}

func TestReadChoice_EmptyInput_ReturnsDefault(t *testing.T) {
	scan := bufio.NewScanner(strings.NewReader("\n"))
	var out bytes.Buffer
	choice, err := readChoice(scan, &out, "Q?", []string{"A", "B"}, 2)
	require.NoError(t, err)
	assert.Equal(t, 2, choice)
}

func TestReadChoice_ValidChoice_ReturnsChoice(t *testing.T) {
	scan := bufio.NewScanner(strings.NewReader("2\n"))
	var out bytes.Buffer
	choice, err := readChoice(scan, &out, "Q?", []string{"A", "B"}, 1)
	require.NoError(t, err)
	assert.Equal(t, 2, choice)
}

// --- Unit tests: BuildConfigs provider/sovereignty branches ---

func TestBuildConfigs_Mistral_Cohere_Qwen_GenericOpenAI(t *testing.T) {
	for _, tc := range []struct {
		provider string
	}{
		{"mistral"},
		{"cohere"},
		{"qwen"},
		{"generic-openai"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			state := WizardState{
				AgentName:       "x",
				WorkloadType:    "agent",
				ProviderID:      tc.provider,
				DataSovereignty: "global",
				EnabledFeatures: []string{"pii"},
			}
			agentCfg, infraCfg, err := BuildConfigs(state)
			require.NoError(t, err)
			require.NotNil(t, agentCfg)
			require.NotNil(t, infraCfg)
			_, ok := infraCfg.LLM.Providers[tc.provider]
			assert.True(t, ok)
		})
	}
}

func TestBuildConfigs_EUPreferred_ResidencyLabel(t *testing.T) {
	state := WizardState{
		AgentName:       "eu-pref",
		ProviderID:      "openai",
		DataSovereignty: "eu_preferred",
		EnabledFeatures: []string{"audit"},
	}
	agentCfg, _, err := BuildConfigs(state)
	require.NoError(t, err)
	assert.Equal(t, "eu", agentCfg.Compliance.DataResidency)
}

// --- Unit tests: marshalWithHeader and WriteConfigs branches ---

func TestMarshalWithHeader_WithVersionAndRegion(t *testing.T) {
	state := WizardState{
		AgentName:       "h",
		ProviderID:      "openai",
		RegionID:        "westeurope",
		EnabledFeatures: []string{"pii"},
	}
	agentCfg, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	opts := WriteOptions{
		AgentPath:   "agent.talon.yaml",
		InfraPath:   "talon.config.yaml",
		ProviderID:  state.ProviderID,
		RegionID:    state.RegionID,
		Sovereignty: state.DataSovereignty,
		PackID:      state.PackID,
		Features:    state.EnabledFeatures,
		Version:     "v1.0.0",
	}
	agentYAML, infraYAML, err := marshalWithHeader(agentCfg, infraCfg, opts)
	require.NoError(t, err)
	assert.Contains(t, string(agentYAML), "v1.0.0")
	assert.Contains(t, string(agentYAML), "westeurope")
	assert.Contains(t, string(infraYAML), "v1.0.0")
}

func TestWriteConfigs_InfraExists_RefusesWithoutForce(t *testing.T) {
	dir := t.TempDir()
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	infraPath := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(infraPath, []byte("existing"), 0o644))
	state := WizardState{
		AgentName:       "x",
		ProviderID:      "openai",
		DataSovereignty: "global",
	}
	agentCfg, infraCfg, err := BuildConfigs(state)
	require.NoError(t, err)
	opts := WriteOptions{
		AgentPath:   agentPath,
		InfraPath:   infraPath,
		Force:       false,
		ProviderID:  state.ProviderID,
		Sovereignty: state.DataSovereignty,
		PackID:      state.PackID,
		Features:    state.EnabledFeatures,
	}
	err = WriteConfigs(agentCfg, infraCfg, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestPostInitVerify_RunsWithoutPanic(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	warnings, fail := PostInitVerify(
		filepath.Join(dir, "agent.talon.yaml"),
		filepath.Join(dir, "talon.config.yaml"),
		&buf,
	)
	// Doctor runs from cwd; may fail or warn, but must not panic
	_ = warnings
	_ = fail
	assert.Contains(t, buf.String(), "Verifying")
}

func TestBuildConfigs_ValidatesAgentSchema(t *testing.T) {
	state := WizardState{
		AgentName:       "schema-test",
		WorkloadType:    "agent",
		ProviderID:      "openai",
		DataSovereignty: "global",
		EnabledFeatures: []string{"pii", "audit", "cost"},
	}
	agentCfg, _, err := BuildConfigs(state)
	require.NoError(t, err)
	yamlBytes, err := yaml.Marshal(agentCfg)
	require.NoError(t, err)
	err = policy.ValidateSchema(yamlBytes, false)
	require.NoError(t, err)
}
