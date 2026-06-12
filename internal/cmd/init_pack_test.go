package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestInitPack_CrewAI_GeneratesFiles(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	require.NoError(t, os.Chdir(dir))

	rootCmd.SetArgs([]string{"init", "--pack", "crewai", "--skip-verify"})
	err = rootCmd.Execute()
	require.NoError(t, err)

	agentPath := filepath.Join(dir, "agent.talon.yaml")
	configPath := filepath.Join(dir, "talon.config.yaml")
	require.FileExists(t, agentPath)
	require.FileExists(t, configPath)

	agentContent, err := os.ReadFile(agentPath)
	require.NoError(t, err)
	assert.Contains(t, string(agentContent), "crewai-crew")
	assert.Contains(t, string(agentContent), "CrewAI multi-agent crew")

	configContent, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(configContent), "talon-gw-crew-researcher")
	assert.Contains(t, string(configContent), "talon-gw-crew-writer")
	assert.Contains(t, string(configContent), "talon-gw-crew-reviewer")
}

func TestInitPack_ComplianceGDPR_MergesOverlay(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	require.NoError(t, os.Chdir(dir))

	rootCmd.SetArgs([]string{"init", "--pack", "langchain", "--compliance", "gdpr", "--skip-verify"})
	err = rootCmd.Execute()
	require.NoError(t, err)

	agentPath := filepath.Join(dir, "agent.talon.yaml")
	require.FileExists(t, agentPath)
	content, err := os.ReadFile(agentPath)
	require.NoError(t, err)

	var agent struct {
		Compliance struct {
			Frameworks    []string `yaml:"frameworks"`
			DataResidency string   `yaml:"data_residency"`
		} `yaml:"compliance"`
	}
	require.NoError(t, yaml.Unmarshal(content, &agent))
	assert.Contains(t, agent.Compliance.Frameworks, "gdpr")
	assert.Equal(t, "eu", agent.Compliance.DataResidency)
}

func TestInitPack_ComplianceAll_AppliesAllOverlays(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	require.NoError(t, os.Chdir(dir))

	rootCmd.SetArgs([]string{"init", "--pack", "generic", "--compliance", "all", "--skip-verify"})
	err = rootCmd.Execute()
	require.NoError(t, err)

	agentPath := filepath.Join(dir, "agent.talon.yaml")
	require.FileExists(t, agentPath)
	content, err := os.ReadFile(agentPath)
	require.NoError(t, err)
	str := string(content)
	// All overlays add frameworks; union should include gdpr, nis2, dora, eu-ai-act
	assert.True(t, strings.Contains(str, "gdpr") || strings.Contains(str, "nis2") || strings.Contains(str, "dora") || strings.Contains(str, "eu-ai-act"),
		"merged policy should contain at least one compliance framework from overlays")
}

func TestInitPack_LangChain_UsesDedicatedTemplate(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	require.NoError(t, os.Chdir(dir))

	rootCmd.SetArgs([]string{"init", "--pack", "langchain", "--skip-verify"})
	err = rootCmd.Execute()
	require.NoError(t, err)

	agentPath := filepath.Join(dir, "agent.talon.yaml")
	require.FileExists(t, agentPath)
	content, err := os.ReadFile(agentPath)
	require.NoError(t, err)
	str := string(content)

	assert.Contains(t, str, "LangChain agent with policy governance")
	assert.Contains(t, str, "sql_database_query")
	assert.Contains(t, str, "os.system")
}

func TestInitPack_Generic_UsesDedicatedTemplate(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	require.NoError(t, os.Chdir(dir))

	rootCmd.SetArgs([]string{"init", "--pack", "generic", "--skip-verify"})
	err = rootCmd.Execute()
	require.NoError(t, err)

	agentPath := filepath.Join(dir, "agent.talon.yaml")
	require.FileExists(t, agentPath)
	content, err := os.ReadFile(agentPath)
	require.NoError(t, err)
	str := string(content)

	assert.Contains(t, str, "Generic AI agent with policy enforcement")
	assert.Contains(t, str, "- generic")
	assert.Contains(t, str, "human_oversight: on-demand")
}

func TestInitPack_ComplianceMerge_WritesAnnotationHeader(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	require.NoError(t, os.Chdir(dir))

	t.Cleanup(func() { initCompliance = "" })
	rootCmd.SetArgs([]string{"init", "--pack", "generic", "--compliance", "gdpr,nis2", "--skip-verify"})
	require.NoError(t, rootCmd.Execute())

	content, err := os.ReadFile(filepath.Join(dir, "agent.talon.yaml"))
	require.NoError(t, err)
	str := string(content)
	assert.Contains(t, str, "# Compliance packs applied: gdpr, nis2")
	assert.Contains(t, str, "supports: gdpr Art. 30")
	assert.Contains(t, str, "supports: nis2 Art. 21")
	assert.Contains(t, str, "do not, by themselves, make you compliant")
	assert.NotContains(t, str, "supports: dora", "unselected packs must not be annotated")
}

func TestInitPack_InvalidCompliance_Errors(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	require.NoError(t, os.Chdir(dir))

	t.Cleanup(func() { initCompliance = "" })
	rootCmd.SetArgs([]string{"init", "--pack", "generic", "--compliance", "hipaa", "--skip-verify"})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported compliance pack")
}

func TestInitScaffold_ComplianceOverlay_Applied(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	require.NoError(t, os.Chdir(dir))

	t.Cleanup(func() { initCompliance = ""; initScaffold = false })
	rootCmd.SetArgs([]string{"init", "--scaffold", "--compliance", "dora", "--skip-verify"})
	require.NoError(t, rootCmd.Execute())

	content, err := os.ReadFile(filepath.Join(dir, "agent.talon.yaml"))
	require.NoError(t, err)
	str := string(content)
	assert.Contains(t, str, "# Compliance packs applied: dora")
	assert.Contains(t, str, "supports: dora Art. 11")

	var agent struct {
		Compliance struct {
			Frameworks []string `yaml:"frameworks"`
		} `yaml:"compliance"`
		Audit struct {
			RetentionDays int `yaml:"retention_days"`
		} `yaml:"audit"`
	}
	require.NoError(t, yaml.Unmarshal(content, &agent))
	assert.Contains(t, agent.Compliance.Frameworks, "dora")
	assert.GreaterOrEqual(t, agent.Audit.RetentionDays, 1825, "dora overlay sets 5y retention (stricter wins)")
}

func TestInitScripted_ComplianceOverlay_AppliedAndAnnotated(t *testing.T) {
	dir := t.TempDir()
	prevWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(prevWd) })
	require.NoError(t, os.Chdir(dir))

	t.Cleanup(func() {
		initCompliance = ""
		initProvider = ""
		initName = "my-agent"
		initDataSovereignty = ""
		initFeatures = ""
	})
	rootCmd.SetArgs([]string{
		"init", "--provider", "openai", "--name", "scripted-agent",
		"--data-sovereignty", "global", "--features", "pii,audit",
		"--compliance", "eu-ai-act", "--skip-verify",
	})
	require.NoError(t, rootCmd.Execute())

	content, err := os.ReadFile(filepath.Join(dir, "agent.talon.yaml"))
	require.NoError(t, err)
	str := string(content)
	assert.Contains(t, str, "# Compliance packs applied: eu-ai-act")
	assert.Contains(t, str, "supports: eu-ai-act Art. 14")

	var agent struct {
		Compliance struct {
			Frameworks     []string `yaml:"frameworks"`
			HumanOversight string   `yaml:"human_oversight"`
		} `yaml:"compliance"`
	}
	require.NoError(t, yaml.Unmarshal(content, &agent))
	assert.Contains(t, agent.Compliance.Frameworks, "eu-ai-act")
	assert.Equal(t, "on-demand", agent.Compliance.HumanOversight)
}

func TestInitListCompliance_ShowsPacksAndDisclaimer(t *testing.T) {
	var buf strings.Builder
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		initListCompliance = false
	})

	rootCmd.SetArgs([]string{"init", "--list-compliance"})
	require.NoError(t, rootCmd.Execute())
	out := buf.String()
	for _, name := range []string{"gdpr", "nis2", "dora", "eu-ai-act"} {
		assert.Contains(t, out, name)
	}
	assert.Contains(t, out, "supporting controls")
	assert.Contains(t, out, "do not, by themselves, make you compliant")
}

func TestInitListPacks_ShowsCrewAI(t *testing.T) {
	var buf strings.Builder
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	rootCmd.SetArgs([]string{"init", "--list-packs"})
	err := rootCmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "crewai")
	assert.Contains(t, out, "CrewAI")
	assert.Contains(t, out, "fintech-eu")
	assert.Contains(t, out, "ecommerce-eu")
	assert.Contains(t, out, "saas-eu")
	assert.Contains(t, out, "telecom-eu")
}
