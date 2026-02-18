package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/config"
)

func TestRunCmd_Flags(t *testing.T) {
	expected := map[string]string{
		"agent":   "default",
		"tenant":  "default",
		"dry-run": "false",
		"policy":  "",
	}

	for name, wantDefault := range expected {
		flag := runCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "run flag %q should be registered", name)
		if flag != nil {
			assert.Equal(t, wantDefault, flag.DefValue, "run flag %q default", name)
		}
	}
}

func TestRunCmd_RequiresExactlyOneArg(t *testing.T) {
	assert.NotNil(t, runCmd.Args, "run command should have an Args validator")
	err := runCmd.Args(runCmd, []string{})
	assert.Error(t, err)
	err = runCmd.Args(runCmd, []string{"a", "b"})
	assert.Error(t, err)
	err = runCmd.Args(runCmd, []string{"hello"})
	assert.NoError(t, err)
}

func TestRunCmd_UseLine(t *testing.T) {
	assert.Equal(t, "run [prompt]", runCmd.Use)
}

func TestBuildProviders_Empty(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AWS_REGION", "")

	cfg := &config.Config{OllamaBaseURL: "http://localhost:11434"}
	providers := buildProviders(cfg)
	assert.Contains(t, providers, "ollama")
	assert.NotContains(t, providers, "openai")
	assert.NotContains(t, providers, "anthropic")
	assert.NotContains(t, providers, "bedrock")
}

func TestBuildProviders_WithEnvVars(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test123")
	t.Setenv("ANTHROPIC_API_KEY", "ant-test123")
	t.Setenv("AWS_REGION", "eu-west-1")

	cfg := &config.Config{OllamaBaseURL: "http://localhost:11434"}
	providers := buildProviders(cfg)
	assert.Contains(t, providers, "openai")
	assert.Contains(t, providers, "anthropic")
	assert.Contains(t, providers, "ollama")
	assert.Contains(t, providers, "bedrock")
}

func TestBuildProviders_OllamaCustomURL(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("AWS_REGION", "")

	cfg := &config.Config{OllamaBaseURL: "http://custom:11434"}
	providers := buildProviders(cfg)
	assert.Contains(t, providers, "ollama")
}
