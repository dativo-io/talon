package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCommand_HasExpectedSubcommands(t *testing.T) {
	expected := []string{
		"version",
		"init",
		"validate",
		"run",
		"serve",
		"audit",
		"costs",
		"secrets",
		"memory",
		"config",
		"report",
	}
	registered := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		registered[cmd.Name()] = true
	}
	for _, name := range expected {
		assert.True(t, registered[name], "subcommand %q should be registered", name)
	}
}

func TestRootCommand_HelpOutput(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "compliance-first AI orchestration platform")
	assert.Contains(t, output, "version")
	assert.Contains(t, output, "init")
	assert.Contains(t, output, "serve")
}

func TestVersionVars_HaveDefaults(t *testing.T) {
	assert.Equal(t, "dev", Version)
	assert.Equal(t, "none", Commit)
	assert.Equal(t, "unknown", BuildDate)
}

func TestRootCommand_GlobalFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
	}{
		{"config flag", "config"},
		{"verbose flag", "verbose"},
		{"log-level flag", "log-level"},
		{"log-format flag", "log-format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := rootCmd.PersistentFlags().Lookup(tt.flagName)
			assert.NotNil(t, flag, "flag %q should be registered", tt.flagName)
		})
	}
}

func TestRootCommand_UseAndShort(t *testing.T) {
	assert.Equal(t, "talon", rootCmd.Use)
	assert.Equal(t, "Policy-as-code for AI agents", rootCmd.Short)
}

func TestPackageLevelTracer_IsNotNil(t *testing.T) {
	assert.NotNil(t, tracer, "package-level tracer should be initialized")
}
