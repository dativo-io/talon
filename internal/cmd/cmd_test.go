package cmd

import (
	"bytes"
	"os"
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
		{"otel flag", "otel"},
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

func TestMemoryAsOfCmd_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	// memory as-of uses fmt.Printf (stdout), so capture process stdout
	oldOut := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = oldOut }()

	rootCmd.SetArgs([]string{"memory", "as-of", "2020-01-01T00:00:00Z"})
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
	assert.Contains(t, string(out), "No memory entries valid at")
}
