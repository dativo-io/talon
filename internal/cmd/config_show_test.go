package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigShowCmd_RunsAndShowsDataDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	var buf bytes.Buffer
	configShowCmd.SetOut(&buf)
	configShowCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"config", "show"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Data directory:")
	assert.Contains(t, out, dir)
	assert.Contains(t, out, "Secrets key:")
	assert.Contains(t, out, "Signing key:")
	assert.Contains(t, out, "Default policy:")
	assert.Contains(t, out, "Secrets DB:")
	assert.Contains(t, out, "Evidence DB:")
	assert.Contains(t, out, "Memory DB:")
	assert.Contains(t, out, "LLM keys (env):")
}

func TestConfigShowCmd_DataDirExistsShown(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir, 0o700))
	t.Setenv("TALON_DATA_DIR", dir)

	var buf bytes.Buffer
	configShowCmd.SetOut(&buf)
	configShowCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"config", "show"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "(exists)")
}

func TestDirExists(t *testing.T) {
	dir := t.TempDir()
	assert.True(t, dirExists(dir))
	assert.False(t, dirExists(filepath.Join(dir, "nonexistent")))
	// A file is not a directory
	f := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	assert.False(t, dirExists(f))
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	assert.True(t, fileExists(f))
	assert.False(t, fileExists(filepath.Join(dir, "nonexistent")))
	assert.False(t, fileExists(dir)) // directory is not a file
}
