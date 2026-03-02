package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderList(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"provider", "list"})
	err := rootCmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "Jurisdiction")
	// At least one built-in provider should appear
	assert.Contains(t, out, "openai")
}

func TestProviderInfo(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"provider", "info", "openai"})
	err := rootCmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "openai")
	assert.Contains(t, out, "Jurisdiction")
}

func TestProviderAllowed(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"provider", "allowed"})
	err := rootCmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "Data sovereignty mode")
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "Allowed")
}
