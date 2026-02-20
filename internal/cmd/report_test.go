package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportCmd_Flags(t *testing.T) {
	flag := reportCmd.Flags().Lookup("tenant")
	require.NotNil(t, flag)
	assert.Equal(t, "default", flag.DefValue)
}

func TestReportCmd_RunSuccess(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", dir)

	var buf bytes.Buffer
	reportCmd.SetOut(&buf)
	reportCmd.SetErr(&buf)
	reportCmd.SetArgs(nil)
	rootCmd.SetArgs([]string{"report"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Compliance summary")
	assert.Contains(t, out, "Evidence records today")
	assert.Contains(t, out, "Evidence records (7d)")
	assert.Contains(t, out, "Cost today (EUR)")
	assert.Contains(t, out, "Cost this month (EUR)")
}
