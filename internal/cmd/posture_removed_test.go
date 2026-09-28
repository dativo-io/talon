package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// #442: enforcement is structural. The posture-management command family and
// the runtime mode override flag must not exist; a command that implies
// enforcement is optional is itself a defect.
func TestEnforceCommandFamilyRemoved(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		assert.NotEqual(t, "enforce", c.Name(), "talon enforce must not be registered (#442)")
	}
	cmd, _, err := rootCmd.Find([]string{"enforce", "status"})
	if err == nil && cmd != nil {
		assert.NotEqual(t, "enforce", cmd.Name())
		assert.NotEqual(t, "status", cmd.Name())
	}
}

func TestServeHasNoGatewayModeFlag(t *testing.T) {
	assert.Nil(t, serveCmd.Flags().Lookup("gateway-mode"), "--gateway-mode was removed (#442)")
}
