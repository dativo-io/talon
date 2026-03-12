package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlanCmd_SubcommandsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, c := range planCmd.Commands() {
		registered[c.Name()] = true
	}
	assert.True(t, registered["pending"], "plan pending should be registered")
	assert.True(t, registered["approve"], "plan approve should be registered")
	assert.True(t, registered["reject"], "plan reject should be registered")
	assert.True(t, registered["execute"], "plan execute should be registered")
}

func TestPlanCmd_FlagDefaults(t *testing.T) {
	tenantFlag := planExecuteCmd.Flags().Lookup("tenant")
	assert.NotNil(t, tenantFlag)
	if tenantFlag != nil {
		assert.Equal(t, "default", tenantFlag.DefValue)
	}

	reviewerFlag := planApproveCmd.Flags().Lookup("reviewed-by")
	assert.NotNil(t, reviewerFlag)
	if reviewerFlag != nil {
		assert.Equal(t, "cli", reviewerFlag.DefValue)
	}

	reasonFlag := planRejectCmd.Flags().Lookup("reason")
	assert.NotNil(t, reasonFlag)
	if reasonFlag != nil {
		assert.Equal(t, "rejected in CLI", reasonFlag.DefValue)
	}
}

func TestPlanCmd_ArgValidation(t *testing.T) {
	assert.Error(t, planApproveCmd.Args(planApproveCmd, []string{}))
	assert.NoError(t, planApproveCmd.Args(planApproveCmd, []string{"plan_123"}))
	assert.Error(t, planRejectCmd.Args(planRejectCmd, []string{}))
	assert.NoError(t, planRejectCmd.Args(planRejectCmd, []string{"plan_123"}))
	assert.Error(t, planExecuteCmd.Args(planExecuteCmd, []string{}))
	assert.NoError(t, planExecuteCmd.Args(planExecuteCmd, []string{"plan_123"}))
}
