package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildGatewayPolicyInput_UsesServerDefaultsWhenCallerCapsUnset(t *testing.T) {
	caller := &CallerConfig{
		Name:     "support-slack-bot",
		TenantID: "default",
		PolicyOverrides: &CallerPolicyOverrides{
			PIIAction: "warn",
		},
	}
	defaults := ServerDefaults{
		MaxDailyCost:   10.0,
		MaxMonthlyCost: 200.0,
	}

	input := buildGatewayPolicyInput(caller, defaults, "openai", "gpt-4o-mini", 0, 0.5, 2.0, 15.0)

	assert.Equal(t, 10.0, input["caller_max_daily_cost"])
	assert.Equal(t, 200.0, input["caller_max_monthly_cost"])
}

func TestBuildGatewayPolicyInput_CallerCapsOverrideServerDefaults(t *testing.T) {
	caller := &CallerConfig{
		Name:     "support-slack-bot",
		TenantID: "default",
		PolicyOverrides: &CallerPolicyOverrides{
			MaxDailyCost:   5.0,
			MaxMonthlyCost: 120.0,
		},
	}
	defaults := ServerDefaults{
		MaxDailyCost:   10.0,
		MaxMonthlyCost: 200.0,
	}

	input := buildGatewayPolicyInput(caller, defaults, "openai", "gpt-4o-mini", 0, 0.5, 2.0, 15.0)

	assert.Equal(t, 5.0, input["caller_max_daily_cost"])
	assert.Equal(t, 120.0, input["caller_max_monthly_cost"])
}
