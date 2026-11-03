package trigger

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

// TestValidatePolicyTriggers (#479): one rule set for startup, reload,
// validate and doctor. Gateway mode refuses every trigger (schedules
// included) because trigger runs bypass gateway.organization_policy; every
// mode refuses a webhook without a vault-bound secret or with
// require_approval.
func TestValidatePolicyTriggers(t *testing.T) {
	webhook := policy.WebhookTrigger{Name: "incoming", Source: "zendesk", SecretName: "incoming-webhook", PromptTemplate: "{{.payload}}"}
	schedule := policy.ScheduleTrigger{Cron: "0 9 * * 1-5", Prompt: "digest"}

	t.Run("no triggers is fine in every mode", func(t *testing.T) {
		for _, gw := range []bool{false, true} {
			assert.NoError(t, ValidatePolicyTriggers(&policy.Policy{Agent: policy.AgentConfig{Name: "a"}}, ServeRules{GatewayServed: gw}))
			assert.NoError(t, ValidatePolicyTriggers(&policy.Policy{Agent: policy.AgentConfig{Name: "a"}, Triggers: &policy.TriggersConfig{}}, ServeRules{GatewayServed: gw}))
		}
		assert.NoError(t, ValidatePolicyTriggers(nil, ServeRules{GatewayServed: true}))
	})

	t.Run("native-only serve accepts a secret-bound webhook and a schedule", func(t *testing.T) {
		pol := &policy.Policy{Agent: policy.AgentConfig{Name: "support"}, Triggers: &policy.TriggersConfig{Webhooks: []policy.WebhookTrigger{webhook}, Schedule: []policy.ScheduleTrigger{schedule}}}
		assert.NoError(t, ValidatePolicyTriggers(pol, ServeRules{}))
	})

	t.Run("gateway served refuses webhooks", func(t *testing.T) {
		pol := &policy.Policy{Agent: policy.AgentConfig{Name: "support"}, Triggers: &policy.TriggersConfig{Webhooks: []policy.WebhookTrigger{webhook}}}
		err := ValidatePolicyTriggers(pol, ServeRules{GatewayServed: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `agent "support" declares triggers (0 schedule, 1 webhook)`)
		assert.Contains(t, err.Error(), "gateway.organization_policy")
	})

	t.Run("gateway served refuses schedules too", func(t *testing.T) {
		pol := &policy.Policy{Agent: policy.AgentConfig{Name: "digest"}, Triggers: &policy.TriggersConfig{Schedule: []policy.ScheduleTrigger{schedule}}}
		err := ValidatePolicyTriggers(pol, ServeRules{GatewayServed: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "(1 schedule, 0 webhook)")
	})

	t.Run("webhook without secret_name", func(t *testing.T) {
		w := webhook
		w.SecretName = " "
		pol := &policy.Policy{Agent: policy.AgentConfig{Name: "support"}, Triggers: &policy.TriggersConfig{Webhooks: []policy.WebhookTrigger{w}}}
		err := ValidatePolicyTriggers(pol, ServeRules{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `webhook "incoming" on agent "support" has no secret_name`)
	})

	t.Run("require_approval is refused", func(t *testing.T) {
		w := webhook
		w.RequireApproval = true
		pol := &policy.Policy{Agent: policy.AgentConfig{Name: "support"}, Triggers: &policy.TriggersConfig{Webhooks: []policy.WebhookTrigger{w}}}
		err := ValidatePolicyTriggers(pol, ServeRules{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "require_approval: true")
		assert.Contains(t, err.Error(), "dropped it")
	})

	t.Run("fleet validation names the first failing agent", func(t *testing.T) {
		good := &policy.Policy{Agent: policy.AgentConfig{Name: "ok"}, Triggers: &policy.TriggersConfig{Webhooks: []policy.WebhookTrigger{webhook}}}
		bad := &policy.Policy{Agent: policy.AgentConfig{Name: "bad"}, Triggers: &policy.TriggersConfig{Webhooks: []policy.WebhookTrigger{{Name: "x", Source: "generic", PromptTemplate: "x"}}}}
		assert.NoError(t, ValidateFleetTriggers([]*policy.Policy{good}, ServeRules{}))
		err := ValidateFleetTriggers([]*policy.Policy{good, bad}, ServeRules{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `agent "bad"`)
		err = ValidateFleetTriggers([]*policy.Policy{good, bad}, ServeRules{GatewayServed: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `agent "ok" declares triggers`, "gateway rule fires on the first agent with any trigger")
	})
}
