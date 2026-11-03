package trigger

import (
	"fmt"
	"strings"

	"github.com/dativo-io/talon/internal/policy"
)

// ServeRules describes the serve mode trigger definitions are validated
// against. The same rules run at startup, on every config reload, in
// `talon validate` and in `talon doctor`, so a definition that serve would
// refuse is refused everywhere with the same message.
type ServeRules struct {
	// GatewayServed is true when the process serves the LLM gateway (or the
	// quickstart facade). Trigger runs execute through the native runner,
	// which applies the agent's own policy WITHOUT gateway.organization_policy
	// and the resolved effective policy — the same reason native execution
	// routes are admin-only in gateway mode (#266). A trigger would hand the
	// agent file's author that ungoverned path on a timer or on an inbound
	// request, so gateway mode refuses triggers altogether (#479).
	GatewayServed bool
}

// ValidatePolicyTriggers checks one agent policy's trigger definitions
// against the serve rules and the webhook contract (#479):
//
//   - no triggers at all when a gateway is served (see ServeRules);
//   - every webhook names the vault secret (`secret_name`) senders must
//     present as a bearer token — an unauthenticated webhook is remote
//     execution for anyone who can reach the port;
//   - `require_approval: true` is refused: Talon has no queue for held
//     trigger events (earlier versions answered 202 and dropped the event).
func ValidatePolicyTriggers(pol *policy.Policy, rules ServeRules) error {
	if pol == nil || pol.Triggers == nil {
		return nil
	}
	agent := pol.Agent.Name
	schedules, webhooks := len(pol.Triggers.Schedule), len(pol.Triggers.Webhooks)
	if rules.GatewayServed && (schedules > 0 || webhooks > 0) {
		return fmt.Errorf("agent %q declares triggers (%d schedule, %d webhook) but a gateway is served: trigger runs execute through the native runner, which does not apply gateway.organization_policy — remove the triggers from this agent or serve it without --gateway (#479)", agent, schedules, webhooks)
	}
	for _, w := range pol.Triggers.Webhooks {
		if strings.TrimSpace(w.SecretName) == "" {
			return fmt.Errorf("webhook %q on agent %q has no secret_name: every webhook names the vault secret its sender presents as a bearer token (#479)", w.Name, agent)
		}
		if w.RequireApproval {
			return fmt.Errorf("webhook %q on agent %q sets require_approval: true, which Talon cannot honour — there is no queue for held trigger events (earlier versions acknowledged the event with 202 and dropped it); remove it, or govern the agent's actions through the Action Gateway approval policy (#479)", w.Name, agent)
		}
	}
	return nil
}

// ValidateFleetTriggers applies ValidatePolicyTriggers to every policy of a
// scanned fleet; the first failure is returned verbatim so startup, reload
// rejection and `talon validate` name the same agent and cause.
func ValidateFleetTriggers(policies []*policy.Policy, rules ServeRules) error {
	for _, pol := range policies {
		if err := ValidatePolicyTriggers(pol, rules); err != nil {
			return err
		}
	}
	return nil
}
