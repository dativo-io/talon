// Governance parity invariants: every evidence-producing entry path (agent
// runner, gateway, MCP server, MCP proxy, graph adapter) must satisfy the
// same minimum contract. ValidateGovernedRecord is the single definition of
// that contract; Store.Store applies it as a fail-open guardrail (structured
// warning, never an error) so posture drift in any path — including future
// ones — is visible at runtime and in smoke tests, without ever losing the
// evidence record itself.
package evidence

import (
	"context"
	"strings"

	"github.com/rs/zerolog/log"
)

// graphModelPlaceholder mirrors the graph adapter's placeholder for runs
// where the external runtime never reported a model. Such records carry no
// data_flow by design when there is no sign any model call happened.
const graphModelPlaceholder = "unknown_graph_model"

// modeChangeMarkerPrefix marks control-plane mode-change records
// (`talon enforce`), which reuse the model_used field as an event marker.
// No data egresses on a mode change, so no data_flow is expected.
const modeChangeMarkerPrefix = "mode_change:"

// ValidateGovernedRecord returns the list of governance parity violations
// for one evidence record. An empty result means the record satisfies the
// cross-path contract. Violations are advisory: evidence is stored anyway
// (evidence by default), but each violation is logged as drift.
func ValidateGovernedRecord(ev *Evidence) []string {
	var violations []string
	if ev.TenantID == "" {
		violations = append(violations, "missing tenant_id")
	}
	if ev.CorrelationID == "" {
		violations = append(violations, "missing correlation_id")
	}
	// Model call => data_flow: any record claiming a model was used must say
	// where the data went (or that it was blocked). Exempt: the graph
	// adapter's model placeholder (no model call observed) and control-plane
	// mode-change markers (no data egresses).
	if isModelCall(ev.Execution.ModelUsed) && ev.DataFlow == nil {
		violations = append(violations, "model call recorded without data_flow")
	}
	if ev.DataFlow != nil && len(ev.DataFlow.Items) == 0 {
		violations = append(violations, "data_flow present but has no items")
	}
	return violations
}

// isModelCall reports whether a model_used value represents an actual model
// call rather than a placeholder or control-plane marker.
func isModelCall(modelUsed string) bool {
	return modelUsed != "" &&
		modelUsed != graphModelPlaceholder &&
		!strings.HasPrefix(modelUsed, modeChangeMarkerPrefix)
}

// warnGovernanceDrift logs one structured warning per parity violation.
// Never fails the store: evidence integrity outranks invariant hygiene.
func warnGovernanceDrift(_ context.Context, ev *Evidence) {
	for _, violation := range ValidateGovernedRecord(ev) {
		log.Warn().
			Str("evidence_id", ev.ID).
			Str("correlation_id", ev.CorrelationID).
			Str("tenant_id", ev.TenantID).
			Str("agent_id", ev.AgentID).
			Str("invocation_type", ev.InvocationType).
			Str("violation", violation).
			Msg("governance_parity_violation")
	}
}
