// Package memory implements governed agent memory with provenance tracking,
// conflict detection, and Constitutional AI governance.
package memory

// Learning categories -- things the agent can learn.
const (
	CategoryFactualCorrections    = "factual_corrections"
	CategoryUserPreferences       = "user_preferences"
	CategoryDomainKnowledge       = "domain_knowledge"
	CategoryProcedureImprovements = "procedure_improvements"
)

// Operational categories -- runtime observations.
const (
	CategoryPolicyHit    = "policy_hit"
	CategoryCostDecision = "cost_decision"
	CategoryPIIRedaction = "pii_redaction"
	CategoryToolApproval = "tool_approval"
	CategoryEscalation   = "escalation"
	CategoryErrorRecovery = "error_recovery"
)

// Hardcoded forbidden categories -- these are ALWAYS rejected regardless of policy.
var hardcodedForbidden = map[string]bool{
	"policy_modifications": true,
	"prompt_injection":     true,
	"credential_data":      true,
}

// IsForbiddenCategory returns true for categories that are always forbidden,
// regardless of policy configuration.
func IsForbiddenCategory(cat string) bool {
	return hardcodedForbidden[cat]
}

// Observation types describe what kind of memory entry this is.
const (
	ObsDecision  = "decision"
	ObsPolicyHit = "policy_hit"
	ObsToolUse   = "tool_use"
	ObsLearning  = "learning"
	ObsError     = "error"
)

// ValidObservationTypes returns the set of valid observation types.
func ValidObservationTypes() []string {
	return []string{ObsDecision, ObsPolicyHit, ObsToolUse, ObsLearning, ObsError}
}

// Source types and their default trust scores.
const (
	SourceManual    = "manual"
	SourceUserInput = "user_input"
	SourceAgentRun  = "agent_run"
	SourceToolOutput = "tool_output"
	SourceWebhook   = "webhook"
)

var trustScores = map[string]int{
	SourceManual:     100,
	SourceUserInput:  90,
	SourceAgentRun:   70,
	SourceToolOutput: 50,
	SourceWebhook:    40,
}

// DeriveTrustScore returns the default trust score for the given source type.
// Unknown source types get a conservative score of 30.
func DeriveTrustScore(sourceType string) int {
	if score, ok := trustScores[sourceType]; ok {
		return score
	}
	return 30
}

// ValidSourceTypes returns all recognized source types.
func ValidSourceTypes() []string {
	return []string{SourceManual, SourceUserInput, SourceAgentRun, SourceToolOutput, SourceWebhook}
}
