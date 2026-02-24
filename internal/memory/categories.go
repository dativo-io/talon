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
	CategoryPolicyHit     = "policy_hit"
	CategoryCostDecision  = "cost_decision"
	CategoryPIIRedaction  = "pii_redaction"
	CategoryToolApproval  = "tool_approval"
	CategoryEscalation    = "escalation"
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

// domainKnowledgeSubtypes are categories that inferCategoryTypeAndMemType can return
// for runs that the legacy inferCategory would have classified as domain_knowledge.
// Policies with allowed_categories: [domain_knowledge, ...] are treated as allowing
// these sub-types for backward compatibility (avoids silent memory loss).
var domainKnowledgeSubtypes = map[string]bool{
	CategoryDomainKnowledge:       true,
	CategoryFactualCorrections:    true,
	CategoryUserPreferences:       true,
	CategoryProcedureImprovements: true,
	CategoryToolApproval:          true,
	CategoryCostDecision:          true,
}

// AllowedWhenDomainKnowledgeAllowed returns true if the category is either
// domain_knowledge or one of its sub-types (tool_approval, cost_decision,
// user_preferences, procedure_improvements, factual_corrections). Used so that
// legacy policies with only allowed_categories: [domain_knowledge, policy_hit]
// do not silently reject writes that are now classified with the finer categories.
func AllowedWhenDomainKnowledgeAllowed(cat string) bool {
	return domainKnowledgeSubtypes[cat]
}

// Memory types (Tulving/CoALA — three-type model for retrieval scoring).
const (
	MemTypeSemanticFact = "semantic"   // What the agent knows: facts, preferences, constraints
	MemTypeEpisodic     = "episodic"   // What happened: specific interactions, outcomes, events
	MemTypeProcedural   = "procedural" // How to do things: learned behaviors, response patterns
)

// TypeWeights for relevance-scored retrieval (Mem0-style).
// Semantic facts are most valuable for prompt injection; episodic provides recent context; procedural fine-tunes behavior.
var TypeWeights = map[string]float64{
	MemTypeSemanticFact: 0.6,
	MemTypeEpisodic:     0.3,
	MemTypeProcedural:   0.1,
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
	SourceManual     = "manual"
	SourceUserInput  = "user_input"
	SourceAgentRun   = "agent_run"
	SourceToolOutput = "tool_output"
	SourceWebhook    = "webhook"
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
