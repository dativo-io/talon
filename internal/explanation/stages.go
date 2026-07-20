package explanation

import "strings"

const (
	StagePolicyEvaluation = "policy_evaluation"
	StageToolExecution    = "tool_execution"
	StageOutputValidation = "output_validation"
	StagePreExecution     = "pre_execution"
	StageExecution        = "execution"
	// StageGraphGovernance is the graph-adapter governance gate (#360):
	// registered additively — remapping the graphadapter facts onto an
	// existing stage would reorder Primary() selection (sorted by Stage
	// first) on existing evidence displays.
	StageGraphGovernance = "graph_governance"
)

var stageAliases = map[string]string{
	"output_scan": StageOutputValidation,
}

// CanonicalStage returns a normalized explanation stage token.
func CanonicalStage(stage string) string {
	s := strings.TrimSpace(stage)
	if s == "" {
		return StagePolicyEvaluation
	}
	if alias, ok := stageAliases[s]; ok {
		return alias
	}
	return s
}

// IsKnownStage reports whether stage is part of the canonical stage set.
func IsKnownStage(stage string) bool {
	switch CanonicalStage(stage) {
	case StagePolicyEvaluation, StageToolExecution, StageOutputValidation, StagePreExecution, StageExecution, StageGraphGovernance:
		return true
	default:
		return false
	}
}
