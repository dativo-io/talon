package explanation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExplanation_BuildFromFactsDeterministicAndSorted(t *testing.T) {
	facts := []Fact{
		{Code: CodePolicyDeniedTool, Decision: DecisionDeny, Stage: "tools", Trigger: "z", PolicyRef: "p1", VersionIdentity: "v1"},
		{Code: CodePolicyDeniedCost, Decision: DecisionDeny, Stage: "policy_evaluation", Trigger: "a", PolicyRef: "p1", VersionIdentity: "v1"},
		{Code: CodePolicyDeniedCost, Decision: DecisionDeny, Stage: "policy_evaluation", Trigger: "a", PolicyRef: "p1", VersionIdentity: "v1"}, // duplicate
	}
	gotA := BuildFromFacts(facts)
	gotB := BuildFromFacts([]Fact{facts[2], facts[0], facts[1]})

	assert.Equal(t, gotA, gotB)
	assert.Len(t, gotA, 2)
	assert.Equal(t, CodePolicyDeniedCost, gotA[0].Code)
	assert.Equal(t, "policy_evaluation", gotA[0].Stage)
}

func TestExplanation_BuildLegacyFactsSortsReasonInput(t *testing.T) {
	reasons := []string{
		"routing policy returned no results (fail-closed)",
		"Input contains PII (policy: block_on_pii)",
	}
	facts := BuildLegacyFacts(false, "deny", reasons, "policy_evaluation", "policy:v1", "v1")
	items := BuildFromFacts(facts)

	assert.Len(t, items, 2)
	assert.Equal(t, CodePolicyDeniedPIIInput, items[0].Code)
	assert.Equal(t, CodePolicyDeniedRouting, items[1].Code)
}
