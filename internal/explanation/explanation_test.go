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

func TestExplanation_NormalizesTriggerTokenLists(t *testing.T) {
	items := BuildFromFacts([]Fact{{
		Code:     CodePolicyDeniedPIIInput,
		Decision: DecisionDeny,
		Stage:    "policy_evaluation",
		Trigger:  "EMAIL,IBAN,EMAIL",
	}})
	requireLen := 1
	assert.Len(t, items, requireLen)
	assert.Equal(t, "EMAIL,IBAN", items[0].Trigger)
}

func TestExplanation_PolicyRef(t *testing.T) {
	assert.Equal(t, "", PolicyRef(""))
	assert.Equal(t, "policy:1.0.0:sha256:abc", PolicyRef("1.0.0:sha256:abc"))
}

func TestExplanation_NormalizesTriggerTokenListsWithWhitespace(t *testing.T) {
	items := BuildFromFacts([]Fact{{
		Code:     CodePolicyDeniedPIIInput,
		Decision: DecisionDeny,
		Stage:    StagePolicyEvaluation,
		Trigger:  "EMAIL, PHONE, EMAIL",
	}})
	assert.Len(t, items, 1)
	assert.Equal(t, "EMAIL,PHONE", items[0].Trigger)
}

func TestExplanation_PreservesSentenceLikeTriggerWithComma(t *testing.T) {
	trigger := "contains comma, but is sentence"
	items := BuildFromFacts([]Fact{{
		Code:     CodePolicyDenied,
		Decision: DecisionDeny,
		Stage:    StagePolicyEvaluation,
		Trigger:  trigger,
	}})
	assert.Len(t, items, 1)
	assert.Equal(t, trigger, items[0].Trigger)
}

func TestExplanation_StageCanonicalizationAndWhitelist(t *testing.T) {
	items := BuildFromFacts([]Fact{{
		Code:     CodePolicyDeniedPIIOutput,
		Decision: DecisionDeny,
		Stage:    "output_scan",
		Trigger:  "EMAIL",
	}})
	assert.Len(t, items, 1)
	assert.Equal(t, StageOutputValidation, items[0].Stage)
	assert.True(t, IsKnownStage(items[0].Stage))
	assert.True(t, IsKnownStage(StagePolicyEvaluation))
	assert.True(t, IsKnownStage(StageToolExecution))
	assert.True(t, IsKnownStage(StagePreExecution))
	assert.True(t, IsKnownStage(StageExecution))
	assert.False(t, IsKnownStage("unknown_stage"))
}
