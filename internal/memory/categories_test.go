package memory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveTrustScore_AllSourceTypes(t *testing.T) {
	tests := []struct {
		sourceType string
		want       int
	}{
		{SourceManual, 100},
		{SourceUserInput, 90},
		{SourceAgentRun, 70},
		{SourceToolOutput, 50},
		{SourceWebhook, 40},
		{"unknown_source", 30},
	}

	for _, tt := range tests {
		t.Run(tt.sourceType, func(t *testing.T) {
			assert.Equal(t, tt.want, DeriveTrustScore(tt.sourceType))
		})
	}
}

func TestIsForbiddenCategory(t *testing.T) {
	assert.True(t, IsForbiddenCategory("policy_modifications"))
	assert.True(t, IsForbiddenCategory("prompt_injection"))
	assert.True(t, IsForbiddenCategory("credential_data"))
	assert.False(t, IsForbiddenCategory(CategoryDomainKnowledge))
	assert.False(t, IsForbiddenCategory(CategoryPolicyHit))
	assert.False(t, IsForbiddenCategory(""))
}

func TestValidObservationTypes(t *testing.T) {
	types := ValidObservationTypes()
	assert.Len(t, types, 5)
	assert.Contains(t, types, ObsDecision)
	assert.Contains(t, types, ObsPolicyHit)
	assert.Contains(t, types, ObsToolUse)
	assert.Contains(t, types, ObsLearning)
	assert.Contains(t, types, ObsError)
}

func TestValidSourceTypes(t *testing.T) {
	types := ValidSourceTypes()
	assert.Len(t, types, 5)
	assert.Contains(t, types, SourceManual)
	assert.Contains(t, types, SourceUserInput)
	assert.Contains(t, types, SourceAgentRun)
	assert.Contains(t, types, SourceToolOutput)
	assert.Contains(t, types, SourceWebhook)
}

func TestMemoryTypeConstantsAndTypeWeights(t *testing.T) {
	assert.Equal(t, "semantic", MemTypeSemanticFact)
	assert.Equal(t, "episodic", MemTypeEpisodic)
	assert.Equal(t, "procedural", MemTypeProcedural)

	assert.Len(t, TypeWeights, 3)
	assert.Equal(t, 0.6, TypeWeights[MemTypeSemanticFact])
	assert.Equal(t, 0.3, TypeWeights[MemTypeEpisodic])
	assert.Equal(t, 0.1, TypeWeights[MemTypeProcedural])
}
