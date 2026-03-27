package classifier

import (
	"testing"

	"github.com/dativo-io/talon/internal/classifier/entity"
	"github.com/stretchr/testify/assert"
)

func TestPresidioAnalyzerResultsToCanonical(t *testing.T) {
	text := "My email is test@example.com"
	results := []PresidioAnalyzerResult{
		{
			Start:      12,
			End:        28,
			Score:      0.85,
			EntityType: "EMAIL_ADDRESS",
		},
	}

	canonical := PresidioAnalyzerResultsToCanonical(text, results)

	assert.Len(t, canonical, 1)
	assert.Equal(t, 1, canonical[0].Id)
	assert.Equal(t, "EMAIL_ADDRESS", canonical[0].Type)
	assert.Equal(t, "test@example.com", canonical[0].Raw)
	assert.Equal(t, 12, canonical[0].Start)
	assert.Equal(t, 28, canonical[0].End)
	assert.Equal(t, entity.SourcePresidio, canonical[0].Source)
	assert.Equal(t, 0.85, canonical[0].Confidence)
	assert.Equal(t, 1, canonical[0].Sensitivity)
}
