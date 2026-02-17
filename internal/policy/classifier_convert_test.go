package policy

import (
	"context"
	"testing"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToClassifierRecognizers_OmittedScoreBecomesNil(t *testing.T) {
	// Custom recognizers from .talon.yaml with score omitted (unmarshals as 0).
	custom := []CustomRecognizerConfig{
		{
			Name:            "Order ID",
			SupportedEntity: "ORDER_ID",
			Patterns: []CustomPatternConfig{
				{Name: "order", Regex: `\bORD-\d{6}\b`, Score: 0}, // omitted in YAML
			},
			Sensitivity: 1,
		},
	}

	recs := ToClassifierRecognizers(custom)
	require.Len(t, recs, 1)
	require.Len(t, recs[0].Patterns, 1)
	assert.Nil(t, recs[0].Patterns[0].Score,
		"omitted score (0) must convert to nil so classifier uses DefaultMinScore")

	// Scanner should still match when built with these recognizers.
	scanner, err := classifier.NewScanner(classifier.WithCustomRecognizers(recs))
	require.NoError(t, err)
	ctx := context.Background()
	result := scanner.Scan(ctx, "See ORD-123456 for details")
	assert.True(t, result.HasPII, "pattern with omitted score must be effective")
}

func TestToClassifierRecognizers_ExplicitScorePreserved(t *testing.T) {
	score := 0.9
	custom := []CustomRecognizerConfig{
		{
			Name:            "Code",
			SupportedEntity: "CODE",
			Patterns: []CustomPatternConfig{
				{Name: "code", Regex: `\bCODE-\w+\b`, Score: score},
			},
			Sensitivity: 1,
		},
	}

	recs := ToClassifierRecognizers(custom)
	require.Len(t, recs, 1)
	require.Len(t, recs[0].Patterns, 1)
	require.NotNil(t, recs[0].Patterns[0].Score)
	assert.Equal(t, 0.9, *recs[0].Patterns[0].Score)
}
