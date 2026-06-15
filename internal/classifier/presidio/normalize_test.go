package presidio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeResults_ByteOffsets(t *testing.T) {
	text := "Email user@example.com"
	results := []RecognizerResult{{
		EntityType:        "EMAIL_ADDRESS",
		Start:             6,
		End:               22,
		Score:             0.91,
		OffsetEncoding:    OffsetEncodingByte,
		ExpectedSubstring: "user@example.com",
	}}

	canonical, err := NormalizeResults(text, results)
	require.NoError(t, err)
	require.Len(t, canonical, 1)
	assert.Equal(t, "email", canonical[0].Type)
	assert.Equal(t, "user@example.com", canonical[0].Raw)
	assert.Equal(t, 6, canonical[0].Start)
	assert.Equal(t, 22, canonical[0].End)
}

func TestNormalizeResults_RuneOffsets(t *testing.T) {
	text := "Müller"
	results := []RecognizerResult{{
		EntityType:        "PERSON",
		Start:             0,
		End:               6,
		Score:             0.8,
		OffsetEncoding:    OffsetEncodingRune,
		ExpectedSubstring: "Müller",
	}}

	canonical, err := NormalizeResults(text, results)
	require.NoError(t, err)
	require.Len(t, canonical, 1)
	assert.Equal(t, "person", canonical[0].Type)
	assert.Equal(t, 0, canonical[0].Start)
	assert.Equal(t, len(text), canonical[0].End)
	if assert.NotNil(t, canonical[0].RuneStart) {
		assert.Equal(t, 0, *canonical[0].RuneStart)
	}
	if assert.NotNil(t, canonical[0].RuneEnd) {
		assert.Equal(t, 6, *canonical[0].RuneEnd)
	}
}

func TestNormalizeResults_InvalidRanges(t *testing.T) {
	text := "abc"
	tests := []RecognizerResult{
		{EntityType: "EMAIL_ADDRESS", Start: -1, End: 1, Score: 0.5, OffsetEncoding: OffsetEncodingByte},
		{EntityType: "EMAIL_ADDRESS", Start: 0, End: 4, Score: 0.5, OffsetEncoding: OffsetEncodingByte},
		{EntityType: "EMAIL_ADDRESS", Start: 2, End: 1, Score: 0.5, OffsetEncoding: OffsetEncodingByte},
	}
	for _, tc := range tests {
		_, err := NormalizeResults(text, []RecognizerResult{tc})
		require.Error(t, err)
	}
}

func TestNormalizeResults_RuneCombiningBoundaryRejected(t *testing.T) {
	text := "Cafe\u0301"
	_, err := NormalizeResults(text, []RecognizerResult{{
		EntityType:     "PERSON",
		Start:          4, // points to combining mark rune boundary
		End:            5,
		Score:          0.7,
		OffsetEncoding: OffsetEncodingRune,
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "combining sequence")
}

func TestNormalizeResults_SubstringMismatchRejected(t *testing.T) {
	text := "hello@example.com"
	_, err := NormalizeResults(text, []RecognizerResult{{
		EntityType:        "EMAIL_ADDRESS",
		Start:             0,
		End:               5,
		Score:             0.8,
		OffsetEncoding:    OffsetEncodingByte,
		ExpectedSubstring: "hello@example.com",
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected substring")
}

func TestNormalizeResults_OptionalAndFallbackFields(t *testing.T) {
	text := "XYZ-001"
	conf := 0.99
	runeStart := 2
	runeEnd := 7

	canonical, err := NormalizeResults(text, []RecognizerResult{{
		EntityType:           "CUSTOM ENTITY",
		Start:                0,
		End:                  len(text),
		Score:                0.4,
		ExpectedConfidence:   &conf,
		ExpectedSensitivity:  42, // out of range should default to 1
		OffsetEncoding:       OffsetEncodingByte,
		OptionalRuneStart:    &runeStart,
		OptionalRuneEnd:      &runeEnd,
		ExpectedSubstring:    text,
		OptionalSourceString: "fixture-presidio",
	}})
	require.NoError(t, err)
	require.Len(t, canonical, 1)
	got := canonical[0]

	assert.Equal(t, "custom_entity", got.Type, "unknown entity types should fallback to lower snake")
	assert.Equal(t, conf, got.Confidence, "expected confidence should override score")
	assert.Equal(t, 1, got.Sensitivity, "invalid expected sensitivity should fallback to default")
	if assert.NotNil(t, got.RuneStart) {
		assert.Equal(t, runeStart, *got.RuneStart)
	}
	if assert.NotNil(t, got.RuneEnd) {
		assert.Equal(t, runeEnd, *got.RuneEnd)
	}
	assert.Equal(t, "fixture-presidio", got.Source)
}

func TestNormalizeResults_MetadataAttributesAreProjected(t *testing.T) {
	text := "abc@example.com"
	canonical, err := NormalizeResults(text, []RecognizerResult{{
		EntityType:        "EMAIL_ADDRESS",
		Start:             0,
		End:               len(text),
		Score:             0.91,
		OffsetEncoding:    OffsetEncodingByte,
		ExpectedSubstring: text,
		Explanation:       "high confidence",
		RecognitionMetadata: map[string]interface{}{
			"pattern_name": "email_basic",
			"flags":        []string{"x", "y"},
		},
		AnalysisExplanation: map[string]interface{}{
			"provider": "test",
		},
		DetectorMetadata: map[string]interface{}{
			"name": "presidio-fixture",
		},
		ProviderMetadata: map[string]interface{}{
			"region": "EU",
		},
	}})
	require.NoError(t, err)
	require.Len(t, canonical, 1)

	attrs := canonical[0].Attributes
	require.NotNil(t, attrs)
	assert.Equal(t, "high confidence", attrs["explanation"])
	assert.Equal(t, "email_basic", attrs["recognition_metadata.pattern_name"])
	assert.Equal(t, `["x","y"]`, attrs["recognition_metadata.flags"])
	assert.Equal(t, "test", attrs["analysis_explanation.provider"])
	assert.Equal(t, "presidio-fixture", attrs["detector_metadata.name"])
	assert.Equal(t, "EU", attrs["provider_metadata.region"])
}

func TestNormalizeResults_UnsupportedOffsetEncodingRejected(t *testing.T) {
	text := "abc@example.com"
	_, err := NormalizeResults(text, []RecognizerResult{{
		EntityType:     "EMAIL_ADDRESS",
		Start:          0,
		End:            len(text),
		Score:          0.8,
		OffsetEncoding: "utf16",
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offset_encoding must be")
}
