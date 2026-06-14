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
