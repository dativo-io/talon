package classifier

import (
	"testing"

	"github.com/dativo-io/talon/internal/classifier/presidio"
	"github.com/stretchr/testify/require"
)

func TestPresidioRuneOffsetsConvertToCanonicalBytes(t *testing.T) {
	text := "Hi 👋🏽 Müller"
	canonical, err := presidio.NormalizeResults(text, []presidio.RecognizerResult{{
		EntityType:     "PERSON",
		Start:          6, // rune index where "Müller" starts
		End:            12,
		Score:          0.9,
		OffsetEncoding: presidio.OffsetEncodingRune,
	}})
	require.NoError(t, err)
	require.Len(t, canonical, 1)
	require.Equal(t, "Müller", text[canonical[0].Start:canonical[0].End])
}

func TestPresidioOffsetInvalidCases(t *testing.T) {
	text := "Cafe\u0301"
	tests := []presidio.RecognizerResult{
		{EntityType: "EMAIL_ADDRESS", Start: -1, End: 1, Score: 0.7, OffsetEncoding: presidio.OffsetEncodingByte},
		{EntityType: "EMAIL_ADDRESS", Start: 0, End: len(text) + 1, Score: 0.7, OffsetEncoding: presidio.OffsetEncodingByte},
		{EntityType: "EMAIL_ADDRESS", Start: 2, End: 1, Score: 0.7, OffsetEncoding: presidio.OffsetEncodingByte},
		{EntityType: "PERSON", Start: 4, End: 5, Score: 0.7, OffsetEncoding: presidio.OffsetEncodingRune}, // combining sequence split
	}
	for _, tc := range tests {
		_, err := presidio.NormalizeResults(text, []presidio.RecognizerResult{tc})
		require.Error(t, err)
	}
}
