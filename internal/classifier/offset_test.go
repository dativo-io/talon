package classifier

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/dativo-io/talon/internal/classifier/presidio"
	"github.com/stretchr/testify/assert"
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

func TestPresidioOffsetUnicodeMatrixRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		substring string
		encoding  string
	}{
		{
			name:      "ascii byte offsets",
			text:      "Invoice ID AB123456",
			substring: "AB123456",
			encoding:  presidio.OffsetEncodingByte,
		},
		{
			name:      "umlaut rune offsets",
			text:      "Contact Müller today",
			substring: "Müller",
			encoding:  presidio.OffsetEncodingRune,
		},
		{
			name:      "combining marks rune offsets",
			text:      "Cafe\u0301 on the corner",
			substring: "Cafe\u0301",
			encoding:  presidio.OffsetEncodingRune,
		},
		{
			name:      "emoji multi-byte rune offsets",
			text:      "Wave 👋🏽 now",
			substring: "👋🏽",
			encoding:  presidio.OffsetEncodingRune,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			startByte := strings.Index(tc.text, tc.substring)
			require.GreaterOrEqual(t, startByte, 0)
			endByte := startByte + len(tc.substring)

			start := startByte
			end := endByte
			if tc.encoding == presidio.OffsetEncodingRune {
				start = utf8.RuneCountInString(tc.text[:startByte])
				end = utf8.RuneCountInString(tc.text[:endByte])
			}

			canonical, err := presidio.NormalizeResults(tc.text, []presidio.RecognizerResult{{
				EntityType:        "PERSON",
				Start:             start,
				End:               end,
				Score:             0.9,
				OffsetEncoding:    tc.encoding,
				ExpectedSubstring: tc.substring,
			}})
			require.NoError(t, err)
			require.Len(t, canonical, 1)
			assert.Equal(t, tc.substring, canonical[0].Raw)
			assert.Equal(t, tc.substring, tc.text[canonical[0].Start:canonical[0].End])
		})
	}

	t.Run("json escaped utf8 string round trip", func(t *testing.T) {
		var escaped string
		err := json.Unmarshal([]byte(`"M\u00fcller \ud83d\udc4b"`), &escaped)
		require.NoError(t, err)

		text := "Actor: " + escaped
		substring := escaped
		startByte := strings.Index(text, substring)
		require.GreaterOrEqual(t, startByte, 0)
		endByte := startByte + len(substring)

		startRune := utf8.RuneCountInString(text[:startByte])
		endRune := utf8.RuneCountInString(text[:endByte])
		canonical, err := presidio.NormalizeResults(text, []presidio.RecognizerResult{{
			EntityType:        "PERSON",
			Start:             startRune,
			End:               endRune,
			Score:             0.8,
			OffsetEncoding:    presidio.OffsetEncodingRune,
			ExpectedSubstring: substring,
		}})
		require.NoError(t, err)
		require.Len(t, canonical, 1)
		assert.Equal(t, substring, text[canonical[0].Start:canonical[0].End])
	})
}
