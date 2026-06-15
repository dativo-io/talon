package presidio

import (
	"testing"
	"unicode/utf8"
)

func FuzzNormalizeResultsOffsets(f *testing.F) {
	f.Add("Hi 👋🏽 Muller", 0, 2)
	f.Add("Cafe\u0301", 0, 4)
	f.Add("jan.kowalski@gmail.com", 0, 3)

	f.Fuzz(func(t *testing.T, text string, a int, b int) {
		if text == "" {
			text = "x"
		}

		start, end := a, b
		if start > end {
			start, end = end, start
		}
		if start < 0 {
			start = 0
		}
		if end < 0 {
			end = 0
		}
		if start > len(text) {
			start = len(text)
		}
		if end > len(text) {
			end = len(text)
		}

		_, _ = NormalizeResults(text, []RecognizerResult{{
			EntityType:     "EMAIL_ADDRESS",
			Start:          start,
			End:            end,
			Score:          0.9,
			OffsetEncoding: OffsetEncodingByte,
		}})

		runes := utf8.RuneCountInString(text)
		rs, re := 0, runes
		if runes > 0 {
			rs = ((a % runes) + runes) % runes
			re = ((b % (runes + 1)) + (runes + 1)) % (runes + 1)
			if rs > re {
				rs, re = re, rs
			}
		}
		_, _ = NormalizeResults(text, []RecognizerResult{{
			EntityType:     "PERSON",
			Start:          rs,
			End:            re,
			Score:          0.8,
			OffsetEncoding: OffsetEncodingRune,
		}})
	})
}
