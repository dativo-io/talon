package llm

import (
	"regexp"
	"strings"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/presidio"
)

// placeholderShaped matches redaction placeholders ([EMAIL], [CREDIT_CARD])
// and enrichment tags that a model might "re-detect" in already-redacted
// text. Reporting them would cause false residual-PII blocks on the
// verify-egress re-scan, so they are dropped before relocation.
var placeholderShaped = regexp.MustCompile(`^(\[[A-Z0-9_]+\]|<PII\b[^>]*/?>)$`)

// RelocateResult separates deterministic detections from dropped ones.
type RelocateResult struct {
	Results []presidio.RecognizerResult
	// Hallucinated counts reported values that do not appear verbatim in the
	// text. They are dropped: an unverifiable claim must not move offsets.
	Hallucinated int
	// PlaceholdersDropped counts reported values that were redaction
	// placeholders rather than PII.
	PlaceholdersDropped int
}

// Relocate turns model detections into byte-offset recognizer results by
// finding every occurrence of each verbatim value in the original text.
// Offsets are computed by Talon, never trusted from the model; the
// ExpectedSubstring carried on each result makes presidio.NormalizeResults
// re-verify them as a final gate.
func Relocate(text string, detections []Detection, confidence float64) RelocateResult {
	out := RelocateResult{}
	seen := map[[2]int]bool{} // dedupe identical spans across duplicate reports

	for _, d := range detections {
		value := strings.TrimSpace(d.Value)
		if value == "" || d.Type == "" {
			continue
		}
		if placeholderShaped.MatchString(value) {
			out.PlaceholdersDropped++
			continue
		}

		found := false
		for from := 0; ; {
			idx := strings.Index(text[from:], value)
			if idx < 0 {
				break
			}
			start := from + idx
			end := start + len(value)
			found = true
			from = start + 1 // advance by one byte to catch overlapping self-occurrences

			span := [2]int{start, end}
			if seen[span] {
				continue
			}
			seen[span] = true

			out.Results = append(out.Results, presidio.RecognizerResult{
				EntityType:          d.Type,
				Start:               start,
				End:                 end,
				Score:               confidence,
				OffsetEncoding:      presidio.OffsetEncodingByte,
				ExpectedSubstring:   value,
				ExpectedSensitivity: classifier.SensitivityForType(d.Type),
			})
		}
		if !found {
			out.Hallucinated++
		}
	}
	return out
}
