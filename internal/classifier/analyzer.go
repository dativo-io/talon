package classifier

import (
	"context"
	"sort"
)

// DetectorTalonRegex identifies the built-in regex/recognizer scanner as the
// analysis engine in evidence records (data_flow.detector).
const DetectorTalonRegex = "talon-regex"

// Analyzer is the engine-neutral text-analysis interface. The built-in
// *Scanner satisfies it; third-party engines (e.g. a Microsoft Presidio HTTP
// adapter mapping RecognizerResult{entity_type, start, end, score} to
// PIIEntity) can plug in by implementing it. Everything downstream —
// tiering, flow digests, evidence — consumes only *Classification.
//
// Offset convention: PIIEntity.Position is a byte offset into the analyzed
// text (Go regexp FindAllStringIndex semantics). Adapters for engines that
// report character/rune offsets (Presidio does) must convert.
type Analyzer interface {
	// Analyze scans text and returns a classification. Implementations
	// must respect ctx cancellation and never retain the input text.
	Analyze(ctx context.Context, text string) (*Classification, error)
	// Detector returns the engine identifier recorded in evidence.
	Detector() string
}

var _ Analyzer = (*Scanner)(nil)

// Analyze implements Analyzer for the built-in regex scanner.
func (s *Scanner) Analyze(ctx context.Context, text string) (*Classification, error) {
	return s.Scan(ctx, text), nil
}

// Detector implements Analyzer for the built-in regex scanner.
func (s *Scanner) Detector() string { return DetectorTalonRegex }

// MergeEntitySpans resolves overlapping or duplicate entity spans into
// non-overlapping entities, the same resolution Redact applies before
// placeholder replacement (and the post-processing Presidio applies in its
// analyzer). Overlapping spans are merged into one entity: the
// higher-sensitivity type wins, the span is extended to cover both, and the
// value is re-sliced from text. Use before counting entities or computing
// value digests so overlapping recognizers do not inflate results.
//
//nolint:gocyclo // overlap merge rules are kept together for deterministic behavior
func MergeEntitySpans(text string, entities []PIIEntity) []PIIEntity {
	if len(entities) == 0 {
		return nil
	}

	type span struct {
		start       int
		end         int
		ptype       string
		fieldPath   string
		sensitivity int
		confidence  float64
	}

	spans := make([]span, len(entities))
	for i, e := range entities {
		spans[i] = span{
			start:       e.Position,
			end:         e.Position + len(e.Value),
			ptype:       e.Type,
			fieldPath:   e.FieldPath,
			sensitivity: e.Sensitivity,
			confidence:  e.Confidence,
		}
	}

	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		lenI := spans[i].end - spans[i].start
		lenJ := spans[j].end - spans[j].start
		if lenI != lenJ {
			return lenI > lenJ
		}
		return spans[i].sensitivity > spans[j].sensitivity
	})

	var merged []span
	for _, m := range spans {
		if len(merged) == 0 {
			merged = append(merged, m)
			continue
		}
		last := &merged[len(merged)-1]
		if m.start < last.end {
			if m.sensitivity > last.sensitivity {
				last.ptype = m.ptype
				last.sensitivity = m.sensitivity
			}
			if m.end > last.end {
				last.end = m.end
			}
			if m.confidence > last.confidence {
				last.confidence = m.confidence
			}
			if last.fieldPath == "" && m.fieldPath != "" {
				last.fieldPath = m.fieldPath
			}
		} else {
			merged = append(merged, m)
		}
	}

	out := make([]PIIEntity, 0, len(merged))
	for _, m := range merged {
		value := ""
		if m.start >= 0 && m.end <= len(text) && m.start <= m.end {
			value = text[m.start:m.end]
		}
		out = append(out, PIIEntity{
			Type:        m.ptype,
			Value:       value,
			Position:    m.start,
			FieldPath:   m.fieldPath,
			Confidence:  m.confidence,
			Sensitivity: m.sensitivity,
		})
	}
	return out
}
