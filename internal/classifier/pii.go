package classifier

import (
	"context"
	"sort"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/classifier")

// PIIEntity represents a detected PII instance.
type PIIEntity struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Position   int     `json:"position"`
	Confidence float64 `json:"confidence"`
}

// Classification holds the result of PII scanning.
type Classification struct {
	HasPII   bool        `json:"has_pii"`
	Entities []PIIEntity `json:"entities"`
	Tier     int         `json:"tier"` // 0-2
	Redacted string      `json:"redacted,omitempty"`
}

// Scanner detects PII in text using EU regex patterns.
type Scanner struct {
	patterns []PIIPattern
}

// NewScanner creates a PII scanner with EU patterns.
func NewScanner() *Scanner {
	return &Scanner{
		patterns: EUPatterns,
	}
}

// Scan analyzes text for PII and returns a classification result.
func (s *Scanner) Scan(ctx context.Context, text string) *Classification {
	_, span := tracer.Start(ctx, "classifier.scan")
	defer span.End()

	result := &Classification{
		HasPII:   false,
		Entities: []PIIEntity{},
		Tier:     0,
	}

	for _, pattern := range s.patterns {
		matches := pattern.Pattern.FindAllStringIndex(text, -1)
		for _, match := range matches {
			entity := PIIEntity{
				Type:       pattern.Type,
				Value:      text[match[0]:match[1]],
				Position:   match[0],
				Confidence: 0.95, // Regex matches are high confidence
			}
			result.Entities = append(result.Entities, entity)
			result.HasPII = true
		}
	}

	result.Tier = s.determineTier(result.Entities)

	span.SetAttributes(
		attribute.Bool("pii.detected", result.HasPII),
		attribute.Int("pii.entity_count", len(result.Entities)),
		attribute.Int("pii.tier", result.Tier),
	)

	return result
}

// Redact replaces PII with type-based placeholders (e.g. "[EMAIL]").
// Uses position-based replacement to handle overlapping patterns correctly,
// keeping the highest-sensitivity match when patterns overlap.
func (s *Scanner) Redact(ctx context.Context, text string) string {
	_, span := tracer.Start(ctx, "classifier.redact")
	defer span.End()

	type match struct {
		start       int
		end         int
		ptype       string
		sensitivity int
	}

	// Collect all matches across all patterns
	var matches []match
	for _, pattern := range s.patterns {
		locs := pattern.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			matches = append(matches, match{
				start:       loc[0],
				end:         loc[1],
				ptype:       pattern.Type,
				sensitivity: pattern.Sensitivity,
			})
		}
	}

	if len(matches) == 0 {
		return text
	}

	// Sort by start position, then by length descending (prefer longer matches),
	// then by sensitivity descending (prefer more sensitive)
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].start != matches[j].start {
			return matches[i].start < matches[j].start
		}
		lenI := matches[i].end - matches[i].start
		lenJ := matches[j].end - matches[j].start
		if lenI != lenJ {
			return lenI > lenJ
		}
		return matches[i].sensitivity > matches[j].sensitivity
	})

	// Merge overlapping matches, keeping the one with highest sensitivity
	var merged []match
	for _, m := range matches {
		if len(merged) == 0 {
			merged = append(merged, m)
			continue
		}
		last := &merged[len(merged)-1]
		if m.start < last.end {
			// Overlapping: keep the one covering more area or higher sensitivity
			if m.sensitivity > last.sensitivity {
				last.ptype = m.ptype
				last.sensitivity = m.sensitivity
			}
			if m.end > last.end {
				last.end = m.end
			}
		} else {
			merged = append(merged, m)
		}
	}

	// Build result by replacing from end to start to preserve indices
	result := []byte(text)
	for i := len(merged) - 1; i >= 0; i-- {
		m := merged[i]
		placeholder := "[" + strings.ToUpper(m.ptype) + "]"
		result = append(result[:m.start], append([]byte(placeholder), result[m.end:]...)...)
	}

	return string(result)
}

// determineTier classifies data sensitivity based on detected entities.
// Tier 0 = no PII, Tier 1 = low-sensitivity PII, Tier 2 = high-sensitivity PII.
func (s *Scanner) determineTier(entities []PIIEntity) int {
	if len(entities) == 0 {
		return 0
	}

	// High-sensitivity types always result in Tier 2
	for _, entity := range entities {
		if entity.Type == "credit_card" || entity.Type == "ssn" || entity.Type == "iban" {
			return 2
		}
	}

	// 1-3 entities of lower sensitivity
	if len(entities) <= 3 {
		return 1
	}

	// Many entities
	return 2
}
