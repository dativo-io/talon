package classifier

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/classifier")

// PIIEntity represents a detected PII instance.
type PIIEntity struct {
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	Position    int     `json:"position"`
	Confidence  float64 `json:"confidence"`
	Sensitivity int     `json:"sensitivity"` // 1-3 from recognizer; 0 means unset (treated as 1 for tiering)
}

// Classification holds the result of PII scanning.
type Classification struct {
	HasPII   bool        `json:"has_pii"`
	Entities []PIIEntity `json:"entities"`
	Tier     int         `json:"tier"` // 0-2
	Redacted string      `json:"redacted,omitempty"`
}

// Scanner detects PII in text using configurable regex patterns.
type Scanner struct {
	patterns []PIIPattern
}

// ScannerOption configures a Scanner via the functional options pattern.
type ScannerOption func(*scannerConfig)

type scannerConfig struct {
	patternFile       string
	enabledEntities   []string
	disabledEntities  []string
	customRecognizers []RecognizerConfig
}

// WithPatternFile loads additional recognizers from a global patterns.yaml file.
// If the file does not exist, it is silently skipped.
func WithPatternFile(path string) ScannerOption {
	return func(c *scannerConfig) { c.patternFile = path }
}

// WithEnabledEntities sets a whitelist of entity types. When non-empty, only
// recognizers with a matching supported_entity will be active.
func WithEnabledEntities(entities []string) ScannerOption {
	return func(c *scannerConfig) { c.enabledEntities = entities }
}

// WithDisabledEntities sets a blacklist of entity types to exclude.
func WithDisabledEntities(entities []string) ScannerOption {
	return func(c *scannerConfig) { c.disabledEntities = entities }
}

// WithCustomRecognizers adds per-agent custom recognizer definitions.
func WithCustomRecognizers(recognizers []RecognizerConfig) ScannerOption {
	return func(c *scannerConfig) { c.customRecognizers = recognizers }
}

// NewScanner creates a PII scanner. Without options it uses the embedded EU
// defaults. Options layer global overrides and per-agent customization on top.
func NewScanner(opts ...ScannerOption) (*Scanner, error) {
	var cfg scannerConfig
	for _, o := range opts {
		o(&cfg)
	}

	// Layer 1: embedded defaults
	defaults, err := DefaultRecognizers()
	if err != nil {
		return nil, fmt.Errorf("loading default recognizers: %w", err)
	}

	// Layer 2: global pattern file (optional)
	var globalRecs []*RecognizerConfig
	if cfg.patternFile != "" {
		rf, err := LoadRecognizerFile(cfg.patternFile)
		if err != nil {
			return nil, fmt.Errorf("loading global pattern file: %w", err)
		}
		if rf != nil {
			globalRecs = toPtrSlice(rf.Recognizers)
		}
	}

	// Layer 3: per-agent custom recognizers
	var agentRecs []*RecognizerConfig
	if len(cfg.customRecognizers) > 0 {
		agentRecs = toPtrSlice(cfg.customRecognizers)
	}

	// Merge all layers
	merged := MergeRecognizers(toPtrSlice(defaults), globalRecs, agentRecs)

	// Apply entity filters
	merged = FilterByEntities(merged, cfg.enabledEntities, cfg.disabledEntities)

	// Compile to runtime patterns
	compiled, err := CompilePIIPatterns(merged)
	if err != nil {
		return nil, fmt.Errorf("compiling patterns: %w", err)
	}

	return &Scanner{patterns: compiled}, nil
}

// MustNewScanner is like NewScanner but panics on error. Useful for zero-config
// startup where the embedded defaults are expected to always compile.
func MustNewScanner(opts ...ScannerOption) *Scanner {
	s, err := NewScanner(opts...)
	if err != nil {
		panic(fmt.Sprintf("classifier.NewScanner: %v", err))
	}
	return s
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
				Type:        pattern.Type,
				Value:       text[match[0]:match[1]],
				Position:    match[0],
				Confidence:  0.95,
				Sensitivity: pattern.Sensitivity,
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

	var merged []match
	for _, m := range matches {
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
		} else {
			merged = append(merged, m)
		}
	}

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
// Uses each entity's Sensitivity from the recognizer (1-3); 0 is treated as 1.
// Any entity with sensitivity >= 2 yields tier 2 so model_routing selects
// restrictive providers for passport, SSN, IBAN, and custom high-sensitivity recognizers.
func (s *Scanner) determineTier(entities []PIIEntity) int {
	if len(entities) == 0 {
		return 0
	}

	for _, entity := range entities {
		eff := entity.Sensitivity
		if eff == 0 {
			eff = 1
		}
		if eff >= 2 {
			return 2
		}
	}

	return 1
}
