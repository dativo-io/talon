package classifier

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/classifier")

const (
	// DefaultMinScore is the Presidio-compatible minimum confidence threshold.
	// Matches below this score are discarded unless boosted by context words.
	DefaultMinScore = 0.5

	// ContextSimilarityFactor is the score boost applied when context words are
	// found near a match. Matches Presidio's default context_similarity_factor.
	ContextSimilarityFactor = 0.35

	// ContextWindowChars is the number of characters to search before and after
	// a match when looking for context words.
	ContextWindowChars = 100
)

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
	minScore float64
}

// ScannerOption configures a Scanner via the functional options pattern.
type ScannerOption func(*scannerConfig)

type scannerConfig struct {
	patternFile       string
	enabledEntities   []string
	disabledEntities  []string
	customRecognizers []RecognizerConfig
	minScore          float64
}

// WithMinScore overrides the default minimum confidence threshold for matches.
func WithMinScore(score float64) ScannerOption {
	return func(c *scannerConfig) { c.minScore = score }
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

	minScore := DefaultMinScore
	if cfg.minScore > 0 {
		minScore = cfg.minScore
	}

	return &Scanner{patterns: compiled, minScore: minScore}, nil
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
// Each match goes through hard validation gates (IBAN checksum/length, Luhn)
// and then Presidio-style score-based context filtering before being accepted.
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
			value := text[match[0]:match[1]]

			// Hard validation gate: IBAN checksum + country length
			if pattern.ValidateIBAN {
				clean := strings.ReplaceAll(value, " ", "")
				if !validateIBANLength(clean) || !validateIBANChecksum(clean) {
					continue
				}
			}

			// Hard validation gate: Luhn checksum for credit cards
			if pattern.ValidateLuhn {
				digits := stripNonDigits(value)
				if !luhnValid(digits) {
					continue
				}
			}

			// Presidio-style confidence: base score + context word boost
			confidence := enhanceScoreWithContext(text, match[0], pattern.Score, pattern.ContextWords)
			if confidence < s.minScore {
				continue
			}

			entity := PIIEntity{
				Type:        pattern.Type,
				Value:       value,
				Position:    match[0],
				Confidence:  confidence,
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
// Uses Scan() for validated detection, then position-based replacement
// to handle overlapping patterns correctly.
func (s *Scanner) Redact(ctx context.Context, text string) string {
	ctx, span := tracer.Start(ctx, "classifier.redact")
	defer span.End()

	classification := s.Scan(ctx, text)
	if !classification.HasPII {
		return text
	}

	type match struct {
		start       int
		end         int
		ptype       string
		sensitivity int
	}

	matches := make([]match, len(classification.Entities))
	for i, e := range classification.Entities {
		matches[i] = match{
			start:       e.Position,
			end:         e.Position + len(e.Value),
			ptype:       e.Type,
			sensitivity: e.Sensitivity,
		}
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

// luhnValid checks whether a digit string passes the Luhn algorithm (ISO/IEC 7812).
func luhnValid(number string) bool {
	n := len(number)
	if n < 2 {
		return false
	}
	sum := 0
	alt := false
	for i := n - 1; i >= 0; i-- {
		d := int(number[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// validateIBANChecksum verifies the MOD-97 check digits per ISO 13616.
// The IBAN is rearranged (country+check moved to end) and converted to digits
// (A=10, B=11, ..., Z=35) then checked: remainder must equal 1.
func validateIBANChecksum(iban string) bool {
	if len(iban) < 5 {
		return false
	}
	// Rearrange: move first 4 chars to end
	rearranged := iban[4:] + iban[:4]
	// Convert letters to digits (A=10, ..., Z=35) and compute mod 97
	var numStr strings.Builder
	for _, ch := range rearranged {
		switch {
		case ch >= '0' && ch <= '9':
			numStr.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			numStr.WriteString(fmt.Sprintf("%d", ch-'A'+10))
		default:
			return false
		}
	}
	n := new(big.Int)
	if _, ok := n.SetString(numStr.String(), 10); !ok {
		return false
	}
	mod := new(big.Int)
	mod.Mod(n, big.NewInt(97))
	return mod.Int64() == 1
}

// validateIBANLength checks that the IBAN has the correct length for its country code.
func validateIBANLength(iban string) bool {
	if len(iban) < 2 {
		return false
	}
	cc := iban[:2]
	expected, ok := IBANLengths[cc]
	if !ok {
		return false
	}
	return len(iban) == expected
}

// enhanceScoreWithContext boosts a match's base score if context words are found
// within +/- ContextWindowChars characters of the match position. This mirrors
// Presidio's LemmaContextAwareEnhancer with a fixed context_similarity_factor.
func enhanceScoreWithContext(text string, position int, baseScore float64, contextWords []string) float64 {
	if len(contextWords) == 0 {
		return baseScore
	}
	start := position - ContextWindowChars
	if start < 0 {
		start = 0
	}
	end := position + ContextWindowChars
	if end > len(text) {
		end = len(text)
	}
	window := strings.ToLower(text[start:end])

	for _, cw := range contextWords {
		if strings.Contains(window, strings.ToLower(cw)) {
			return baseScore + ContextSimilarityFactor
		}
	}
	return baseScore
}

// stripNonDigits removes all non-digit characters from s.
func stripNonDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			b.WriteRune(ch)
		}
	}
	return b.String()
}
