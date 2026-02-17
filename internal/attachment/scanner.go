package attachment

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"

	"github.com/dativo-io/talon/internal/classifier"
	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/attachment")

// InjectionAttempt represents a detected injection pattern in content.
type InjectionAttempt struct {
	Pattern  string `json:"pattern"`
	Position int    `json:"position"`
	Severity int    `json:"severity"`
	Context  string `json:"context"` // Surrounding text snippet
}

// ScanResult contains the results of injection pattern scanning.
type ScanResult struct {
	InjectionsFound []InjectionAttempt `json:"injections_found"`
	MaxSeverity     int                `json:"max_severity"`
	Safe            bool               `json:"safe"`
}

// Scanner detects prompt injection attempts in text content.
type Scanner struct {
	patterns []InjectionPattern
}

// ScannerOption configures an injection Scanner.
type ScannerOption func(*scannerConfig)

type scannerConfig struct {
	patternFile       string
	customRecognizers []classifier.RecognizerConfig
}

// WithInjectionPatternFile loads additional injection recognizers from a YAML file.
func WithInjectionPatternFile(path string) ScannerOption {
	return func(c *scannerConfig) { c.patternFile = path }
}

// WithInjectionRecognizers adds custom injection recognizer definitions.
func WithInjectionRecognizers(recognizers []classifier.RecognizerConfig) ScannerOption {
	return func(c *scannerConfig) { c.customRecognizers = recognizers }
}

// NewScanner creates an injection scanner. Without options it uses the embedded
// defaults. Options layer global overrides and custom patterns on top.
func NewScanner(opts ...ScannerOption) (*Scanner, error) {
	var cfg scannerConfig
	for _, o := range opts {
		o(&cfg)
	}

	// Layer 1: embedded defaults
	defaults, err := DefaultInjectionRecognizers()
	if err != nil {
		return nil, fmt.Errorf("loading default injection recognizers: %w", err)
	}

	// Layer 2: global pattern file (optional)
	var globalRecs []*classifier.RecognizerConfig
	if cfg.patternFile != "" {
		rf, err := classifier.LoadRecognizerFile(cfg.patternFile)
		if err != nil {
			return nil, fmt.Errorf("loading injection pattern file: %w", err)
		}
		if rf != nil {
			globalRecs = make([]*classifier.RecognizerConfig, len(rf.Recognizers))
			for i := range rf.Recognizers {
				globalRecs[i] = &rf.Recognizers[i]
			}
		}
	}

	// Layer 3: per-agent custom recognizers
	var agentRecs []*classifier.RecognizerConfig
	for i := range cfg.customRecognizers {
		agentRecs = append(agentRecs, &cfg.customRecognizers[i])
	}

	// Merge all layers
	defaultPtrs := make([]*classifier.RecognizerConfig, len(defaults))
	for i := range defaults {
		defaultPtrs[i] = &defaults[i]
	}
	merged := classifier.MergeRecognizers(defaultPtrs, globalRecs, agentRecs)

	// Compile to runtime patterns
	compiled, err := CompileInjectionPatterns(merged)
	if err != nil {
		return nil, fmt.Errorf("compiling injection patterns: %w", err)
	}

	return &Scanner{patterns: compiled}, nil
}

// MustNewScanner is like NewScanner but panics on error.
func MustNewScanner(opts ...ScannerOption) *Scanner {
	s, err := NewScanner(opts...)
	if err != nil {
		panic(fmt.Sprintf("attachment.NewScanner: %v", err))
	}
	return s
}

// Scan analyzes text for prompt injection patterns.
func (s *Scanner) Scan(ctx context.Context, text string) *ScanResult {
	_, span := tracer.Start(ctx, "attachment.scan")
	defer span.End()

	result := &ScanResult{
		InjectionsFound: []InjectionAttempt{},
		MaxSeverity:     0,
		Safe:            true,
	}

	for _, pattern := range s.patterns {
		matches := pattern.Pattern.FindAllStringIndex(text, -1)
		for _, match := range matches {
			ctxStart := max(0, match[0]-50)
			ctxEnd := min(len(text), match[1]+50)
			snippet := text[ctxStart:ctxEnd]

			attempt := InjectionAttempt{
				Pattern:  pattern.Name,
				Position: match[0],
				Severity: pattern.Severity,
				Context:  snippet,
			}
			result.InjectionsFound = append(result.InjectionsFound, attempt)

			if pattern.Severity > result.MaxSeverity {
				result.MaxSeverity = pattern.Severity
			}

			result.Safe = false
		}
	}

	span.SetAttributes(
		attribute.Int("injection.count", len(result.InjectionsFound)),
		attribute.Int("injection.max_severity", result.MaxSeverity),
		attribute.Bool("injection.safe", result.Safe),
	)

	return result
}
