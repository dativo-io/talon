package attachment

import (
	"context"

	"go.opentelemetry.io/otel/attribute"

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

// NewScanner creates an injection scanner with default patterns.
func NewScanner() *Scanner {
	return &Scanner{
		patterns: InjectionPatterns,
	}
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
			// Extract context (50 chars before and after)
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
