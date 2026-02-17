package attachment

import (
	"fmt"
	"regexp"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/patterns"
)

// InjectionPattern detects prompt injection attempts in attachment content.
type InjectionPattern struct {
	Name        string
	Description string
	Pattern     *regexp.Regexp
	Severity    int // 1-3
}

// DefaultInjectionRecognizers returns the built-in injection recognizers
// parsed from the embedded injection.yaml file.
func DefaultInjectionRecognizers() ([]classifier.RecognizerConfig, error) {
	rf, err := classifier.ParseRecognizerFile(patterns.InjectionYAML())
	if err != nil {
		return nil, fmt.Errorf("parsing embedded injection patterns: %w", err)
	}
	return rf.Recognizers, nil
}

// CompileInjectionPatterns converts recognizer configs into compiled
// InjectionPattern entries. Disabled recognizers are skipped.
func CompileInjectionPatterns(recognizers []classifier.RecognizerConfig) ([]InjectionPattern, error) {
	var result []InjectionPattern

	for i := range recognizers {
		rec := &recognizers[i]
		if rec.Enabled != nil && !*rec.Enabled {
			continue
		}
		for _, p := range rec.Patterns {
			compiled, err := regexp.Compile(p.Regex)
			if err != nil {
				return nil, fmt.Errorf("compiling injection pattern %q in %q: %w", p.Name, rec.Name, err)
			}
			result = append(result, InjectionPattern{
				Name:        rec.Name,
				Description: p.Name,
				Pattern:     compiled,
				Severity:    rec.Severity,
			})
		}
	}

	return result, nil
}

// InjectionPatterns is the compiled default injection pattern set, built at
// init time from the embedded YAML. Kept for backward compatibility.
var InjectionPatterns []InjectionPattern

func init() {
	recs, err := DefaultInjectionRecognizers()
	if err != nil {
		panic(fmt.Sprintf("loading embedded injection patterns: %v", err))
	}
	compiled, err := CompileInjectionPatterns(recs)
	if err != nil {
		panic(fmt.Sprintf("compiling embedded injection patterns: %v", err))
	}
	InjectionPatterns = compiled
}
