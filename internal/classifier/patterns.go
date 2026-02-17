package classifier

import (
	"fmt"
	"regexp"

	"github.com/dativo-io/talon/patterns"
)

// PIIPattern represents a compiled, ready-to-use PII detection pattern.
type PIIPattern struct {
	Name        string
	Type        string
	Pattern     *regexp.Regexp
	Countries   []string
	Sensitivity int // 1-3, higher = more sensitive
}

// DefaultRecognizers returns the built-in PII recognizers parsed from the
// embedded pii_eu.yaml file. This is the first layer in the merge chain.
func DefaultRecognizers() ([]RecognizerConfig, error) {
	rf, err := ParseRecognizerFile(patterns.PIIEUYAML())
	if err != nil {
		return nil, fmt.Errorf("parsing embedded PII patterns: %w", err)
	}
	return rf.Recognizers, nil
}

// EUPatterns is the compiled default pattern set, built at init time from
// the embedded YAML. Kept for backward compatibility with code that references
// this variable directly.
var EUPatterns []PIIPattern

func init() {
	recs, err := DefaultRecognizers()
	if err != nil {
		panic(fmt.Sprintf("loading embedded PII patterns: %v", err))
	}
	compiled, err := CompilePIIPatterns(recs)
	if err != nil {
		panic(fmt.Sprintf("compiling embedded PII patterns: %v", err))
	}
	EUPatterns = compiled
}
