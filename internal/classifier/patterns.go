package classifier

import (
	"fmt"
	"regexp"

	"github.com/dativo-io/talon/patterns"
)

// PIIPattern represents a compiled, ready-to-use PII detection pattern.
type PIIPattern struct {
	Name         string
	Type         string
	Pattern      *regexp.Regexp
	Countries    []string
	Sensitivity  int      // 1-3, higher = more sensitive
	Score        float64  // base confidence from YAML (Presidio-compatible)
	ContextWords []string // merged from all supported_languages[].context
	ValidateLuhn bool     // Talon extension: ISO/IEC 7812 checksum gate
	ValidateIBAN bool     // Talon extension: ISO 13616 MOD-97 + country length gate
}

// IBANLengths maps EU+UK country codes to their exact IBAN character length (ISO 13616).
// Used by ValidateIBAN to reject strings that match the IBAN regex but have the wrong
// length for their country (e.g. VAT IDs like DE123456789 are 11 chars, not DE's 22).
var IBANLengths = map[string]int{
	"AT": 20, "BE": 16, "BG": 22, "CY": 28, "CZ": 24,
	"DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18,
	"FR": 27, "GB": 22, "GR": 27, "HR": 21, "HU": 28,
	"IE": 22, "IT": 27, "LT": 20, "LU": 20, "LV": 21,
	"MT": 31, "NL": 18, "PL": 28, "PT": 25, "RO": 24,
	"SE": 24, "SI": 19, "SK": 24,
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
