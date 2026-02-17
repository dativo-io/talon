package classifier

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// RecognizerFile is the top-level YAML structure for a recognizer config file.
// Mirrors Presidio's recognizer registry YAML format.
type RecognizerFile struct {
	Recognizers []RecognizerConfig `yaml:"recognizers"`
}

// RecognizerConfig mirrors Presidio's YAML recognizer schema with Talon extensions.
type RecognizerConfig struct {
	Name               string           `yaml:"name" json:"name"`
	SupportedEntity    string           `yaml:"supported_entity" json:"supported_entity"`
	Enabled            *bool            `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Patterns           []PatternConfig  `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	SupportedLanguages []LanguageContext `yaml:"supported_languages,omitempty" json:"supported_languages,omitempty"`
	DenyList           []string         `yaml:"deny_list,omitempty" json:"deny_list,omitempty"`
	DenyListScore      float64          `yaml:"deny_list_score,omitempty" json:"deny_list_score,omitempty"`
	// Talon extensions (safe to include — Presidio ignores unknown fields)
	Sensitivity int      `yaml:"sensitivity,omitempty" json:"sensitivity,omitempty"`
	Countries   []string `yaml:"countries,omitempty" json:"countries,omitempty"`
	// Injection-specific extension (used by attachment scanner only)
	Severity int `yaml:"severity,omitempty" json:"severity,omitempty"`
}

// PatternConfig is a single regex pattern within a recognizer.
type PatternConfig struct {
	Name  string  `yaml:"name" json:"name"`
	Regex string  `yaml:"regex" json:"regex"`
	Score float64 `yaml:"score" json:"score"`
}

// LanguageContext holds context words for a specific language.
type LanguageContext struct {
	Language string   `yaml:"language" json:"language"`
	Context  []string `yaml:"context,omitempty" json:"context,omitempty"`
}

// isEnabled returns true if the recognizer is enabled (defaults to true when nil).
func (r *RecognizerConfig) isEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// ParseRecognizerFile parses recognizer YAML bytes into a RecognizerFile.
func ParseRecognizerFile(data []byte) (*RecognizerFile, error) {
	var rf RecognizerFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parsing recognizer YAML: %w", err)
	}
	return &rf, nil
}

// LoadRecognizerFile reads and parses a recognizer YAML file from disk.
// Returns nil (not an error) if the file does not exist, so callers can
// treat a missing global config as a no-op.
func LoadRecognizerFile(path string) (*RecognizerFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading recognizer file %s: %w", path, err)
	}
	return ParseRecognizerFile(data)
}

// MergeRecognizers performs a 3-layer merge: defaults, then global overrides,
// then per-agent overrides. Later layers override earlier ones by matching on
// the recognizer Name field. New recognizers are appended.
func MergeRecognizers(layers ...[]*RecognizerConfig) []RecognizerConfig {
	index := make(map[string]int)
	var merged []RecognizerConfig

	for _, layer := range layers {
		for _, rc := range layer {
			if rc == nil {
				continue
			}
			if idx, exists := index[rc.Name]; exists {
				merged[idx] = *rc
			} else {
				index[rc.Name] = len(merged)
				merged = append(merged, *rc)
			}
		}
	}

	return merged
}

// toPtrSlice converts []RecognizerConfig to []*RecognizerConfig for MergeRecognizers.
func toPtrSlice(configs []RecognizerConfig) []*RecognizerConfig {
	ptrs := make([]*RecognizerConfig, len(configs))
	for i := range configs {
		ptrs[i] = &configs[i]
	}
	return ptrs
}

// CompilePIIPatterns converts a list of recognizer configs into the compiled
// []PIIPattern slice used by the Scanner at runtime. Disabled recognizers are
// skipped. Each regex pattern in a recognizer produces one PIIPattern entry,
// with the entity type normalized to the lower_snake_case used internally.
func CompilePIIPatterns(recognizers []RecognizerConfig) ([]PIIPattern, error) {
	var patterns []PIIPattern

	for _, rec := range recognizers {
		if !rec.isEnabled() {
			continue
		}
		for _, p := range rec.Patterns {
			compiled, err := regexp.Compile(p.Regex)
			if err != nil {
				return nil, fmt.Errorf("compiling pattern %q in recognizer %q: %w", p.Name, rec.Name, err)
			}
			patterns = append(patterns, PIIPattern{
				Name:        rec.Name,
				Type:        entityToType(rec.SupportedEntity),
				Pattern:     compiled,
				Countries:   rec.Countries,
				Sensitivity: rec.Sensitivity,
			})
		}
	}

	return patterns, nil
}

// FilterByEntities applies enabled/disabled entity filters to a recognizer list.
// If enabledEntities is non-empty, only recognizers with matching supported_entity
// are kept (whitelist). Then any recognizer in disabledEntities is removed (blacklist).
func FilterByEntities(recognizers []RecognizerConfig, enabledEntities, disabledEntities []string) []RecognizerConfig {
	result := recognizers

	if len(enabledEntities) > 0 {
		allowed := make(map[string]bool, len(enabledEntities))
		for _, e := range enabledEntities {
			allowed[e] = true
		}
		var filtered []RecognizerConfig
		for _, r := range result {
			if allowed[r.SupportedEntity] {
				filtered = append(filtered, r)
			}
		}
		result = filtered
	}

	if len(disabledEntities) > 0 {
		blocked := make(map[string]bool, len(disabledEntities))
		for _, e := range disabledEntities {
			blocked[e] = true
		}
		var filtered []RecognizerConfig
		for _, r := range result {
			if !blocked[r.SupportedEntity] {
				filtered = append(filtered, r)
			}
		}
		result = filtered
	}

	return result
}

// entityToType converts Presidio entity names (SCREAMING_SNAKE) to the
// lower_snake_case type strings used internally (e.g. "EMAIL_ADDRESS" -> "email").
var entityTypeMap = map[string]string{
	"EMAIL_ADDRESS": "email",
	"PHONE_NUMBER":  "phone",
	"IBAN_CODE":     "iban",
	"CREDIT_CARD":   "credit_card",
	"EU_VAT_ID":     "vat_id",
	"DE_SSN":        "ssn",
	"UK_NINO":       "ssn",
	"FR_SSN":        "ssn",
	"IP_ADDRESS":    "ip_address",
	"PASSPORT":      "passport",
}

// entityToType maps a Presidio entity name to the internal type string.
// Unknown entities are lowercased with underscores replacing spaces.
func entityToType(entity string) string {
	if t, ok := entityTypeMap[entity]; ok {
		return t
	}
	return toLowerSnake(entity)
}

// toLowerSnake converts SCREAMING_SNAKE_CASE to lower_snake_case.
func toLowerSnake(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result = append(result, c+'a'-'A')
		} else {
			result = append(result, c)
		}
	}
	return string(result)
}
