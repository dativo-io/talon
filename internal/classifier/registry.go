package classifier

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// RecognizerFile is the top-level YAML structure for a recognizer config file.
// Mirrors Presidio's recognizer registry YAML format.
type RecognizerFile struct {
	Recognizers []RecognizerConfig `yaml:"recognizers"`
}

// RecognizerConfig mirrors Presidio's YAML recognizer schema with Talon extensions.
type RecognizerConfig struct {
	Name               string            `yaml:"name" json:"name"`
	SupportedEntity    string            `yaml:"supported_entity" json:"supported_entity"`
	Enabled            *bool             `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Patterns           []PatternConfig   `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	SupportedLanguages []LanguageContext `yaml:"supported_languages,omitempty" json:"supported_languages,omitempty"`
	DenyList           []string          `yaml:"deny_list,omitempty" json:"deny_list,omitempty"`
	DenyListScore      float64           `yaml:"deny_list_score,omitempty" json:"deny_list_score,omitempty"`
	// Talon extensions (safe to include — Presidio ignores unknown fields)
	Sensitivity   int      `yaml:"sensitivity,omitempty" json:"sensitivity,omitempty"`
	Countries     []string `yaml:"countries,omitempty" json:"countries,omitempty"`
	ValidateLuhn  bool     `yaml:"validate_luhn,omitempty" json:"validate_luhn,omitempty"`
	ValidateIBAN  bool     `yaml:"validate_iban,omitempty" json:"validate_iban,omitempty"`
	ValidateBSN   bool     `yaml:"validate_bsn,omitempty" json:"validate_bsn,omitempty"`
	ValidatePESEL bool     `yaml:"validate_pesel,omitempty" json:"validate_pesel,omitempty"`
	ValidateDNI   bool     `yaml:"validate_dni,omitempty" json:"validate_dni,omitempty"`
	ValidateNIE   bool     `yaml:"validate_nie,omitempty" json:"validate_nie,omitempty"`
	ValidateNIF   bool     `yaml:"validate_nif,omitempty" json:"validate_nif,omitempty"`
	ValidateIPv4  bool     `yaml:"validate_ipv4,omitempty" json:"validate_ipv4,omitempty"`
	// Injection-specific extension (used by attachment scanner only)
	Severity int `yaml:"severity,omitempty" json:"severity,omitempty"`
}

// PatternConfig is a single regex pattern within a recognizer.
// Score is optional; when omitted (nil), DefaultMinScore is used at compile time
// so that custom patterns are not filtered out by the scanner's minScore threshold.
type PatternConfig struct {
	Name  string   `yaml:"name" json:"name"`
	Regex string   `yaml:"regex" json:"regex"`
	Score *float64 `yaml:"score,omitempty" json:"score,omitempty"`
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
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&rf); err != nil {
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

	for i := range recognizers {
		rec := &recognizers[i]
		if !rec.isEnabled() {
			continue
		}

		// Merge context words from all supported languages into a single slice.
		var contextWords []string
		for _, lang := range rec.SupportedLanguages {
			contextWords = append(contextWords, lang.Context...)
		}

		for _, p := range rec.Patterns {
			if p.Score != nil && (*p.Score < 0 || *p.Score > 1) {
				return nil, fmt.Errorf("pattern %q in recognizer %q has score outside [0,1]", p.Name, rec.Name)
			}
			compiled, err := regexp.Compile(p.Regex)
			if err != nil {
				return nil, fmt.Errorf("compiling pattern %q in recognizer %q: %w", p.Name, rec.Name, err)
			}
			baseScore := DefaultMinScore
			if p.Score != nil {
				baseScore = *p.Score
			}
			patterns = append(patterns, PIIPattern{
				Name:          rec.Name,
				EntityType:    rec.SupportedEntity,
				Type:          entityToType(rec.SupportedEntity),
				Pattern:       compiled,
				Countries:     rec.Countries,
				Sensitivity:   rec.Sensitivity,
				Score:         baseScore,
				ContextWords:  contextWords,
				ValidateLuhn:  rec.ValidateLuhn,
				ValidateIBAN:  rec.ValidateIBAN,
				ValidateBSN:   rec.ValidateBSN,
				ValidatePESEL: rec.ValidatePESEL,
				ValidateDNI:   rec.ValidateDNI,
				ValidateNIE:   rec.ValidateNIE,
				ValidateNIF:   rec.ValidateNIF,
				ValidateIPv4:  rec.ValidateIPv4,
			})
		}
	}

	return patterns, nil
}

// ValidateRecognizerLayer validates recognizers loaded from a specific layer.
// Duplicate recognizer names within the same layer fail. Cross-layer overrides
// are handled later by MergeRecognizers and are allowed.
//
//nolint:gocyclo // all fail-fast checks are centralized to keep validation semantics consistent
func ValidateRecognizerLayer(layerName string, recognizers []RecognizerConfig, allowUnknownEntities bool) error {
	seenNames := make(map[string]struct{}, len(recognizers))
	for i := range recognizers {
		r := recognizers[i]
		name := strings.TrimSpace(r.Name)
		if name == "" {
			return fmt.Errorf("%s recognizer[%d]: name is required", layerName, i)
		}
		if _, exists := seenNames[name]; exists {
			return fmt.Errorf("%s recognizer %q is duplicated in the same layer", layerName, name)
		}
		seenNames[name] = struct{}{}

		if strings.TrimSpace(r.SupportedEntity) == "" {
			return fmt.Errorf("%s recognizer %q: supported_entity is required", layerName, name)
		}
		if !allowUnknownEntities {
			if _, ok := entityTypeMap[r.SupportedEntity]; !ok {
				return fmt.Errorf("%s recognizer %q: unknown supported_entity %q", layerName, name, r.SupportedEntity)
			}
		}
		if r.Sensitivity != 0 && (r.Sensitivity < 1 || r.Sensitivity > 3) {
			return fmt.Errorf("%s recognizer %q: sensitivity must be in [1,3]", layerName, name)
		}
		for pIdx := range r.Patterns {
			p := r.Patterns[pIdx]
			if strings.TrimSpace(p.Name) == "" {
				return fmt.Errorf("%s recognizer %q pattern[%d]: name is required", layerName, name, pIdx)
			}
			if strings.TrimSpace(p.Regex) == "" {
				return fmt.Errorf("%s recognizer %q pattern %q: regex is required", layerName, name, p.Name)
			}
			if p.Score != nil && (*p.Score < 0 || *p.Score > 1) {
				return fmt.Errorf("%s recognizer %q pattern %q: score must be in [0,1]", layerName, name, p.Name)
			}
			if _, err := regexp.Compile(p.Regex); err != nil {
				return fmt.Errorf("%s recognizer %q pattern %q: invalid regex: %w", layerName, name, p.Name, err)
			}
		}
	}
	return nil
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
		for i := range result {
			if allowed[result[i].SupportedEntity] {
				filtered = append(filtered, result[i])
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
		for i := range result {
			if !blocked[result[i].SupportedEntity] {
				filtered = append(filtered, result[i])
			}
		}
		result = filtered
	}

	return result
}

// entityToType converts Presidio entity names (SCREAMING_SNAKE) to the
// lower_snake_case type strings used internally (e.g. "EMAIL_ADDRESS" -> "email").
var entityTypeMap = map[string]string{
	"EMAIL_ADDRESS":   "email",
	"PHONE_NUMBER":    "phone",
	"IBAN_CODE":       "iban",
	"CREDIT_CARD":     "credit_card",
	"EU_VAT_ID":       "vat_id",
	"DE_SSN":          "ssn",
	"UK_NINO":         "ssn",
	"FR_SSN":          "ssn",
	"IP_ADDRESS":      "ip_address",
	"PASSPORT":        "passport",
	"DE_ID_CARD":      "national_id",
	"DE_TAX_ID":       "tax_id",
	"FR_NIR":          "ssn",
	"FR_ID_CARD":      "national_id",
	"NL_BSN":          "national_id",
	"PL_PESEL":        "national_id",
	"PL_NIP":          "tax_id",
	"ES_DNI":          "national_id",
	"ES_NIE":          "national_id",
	"BE_NATIONAL_ID":  "national_id",
	"AT_SVN":          "national_id",
	"SE_PERSONNUMMER": "national_id",
	"DK_CPR":          "national_id",
	"IE_PPS":          "national_id",
	"PT_NIF":          "tax_id",
	"IMSI":            "imsi",
	"ICCID":           "iccid",
	"EID":             "eid",
	"PERSON":          "person",
	"LOCATION":        "location",
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
