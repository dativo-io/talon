package gateway

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// TierLevel is a data classification tier that operators may write either as
// a number (0, 1, 2) or as a named alias (public, internal, confidential) in
// configuration. Numbering follows the industry convention (ISO 27001
// practice, Microsoft Purview/AGT): ascending sensitivity, 0 = public.
// Internally — and in evidence records — tiers stay numeric for stability.
type TierLevel int

// Named tier aliases accepted in config (case-insensitive).
const (
	TierPublic       TierLevel = 0
	TierInternal     TierLevel = 1
	TierConfidential TierLevel = 2
)

var tierNames = map[string]TierLevel{
	"public":       TierPublic,
	"internal":     TierInternal,
	"confidential": TierConfidential,
}

// ParseTierLevel converts a config value to a TierLevel. It accepts the
// named aliases (public, internal, confidential; case-insensitive) and
// numeric strings. Range validation for numeric values stays with the
// agent's config validation so error messages carry config context.
func ParseTierLevel(s string) (TierLevel, error) {
	name := strings.ToLower(strings.TrimSpace(s))
	if t, ok := tierNames[name]; ok {
		return t, nil
	}
	if n, err := strconv.Atoi(name); err == nil {
		return TierLevel(n), nil
	}
	return 0, fmt.Errorf("invalid tier %q: must be 0-2 or one of public, internal, confidential", s)
}

// String returns the named alias for known tiers, the number otherwise.
func (t TierLevel) String() string {
	switch t {
	case TierPublic:
		return "public"
	case TierInternal:
		return "internal"
	case TierConfidential:
		return "confidential"
	default:
		return strconv.Itoa(int(t))
	}
}

// UnmarshalYAML accepts `tier: 2` and `tier: confidential` interchangeably.
func (t *TierLevel) UnmarshalYAML(value *yaml.Node) error {
	var n int
	if err := value.Decode(&n); err == nil {
		*t = TierLevel(n)
		return nil
	}
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("invalid tier value: %w", err)
	}
	parsed, err := ParseTierLevel(s)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

// UnmarshalJSON mirrors UnmarshalYAML for JSON-sourced config.
func (t *TierLevel) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*t = TierLevel(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("invalid tier value: %s", string(b))
	}
	parsed, err := ParseTierLevel(s)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}
