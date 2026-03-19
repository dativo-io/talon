package classifier

import (
	"context"
)

// EnrichmentConfig holds semantic enrichment settings. Callers (e.g. runner)
// populate this from policy; classifier does not depend on policy package.
type EnrichmentConfig struct {
	Enabled               bool
	Mode                  string   // off | shadow | enforce
	AllowedAttributes     []string // e.g. ["gender", "scope"]
	ConfidenceThreshold   float64
	EmitUnknownAttributes bool
	DefaultPersonGender   string
	DefaultLocationScope  string
	PreserveTitles        bool
}

// EnrichmentPolicy is implemented by the caller (e.g. policy engine adapter)
// to decide which attributes may be emitted for an entity. Classifier does not
// import policy package.
type EnrichmentPolicy interface {
	EmitAttributes(ctx context.Context, mode string, allowed []string, entityType string, attrs map[string]string) []string
}
