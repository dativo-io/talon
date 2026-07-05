// Package pricing provides config-driven LLM cost estimation from a YAML pricing table.
package pricing

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// defaultModelsYAML is the embedded default pricing table used when pricing/models.yaml is not found.
// Keep in sync with repo root pricing/models.yaml when updating provider/model prices.
//
//go:embed default_models.yaml
var defaultModelsYAML []byte

// apiModelSuffix matches common API model ID suffixes so we can fall back to base model in pricing.
// e.g. gpt-4o-2024-08-06 -> gpt-4o, claude-3-5-sonnet-20241022-v2 -> claude-3-5-sonnet
var apiModelSuffix = regexp.MustCompile(`-(?:20\d{2}-\d{2}-\d{2}|v\d+(?::\d+)?)$`)

// unknownModelWarned tracks (providerID, model) pairs we have already logged to avoid spam.
var unknownModelWarned sync.Map

// WarnUnknownModelOnce logs a warning the first time an unknown model is used for cost estimation.
func WarnUnknownModelOnce(providerID, model string) {
	key := providerID + "|" + model
	if _, loaded := unknownModelWarned.LoadOrStore(key, struct{}{}); !loaded {
		log.Warn().Str("provider", providerID).Str("model", model).Msg("unknown model for cost estimation")
	}
}

// ModelPricing holds per-1M-token USD prices for a single model.
type ModelPricing struct {
	InputPer1M  float64 `yaml:"input_per_1m"`
	OutputPer1M float64 `yaml:"output_per_1m"`
	// CacheReadPer1M / CacheWritePer1M price prompt-cache read/write tokens
	// (#196). Optional: when absent (0), cache tokens fall back to the input
	// rate — fail-conservative, never lower than pre-change reported cost.
	CacheReadPer1M  float64 `yaml:"cache_read_per_1m,omitempty"`
	CacheWritePer1M float64 `yaml:"cache_write_per_1m,omitempty"`
}

// ProviderPricing holds model pricing for a provider, with optional inherit from another provider.
type ProviderPricing struct {
	Models  map[string]ModelPricing `yaml:"models"`
	Inherit string                  `yaml:"inherit,omitempty"`
}

// PricingTable is the root structure of pricing/models.yaml.
//
//nolint:revive // exported type name matches package; "PricingTable" is the documented API
type PricingTable struct {
	Version   string                     `yaml:"version"`
	Providers map[string]ProviderPricing `yaml:"providers"`
}

// loadFromData parses YAML bytes, resolves inherit references (single depth, no chains),
// and validates that no prices are negative. Used by Load and by the embedded default.
func loadFromData(data []byte) (*PricingTable, error) {
	var raw PricingTable
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing pricing YAML: %w", err)
	}

	if raw.Providers == nil {
		raw.Providers = make(map[string]ProviderPricing)
	}

	// Resolve inherit and validate
	resolved := make(map[string]ProviderPricing, len(raw.Providers))
	for id, pp := range raw.Providers {
		if pp.Models == nil {
			pp.Models = make(map[string]ModelPricing)
		}
		if pp.Inherit != "" {
			parent, ok := raw.Providers[pp.Inherit]
			if !ok {
				return nil, fmt.Errorf("provider %q inherits from unknown provider %q", id, pp.Inherit)
			}
			// Merge: parent models first, then override with own
			merged := make(map[string]ModelPricing)
			for k, v := range parent.Models {
				merged[k] = v
			}
			for k, v := range pp.Models {
				merged[k] = v
			}
			pp.Models = merged
			pp.Inherit = ""
		}
		if err := validateProviderPricing(id, pp); err != nil {
			return nil, err
		}
		resolved[id] = pp
	}

	return &PricingTable{Version: raw.Version, Providers: resolved}, nil
}

// Load parses the YAML file at path, resolves inherit references (single depth, no chains),
// and validates that no prices are negative. Returns an error if the file is missing or malformed.
func Load(path string) (*PricingTable, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading pricing file %s: %w", path, err)
	}
	table, err := loadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return table, nil
}

func validateProviderPricing(providerID string, pp ProviderPricing) error {
	for model, m := range pp.Models {
		if m.InputPer1M < 0 || m.OutputPer1M < 0 {
			return fmt.Errorf("provider %q model %q: negative price not allowed (input_per_1m=%g, output_per_1m=%g)",
				providerID, model, m.InputPer1M, m.OutputPer1M)
		}
	}
	return nil
}

// LoadOrDefault calls Load and on error falls back to the embedded default pricing table
// (so cost estimation still works when pricing/models.yaml is missing). Logs at info when
// using the embedded default. Never panics.
func LoadOrDefault(path string) *PricingTable {
	if path == "" {
		path = "pricing/models.yaml"
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	table, err := Load(path)
	if err != nil {
		defaultTable, defaultErr := loadFromData(defaultModelsYAML)
		if defaultErr != nil {
			log.Warn().Err(defaultErr).Msg("embedded default pricing invalid; cost estimation will return 0")
			return &PricingTable{Version: "1", Providers: map[string]ProviderPricing{}}
		}
		log.Info().Err(err).Str("path_attempted", abs).Msg("pricing file not found; using embedded default pricing")
		return defaultTable
	}
	return table
}

// Estimate looks up provider and model, computes cost in USD, and returns (cost, true) if found.
// Returns (0.0, false) if provider or model is not in the table. Safe for concurrent use.
// If the provider exists with an empty models map (e.g. ollama), returns (0.0, true) for any model (free).
// Model lookup tries exact key first, then a base name (e.g. gpt-4o-2024-08-06 -> gpt-4o) so API-returned
// model IDs still match pricing table keys.
func (t *PricingTable) Estimate(providerID, model string, inputTokens, outputTokens int) (cost float64, known bool) {
	m, known, free := t.resolveModel(providerID, model)
	if !known || free {
		return 0, known
	}
	// Per 1M tokens: (input/1e6)*input_per_1m + (output/1e6)*output_per_1m
	cost = (float64(inputTokens)/1e6)*m.InputPer1M + (float64(outputTokens)/1e6)*m.OutputPer1M
	return cost, true
}

// EstimateCached prices a full token breakdown including prompt-cache read and
// write tokens (#196). cacheFallback is true when cache tokens were priced at
// the input rate because the model has no explicit cache rate — a
// fail-conservative fallback that never reports less than the input rate.
func (t *PricingTable) EstimateCached(providerID, model string, inputTokens, cacheReadTokens, cacheWriteTokens, outputTokens int) (cost float64, known, cacheFallback bool) {
	m, known, free := t.resolveModel(providerID, model)
	if !known || free {
		return 0, known, false
	}
	cacheReadRate := m.CacheReadPer1M
	if cacheReadRate == 0 && cacheReadTokens > 0 {
		cacheReadRate = m.InputPer1M
		cacheFallback = true
	}
	cacheWriteRate := m.CacheWritePer1M
	if cacheWriteRate == 0 && cacheWriteTokens > 0 {
		cacheWriteRate = m.InputPer1M
		cacheFallback = true
	}
	cost = (float64(inputTokens)/1e6)*m.InputPer1M +
		(float64(cacheReadTokens)/1e6)*cacheReadRate +
		(float64(cacheWriteTokens)/1e6)*cacheWriteRate +
		(float64(outputTokens)/1e6)*m.OutputPer1M
	return cost, true, cacheFallback
}

// resolveModel looks up a model's pricing. Returns (pricing, known, free):
// known=false when the provider/model is absent; free=true when the provider
// exists with an empty models map (e.g. ollama). Model lookup tries the exact
// key, then a base name (stripping an API-style suffix like -2024-08-06).
func (t *PricingTable) resolveModel(providerID, model string) (ModelPricing, bool, bool) {
	if t == nil || t.Providers == nil {
		return ModelPricing{}, false, false
	}
	pp, ok := t.Providers[providerID]
	if !ok || pp.Models == nil {
		return ModelPricing{}, false, false
	}
	m, ok := pp.Models[model]
	if !ok {
		if len(pp.Models) == 0 {
			return ModelPricing{}, true, true // free provider (ollama)
		}
		if base := apiModelSuffix.ReplaceAllString(model, ""); base != model {
			m, ok = pp.Models[base]
		}
		if !ok {
			return ModelPricing{}, false, false
		}
	}
	return m, true, false
}

// ModelCount returns the number of models configured for a provider (for PricingAvailable / CLI).
func (t *PricingTable) ModelCount(providerID string) int {
	if t == nil || t.Providers == nil {
		return 0
	}
	pp, ok := t.Providers[providerID]
	if !ok || pp.Models == nil {
		return 0
	}
	return len(pp.Models)
}
