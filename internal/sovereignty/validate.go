package sovereignty

import (
	"fmt"
	"strings"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
)

// ValidateAirGap checks operator and gateway configuration for air-gap mode.
// Returns an error when the deployment cannot be considered provably in-region.
func ValidateAirGap(op *config.Config, gw *gateway.GatewayConfig) error {
	if op == nil || op.Sovereignty == nil || !op.Sovereignty.AirGapEnabled() {
		return nil
	}
	if op.UsingDefaultKeys() {
		return fmt.Errorf("air_gap mode requires explicit TALON_SECRETS_KEY and TALON_SIGNING_KEY (no generated defaults)")
	}
	if op.LLM != nil && op.LLM.Routing != nil {
		mode := op.LLM.Routing.DataSovereigntyMode
		if mode != "" && mode != "eu_strict" {
			return fmt.Errorf("air_gap mode requires llm.routing.data_sovereignty_mode eu_strict (got %q)", mode)
		}
	}
	if gw == nil {
		return nil
	}
	for name := range gw.Providers {
		p := gw.Providers[name]
		if !p.Enabled {
			continue
		}
		region := strings.ToUpper(strings.TrimSpace(p.Region))
		if region == "" {
			return fmt.Errorf("air_gap gateway provider %q: region must be set (EU or LOCAL)", name)
		}
		if region != "EU" && region != "LOCAL" {
			return fmt.Errorf("air_gap gateway provider %q: region %q is not permitted (use EU or LOCAL)", name, region)
		}
	}
	return nil
}
