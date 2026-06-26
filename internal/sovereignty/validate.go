package sovereignty

import (
	"fmt"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
)

// ValidateAirGap checks operator and gateway configuration for air-gap mode.
// Returns an error when the deployment cannot be considered provably in-region.
// The provider/region gate (eu_strict) is enforced by ValidateSovereignty;
// ValidateAirGap adds the air-gap-specific requirement that crypto keys are
// explicit so signed evidence cannot be forged with a derived default key.
func ValidateAirGap(op *config.Config, gw *gateway.GatewayConfig) error {
	if op == nil || op.Sovereignty == nil || !op.Sovereignty.AirGapEnabled() {
		return nil
	}
	if op.UsingDefaultKeys() {
		return fmt.Errorf("air_gap mode requires explicit TALON_SECRETS_KEY and TALON_SIGNING_KEY (no generated defaults)")
	}
	// air_gap implies eu_strict (config resolution); enforce the provider gate.
	return ValidateSovereignty(op, gw)
}
