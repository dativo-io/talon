package sovereignty

import (
	"fmt"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
)

// ValidateAirGap checks operator configuration for air-gap mode. Returns an
// error when explicit crypto keys are missing. Provider exclusions under
// eu_strict are non-fatal and enforced at runtime via EvaluateSovereignty and
// gateway per-request denial.
func ValidateAirGap(op *config.Config, gw *gateway.GatewayConfig) error {
	_ = gw
	if op == nil || op.Sovereignty == nil || !op.Sovereignty.AirGapEnabled() {
		return nil
	}
	if op.UsingDefaultKeys() {
		return fmt.Errorf("air_gap mode requires explicit TALON_SECRETS_KEY and TALON_SIGNING_KEY (no generated defaults)")
	}
	return nil
}
