// Package sovereignty implements air-gapped deployment presets, egress guards,
// and validation for EU in-region self-host operation (feature bet 5.3).
package sovereignty

import (
	"github.com/dativo-io/talon/internal/config"
)

// Deployment mode aliases re-exported from config for callers outside config.
const (
	ModeStandard = config.SovereigntyModeStandard
	ModeAirGap   = config.SovereigntyModeAirGap
)
