package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestResolveEffectivePolicy_CostCaps guards the single source of truth for
// effective budget caps (#216). Both budget enforcement (via the policy input)
// and budget-utilization metrics/alerts read this, so the dashboard denominator
// and the enforced cap can never drift: a per-agent override replaces the
// organization baseline only when set (> 0).
func TestResolveEffectivePolicy_CostCaps(t *testing.T) {
	baseline := OrganizationPolicy{Defaults: OrgDefaults{DailyCost: 100, MonthlyCost: 2000}}

	costCaps := func(override *PolicyOverride) (daily, monthly float64) {
		eff := ResolveEffectivePolicy(baseline, ProviderConfig{}, override)
		return eff.MaxDailyCost, eff.MaxMonthlyCost
	}

	t.Run("nil override uses the organization baseline", func(t *testing.T) {
		daily, monthly := costCaps(nil)
		assert.Equal(t, 100.0, daily)
		assert.Equal(t, 2000.0, monthly)
	})

	t.Run("empty override uses the organization baseline", func(t *testing.T) {
		daily, monthly := costCaps(&PolicyOverride{})
		assert.Equal(t, 100.0, daily)
		assert.Equal(t, 2000.0, monthly)
	})

	t.Run("daily override replaces only daily", func(t *testing.T) {
		daily, monthly := costCaps(&PolicyOverride{MaxDailyCost: 5})
		assert.Equal(t, 5.0, daily)
		assert.Equal(t, 2000.0, monthly)
	})

	t.Run("monthly override replaces only monthly", func(t *testing.T) {
		daily, monthly := costCaps(&PolicyOverride{MaxMonthlyCost: 50})
		assert.Equal(t, 100.0, daily)
		assert.Equal(t, 50.0, monthly)
	})

	t.Run("both overrides replace both", func(t *testing.T) {
		daily, monthly := costCaps(&PolicyOverride{MaxDailyCost: 5, MaxMonthlyCost: 50})
		assert.Equal(t, 5.0, daily)
		assert.Equal(t, 50.0, monthly)
	})

	t.Run("zero override does not zero out the baseline", func(t *testing.T) {
		// An override left at its zero value means "unset", not "cap of 0".
		daily, monthly := costCaps(&PolicyOverride{MaxDailyCost: 0, MaxMonthlyCost: 0})
		assert.Equal(t, 100.0, daily)
		assert.Equal(t, 2000.0, monthly)
	})

	t.Run("override above baseline is honored (a laxer per-agent cap)", func(t *testing.T) {
		daily, monthly := costCaps(&PolicyOverride{MaxDailyCost: 500, MaxMonthlyCost: 9000})
		assert.Equal(t, 500.0, daily)
		assert.Equal(t, 9000.0, monthly)
	})
}
