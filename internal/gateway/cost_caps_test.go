package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestResolveCostCaps guards the single source of truth for effective budget
// caps (#216). Both budget enforcement (via the policy input) and
// budget-utilization metrics/alerts read this, so the dashboard denominator and
// the enforced cap can never drift: a per-caller override replaces the server
// default only when set (> 0).
func TestResolveCostCaps(t *testing.T) {
	defaults := &ServerDefaults{MaxDailyCost: 100, MaxMonthlyCost: 2000}

	t.Run("nil overrides use server defaults", func(t *testing.T) {
		daily, monthly := ResolveCostCaps(defaults, nil)
		assert.Equal(t, 100.0, daily)
		assert.Equal(t, 2000.0, monthly)
	})

	t.Run("empty overrides use server defaults", func(t *testing.T) {
		daily, monthly := ResolveCostCaps(defaults, &CallerPolicyOverrides{})
		assert.Equal(t, 100.0, daily)
		assert.Equal(t, 2000.0, monthly)
	})

	t.Run("daily override replaces only daily", func(t *testing.T) {
		daily, monthly := ResolveCostCaps(defaults, &CallerPolicyOverrides{MaxDailyCost: 5})
		assert.Equal(t, 5.0, daily)
		assert.Equal(t, 2000.0, monthly)
	})

	t.Run("monthly override replaces only monthly", func(t *testing.T) {
		daily, monthly := ResolveCostCaps(defaults, &CallerPolicyOverrides{MaxMonthlyCost: 50})
		assert.Equal(t, 100.0, daily)
		assert.Equal(t, 50.0, monthly)
	})

	t.Run("both overrides replace both", func(t *testing.T) {
		daily, monthly := ResolveCostCaps(defaults, &CallerPolicyOverrides{MaxDailyCost: 5, MaxMonthlyCost: 50})
		assert.Equal(t, 5.0, daily)
		assert.Equal(t, 50.0, monthly)
	})

	t.Run("zero override does not zero out the default", func(t *testing.T) {
		// An override left at its zero value means "unset", not "cap of 0".
		daily, monthly := ResolveCostCaps(defaults, &CallerPolicyOverrides{MaxDailyCost: 0, MaxMonthlyCost: 0})
		assert.Equal(t, 100.0, daily)
		assert.Equal(t, 2000.0, monthly)
	})

	t.Run("override above default is honored (a laxer per-caller cap)", func(t *testing.T) {
		daily, monthly := ResolveCostCaps(defaults, &CallerPolicyOverrides{MaxDailyCost: 500, MaxMonthlyCost: 9000})
		assert.Equal(t, 500.0, daily)
		assert.Equal(t, 9000.0, monthly)
	})
}
