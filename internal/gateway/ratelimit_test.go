package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_GlobalLimit(t *testing.T) {
	rl := NewRateLimiter(5, 100)

	allowed := 0
	for i := 0; i < 20; i++ {
		if rl.Allow("caller-a") {
			allowed++
		}
	}
	// Token bucket burst=5, so first 5 should be allowed, then rate-limited
	assert.LessOrEqual(t, allowed, 6, "global limit should cap requests")
	assert.GreaterOrEqual(t, allowed, 4, "burst should allow at least 4")
}

func TestRateLimiter_PerCallerLimit(t *testing.T) {
	rl := NewRateLimiter(1000, 3)

	allowed := 0
	for i := 0; i < 20; i++ {
		if rl.Allow("caller-a") {
			allowed++
		}
	}
	assert.LessOrEqual(t, allowed, 4, "per-caller limit should cap requests")

	// A different caller gets its own bucket
	assert.True(t, rl.Allow("caller-b"), "different caller should have separate bucket")
}

func TestRateLimiter_CallerIsolation(t *testing.T) {
	rl := NewRateLimiter(1000, 2)

	// Exhaust caller-a's bucket
	rl.Allow("caller-a")
	rl.Allow("caller-a")
	rl.Allow("caller-a")

	// caller-b should still be allowed
	assert.True(t, rl.Allow("caller-b"), "caller-b should not be affected by caller-a")
}
