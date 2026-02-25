package gateway

import (
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter enforces per-caller and global request rate limits.
// Uses token bucket algorithm via golang.org/x/time/rate.
type RateLimiter struct {
	mu        sync.Mutex
	global    *rate.Limiter
	callers   map[string]*rate.Limiter
	perCaller rate.Limit
	burst     int
}

// NewRateLimiter creates a rate limiter from the gateway config.
// globalRPM is the total requests/minute across all callers.
// perCallerRPM is the per-caller requests/minute.
func NewRateLimiter(globalRPM, perCallerRPM int) *RateLimiter {
	globalRate := rate.Limit(float64(globalRPM) / 60.0)
	callerRate := rate.Limit(float64(perCallerRPM) / 60.0)
	globalBurst := globalRPM
	if globalBurst < 1 {
		globalBurst = 1
	}
	callerBurst := perCallerRPM
	if callerBurst < 1 {
		callerBurst = 1
	}
	return &RateLimiter{
		global:    rate.NewLimiter(globalRate, globalBurst),
		callers:   make(map[string]*rate.Limiter),
		perCaller: callerRate,
		burst:     callerBurst,
	}
}

// Allow checks whether a request from the given caller is allowed.
// Returns true if allowed, false if rate limited.
func (rl *RateLimiter) Allow(callerName string) bool {
	if !rl.global.Allow() {
		return false
	}
	rl.mu.Lock()
	limiter, ok := rl.callers[callerName]
	if !ok {
		limiter = rate.NewLimiter(rl.perCaller, rl.burst)
		rl.callers[callerName] = limiter
	}
	rl.mu.Unlock()
	return limiter.Allow()
}
