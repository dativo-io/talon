package gateway

import (
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter enforces per-agent and global request rate limits.
// Uses token bucket algorithm via golang.org/x/time/rate.
type RateLimiter struct {
	mu       sync.Mutex
	global   *rate.Limiter
	agents   map[string]*rate.Limiter
	perAgent rate.Limit
	burst    int
}

// NewRateLimiter creates a rate limiter from the gateway config.
// globalRPM is the total requests/minute across all agents.
// perAgentRPM is the per-agent requests/minute.
func NewRateLimiter(globalRPM, perAgentRPM int) *RateLimiter {
	globalRate := rate.Limit(float64(globalRPM) / 60.0)
	agentRate := rate.Limit(float64(perAgentRPM) / 60.0)
	globalBurst := globalRPM
	if globalBurst < 1 {
		globalBurst = 1
	}
	agentBurst := perAgentRPM
	if agentBurst < 1 {
		agentBurst = 1
	}
	return &RateLimiter{
		global:   rate.NewLimiter(globalRate, globalBurst),
		agents:   make(map[string]*rate.Limiter),
		perAgent: agentRate,
		burst:    agentBurst,
	}
}

// Allow checks whether a request from the given agent is allowed.
// Returns true if allowed, false if rate limited.
func (rl *RateLimiter) Allow(agentName string) bool {
	if !rl.global.Allow() {
		return false
	}
	rl.mu.Lock()
	limiter, ok := rl.agents[agentName]
	if !ok {
		limiter = rate.NewLimiter(rl.perAgent, rl.burst)
		rl.agents[agentName] = limiter
	}
	rl.mu.Unlock()
	return limiter.Allow()
}
