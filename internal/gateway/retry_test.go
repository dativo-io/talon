package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Same-provider retries with backoff (#139). Retries default OFF — every
// pre-#139 failover test runs unchanged — and are enabled per test via the
// shared identity pointer (failoverAgent), the same way policy tweaks work
// across the failover suite.

func enableRetries(gw *Gateway, maxAttempts int) {
	agent := failoverAgent(gw)
	if agent.Override == nil {
		agent.Override = &PolicyOverride{}
	}
	agent.Override.Retry = &RetryConfig{MaxAttempts: maxAttempts, InitialBackoff: "1ms", MaxBackoff: "5ms"}
}

const retryTestBody = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`

// A transient 503 that recovers is served by the SAME provider on a retry —
// the fallback chain is never engaged, and the failed attempt is a signed
// record carrying its retry ordinal.
func TestRetry_TransientRecoversOnSameProvider(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	primary.recoverAfter.Store(1) // fail once, then healthy
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, evStore := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")
	enableRetries(gw, 2)

	w := makeFailoverRequest(gw, retryTestBody)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.EqualValues(t, 2, primary.calls.Load(), "first attempt + one retry on the SAME provider")
	assert.EqualValues(t, 0, backup.calls.Load(), "fallback chain must not engage when a retry succeeds")

	attempts, final := failoverRecords(t, evStore, correlationIDFromResponse(t, w))
	require.Len(t, attempts, 1, "the failed first attempt is signed evidence")
	require.NotNil(t, attempts[0].Failover)
	assert.Equal(t, 0, attempts[0].Failover.Retry, "ordinal 0 = the first attempt failed")
	assert.Equal(t, "openai", attempts[0].Failover.Provider)
	require.NotNil(t, final)
	assert.True(t, final.PolicyDecision.Allowed)
	assert.Nil(t, final.Failover, "no fallback engaged → terminal record carries no failover context")
}

// Non-transient failures are never retried: a 400 goes straight through with
// a single upstream call, retry budget or not.
func TestRetry_NonTransientNotRetried(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusBadRequest)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, _ := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")
	enableRetries(gw, 3)

	w := makeFailoverRequest(gw, retryTestBody)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.EqualValues(t, 1, primary.calls.Load(), "permanent failures must not be retried")
	assert.EqualValues(t, 0, backup.calls.Load())
}

// The documented sequence: exhaust the retry budget on the primary FIRST,
// then walk the policy-valid fallback chain. Every failed attempt carries its
// retry ordinal; the terminal record carries the fallback decision.
func TestRetry_ExhaustedThenFallback(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable) // never recovers
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, evStore := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")
	enableRetries(gw, 1)

	w := makeFailoverRequest(gw, retryTestBody)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.EqualValues(t, 2, primary.calls.Load(), "first attempt + the full retry budget before any fallback")
	assert.EqualValues(t, 1, backup.calls.Load(), "fallback engages only after retries are exhausted")

	attempts, final := failoverRecords(t, evStore, correlationIDFromResponse(t, w))
	require.Len(t, attempts, 2, "both failed primary attempts are signed evidence")
	ordinals := []int{attempts[0].Failover.Retry, attempts[1].Failover.Retry}
	assert.ElementsMatch(t, []int{0, 1}, ordinals, "attempt sequence carries retry ordinals")
	require.NotNil(t, final)
	require.NotNil(t, final.Failover, "terminal record carries the fallback decision")
	assert.Equal(t, "backup", final.Failover.Provider)
}

// With no retry config (the default), behavior is byte-identical to pre-#139:
// one primary attempt, immediate fallback.
func TestRetry_DefaultOffImmediateFallback(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	primary.recoverAfter.Store(1) // WOULD recover on a retry — but none is configured
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, _ := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")

	w := makeFailoverRequest(gw, retryTestBody)
	require.Equal(t, http.StatusOK, w.Code)
	assert.EqualValues(t, 1, primary.calls.Load(), "no retry config → single primary attempt")
	assert.EqualValues(t, 1, backup.calls.Load(), "fallback engages immediately")
}

// Backoff bounds: full jitter within the exponential window, floored by a
// numeric Retry-After, always capped at MaxBackoff.
func TestRetryBackoff_Bounds(t *testing.T) {
	s := retrySettings{MaxAttempts: 3, InitialBackoff: 10 * time.Millisecond, MaxBackoff: 40 * time.Millisecond}
	for attempt := 0; attempt < 5; attempt++ {
		for i := 0; i < 50; i++ {
			d := retryBackoff(attempt, s, 0)
			assert.GreaterOrEqual(t, d, time.Duration(0))
			assert.LessOrEqual(t, d, s.MaxBackoff, "attempt %d must respect the cap", attempt)
		}
	}
	assert.Equal(t, 25*time.Millisecond, retryBackoff(0, s, 25*time.Millisecond), "Retry-After floors the sleep")
	assert.Equal(t, s.MaxBackoff, retryBackoff(0, s, time.Minute), "Retry-After is capped at MaxBackoff")

	h := http.Header{}
	h.Set("Retry-After", "2")
	assert.Equal(t, 2*time.Second, retryAfterHint(h))
	h.Set("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
	assert.Equal(t, time.Duration(0), retryAfterHint(h), "HTTP-date forms are ignored")
}

// Effective-policy resolution: org defaults.retry is the baseline; the
// agent's retries block replaces it as a WHOLE (one explicit override, #266).
func TestResolveEffectivePolicy_Retry(t *testing.T) {
	base := OrganizationPolicy{Defaults: OrgDefaults{
		Retry: &RetryConfig{MaxAttempts: 2, InitialBackoff: "100ms", MaxBackoff: "1s"},
	}}

	eff := ResolveEffectivePolicy(base, ProviderConfig{}, nil)
	assert.Equal(t, 2, eff.RetryMaxAttempts)
	assert.Equal(t, 100*time.Millisecond, eff.RetryInitialBackoff)
	assert.Equal(t, time.Second, eff.RetryMaxBackoff)

	eff = ResolveEffectivePolicy(base, ProviderConfig{}, &PolicyOverride{
		Retry: &RetryConfig{MaxAttempts: 4}, // whole-block replace: backoffs fall to defaults
	})
	assert.Equal(t, 4, eff.RetryMaxAttempts)
	assert.Equal(t, 250*time.Millisecond, eff.RetryInitialBackoff, "override block replaces wholesale — org backoffs do not leak through")
	assert.Equal(t, 2*time.Second, eff.RetryMaxBackoff)

	eff = ResolveEffectivePolicy(OrganizationPolicy{}, ProviderConfig{}, nil)
	assert.Equal(t, 0, eff.RetryMaxAttempts, "no config anywhere → retries off")
}
