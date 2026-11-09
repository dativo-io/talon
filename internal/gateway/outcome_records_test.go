package gateway

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/cache"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/testutil"
)

// TestOutcomeOf_RealGatewayRecords reads records the gateway itself writes
// (#553 review): the console's dispatch claims must hold for production
// evidence, not only for hand-built records.
func TestOutcomeOf_RealGatewayRecords(t *testing.T) {
	t.Run("cache hit: not dispatched, answered from cache, provider not called", func(t *testing.T) {
		primary := newFailoverUpstream(t, http.StatusOK)
		backup := newFailoverUpstream(t, http.StatusOK)
		gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")
		cacheStore, err := cache.NewStore(filepath.Join(t.TempDir(), "c.db"), testutil.TestSigningKey)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cacheStore.Close() })
		cachePolicy, err := cache.NewEvaluator(context.Background())
		require.NoError(t, err)
		gw.SetCache(cacheStore, cache.NewBM25(), nil, cachePolicy, true, 3600, nil, 0.9, 100)

		w1 := makeFailoverRequest(gw, failoverTestBody)
		require.Equal(t, http.StatusOK, w1.Code)
		_, first := failoverRecords(t, store, correlationIDFromResponse(t, w1))
		require.NotNil(t, first)
		o1 := evidence.OutcomeOf(first)
		assert.Equal(t, evidence.DispatchDispatched, o1.Dispatch)
		assert.Equal(t, evidence.DownstreamCompleted, o1.Downstream)
		callsAfterFirst := primary.calls.Load()

		w2 := makeFailoverRequest(gw, failoverTestBody)
		require.Equal(t, http.StatusOK, w2.Code)
		_, hit := failoverRecords(t, store, correlationIDFromResponse(t, w2))
		require.NotNil(t, hit)
		require.True(t, hit.CacheHit, "the second identical request is a cache hit")
		assert.Equal(t, callsAfterFirst, primary.calls.Load(), "the provider was not called for the cache hit")
		o2 := evidence.OutcomeOf(hit)
		assert.Equal(t, "allowed", o2.Decision)
		assert.Equal(t, evidence.DispatchNotDispatched, o2.Dispatch, "a cache hit is not a provider dispatch")
		assert.Equal(t, evidence.DownstreamCache, o2.Downstream)
		assert.Contains(t, o2.Basis, "cache")
	})

	t.Run("provider 503 then fallback: the failed attempt was dispatched and answered with an error", func(t *testing.T) {
		primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
		backup := newFailoverUpstream(t, http.StatusOK)
		gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "gpt-4o-mini-eu")
		w := makeFailoverRequest(gw, failoverTestBody)
		require.Equal(t, http.StatusOK, w.Code)
		attempts, final := failoverRecords(t, store, correlationIDFromResponse(t, w))
		require.NotEmpty(t, attempts)
		a := evidence.OutcomeOf(attempts[0])
		assert.Equal(t, evidence.DispatchDispatched, a.Dispatch)
		assert.Equal(t, evidence.DownstreamFailed, a.Downstream)
		assert.Contains(t, a.Basis, "HTTP 503")
		require.NotNil(t, final)
		f := evidence.OutcomeOf(final)
		assert.Equal(t, evidence.DispatchDispatched, f.Dispatch)
		assert.Equal(t, evidence.DownstreamCompleted, f.Downstream, "the fallback answered")
	})

	t.Run("connection failure: delivery not proven, dispatch unknown", func(t *testing.T) {
		primary := newFailoverUpstream(t, http.StatusOK)
		backup := newFailoverUpstream(t, http.StatusOK)
		gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "gpt-4o-mini-eu")
		primary.server.Close() // nothing listens: the transport fails
		w := makeFailoverRequest(gw, failoverTestBody)
		require.Equal(t, http.StatusOK, w.Code, "the fallback still answers")
		attempts, _ := failoverRecords(t, store, correlationIDFromResponse(t, w))
		require.NotEmpty(t, attempts)
		a := evidence.OutcomeOf(attempts[0])
		assert.Equal(t, evidence.DispatchUnknown, a.Dispatch, "a transport error does not prove the provider received the request")
		assert.Equal(t, evidence.DownstreamUnknown, a.Downstream)
	})
}
