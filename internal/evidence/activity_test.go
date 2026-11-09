package evidence

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Hand-designed dataset for the activity series. Window of interest:
// [2026-03-15T10:00Z, 2026-03-15T11:00Z) at 5m, i.e. 12 buckets.
//
//	id        agent type                      ts (UTC)     allowed error  cost  bucket
//	r1        a     gateway                   10:00:10     yes     -      0.10  10:00
//	r2        a     gateway                   10:04:59     no      -      0     10:00
//	r3        b     gateway                   10:05:00     yes     yes    0     10:05
//	r4        a     gateway_failover_attempt  10:05:30     yes     yes    0     (provider attempt: not request class)
//	r5        a     budget_threshold          10:10:00     no      -      0     (operator event: not request class)
//	r6        a     gateway                   10:59:59     yes     -      0.25  10:55
//	r7        a     gateway                   11:00:00     yes     -      9.99  (outside window)
//	r8(acme)  a     gateway                   10:00:30     yes     -      5.00  (other tenant)
func seedActivityFixture(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "evidence.db"), "activity-test-signing-key-000001")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	put := func(id, tenant, agent, typ string, ts time.Time, allowed bool, errText string, cost float64) {
		require.NoError(t, store.Store(ctx, &Evidence{
			ID: id, CorrelationID: "corr_" + id, TenantID: tenant, AgentID: agent, InvocationType: typ, Timestamp: ts,
			PolicyDecision: PolicyDecision{Allowed: allowed, Action: map[bool]string{true: "allow", false: "deny"}[allowed]},
			Execution:      Execution{ModelUsed: "m", Cost: cost, Error: errText},
		}))
	}
	day := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	put("r1", "default", "a", "gateway", day.Add(10*time.Hour+10*time.Second), true, "", 0.10)
	put("r2", "default", "a", "gateway", day.Add(10*time.Hour+4*time.Minute+59*time.Second), false, "", 0)
	put("r3", "default", "b", "gateway", day.Add(10*time.Hour+5*time.Minute), true, "upstream status 503", 0)
	put("r4", "default", "a", "gateway_failover_attempt", day.Add(10*time.Hour+5*time.Minute+30*time.Second), true, "upstream status 529", 0)
	put("r5", "default", "a", "budget_threshold", day.Add(10*time.Hour+10*time.Minute), false, "", 0)
	put("r6", "default", "a", "gateway", day.Add(10*time.Hour+59*time.Minute+59*time.Second), true, "", 0.25)
	put("r7", "default", "a", "gateway", day.Add(11*time.Hour), true, "", 9.99)
	put("r8", "acme", "a", "gateway", day.Add(10*time.Hour+30*time.Second), true, "", 5.00)
	return store
}

func TestActivityBuckets_HandExpectations(t *testing.T) {
	store := seedActivityFixture(t)
	from := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	// Sanity: the record classes the fixture relies on.
	require.NotEqual(t, ClassRequest, RecordClassOf("gateway_failover_attempt"))
	require.NotEqual(t, ClassRequest, RecordClassOf("budget_threshold"))
	require.Equal(t, ClassRequest, RecordClassOf("proxy_tool_blocked"), "intercepted tool actions are request-class")

	s, err := store.ActivityBuckets(context.Background(), "default", "", from, to, 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, "5m", s.Bucket)
	assert.Equal(t, "request_class", s.Scope)
	assert.Equal(t, from, s.From)
	assert.Equal(t, to, s.To)
	require.Len(t, s.Buckets, 12, "dense series: every 5-minute bucket is present")

	b0 := s.Buckets[0]
	assert.Equal(t, from, b0.Start)
	assert.Equal(t, 2, b0.Requests, "r1 + r2 (r8 is another tenant)")
	assert.Equal(t, 1, b0.Denied)
	assert.Equal(t, 0, b0.Errors)
	assert.InDelta(t, 0.10, b0.Cost, 1e-9)

	b1 := s.Buckets[1]
	assert.Equal(t, from.Add(5*time.Minute), b1.Start)
	assert.Equal(t, 1, b1.Requests, "r3 only: r4 is a provider sub-attempt")
	assert.Equal(t, 1, b1.Errors)
	assert.Zero(t, b1.Cost)

	b2 := s.Buckets[2]
	assert.Zero(t, b2.Requests, "r5 is a control-plane record, not request-class traffic")

	for i := 3; i < 11; i++ {
		assert.Zero(t, s.Buckets[i].Requests, "bucket %d is empty but present", i)
	}
	b11 := s.Buckets[11]
	assert.Equal(t, from.Add(55*time.Minute), b11.Start)
	assert.Equal(t, 1, b11.Requests, "r6 at 10:59:59; r7 at 11:00:00 is outside [from, to)")
	assert.InDelta(t, 0.25, b11.Cost, 1e-9)

	// Totals over the series equal the fleet traffic counters for the same window and class.
	traffic, err := store.AgentTrafficStats(context.Background(), "default", from, to)
	require.NoError(t, err)
	var reqs, denied int
	for _, b := range s.Buckets {
		reqs += b.Requests
		denied += b.Denied
	}
	assert.Equal(t, traffic["a"].Requests+traffic["b"].Requests, reqs)
	assert.Equal(t, traffic["a"].Denied+traffic["b"].Denied, denied)
	assert.Equal(t, 4, reqs, "hand count: r1, r2, r3, r6")
	assert.Equal(t, 1, denied, "hand count: r2")
}

func TestActivityBuckets_AgentFilterAlignmentAndBounds(t *testing.T) {
	store := seedActivityFixture(t)
	ctx := context.Background()
	from := time.Date(2026, 3, 15, 10, 2, 0, 0, time.UTC) // not on the grid
	to := time.Date(2026, 3, 15, 10, 7, 0, 0, time.UTC)

	s, err := store.ActivityBuckets(ctx, "default", "a", from, to, 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC), s.From, "from aligned down")
	assert.Equal(t, time.Date(2026, 3, 15, 10, 10, 0, 0, time.UTC), s.To, "to aligned up")
	require.Len(t, s.Buckets, 2)
	assert.Equal(t, 2, s.Buckets[0].Requests, "agent a: r1, r2")
	assert.Equal(t, 0, s.Buckets[1].Requests, "agent a has no request-class record at 10:05 (r4 is an attempt)")

	// 24h buckets are UTC calendar days.
	day, err := store.ActivityBuckets(ctx, "default", "", time.Date(2026, 3, 15, 6, 0, 0, 0, time.UTC), time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), 24*time.Hour)
	require.NoError(t, err)
	require.Len(t, day.Buckets, 1)
	assert.Equal(t, time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), day.Buckets[0].Start)
	assert.Equal(t, 5, day.Buckets[0].Requests, "r1, r2, r3, r6, r7 across the whole day")

	_, err = store.ActivityBuckets(ctx, "default", "", from, from.Add(8*24*time.Hour), 5*time.Minute)
	require.ErrorContains(t, err, "exceed the bound")
	_, err = store.ActivityBuckets(ctx, "default", "", from, to, 7*time.Minute)
	require.ErrorContains(t, err, "unsupported bucket size")
	// Tenant "" spans every tenant: the default tenant's buckets plus the
	// other tenants' records in the same window, never fewer.
	all, err := store.ActivityBuckets(ctx, "", "", time.Date(2026, 3, 15, 6, 0, 0, 0, time.UTC), time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), 24*time.Hour)
	require.NoError(t, err)
	require.Len(t, all.Buckets, 1)
	assert.Equal(t, "", all.TenantID)
	assert.GreaterOrEqual(t, all.Buckets[0].Requests, day.Buckets[0].Requests)
	_, err = store.ActivityBuckets(ctx, "default", "", to, from, 5*time.Minute)
	require.ErrorContains(t, err, "is empty")
}

func TestIndexOf_MatchesListIndexProjection(t *testing.T) {
	store := seedActivityFixture(t)
	ctx := context.Background()
	listed, err := store.ListIndex(ctx, "default", "", time.Time{}, time.Time{}, 0, "", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, listed)
	for _, row := range listed {
		full, err := store.Get(ctx, row.ID)
		require.NoError(t, err)
		assert.Equal(t, row, IndexOf(full), "record %s", row.ID)
	}
}

func TestDetail_VerificationStateReflectsTheSignature(t *testing.T) {
	store := seedActivityFixture(t)
	ctx := context.Background()
	d, err := store.Detail(ctx, "r1")
	require.NoError(t, err)
	assert.Equal(t, "valid", d.Verification.State)
	assert.True(t, d.Valid())
	assert.False(t, d.Verification.CheckedAt.IsZero())
	assert.Equal(t, "r1", d.Record.ID)

	// Tamper with the stored JSON: the signature no longer matches.
	_, err = store.db.ExecContext(ctx, `UPDATE evidence SET evidence_json = replace(evidence_json, '"cost":0.1', '"cost":0.01') WHERE id = 'r1'`)
	require.NoError(t, err)
	tampered, err := store.Detail(ctx, "r1")
	require.NoError(t, err)
	assert.Equal(t, "invalid", tampered.Verification.State, "a signed record is not a verified record")
	assert.InDelta(t, 0.01, tampered.Record.Execution.Cost, 1e-9)

	_, err = store.Detail(ctx, "does-not-exist")
	require.Error(t, err)
}

// TestActivityBuckets_FractionalSecondBoundary (#535 review): a window that
// ends a fraction of a second after a bucket edge must still contain the
// bucket that the SQL query includes records for.
func TestActivityBuckets_FractionalSecondBoundary(t *testing.T) {
	store := pageStoreForActivity(t)
	ctx := context.Background()
	edge := time.Date(2026, 3, 15, 10, 5, 0, 0, time.UTC)
	require.NoError(t, store.Store(ctx, &Evidence{
		ID: "frac", CorrelationID: "c_frac", TenantID: "default", AgentID: "a", InvocationType: "gateway",
		Timestamp:      edge.Add(200 * time.Millisecond),
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"}, Execution: Execution{Cost: 0.5},
	}))
	s, err := store.ActivityBuckets(ctx, "default", "", edge.Add(-5*time.Minute), edge.Add(500*time.Millisecond), 5*time.Minute)
	require.NoError(t, err)
	require.Len(t, s.Buckets, 2, "the 10:05 bucket is part of the series")
	assert.Equal(t, edge.Add(5*time.Minute), s.To)
	assert.Equal(t, 1, s.Buckets[1].Requests)
	assert.InDelta(t, 0.5, s.Buckets[1].Cost, 1e-9)
	var total int
	for _, b := range s.Buckets {
		total += b.Requests
	}
	assert.Equal(t, 1, total, "no record is counted outside a returned bucket")
}

func pageStoreForActivity(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "evidence.db"), "activity-frac-test-signing-key-01")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}
