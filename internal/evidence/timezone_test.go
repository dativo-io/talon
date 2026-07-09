package evidence

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStore_NormalizesTimestampToUTC is the regression guard for #216: the
// mattn/go-sqlite3 driver serializes a time.Time with its original offset, and
// cost-window queries compare those strings lexicographically. A record written
// in a non-UTC server location must still land in the correct UTC day, or budget
// enforcement and `talon costs` (both UTC-windowed) disagree around midnight.
func TestStore_NormalizesTimestampToUTC(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// A fixed zone 8h behind UTC. The instant below is 02:00 UTC on the 9th,
	// which in this zone is 18:00 on the 8th — a different calendar day.
	west := time.FixedZone("WEST", -8*3600)
	instantUTC := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)

	ev := &Evidence{
		ID:             "tz-utc-norm-1",
		CorrelationID:  "corr",
		Timestamp:      instantUTC.In(west), // written in server-local time, as the gateway does
		TenantID:       "default",
		AgentID:        "caller-1",
		InvocationType: "gateway",
		PolicyDecision: PolicyDecision{Allowed: true},
		Execution:      Execution{ModelUsed: "gpt-4o", Cost: 1.0, Tokens: TokenUsage{Input: 10, Output: 20}},
	}
	require.NoError(t, store.Store(ctx, ev))

	// The record must fall in the UTC 9th window, not the UTC 8th.
	utc9Start := time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC)
	utc9End := utc9Start.Add(24 * time.Hour)
	utc8Start := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)

	on9th, err := store.CostByAgent(ctx, "default", utc9Start, utc9End)
	require.NoError(t, err)
	on8th, err := store.CostByAgent(ctx, "default", utc8Start, utc9Start)
	require.NoError(t, err)

	assert.InDelta(t, 1.0, on9th["caller-1"], 1e-9, "record's instant is 02:00 UTC on the 9th; it must bucket into the UTC 9th window")
	assert.InDelta(t, 0.0, on8th["caller-1"], 1e-9, "record must not leak into the UTC 8th window despite being written in a -08:00 zone")

	// The persisted struct is normalized to UTC (same instant, UTC location).
	assert.Equal(t, time.UTC, ev.Timestamp.Location())
	assert.True(t, ev.Timestamp.Equal(instantUTC))
}

// TestTimeline_TargetWithLocalOffsetBucketsInUTC guards the Timeline neighbor
// query (#216): its `target` is unmarshaled from evidence_json, so a pre-fix
// record retains the offset baked into its JSON string. Binding that raw to
// `timestamp < ?` / `timestamp > ?` compared lexicographically against the
// UTC-stored timestamp column, pulling the wrong before/after neighbors. The
// bound must be normalized to UTC.
func TestTimeline_TargetWithLocalOffsetBucketsInUTC(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	west := time.FixedZone("WEST", -8*3600)

	// Three records at 01:00, 02:00, 03:00 UTC on the 9th — the middle one is
	// the target. Store the neighbors normally (UTC-normalized on write).
	mkRecord := func(id string, ts time.Time) *Evidence {
		return &Evidence{
			ID: id, CorrelationID: "corr", Timestamp: ts, TenantID: "default", AgentID: "a1",
			InvocationType: "gateway", PolicyDecision: PolicyDecision{Allowed: true},
			Execution: Execution{ModelUsed: "gpt-4o", Cost: 1.0},
		}
	}
	nbrBefore := time.Date(2026, 7, 9, 1, 0, 0, 0, time.UTC)
	target := time.Date(2026, 7, 9, 2, 0, 0, 0, time.UTC)
	nbrAfter := time.Date(2026, 7, 9, 3, 0, 0, 0, time.UTC)

	require.NoError(t, store.Store(ctx, mkRecord("tl-before", nbrBefore)))
	require.NoError(t, store.Store(ctx, mkRecord("tl-after", nbrAfter)))

	// The target simulates a pre-fix record: its evidence_json carries a -08:00
	// offset (02:00 UTC == 18:00 on the 8th in WEST). We bypass Store's write-time
	// normalization by writing the raw row directly, mirroring rows already on disk.
	targetJSON, err := marshalEvidenceRaw(mkRecord("tl-target", target.In(west)))
	require.NoError(t, err)
	_, err = store.db.ExecContext(ctx,
		`INSERT INTO evidence (id, correlation_id, timestamp, tenant_id, agent_id, invocation_type, evidence_json, signature)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"tl-target", "corr", target.In(west), "default", "a1", "gateway", targetJSON, "sig")
	require.NoError(t, err)

	timeline, err := store.Timeline(ctx, "tl-target", 1, 1)
	require.NoError(t, err)

	var ids []string
	for _, e := range timeline {
		ids = append(ids, e.ID)
	}
	// Correct chronological order: before, target, after. Before the fix the
	// local-offset target string mis-sorted and the wrong neighbors were pulled.
	assert.Equal(t, []string{"tl-before", "tl-target", "tl-after"}, ids)
}

// marshalEvidenceRaw marshals an evidence record to JSON without going through
// Store's UTC normalization — used to simulate a pre-#216 on-disk record whose
// timestamp string carries a non-UTC offset.
func marshalEvidenceRaw(ev *Evidence) (string, error) {
	b, err := json.Marshal(ev)
	return string(b), err
}
