package registration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

// An intent without a terminal record is an interrupted registration; a
// completion or a rollback under the same correlation id ends it. The
// lookup is scoped by use case, reads operator records only, works on a
// read-only connection and writes nothing.
func TestFindInterrupted(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "evidence.db")
	const key = "registration-test-signing-key-0001"
	store, err := evidence.NewStore(path, key)
	require.NoError(t, err)
	now := time.Now().UTC()
	n := 0
	put := func(name, correlation, typ string) string {
		n++
		id := "al_" + typ + "_" + correlation
		require.NoError(t, store.Store(ctx, &evidence.Evidence{
			ID: id, CorrelationID: correlation, TenantID: "acme", AgentID: name, Timestamp: now.Add(time.Duration(n) * time.Second), InvocationType: typ,
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: typ},
		}))
		return id
	}
	put("done", "c-done", TypeIntent)
	put("done", "c-done", TypeRegistered)
	put("undone", "c-undone", TypeIntent)
	put("undone", "c-undone", TypeRolledBack)
	firstDangling := put("crashed", "c-crash-1", TypeIntent)
	secondDangling := put("crashed", "c-crash-2", TypeIntent)
	otherDangling := put("other", "c-other", TypeIntent)
	// Traffic and other operator events of the same use case are irrelevant.
	put("crashed", "c-traffic", "gateway")
	put("crashed", "c-enabled", "agent_enabled")
	require.NoError(t, store.Close())

	ro, err := evidence.OpenReadOnly(path, key)
	require.NoError(t, err)
	defer ro.Close()

	got, err := FindInterrupted(ctx, ro, "crashed")
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, secondDangling, got[0].IntentID, "newest first")
	require.Equal(t, firstDangling, got[1].IntentID)
	require.Equal(t, "crashed", got[0].Name)
	require.Equal(t, "acme", got[0].Tenant)
	require.Equal(t, "c-crash-2", got[0].Correlation)
	require.False(t, got[0].At.IsZero())

	for _, name := range []string{"done", "undone", "never-registered"} {
		got, err = FindInterrupted(ctx, ro, name)
		require.NoError(t, err)
		require.Empty(t, got, name)
	}

	all, err := FindInterrupted(ctx, ro, "")
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, in := range all {
		ids[in.IntentID] = true
	}
	require.Equal(t, map[string]bool{firstDangling: true, secondDangling: true, otherDangling: true}, ids, "every use case, and only the dangling intents")

	// Every registration record type is an operator event: none of them can
	// ever be counted as application traffic.
	for _, typ := range []string{TypeIntent, TypeRegistered, TypeRolledBack} {
		require.Equal(t, evidence.ClassOperatorEvent, evidence.RecordClassOf(typ), typ)
		require.False(t, evidence.IsRequestClass(typ), typ)
	}
}
