package registration

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

const testKey = "registration-test-signing-key-0001"

type recorder struct {
	t     *testing.T
	store *evidence.Store
	now   time.Time
	n     int
}

func newRecorder(t *testing.T, path string) *recorder {
	t.Helper()
	store, err := evidence.NewStore(path, testKey)
	require.NoError(t, err)
	return &recorder{t: t, store: store, now: time.Now().UTC().Add(-time.Hour)}
}

func (r *recorder) put(tenant, name, correlation, typ string, reasons ...string) string {
	r.t.Helper()
	r.n++
	id := fmt.Sprintf("al_%s_%s_%d", typ, correlation, r.n)
	require.NoError(r.t, r.store.Store(context.Background(), &evidence.Evidence{
		ID: id, CorrelationID: correlation, TenantID: tenant, AgentID: name, Timestamp: r.now.Add(time.Duration(r.n) * time.Second), InvocationType: typ,
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: typ, Reasons: reasons},
	}))
	return id
}

// An intent without a terminal record is unresolved; a completion or a
// rollback under the same correlation id, tenant and use case resolves it.
// The lookup is scoped by use case, reads operator records only, verifies
// each intent, works on a read-only connection and writes nothing.
func TestFindUnresolved(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "evidence.db")
	r := newRecorder(t, path)
	commit := Commitments{SecretName: "crashed-talon-key", KeyOwnershipToken: "dG9rZW4tdG9rZW4t", AgentFile: "/srv/agents/crashed/agent.talon.yaml", FileSHA256: "abc123"}
	r.put("acme", "done", "c-done", TypeIntent)
	r.put("acme", "done", "c-done", TypeRegistered)
	r.put("acme", "undone", "c-undone", TypeIntent)
	r.put("acme", "undone", "c-undone", TypeRolledBack)
	first := r.put("acme", "crashed", "c-crash-1", TypeIntent)
	second := r.put("acme", "crashed", "c-crash-2", TypeIntent, append([]string{"company policy: configured"}, commit.Reasons()...)...)
	other := r.put("acme", "other", "c-other", TypeIntent)
	// A terminal record of ANOTHER use case or tenant that happens to carry
	// the same correlation id resolves nothing (scope consistency).
	scoped := r.put("acme", "scoped", "c-shared", TypeIntent)
	r.put("acme", "someone-else", "c-shared", TypeRegistered)
	r.put("globex", "scoped", "c-shared", TypeRolledBack)
	// Traffic and other operator events of the same use case are irrelevant.
	r.put("acme", "crashed", "c-traffic", "gateway")
	r.put("acme", "crashed", "c-enabled", "agent_enabled")
	require.NoError(t, r.store.Close())

	ro, err := evidence.OpenReadOnly(path, testKey)
	require.NoError(t, err)
	defer ro.Close()

	got, err := FindUnresolved(ctx, ro, "crashed")
	require.NoError(t, err)
	require.True(t, got.Complete)
	require.Len(t, got.Unresolved, 2)
	require.Equal(t, second, got.Unresolved[0].IntentID, "newest first")
	require.Equal(t, first, got.Unresolved[1].IntentID)
	require.Equal(t, "crashed", got.Unresolved[0].Name)
	require.Equal(t, "acme", got.Unresolved[0].Tenant)
	require.Equal(t, "c-crash-2", got.Unresolved[0].Correlation)
	require.False(t, got.Unresolved[0].At.IsZero())
	require.True(t, got.Unresolved[0].Verified)
	require.Equal(t, commit, got.Unresolved[0].Commitments, "what the signed intent committed to")
	require.Equal(t, Commitments{}, got.Unresolved[1].Commitments, "an intent without commitments proves ownership of nothing")

	for _, name := range []string{"done", "undone", "never-registered"} {
		got, err = FindUnresolved(ctx, ro, name)
		require.NoError(t, err)
		require.Empty(t, got.Unresolved, name)
		require.True(t, got.Complete)
	}
	got, err = FindUnresolved(ctx, ro, "scoped")
	require.NoError(t, err)
	require.Len(t, got.Unresolved, 1, "a terminal record of another use case or tenant does not resolve this intent")
	require.Equal(t, scoped, got.Unresolved[0].IntentID)

	all, err := FindUnresolved(ctx, ro, "")
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, in := range all.Unresolved {
		ids[in.IntentID] = true
	}
	require.Equal(t, map[string]bool{first: true, second: true, other: true, scoped: true}, ids, "every use case, and only the unresolved intents")

	// Every registration record type is an operator event: none of them can
	// ever be counted as application traffic.
	for _, typ := range []string{TypeIntent, TypeRegistered, TypeRolledBack} {
		require.Equal(t, evidence.ClassOperatorEvent, evidence.RecordClassOf(typ), typ)
		require.False(t, evidence.IsRequestClass(typ), typ)
	}
}

// #567 review. An unresolved registration stays visible however many
// registrations follow it (the earlier lookup read the 50 newest intents
// only); a store with more unresolved registrations than one lookup reads
// says that its list is partial; a tampered intent is listed as unverified;
// and the lookup starts from the intents, not from the whole store.
func TestFindUnresolved_OldIntentsStayVisibleAndPartialListsSaySo(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "evidence.db")
	r := newRecorder(t, path)
	old := r.put("acme", "abandoned", "c-old", TypeIntent)
	for i := 0; i < 75; i++ {
		c := fmt.Sprintf("c-ok-%03d", i)
		name := fmt.Sprintf("app-%03d", i)
		r.put("acme", name, c, TypeIntent)
		r.put("acme", name, c, TypeRegistered)
		r.put("acme", name, "t-"+c, "gateway")
	}
	got, err := FindUnresolved(ctx, r.store, "")
	require.NoError(t, err)
	require.True(t, got.Complete)
	require.Len(t, got.Unresolved, 1, "75 completed registrations later, the old unresolved one is still found")
	require.Equal(t, old, got.Unresolved[0].IntentID)
	got, err = FindUnresolved(ctx, r.store, "abandoned")
	require.NoError(t, err)
	require.Len(t, got.Unresolved, 1)

	// The statement starts from the registration intents (partial index)
	// and searches each intent's terminal records by index: no scan of the
	// store.
	db := r.store.DB()
	rows, err := db.QueryContext(ctx, `EXPLAIN QUERY PLAN SELECT e.evidence_json FROM evidence e
		 WHERE e.invocation_type = 'agent_registration_intent' AND (? = '' OR e.agent_id = ?)
		   AND NOT EXISTS (
		     SELECT 1 FROM evidence t
		     WHERE t.correlation_id = e.correlation_id
		       AND t.invocation_type IN ('agent_registered', 'agent_registration_rolled_back')
		       AND t.tenant_id = e.tenant_id AND t.agent_id = e.agent_id)
		 ORDER BY e.timestamp DESC, e.id DESC LIMIT ?`, "", "", 10)
	require.NoError(t, err)
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &unused, &detail))
		plan = append(plan, detail)
	}
	require.NoError(t, rows.Close())
	joined := strings.Join(plan, " | ")
	require.Contains(t, joined, "USING INDEX idx_evidence_registration_intent", joined)
	require.Contains(t, joined, "SEARCH t USING INDEX", "each intent's terminal records are an index search: %s", joined)
	require.NotContains(t, joined, "SCAN t", joined)

	// A tampered intent is still listed, as unverified.
	_, err = db.ExecContext(ctx, `UPDATE evidence SET evidence_json = replace(evidence_json, '"agent_id":"abandoned"', '"agent_id":"abandoned","team":"x"') WHERE id = ?`, old)
	require.NoError(t, err)
	got, err = FindUnresolved(ctx, r.store, "abandoned")
	require.NoError(t, err)
	require.Len(t, got.Unresolved, 1)
	require.False(t, got.Unresolved[0].Verified, "a record changed after signing does not verify")

	// More unresolved registrations than one lookup reads: the list is
	// partial and says so; it is never a definitive answer.
	for i := 0; i < maxUnresolved+5; i++ {
		r.put("acme", "flood", fmt.Sprintf("c-flood-%03d", i), TypeIntent)
	}
	got, err = FindUnresolved(ctx, r.store, "")
	require.NoError(t, err)
	require.False(t, got.Complete)
	require.Len(t, got.Unresolved, maxUnresolved)
	require.NoError(t, r.store.Close())

	// A store that cannot be read is an error, never "none".
	closed, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "absent.db")+"?mode=ro")
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	_, err = FindUnresolved(ctx, r.store, "")
	require.Error(t, err, "a closed store")
}
