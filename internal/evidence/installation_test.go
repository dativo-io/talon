package evidence

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #593: an installation event is identified by its record provenance — the
// reserved namespace AND a registered installation type — never by the
// tenant name alone.
func TestIsInstallationEvent(t *testing.T) {
	for _, c := range []struct {
		tenant, typ string
		want        bool
	}{
		{InstallationTenantID, InvocationTypeConfigReload, true},
		{InstallationTenantID, InvocationTypeRecoveryResumed, true},
		{InstallationTenantID, "mode_change", true}, // legacy talon enforce (#442)
		{InstallationTenantID, "gateway", false},    // a customer tenant named "system"
		{InstallationTenantID, InvocationTypeActionLifecycle, false},
		{InstallationTenantID, "", false},
		{"default", InvocationTypeConfigReload, false},
		{"acme", InvocationTypeRecoveryResumed, false},
		{"System", InvocationTypeConfigReload, false},
	} {
		assert.Equal(t, c.want, IsInstallationEvent(c.tenant, c.typ), "%q/%q", c.tenant, c.typ)
	}
	// Every installation type is non-request class: none of them can count
	// as traffic, denials or spend.
	for typ := range installationEventType {
		assert.False(t, IsRequestClass(typ), typ)
	}
}

func installationStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "evidence.db"), "installation-test-signing-key-0001")
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func putRecord(t *testing.T, s *Store, id, tenant, agent, typ string, at time.Time, allowed bool) {
	t.Helper()
	require.NoError(t, s.Store(context.Background(), &Evidence{
		ID: id, CorrelationID: id, Timestamp: at, TenantID: tenant, AgentID: agent, InvocationType: typ,
		PolicyDecision: PolicyDecision{Allowed: allowed},
	}))
}

func ids(evs []Evidence) []string {
	out := make([]string, 0, len(evs))
	for i := range evs {
		out = append(out, evs[i].ID)
	}
	return out
}

func TestStore_InstallationEventsAreNotTenantActivity(t *testing.T) {
	ctx := context.Background()
	s := installationStore(t)
	t0 := time.Now().UTC().Add(-time.Hour)
	putRecord(t, s, "d1", "default", "hr-analytics-assistant", "gateway", t0, true)
	putRecord(t, s, "cr-ok", InstallationTenantID, "talon-serve", InvocationTypeConfigReload, t0.Add(time.Minute), true)
	putRecord(t, s, "cr-bad", InstallationTenantID, "talon-serve", InvocationTypeConfigReload, t0.Add(2*time.Minute), false)
	putRecord(t, s, "rr", InstallationTenantID, "talon-backup", InvocationTypeRecoveryResumed, t0.Add(3*time.Minute), true)
	putRecord(t, s, "mc", InstallationTenantID, "talon-cli", "mode_change", t0.Add(4*time.Minute), true)
	putRecord(t, s, "a1", "acme", "acme-bot", "gateway", t0.Add(5*time.Minute), true) // historical: no agent today

	got, err := s.ListActivityTenantIDs(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"acme", "default"}, got, "installation events make no tenant")
	all, err := s.ListTenantIDs(ctx, time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, []string{"acme", "default", InstallationTenantID}, all, "the records themselves are untouched")

	inst, err := s.ListInstallationEvents(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"mc", "rr", "cr-bad", "cr-ok"}, ids(inst), "newest first, installation events only")
	inst, err = s.ListInstallationEvents(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"mc", "rr"}, ids(inst), "bounded")

	act, err := s.ListActivity(ctx, "", "", time.Time{}, time.Time{}, 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"a1", "d1"}, ids(act))
	every, err := s.List(ctx, "", "", time.Time{}, time.Time{}, 0)
	require.NoError(t, err)
	assert.Len(t, every, 6, "List is unchanged: it still returns every record")

	// A customer tenant named "system" (a valid tenant_id): its own records
	// are activity; the installation's records under the same name are not.
	putRecord(t, s, "sys-traffic", InstallationTenantID, "payroll-bot", "gateway", t0.Add(6*time.Minute), true)
	got, err = s.ListActivityTenantIDs(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"acme", "default", InstallationTenantID}, got)
	act, err = s.ListActivity(ctx, InstallationTenantID, "", time.Time{}, time.Time{}, 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"sys-traffic"}, ids(act), "never silently discarded")
	inst, err = s.ListInstallationEvents(ctx, 10)
	require.NoError(t, err)
	assert.NotContains(t, ids(inst), "sys-traffic")

	// Read-only: the records still verify.
	for _, id := range []string{"cr-ok", "cr-bad", "rr", "mc", "sys-traffic"} {
		d, err := s.Detail(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "valid", string(d.Verification.State), id)
	}
}

func TestStore_NoInstallationEvents(t *testing.T) {
	ctx := context.Background()
	s := installationStore(t)
	got, err := s.ListActivityTenantIDs(ctx)
	require.NoError(t, err)
	assert.Empty(t, got)
	inst, err := s.ListInstallationEvents(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, inst)
}
