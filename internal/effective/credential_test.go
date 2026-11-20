package effective

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/registration"
	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/secrets"
)

const (
	keySecret = "hr-analytics-assistant-talon-key"
	vaultKey  = "0123456789abcdef0123456789abcdef"
)

// keyed is the People Analytics fixture whose agent file binds a Talon key,
// with a vault next to the evidence store, as a registered use case has.
type keyed struct {
	fixture
	t     *testing.T
	vault string
}

func newKeyed(t *testing.T) *keyed {
	t.Helper()
	f := peopleAnalytics(t)
	file := filepath.Join(f.agents, "hr-analytics-assistant", "agent.talon.yaml")
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	bound := strings.Replace(string(raw), "  version: \"1.0.0\"\n", "  version: \"1.0.0\"\n  key:\n    secret_name: "+keySecret+"\n", 1)
	require.NotEqual(t, string(raw), bound)
	require.NoError(t, os.WriteFile(file, []byte(bound), 0o600))
	return &keyed{fixture: f, t: t, vault: filepath.Join(f.dir, "secrets.db")}
}

func (k *keyed) store(do func(*secrets.SecretStore)) {
	k.t.Helper()
	s, err := secrets.NewSecretStore(k.vault, vaultKey)
	require.NoError(k.t, err)
	defer s.Close()
	do(s)
}

// stamp moves the write the vault recorded last to at. The vault stamps
// writes with the wall clock; the tests need a timeline they control, so
// they set the recorded time of each write (and nothing else).
func (k *keyed) stamp(at time.Time) time.Time {
	k.t.Helper()
	db, err := sql.Open("sqlite3", k.vault)
	require.NoError(k.t, err)
	defer db.Close()
	ctx := context.Background()
	_, err = db.ExecContext(ctx, `UPDATE secret_access_log SET timestamp = ? WHERE id = (
		SELECT id FROM secret_access_log WHERE secret_name = ? AND reason IN ('create', 'set') ORDER BY rowid DESC LIMIT 1)`, at, keySecret)
	require.NoError(k.t, err)
	_, err = db.ExecContext(ctx, `UPDATE secrets SET created_at = MIN(created_at, ?) WHERE name = ?`, at, keySecret)
	require.NoError(k.t, err)
	got := k.since()
	require.True(k.t, got.Equal(at), "the vault reports the write at %s, want %s", got, at)
	return got
}

// issue stores a NEW key under the secret name at the given time, as a
// registration does.
func (k *keyed) issue(value string, at time.Time) time.Time {
	k.t.Helper()
	k.store(func(s *secrets.SecretStore) {
		_, err := s.Create(context.Background(), keySecret, []byte(value), secrets.ACL{})
		require.NoError(k.t, err)
	})
	return k.stamp(at)
}

// replace writes another value under the same name (`talon secrets set`).
func (k *keyed) replace(value string, at time.Time) time.Time {
	k.t.Helper()
	k.store(func(s *secrets.SecretStore) {
		require.NoError(k.t, s.Set(context.Background(), keySecret, []byte(value), secrets.ACL{}))
	})
	return k.stamp(at)
}

func (k *keyed) revoke() {
	k.t.Helper()
	k.store(func(s *secrets.SecretStore) { require.NoError(k.t, s.Delete(context.Background(), keySecret)) })
}

func (k *keyed) since() time.Time {
	k.t.Helper()
	w, err := secrets.CredentialWritesReadOnly(context.Background(), k.vault, keySecret)
	require.NoError(k.t, err)
	return w.LastWrittenAt
}

func (k *keyed) inputs() Inputs {
	in := k.fixture.inputs()
	in.SecretsDB = k.vault
	return in
}

// request records one authenticated LLM gateway request under the policy the
// current files compile to.
func (k *keyed) request(id string, at time.Time) {
	k.t.Helper()
	agent, eff := k.currentDigests(k.t)
	k.put(k.t, id, "gateway", at, func(ev *evidence.Evidence) {
		ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: agent, Effective: eff}
	})
}

func (k *keyed) registered(id string, at time.Time) {
	k.t.Helper()
	k.put(k.t, id, registration.TypeRegistered, at, nil)
}

// process is a runtime record of a `talon serve` that started at started and
// activated its current generation at activated.
func process(id string, started, activated time.Time, running bool) runtimestatus.Process {
	p := runtimestatus.Process{
		Record: runtimestatus.Record{
			InstanceID: id, Roles: []string{runtimestatus.RoleGateway}, StartedAt: started, WrittenAt: activated.Add(time.Hour),
			Catalog: &runtimestatus.Catalog{ActivatedAt: activated, Agents: []runtimestatus.Agent{{Name: uc}}},
		},
		Assessed: runtimestatus.Running, Current: true,
	}
	if !running {
		stopped := activated.Add(time.Minute)
		p.Assessed, p.StoppedAt = "stopped", &stopped
	}
	return p
}

func withRuntime(in Inputs, ps ...runtimestatus.Process) Inputs {
	in.Runtime, in.RuntimeReadable = &runtimestatus.View{Processes: ps}, true
	return in
}

// #567 review. A use case can be removed and registered again under the
// same name, and its key can be replaced. Signed traffic of the earlier
// credential stays in the store. It must stay readable as history, and it
// must never be presented as a verified connection of the credential that
// exists now. Evidence does not record which credential a request
// presented, so the attribution is inferred from when the vault says the
// current value was written and when the serving process STARTED,
// conservatively: a process reads its keys from the vault when it starts,
// while a reload can keep the previous key (gateway.resolveAgentKey).
func TestVerification_TrafficIsAttributedToTheCurrentCredential(t *testing.T) {
	ctx := context.Background()
	// A timeline in the past, one hour between the credential writes.
	t1 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Second)
	t2 := t1.Add(time.Hour)

	t.Run("the original registration: its traffic verifies", func(t *testing.T) {
		k := newKeyed(t)
		w := k.issue("key-A", t1)
		k.registered("reg-A", w.Add(time.Second))
		k.request("req-1", w.Add(time.Minute))
		r, err := Build(ctx, k.inputs())
		require.NoError(t, err)
		c := r.Verification.Credential
		require.Equal(t, CredentialKnown, c.State)
		assert.Equal(t, keySecret, c.SecretName)
		assert.True(t, c.Since.Equal(w))
		assert.Equal(t, 1, c.Writes)
		require.NotNil(t, c.Registration)
		assert.Equal(t, "reg-A", c.Registration.EvidenceID)
		assert.Equal(t, "valid", c.Registration.Verification)
		g := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, CredentialCurrent, g.Credential, "no other credential ever existed under this name")
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
		// It stays verified whatever the runtime does later (a reload for
		// another use case): there is only one credential it can have used.
		later := withRuntime(k.inputs(), process("serve1", w.Add(-time.Hour), w.Add(2*time.Hour), true))
		r, err = Build(ctx, later)
		require.NoError(t, err)
		assert.Equal(t, CredentialCurrent, observation(t, r, BoundaryLLMGateway).Credential)
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
	})

	t.Run("re-registration: earlier traffic is history, not a verified connection", func(t *testing.T) {
		k := newKeyed(t)
		w1 := k.issue("key-A", t1)
		k.registered("reg-A", w1.Add(time.Second))
		k.request("req-old", w1.Add(time.Minute))
		// The use case is removed, its key revoked, and the same name is
		// registered again with identical policy configuration.
		k.revoke()
		w2 := k.issue("key-B", t2)
		require.True(t, w2.After(w1))
		k.registered("reg-B", w2.Add(time.Second))

		// Before any request with key B.
		r, err := Build(ctx, k.inputs())
		require.NoError(t, err)
		c := r.Verification.Credential
		assert.Equal(t, 2, c.Writes, "the vault's log remembers that another value existed under the name")
		assert.True(t, c.Since.Equal(w2))
		assert.Equal(t, "reg-B", c.Registration.EvidenceID, "the current registration")
		g := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, "req-old", g.EvidenceID, "the earlier request stays visible")
		assert.Equal(t, "valid", g.Verification)
		assert.Equal(t, PolicyMatchesCurrent, g.Policy, "its own facts are unchanged")
		assert.Equal(t, CredentialPrevious, g.Credential)
		assert.Contains(t, g.CredentialNote, "historical evidence")
		assert.Equal(t, ReadingTrafficHistorical, r.Verification.Reading.Code, "identical policy and a valid signature do not make it the new registration's traffic")
		assert.NotContains(t, r.Verification.Reading.Text, "Authenticated traffic observed under the expected policy")
		assert.Contains(t, r.Verification.Reading.Text, "No authenticated traffic since the current credential was stored")
		require.NotNil(t, r.LastDecision, "history stays available for investigation")
		assert.Equal(t, "req-old", r.LastDecision.EvidenceID)
		assert.Contains(t, strings.Join(r.Verification.NotEstablished, "\n"), "that the application uses the credential stored now")

		// A delayed request from the runtime generation that was built
		// BEFORE the new registration (its key A is still valid there: the
		// file is byte-identical, so no reload happened). It is newer than
		// the registration and proves nothing about key B.
		k.request("req-delayed", w2.Add(time.Minute))
		stale := withRuntime(k.inputs(), process("serve1", w1.Add(-time.Hour), w1.Add(2*time.Second), true))
		r, err = Build(ctx, stale)
		require.NoError(t, err)
		g = observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, "req-delayed", g.EvidenceID)
		assert.Equal(t, CredentialNotEstablished, g.Credential)
		assert.Contains(t, g.CredentialNote, "a request with the earlier key would look the same")
		assert.Equal(t, ReadingTrafficCredentialUnproven, r.Verification.Reading.Code)
		assert.Equal(t, RuntimePredatesCurrent, r.Verification.Credential.Runtime)
		assert.Contains(t, r.Verification.Reading.Text, "does NOT hold the credential stored now")
		// Without runtime records the same request is not established either.
		r, err = Build(ctx, k.inputs())
		require.NoError(t, err)
		assert.Equal(t, CredentialNotEstablished, observation(t, r, BoundaryLLMGateway).Credential)

		// The process restarts (it now holds key B) and a request arrives:
		// that one is the new registration's traffic.
		restarted := w2.Add(2 * time.Minute)
		k.request("req-new", restarted.Add(time.Minute))
		fresh := withRuntime(k.inputs(), process("serve1", w1.Add(-time.Hour), w1.Add(2*time.Second), false), process("serve2", restarted, restarted, true))
		r, err = Build(ctx, fresh)
		require.NoError(t, err)
		g = observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, "req-new", g.EvidenceID)
		assert.Equal(t, CredentialCurrent, g.Credential)
		assert.Equal(t, RuntimeHoldsCurrent, r.Verification.Credential.Runtime)
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
	})

	t.Run("a reload after the new credential does not establish it; a process started after it does, and stays so", func(t *testing.T) {
		k := newKeyed(t)
		w1 := k.issue("key-A", t1)
		k.revoke()
		w2 := k.issue("key-B", t2)
		reloaded := w2.Add(time.Minute)
		// The process started long before; its current generation was
		// activated after key B was stored. A rebuild reads the vault again,
		// but keeps the previous generation's key when that read fails
		// (gateway.resolveAgentKey), and no record says which happened: the
		// process may still accept key A.
		in := withRuntime(k.inputs(), process("serve1", w1.Add(-time.Hour), reloaded, true))
		k.request("before-reload", w2.Add(30*time.Second))
		r, err := Build(ctx, in)
		require.NoError(t, err)
		assert.Equal(t, CredentialNotEstablished, observation(t, r, BoundaryLLMGateway).Credential)
		assert.Equal(t, RuntimeNotEstablished, r.Verification.Credential.Runtime, "a rebuilt generation is not proof that the new key was read")
		assert.Contains(t, r.Verification.Credential.RuntimeNote, "keeps the previous key when that read fails")
		assert.Contains(t, r.Verification.Reading.Text, "that it holds the credential stored now is not established")
		k.request("after-reload", reloaded.Add(time.Second))
		r, err = Build(ctx, in)
		require.NoError(t, err)
		g := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, "after-reload", g.EvidenceID)
		assert.Equal(t, CredentialNotEstablished, g.Credential, "the time of a record after a reload is not proof of the current credential")
		assert.Contains(t, g.CredentialNote, "had started before that write")
		assert.Equal(t, ReadingTrafficCredentialUnproven, r.Verification.Reading.Code)

		// A process that STARTED after key B was stored can only hold key B.
		restart := reloaded.Add(time.Minute)
		k.request("after-restart", restart.Add(time.Second))
		started := process("serve2", restart, restart, true)
		r, err = Build(ctx, withRuntime(k.inputs(), process("serve1", w1.Add(-time.Hour), reloaded, false), started))
		require.NoError(t, err)
		assert.Equal(t, CredentialCurrent, observation(t, r, BoundaryLLMGateway).Credential)
		assert.Equal(t, RuntimeHoldsCurrent, r.Verification.Credential.Runtime)
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
		// It stays verified when that process reloads later for an unrelated
		// reason (another use case is registered): the proof is the start
		// time, which does not change.
		later := process("serve2", restart, restart.Add(3*time.Hour), true)
		r, err = Build(ctx, withRuntime(k.inputs(), later))
		require.NoError(t, err)
		assert.Equal(t, CredentialCurrent, observation(t, r, BoundaryLLMGateway).Credential)
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
		// When no runtime record covers the moment any more (records of
		// stopped processes are pruned), it is no longer established, and
		// the note says why.
		gone := process("serve3", restart.Add(5*time.Hour), restart.Add(5*time.Hour), true)
		r, err = Build(ctx, withRuntime(k.inputs(), gone))
		require.NoError(t, err)
		g = observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, CredentialNotEstablished, g.Credential)
		assert.Contains(t, g.CredentialNote, "no runtime record covers that moment")
	})

	t.Run("key replacement: earlier traffic does not say that the replacement works", func(t *testing.T) {
		k := newKeyed(t)
		w1 := k.issue("key-A", t1)
		started := w1.Add(time.Second)
		k.request("req-old-key", w1.Add(time.Minute))
		running := process("serve1", started, started, true)
		r, err := Build(ctx, withRuntime(k.inputs(), running))
		require.NoError(t, err)
		require.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)

		// `talon secrets set`: the value is replaced; the process is not
		// restarted yet and still accepts the old key.
		w2 := k.replace("key-B", t2)
		require.True(t, w2.After(w1))
		r, err = Build(ctx, withRuntime(k.inputs(), running))
		require.NoError(t, err)
		g := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, CredentialPrevious, g.Credential)
		assert.Equal(t, ReadingTrafficHistorical, r.Verification.Reading.Code)
		assert.Equal(t, RuntimePredatesCurrent, r.Verification.Credential.Runtime, "a change of the secret alone triggers no reload")
		assert.Contains(t, r.Verification.Credential.RuntimeNote, "Restart it")
		// The old key still works on the running process: that request is
		// newer than the replacement and is not counted for it.
		k.request("req-old-key-after", w2.Add(time.Minute))
		r, err = Build(ctx, withRuntime(k.inputs(), running))
		require.NoError(t, err)
		assert.Equal(t, CredentialNotEstablished, observation(t, r, BoundaryLLMGateway).Credential)
		assert.Equal(t, ReadingTrafficCredentialUnproven, r.Verification.Reading.Code)

		// After the restart, a request can only have used the replacement.
		restart := w2.Add(2 * time.Minute)
		k.request("req-new-key", restart.Add(time.Second))
		r, err = Build(ctx, withRuntime(k.inputs(), process("serve2", restart, restart, true)))
		require.NoError(t, err)
		assert.Equal(t, CredentialCurrent, observation(t, r, BoundaryLLMGateway).Credential)
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
	})

	t.Run("a use case configured by hand, without a registration record", func(t *testing.T) {
		k := newKeyed(t)
		k.store(func(s *secrets.SecretStore) {
			require.NoError(t, s.Set(ctx, keySecret, []byte("hand-made-key"), secrets.ACL{}))
		})
		w := k.stamp(t1)
		k.request("req-1", w.Add(time.Minute))
		r, err := Build(ctx, k.inputs())
		require.NoError(t, err)
		c := r.Verification.Credential
		assert.Nil(t, c.Registration, "no 'talon agents add' record exists, and none is required")
		assert.Equal(t, CredentialKnown, c.State)
		assert.Equal(t, 1, c.Writes)
		assert.Equal(t, CredentialCurrent, observation(t, r, BoundaryLLMGateway).Credential)
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
	})

	t.Run("a vault whose log holds no write for the name: when the value was stored is not known", func(t *testing.T) {
		k := newKeyed(t)
		w := k.issue("key-A", t1)
		k.request("req-1", w.Add(time.Minute))
		db, err := sql.Open("sqlite3", k.vault)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, `DELETE FROM secret_access_log WHERE secret_name = ?`, keySecret)
		require.NoError(t, err)
		require.NoError(t, db.Close())
		r, err := Build(ctx, withRuntime(k.inputs(), process("serve1", w.Add(time.Second), w.Add(time.Second), true)))
		require.NoError(t, err)
		assert.Equal(t, 0, r.Verification.Credential.Writes)
		g := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, CredentialUnknown, g.Credential, "an unlogged later write cannot be excluded")
		assert.Contains(t, g.CredentialNote, "holds no write for this secret name")
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code, "the record's own facts still hold, with the caveat")
		assert.Contains(t, r.Verification.Reading.Text, "which credential it was authenticated with is not established")
	})

	t.Run("what cannot be read is unknown, and is said", func(t *testing.T) {
		k := newKeyed(t)
		w := k.issue("key-A", t1)
		k.request("req-1", w.Add(time.Minute))

		// No vault given (a reader without access to it).
		r, err := Build(ctx, k.fixture.inputs())
		require.NoError(t, err)
		assert.Equal(t, CredentialUnread, r.Verification.Credential.State)
		g := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, CredentialUnknown, g.Credential)
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code, "the record's own facts still hold")
		assert.Contains(t, r.Verification.Reading.Text, "which credential it was authenticated with is not established")

		// The key was removed from a vault that can be read: the earlier
		// request is history, not a (caveated) verified connection.
		k.revoke()
		r, err = Build(ctx, k.inputs())
		require.NoError(t, err)
		assert.Equal(t, CredentialAbsent, r.Verification.Credential.State)
		assert.Contains(t, r.Verification.Credential.Note, "no credential of this use case is stored now")
		g = observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, CredentialPrevious, g.Credential)
		assert.Contains(t, g.CredentialNote, "no longer stored")
		assert.Equal(t, ReadingTrafficHistorical, r.Verification.Reading.Code)
		assert.Contains(t, r.Verification.Reading.Text, "No credential of this use case is stored now")
		assert.NotContains(t, r.Verification.Reading.Text, "Authenticated traffic observed")

		// A use case whose file binds no key at all.
		f := peopleAnalytics(t)
		f.put(t, "req-1", "gateway", time.Now().UTC(), nil)
		in := f.inputs()
		in.SecretsDB = k.vault
		r, err = Build(ctx, in)
		require.NoError(t, err)
		assert.Equal(t, CredentialNoKey, r.Verification.Credential.State)
		assert.Equal(t, CredentialUnknown, observation(t, r, BoundaryLLMGateway).Credential)
	})

	t.Run("a verified workload identity is not a use of the key", func(t *testing.T) {
		k := newKeyed(t)
		w1 := k.issue("key-A", t1)
		k.revoke()
		w2 := k.issue("key-B", t2)
		agent, eff := k.currentDigests(t)
		k.put(t, "delegated", "gateway", w1.Add(time.Second), func(ev *evidence.Evidence) {
			ev.WorkloadIdentity = &evidence.WorkloadIdentity{Status: "verified", Runtime: "openshell", AuthMethod: "hop_assertion"}
			ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: agent, Effective: eff}
		})
		_ = w2
		r, err := Build(ctx, k.inputs())
		require.NoError(t, err)
		g := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, CredentialNotApplicable, g.Credential, "its identity never depended on the key")
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
	})
}

// The vault facts come from a read-only connection: no schema statement, no
// access-log row and no value is read.
func TestCredentialFacts_ReadTheVaultReadOnly(t *testing.T) {
	ctx := context.Background()
	k := newKeyed(t)
	w := k.issue("key-A", time.Now().UTC().Add(-time.Hour).Truncate(time.Second))
	k.request("req-1", w.Add(time.Minute))
	before, err := os.ReadFile(k.vault)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		r, err := Build(ctx, k.inputs())
		require.NoError(t, err)
		raw, err := os.ReadFile(k.vault)
		require.NoError(t, err)
		require.Equal(t, before, raw, "reading the credential facts changes nothing in the vault file")
		require.NotContains(t, r.Verification.Credential.Note+r.Verification.Credential.RuntimeNote, "key-A")
	}
	// A path where no vault file is visible (a reader without the vault, a
	// console on another host): nothing is concluded from it, in particular
	// not that the key is gone, and nothing is created.
	in := k.inputs()
	in.SecretsDB = filepath.Join(t.TempDir(), "absent.db")
	r, err := Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, CredentialUnread, r.Verification.Credential.State)
	assert.Contains(t, r.Verification.Credential.Note, "no vault file is visible to this process")
	g := observation(t, r, BoundaryLLMGateway)
	assert.Equal(t, CredentialUnknown, g.Credential)
	assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code, "the record's own facts hold, with the caveat")
	assert.Contains(t, r.Verification.Reading.Text, "which credential it was authenticated with is not established")
	_, statErr := os.Stat(in.SecretsDB)
	assert.True(t, os.IsNotExist(statErr))
}
