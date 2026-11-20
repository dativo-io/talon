package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/registration"
	"github.com/dativo-io/talon/internal/secrets"
)

// Regressions of the #567 review: concurrent registration and interruption
// recovery, and file publication ownership.

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func shortLockWait(t *testing.T) {
	t.Helper()
	old := registrationLockWait
	registrationLockWait = 150 * time.Millisecond
	t.Cleanup(func() { registrationLockWait = old })
}

// The reviewed interleaving. Registration A writes its signed intent and is
// still ALIVE, paused before it creates its key. Registration B starts for
// the same name. Before the lock B saw "an intent without a terminal record
// and no artifacts", recorded A as rolled back and went on, after which A
// completed too: the evidence said A was rolled back although A registered.
//
// Now B cannot get past the lock: it waits, gives up, and has changed
// nothing. A's intent is reported as IN PROGRESS, never as interrupted, by
// B, by a dry run and by `talon doctor`. A registration that names another
// tenant or another agents_dir takes the same lock. A then completes, and
// the evidence is one intent and one completion.
func TestAgentsAdd_LiveRegistrationIsInProgressNeverInterrupted(t *testing.T) {
	ctx := context.Background()
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	agentsAddTenant = "acme"
	shortLockWait(t)

	paused, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	registrationFault = func(point string) error {
		if point == stepIntentRecorded {
			once.Do(func() {
				close(paused)
				<-resume
			})
		}
		return nil
	}
	var outA bytes.Buffer
	doneA := make(chan error, 1)
	go func() { doneA <- runAgentsAdd(ctx, &outA, cfg, "refund-bot") }()
	<-paused

	// A: intent written, alive, nothing created yet.
	in := unresolved(t, cfg, "refund-bot")
	require.Len(t, in, 1)
	_, hasKey := vaultValue(t, cfg, "refund-bot-talon-key")
	require.False(t, hasKey)
	require.False(t, pathExists(filepath.Join(agentsDir, "refund-bot")))
	require.Equal(t, registration.LockHeld, registration.Probe(cfg.DataDir))

	// B, same name: refused at the lock. It names A's state correctly.
	assertUntouched := func(why string) {
		t.Helper()
		recs := registrationRecords(t, cfg, "acme", "refund-bot")
		require.Len(t, recs[registration.TypeIntent], 1, why)
		require.Empty(t, recs[registration.TypeRolledBack], "%s: a live registration is never recorded as rolled back", why)
		require.Empty(t, recs[registration.TypeRegistered], why)
		_, k := vaultValue(t, cfg, "refund-bot-talon-key")
		require.False(t, k, why)
		require.Empty(t, registrationRecords(t, cfg, "other", "refund-bot"), why)
	}
	var outB bytes.Buffer
	errB := runAgentsAdd(ctx, &outB, cfg, "refund-bot")
	require.ErrorIs(t, errB, registration.ErrLockBusy)
	require.ErrorContains(t, errB, "in progress, not interrupted")
	require.Empty(t, printedKeyRe.FindString(outB.String()+errB.Error()))
	assertUntouched("B with the same name")

	// The same name under another tenant, and through another agents_dir:
	// neither argument is a way around the lock, because the vault and the
	// evidence store are the same.
	agentsAddTenant = "other"
	errB = runAgentsAdd(ctx, &outB, cfg, "refund-bot")
	require.ErrorIs(t, errB, registration.ErrLockBusy, "another tenant argument")
	agentsAddTenant = "acme"
	elsewhere := *cfg
	elsewhere.AgentsDir = filepath.Join(t.TempDir(), "other-agents")
	errB = runAgentsAdd(ctx, &outB, &elsewhere, "refund-bot")
	require.ErrorIs(t, errB, registration.ErrLockBusy, "another agents_dir")
	require.False(t, pathExists(elsewhere.AgentsDir), "the refused registration created no directory there")
	assertUntouched("B through another tenant or agents_dir")

	// A dry run reads only, and says that a registration is running.
	agentsAddDryRun = true
	var dry bytes.Buffer
	require.NoError(t, runAgentsAdd(ctx, &dry, cfg, "refund-bot"))
	agentsAddDryRun = false
	require.Contains(t, dry.String(), "a registration is running now")
	require.Contains(t, dry.String(), in[0].IntentID)
	assertUntouched("a dry run")

	// `talon doctor` inspects the active registration: in progress.
	check := checkRegistrationsForTest(t, cfg)
	require.Equal(t, "pass", check.Status)
	require.Contains(t, check.Message, "IN PROGRESS")
	require.Contains(t, check.Message, in[0].IntentID)
	require.NotContains(t, check.Message, "INTERRUPTED")

	// A continues and completes.
	close(resume)
	require.NoError(t, <-doneA)
	key := printedKeyRe.FindString(outA.String())
	require.NotEmpty(t, key)
	stored, _ := vaultValue(t, cfg, "refund-bot-talon-key")
	require.Equal(t, key, stored)
	require.True(t, registered(t, agentsDir, "refund-bot"))
	require.True(t, registered(t, agentsDir, "support"), "the existing application is unaffected")
	recs := registrationRecords(t, cfg, "acme", "refund-bot")
	require.Len(t, recs[registration.TypeIntent], 1)
	require.Len(t, recs[registration.TypeRegistered], 1)
	require.Empty(t, recs[registration.TypeRolledBack], "A registered: no record says it was rolled back")
	require.Equal(t, recs[registration.TypeIntent][0].CorrelationID, recs[registration.TypeRegistered][0].CorrelationID)
	require.Empty(t, unresolved(t, cfg, "refund-bot"))
	require.Equal(t, registration.LockFree, registration.Probe(cfg.DataDir))
	require.Equal(t, "pass", checkRegistrationsForTest(t, cfg).Status)

	// B, retried now, finds the name registered and writes nothing.
	errB = runAgentsAdd(ctx, &outB, cfg, "refund-bot")
	require.ErrorContains(t, errB, "already registered")
	require.Len(t, registrationRecords(t, cfg, "acme", "refund-bot")[registration.TypeIntent], 1)
}

// Found by the five-process acceptance race (#567 review). Registration B
// planned BEFORE it took the lock, saw the key that the still-running
// registration A had just stored, and refused with "vault secret ... already
// exists ... remove the existing secret deliberately with 'talon secrets
// delete ...'": a deletion hint about the key of a live registration.
//
// Whether a name is free is now decided under the lock only. While A runs,
// whatever A has created so far, B is refused at the lock ("in progress")
// and a dry run says that a registration is running; neither mentions a
// deletion or calls the name taken. After A has completed, B is refused
// because the name is registered.
func TestAgentsAdd_ARunningRegistrationIsNeverJudgedByItsArtifacts(t *testing.T) {
	for _, step := range []string{stepKeyStored, stepFilePublished, stepFleetValidated} {
		t.Run("A paused after "+step, func(t *testing.T) {
			ctx := context.Background()
			cfg, agentsDir := setupAddFleet(t)
			resetAgentsAddFlags(t)
			agentsAddTenant = "acme"
			shortLockWait(t)

			paused, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			registrationFault = func(point string) error {
				if point == step {
					once.Do(func() {
						close(paused)
						<-resume
					})
				}
				return nil
			}
			var outA bytes.Buffer
			doneA := make(chan error, 1)
			go func() { doneA <- runAgentsAdd(ctx, &outA, cfg, "refund-bot") }()
			<-paused
			_, hasKey := vaultValue(t, cfg, "refund-bot-talon-key")
			require.True(t, hasKey, "A has stored its key and is still running")

			noJudgment := func(text string) {
				t.Helper()
				for _, forbidden := range []string{"secrets delete", "already exists", "already registered", "rm -r"} {
					require.NotContains(t, text, forbidden, "a running registration's work in progress was judged")
				}
			}
			// B, a real run: refused at the lock, nothing judged or changed.
			var outB bytes.Buffer
			errB := runAgentsAdd(ctx, &outB, cfg, "refund-bot")
			require.ErrorIs(t, errB, registration.ErrLockBusy)
			require.ErrorContains(t, errB, "in progress, not interrupted")
			noJudgment(errB.Error() + outB.String())
			recs := registrationRecords(t, cfg, "acme", "refund-bot")
			require.Len(t, recs[registration.TypeIntent], 1)
			require.Empty(t, recs[registration.TypeRolledBack])

			// A dry run of the same name: reads only, says what is going on.
			agentsAddDryRun = true
			var dry bytes.Buffer
			require.NoError(t, runAgentsAdd(ctx, &dry, cfg, "refund-bot"))
			require.Contains(t, dry.String(), "a registration is running now")
			noJudgment(dry.String())
			// A dry run of ANOTHER name that is taken: while a registration
			// runs, the name is not judged either.
			errDry := runAgentsAdd(ctx, &dry, cfg, "support")
			require.ErrorContains(t, errDry, "a registration is running now")
			require.ErrorContains(t, errDry, "not judged")
			agentsAddDryRun = false

			// A completes: its key is the stored one, and nothing says it
			// was rolled back.
			close(resume)
			require.NoError(t, <-doneA)
			key := printedKeyRe.FindString(outA.String())
			stored, _ := vaultValue(t, cfg, "refund-bot-talon-key")
			require.Equal(t, key, stored)
			require.True(t, registered(t, agentsDir, "refund-bot"))
			recs = registrationRecords(t, cfg, "acme", "refund-bot")
			require.Len(t, recs[registration.TypeIntent], 1)
			require.Len(t, recs[registration.TypeRegistered], 1)
			require.Empty(t, recs[registration.TypeRolledBack])

			// Now the judgment is sound, and it is made under the lock.
			errB = runAgentsAdd(ctx, &outB, cfg, "refund-bot")
			require.ErrorContains(t, errB, "already registered")
			agentsAddDryRun = true
			require.ErrorContains(t, runAgentsAdd(ctx, &dry, cfg, "support"), "already registered")
			agentsAddDryRun = false
		})
	}
}

// The exact interleaving of that race, held still. B has read the name's
// unfinished registrations (none) and has not yet looked at the vault. A
// then writes its intent and stores its key, and is still running. B goes
// on: with the judgment made before the lock, B found "a secret that
// already exists" and printed a deletion hint about A's live key. B must
// instead reach the lock, find it held, and say that a registration is in
// progress.
func TestAgentsAdd_PlanningBeforeTheLockNeverJudgesTheName(t *testing.T) {
	ctx := context.Background()
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	agentsAddTenant = "acme"
	shortLockWait(t)

	bPlanned, bResume := make(chan struct{}), make(chan struct{})
	aPaused, aResume := make(chan struct{}), make(chan struct{})
	var plans atomic.Int32
	var aOnce sync.Once
	registrationFault = func(point string) error {
		switch point {
		case pointPlanRead:
			if plans.Add(1) == 1 { // B's plan, made before the lock
				close(bPlanned)
				<-bResume
			}
		case stepKeyStored:
			aOnce.Do(func() {
				close(aPaused)
				<-aResume
			})
		}
		return nil
	}
	var outA, outB bytes.Buffer
	doneA, doneB := make(chan error, 1), make(chan error, 1)
	go func() { doneB <- runAgentsAdd(ctx, &outB, cfg, "refund-bot") }()
	<-bPlanned // B saw no unfinished registration of the name
	go func() { doneA <- runAgentsAdd(ctx, &outA, cfg, "refund-bot") }()
	<-aPaused // A: intent written, key stored, still running
	_, hasKey := vaultValue(t, cfg, "refund-bot-talon-key")
	require.True(t, hasKey)

	close(bResume)
	errB := <-doneB
	require.ErrorIs(t, errB, registration.ErrLockBusy, "B must reach the lock, not judge A's key: %v", errB)
	require.ErrorContains(t, errB, "in progress, not interrupted")
	for _, forbidden := range []string{"secrets delete", "already exists", "already registered"} {
		require.NotContains(t, errB.Error()+outB.String(), forbidden, "a deletion hint or a verdict about a live registration's key")
	}
	_, hasKey = vaultValue(t, cfg, "refund-bot-talon-key")
	require.True(t, hasKey, "B changed nothing")

	close(aResume)
	require.NoError(t, <-doneA)
	require.True(t, registered(t, agentsDir, "refund-bot"))
	recs := registrationRecords(t, cfg, "acme", "refund-bot")
	require.Len(t, recs[registration.TypeIntent], 1)
	require.Len(t, recs[registration.TypeRegistered], 1)
	require.Empty(t, recs[registration.TypeRolledBack])
}

// Found by repeating the five-process race: a plan made before the lock
// can read the evidence store at the moment another registration is
// creating it, when the file exists and its table does not yet. That is a
// store without records, not an unreadable one. A store that cannot be read
// for another reason is still an error.
func TestAgentsAdd_AnEvidenceStoreWithoutItsTableHoldsNoRecords(t *testing.T) {
	ctx := context.Background()
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	agentsAddTenant = "acme"
	require.NoError(t, cfg.EnsureDataDir())
	require.NoError(t, os.WriteFile(cfg.EvidenceDBPath(), nil, 0o600))

	lookup, err := unresolvedRegistrations(ctx, cfg, "refund-bot")
	require.NoError(t, err)
	require.True(t, lookup.Complete)
	require.Empty(t, lookup.Unresolved)
	// The registration proceeds and creates the store's schema itself.
	var out bytes.Buffer
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
	require.True(t, registered(t, agentsDir, "refund-bot"))
	require.Len(t, registrationRecords(t, cfg, "acme", "refund-bot")[registration.TypeRegistered], 1)

	// A file that is not a database is not "no records".
	other, _ := setupAddFleet(t)
	require.NoError(t, other.EnsureDataDir())
	require.NoError(t, os.WriteFile(other.EvidenceDBPath(), []byte("this is not a database, it is a text file of some length"), 0o600))
	_, err = unresolvedRegistrations(ctx, other, "refund-bot")
	require.ErrorContains(t, err, "reading the evidence store")
}

// killedAt runs one registration of refund-bot in a subprocess that is
// SIGKILLed at step, and returns the unresolved intent it left.
func killedAt(t *testing.T, cfg *config.Config, step string) registration.Unresolved {
	t.Helper()
	child := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestAgentsAdd_CrashHelper$")
	child.Env = append(os.Environ(), "TALON_TEST_CRASH_STEP="+step)
	var out bytes.Buffer
	child.Stdout, child.Stderr = &out, &out
	err := child.Run()
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit)
	ws, _ := exit.Sys().(syscall.WaitStatus)
	require.True(t, ws.Signaled() && ws.Signal() == syscall.SIGKILL, "%v\n%s", err, out.String())
	in := unresolved(t, cfg, "refund-bot")
	require.Len(t, in, 1)
	return in[0]
}

func crashEnv(t *testing.T) (cfg *config.Config, agentsDir string) {
	t.Helper()
	env := addEnv(t, t.TempDir(), "")
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	require.NoError(t, err)
	resetAgentsAddFlags(t)
	agentsAddTenant = "acme"
	return cfg, env["TALON_AGENTS_DIR"]
}

// An unfinished intent is never a reason to delete something. What is under
// the name is removed only when the signed intent proves that registration
// created it; anything else is left untouched, and the message recommends
// no deletion.
func TestAgentsAdd_UnfinishedIntentNeverJustifiesDeletingWhatItDidNotCreate(t *testing.T) {
	ctx := context.Background()
	noDeletionAdvice := func(t *testing.T, err error) {
		t.Helper()
		for _, bad := range []string{"rm ", "rmdir", "talon secrets delete", "remove what it left"} {
			require.NotContains(t, err.Error(), bad, "the message must not recommend a deletion")
		}
	}

	t.Run("artifacts of a successful registration next to another attempt's unfinished intent", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		var out bytes.Buffer
		require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
		key := printedKeyRe.FindString(out.String())
		file := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
		before, err := os.ReadFile(file)
		require.NoError(t, err)

		// Another attempt's intent has no terminal record (as the reviewed
		// race, or a lost rollback record, left it). Its commitments are
		// its own: another key version, another file.
		store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
		require.NoError(t, err)
		vault, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		other, err := vault.NewOwnership("refund-bot-talon-key")
		require.NoError(t, err)
		require.NoError(t, vault.Close())
		abs, _ := filepath.Abs(file)
		c := registration.Commitments{SecretName: "refund-bot-talon-key", KeyOwnershipToken: other.Token(), AgentFile: abs, FileSHA256: strings.Repeat("ab", 32), Marker: strings.Repeat("cd", 16)}
		// The registered file carries the marker of the registration that
		// wrote it, which is not the other attempt's.
		require.Equal(t, []string{markerOf(t, file)}, committedMarkers(t, cfg, "refund-bot"))
		require.NotEqual(t, c.Marker, markerOf(t, file))
		require.NoError(t, store.Store(ctx, &evidence.Evidence{
			ID: "al_other_attempt", CorrelationID: "al_other_corr", TenantID: "acme", AgentID: "refund-bot", Timestamp: time.Now().UTC(),
			InvocationType: registration.TypeIntent, PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: registration.TypeIntent, Reasons: c.Reasons()},
		}))
		require.NoError(t, store.Close())
		require.Len(t, unresolved(t, cfg, "refund-bot"), 1)

		err = runAgentsAdd(ctx, &out, cfg, "refund-bot")
		require.ErrorContains(t, err, "already registered", "the name is simply taken")
		noDeletionAdvice(t, err)
		// The successful registration's artifacts are exactly as they were.
		stored, ok := vaultValue(t, cfg, "refund-bot-talon-key")
		require.True(t, ok)
		require.Equal(t, key, stored, "the registered application's key was not touched")
		after, err := os.ReadFile(file)
		require.NoError(t, err)
		require.Equal(t, before, after)
		require.True(t, registered(t, agentsDir, "refund-bot"))
		// The unfinished attempt is resolved truthfully: it left nothing.
		recs := registrationRecords(t, cfg, "acme", "refund-bot")
		require.Len(t, recs[registration.TypeRolledBack], 1)
		require.Equal(t, "al_other_corr", recs[registration.TypeRolledBack][0].CorrelationID)
		note := strings.Join(recs[registration.TypeRolledBack][0].PolicyDecision.Reasons, " | ")
		require.Contains(t, note, "neither the key version nor the agent file its signed intent committed to exists")
		require.Contains(t, note, "is not what that intent committed to and was not touched")
		require.Len(t, recs[registration.TypeRegistered], 1, "the successful registration's record is the only completion")
		require.Empty(t, unresolved(t, cfg, "refund-bot"))
	})

	t.Run("an intent that commits to nothing next to someone's secret", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		require.NoError(t, cfg.EnsureDataDir())
		vault, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		require.NoError(t, vault.Set(ctx, "refund-bot-talon-key", []byte("someone-elses-key-in-use"), secrets.ACL{}))
		require.NoError(t, vault.Close())
		store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
		require.NoError(t, err)
		require.NoError(t, store.Store(ctx, &evidence.Evidence{
			ID: "al_legacy", CorrelationID: "al_legacy_corr", TenantID: "acme", AgentID: "refund-bot", Timestamp: time.Now().UTC(),
			InvocationType: registration.TypeIntent, PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: registration.TypeIntent},
		}))
		require.NoError(t, store.Close())

		var out bytes.Buffer
		err = runAgentsAdd(ctx, &out, cfg, "refund-bot")
		require.ErrorContains(t, err, "NOTHING was changed")
		require.ErrorContains(t, err, "who created it is not established")
		noDeletionAdvice(t, err)
		got, _ := vaultValue(t, cfg, "refund-bot-talon-key")
		require.Equal(t, "someone-elses-key-in-use", got)
		require.False(t, pathExists(filepath.Join(agentsDir, "refund-bot")))
		recs := registrationRecords(t, cfg, "acme", "refund-bot")
		require.Len(t, recs[registration.TypeIntent], 1, "nothing was written")
		require.Empty(t, recs[registration.TypeRolledBack])
		require.Len(t, unresolved(t, cfg, "refund-bot"), 1, "it stays unresolved until someone establishes whose secret that is")
	})

	t.Run("its own key next to a file it did not publish", func(t *testing.T) {
		cfg, agentsDir := crashEnv(t)
		in := killedAt(t, cfg, stepKeyStored)
		leftKey, ok := vaultValue(t, cfg, "refund-bot-talon-key")
		require.True(t, ok)
		// An operator writes an agent file of that name by hand meanwhile.
		file := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
		manual := []byte("agent:\n  name: refund-bot\n  version: \"1.0.0\"\n  tenant_id: acme\n  key:\n    secret_name: refund-bot-talon-key\npolicies:\n  cost_limits: {}\n")
		require.NoError(t, os.WriteFile(file, manual, 0o600))

		var out bytes.Buffer
		err := runAgentsAdd(context.Background(), &out, cfg, "refund-bot")
		require.ErrorContains(t, err, in.IntentID)
		require.ErrorContains(t, err, "NOTHING was changed")
		require.ErrorContains(t, err, `vault secret "refund-bot-talon-key": is the one that registration created`)
		require.ErrorContains(t, err, "is NOT attributed to that registration: it does not carry that registration's marker")
		noDeletionAdvice(t, err)
		got, _ := vaultValue(t, cfg, "refund-bot-talon-key")
		require.Equal(t, leftKey, got, "not even its own key is removed while something else is under the name")
		after, rerr := os.ReadFile(file)
		require.NoError(t, rerr)
		require.Equal(t, manual, after)
		require.Empty(t, registrationRecords(t, cfg, "acme", "refund-bot")[registration.TypeRolledBack])
	})

	t.Run("an intent record that does not verify proves nothing", func(t *testing.T) {
		cfg, agentsDir := crashEnv(t)
		in := killedAt(t, cfg, stepFilePublished)
		leftKey, _ := vaultValue(t, cfg, "refund-bot-talon-key")
		store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
		require.NoError(t, err)
		_, err = store.DB().ExecContext(context.Background(), `UPDATE evidence SET evidence_json = replace(evidence_json, '"agent_id":"refund-bot"', '"agent_id":"refund-bot","team":"forged"') WHERE id = ?`, in.IntentID)
		require.NoError(t, err)
		require.NoError(t, store.Close())

		var out bytes.Buffer
		err = runAgentsAdd(context.Background(), &out, cfg, "refund-bot")
		require.ErrorContains(t, err, "does not verify")
		require.ErrorContains(t, err, "justifies no recovery")
		noDeletionAdvice(t, err)
		got, _ := vaultValue(t, cfg, "refund-bot-talon-key")
		require.Equal(t, leftKey, got)
		require.True(t, pathExists(filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")))
	})
}

// Where the registration lock does not exist (a platform without the
// advisory lock), registrations cannot be serialized and a running one
// cannot be told from an interrupted one. Registration does not pretend: it
// refuses, before creating anything. A dry run, which writes nothing, works.
func TestAgentsAdd_RefusesWhereTheLockIsNotAvailable(t *testing.T) {
	ctx := context.Background()
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	agentsAddTenant = "acme"
	old := registrationLockSupported
	registrationLockSupported = false
	t.Cleanup(func() { registrationLockSupported = old })

	var out bytes.Buffer
	err := runAgentsAdd(ctx, &out, cfg, "refund-bot")
	require.ErrorIs(t, err, registration.ErrLockUnsupported)
	require.ErrorContains(t, err, "nothing was written")
	require.Empty(t, printedKeyRe.FindString(out.String()+err.Error()))
	require.NoDirExists(t, cfg.DataDir, "not even the data directory or a lock file was created")
	require.False(t, pathExists(filepath.Join(agentsDir, "refund-bot")))
	require.True(t, registered(t, agentsDir, "support"), "the existing application is unaffected")

	agentsAddDryRun = true
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"), "a dry run reads only and needs no lock")
	agentsAddDryRun = false
	require.NoDirExists(t, cfg.DataDir)
}

var markerLineRe = regexp.MustCompile(`(?m)^# registration: ([0-9a-f]{32})$`)

// markerOf returns the registration marker a generated agent file carries.
func markerOf(t *testing.T, file string) string {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	m := markerLineRe.FindSubmatch(raw)
	require.NotNil(t, m, "the generated file carries no registration marker:\n%s", raw)
	return string(m[1])
}

// committedMarkers returns the markers the signed intents of the name
// committed to.
func committedMarkers(t *testing.T, cfg *config.Config, name string) []string {
	t.Helper()
	var out []string
	intents := registrationRecords(t, cfg, "acme", name)[registration.TypeIntent]
	for i := range intents {
		for _, r := range intents[i].PolicyDecision.Reasons {
			if strings.HasPrefix(r, "registration marker: ") {
				out = append(out, strings.TrimPrefix(r, "registration marker: "))
			}
		}
	}
	return out
}

// The generated agent file is the same for every registration of the same
// name, owner and tenant. A digest of it therefore also matches a file that
// someone else created with the same content: on its own it is not proof
// that a file is the interrupted registration's (#567 review). Each
// registration writes a random marker into its file and its signed intent
// commits to it; recovery removes a file only when the marker, the path and
// the digest all match and the artifact is a regular file that is not
// reached through a symbolic link. Everything else is left untouched, with
// no deletion advice.
func TestAgentsAdd_RecoveryRemovesAFileOnlyWhenItIsProvablyTheRegistrations(t *testing.T) {
	ctx := context.Background()
	noDeletionAdvice := func(t *testing.T, err error) {
		t.Helper()
		for _, bad := range []string{"rm ", "rmdir", "talon secrets delete", "remove what it left"} {
			require.NotContains(t, err.Error(), bad, "the message must not recommend a deletion")
		}
	}
	// deterministic is the file as every registration of refund-bot/acme
	// generates it apart from its marker: what an operator who creates the
	// use case by hand from the documented shape would write.
	deterministic := func(t *testing.T, cfg *config.Config) []byte {
		t.Helper()
		plan, err := planRegistration(ctx, cfg, registrationRequest{Name: "refund-bot", Tenant: "acme", AllowNoCompanyPolicy: true}, false)
		require.NoError(t, err)
		require.Empty(t, plan.Marker)
		return plan.Content
	}
	unrelated := func(t *testing.T, agentsDir string) func() {
		t.Helper()
		support := filepath.Join(agentsDir, "support", "agent.talon.yaml")
		before, err := os.ReadFile(support)
		require.NoError(t, err)
		return func() {
			t.Helper()
			after, err := os.ReadFile(support)
			require.NoError(t, err)
			require.Equal(t, before, after, "an unrelated application's file was touched")
		}
	}

	t.Run("two registrations never generate the same file, and each intent commits to its own marker", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		var out bytes.Buffer
		require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
		file := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
		first, firstRaw := markerOf(t, file), mustRead(t, file)
		require.Equal(t, []string{first}, committedMarkers(t, cfg, "refund-bot"))
		// The same name again, after it was removed: identical inputs.
		require.NoError(t, os.RemoveAll(filepath.Dir(file)))
		vault, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		require.NoError(t, vault.Delete(ctx, "refund-bot-talon-key"))
		require.NoError(t, vault.Close())
		require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
		second := markerOf(t, file)
		require.NotEqual(t, first, second)
		require.NotEqual(t, firstRaw, mustRead(t, file), "the two files differ, so their digests do")
		require.ElementsMatch(t, []string{first, second}, committedMarkers(t, cfg, "refund-bot"))
		// The marker changes nothing a loader sees: the fleet validates and
		// a dry run shows no marker of its own.
		require.True(t, registered(t, agentsDir, "refund-bot"))
		require.NotRegexp(t, markerLineRe, string(deterministic(t, cfg)))
	})

	t.Run("it died before publishing; an operator creates the same file by hand: not removed", func(t *testing.T) {
		for _, step := range []string{stepIntentRecorded, stepKeyStored} {
			t.Run("killed after "+step, func(t *testing.T) {
				cfg, agentsDir := crashEnv(t)
				in := killedAt(t, cfg, step)
				stillThere := unrelated(t, agentsDir)
				file := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
				require.False(t, pathExists(file), "the interrupted registration published no file")
				manual := deterministic(t, cfg)
				require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
				require.NoError(t, os.WriteFile(file, manual, 0o600))
				leftKey, hadKey := vaultValue(t, cfg, "refund-bot-talon-key")
				require.Equal(t, step == stepKeyStored, hadKey)

				var out bytes.Buffer
				err := runAgentsAdd(context.Background(), &out, cfg, "refund-bot")
				require.Error(t, err)
				noDeletionAdvice(t, err)
				require.Equal(t, manual, mustRead(t, file), "the operator's file was not removed or changed")
				stillThere()
				if step == stepKeyStored {
					// Its own key is there next to a file that is not its
					// own: nothing is touched at all.
					require.ErrorContains(t, err, "NOTHING was changed")
					require.ErrorContains(t, err, "it does not carry that registration's marker")
					got, _ := vaultValue(t, cfg, "refund-bot-talon-key")
					require.Equal(t, leftKey, got)
					require.Len(t, unresolved(t, cfg, "refund-bot"), 1)
					return
				}
				// It left nothing of its own: that is recorded, and the name
				// is taken by the operator's use case.
				require.ErrorContains(t, err, "already registered")
				recs := registrationRecords(t, cfg, "acme", "refund-bot")
				require.Len(t, recs[registration.TypeRolledBack], 1)
				require.Equal(t, in.Correlation, recs[registration.TypeRolledBack][0].CorrelationID)
				require.Contains(t, strings.Join(recs[registration.TypeRolledBack][0].PolicyDecision.Reasons, " | "), "is not what that intent committed to and was not touched")
			})
		}
	})

	t.Run("its own file and key: exactly those are removed", func(t *testing.T) {
		cfg, agentsDir := crashEnv(t)
		in := killedAt(t, cfg, stepFilePublished)
		stillThere := unrelated(t, agentsDir)
		file := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
		require.Equal(t, in.Commitments.Marker, markerOf(t, file), "the leftover file is identifiable as that registration's")
		note := filepath.Join(agentsDir, "refund-bot", "NOTES.md")
		require.NoError(t, os.WriteFile(note, []byte("operator notes"), 0o600))

		var out bytes.Buffer
		require.NoError(t, runAgentsAdd(context.Background(), &out, cfg, "refund-bot"))
		require.Contains(t, out.String(), "it carries the registration marker and has the SHA-256 the signed intent committed to")
		require.NotEqual(t, in.Commitments.Marker, markerOf(t, file), "the file there now is the new registration's")
		require.Equal(t, "operator notes", string(mustRead(t, note)), "an unrelated file in the directory survives")
		stillThere()
	})

	failsSafely := func(t *testing.T, tamper func(t *testing.T, file string), want string) {
		t.Helper()
		cfg, agentsDir := crashEnv(t)
		in := killedAt(t, cfg, stepFilePublished)
		stillThere := unrelated(t, agentsDir)
		file := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
		leftKey, _ := vaultValue(t, cfg, "refund-bot-talon-key")
		tamper(t, file)
		after := mustRead(t, file)

		var out bytes.Buffer
		err := runAgentsAdd(context.Background(), &out, cfg, "refund-bot")
		require.ErrorContains(t, err, in.IntentID)
		require.ErrorContains(t, err, "NOTHING was changed")
		require.ErrorContains(t, err, want)
		noDeletionAdvice(t, err)
		require.Equal(t, after, mustRead(t, file), "what is at the path was not removed or changed")
		got, _ := vaultValue(t, cfg, "refund-bot-talon-key")
		require.Equal(t, leftKey, got, "not even its own key is removed")
		require.Empty(t, registrationRecords(t, cfg, "acme", "refund-bot")[registration.TypeRolledBack])
		require.Len(t, unresolved(t, cfg, "refund-bot"), 1)
		stillThere()
	}
	t.Run("the file was altered since: fails safely", func(t *testing.T) {
		failsSafely(t, func(t *testing.T, file string) {
			raw := mustRead(t, file)
			require.NoError(t, os.WriteFile(file, append(raw, []byte("# reviewed and edited by an operator\n")...), 0o600))
		}, "carries that registration's marker but its content differs")
	})
	t.Run("another file replaced it: fails safely", func(t *testing.T) {
		failsSafely(t, func(t *testing.T, file string) {
			require.NoError(t, os.Remove(file))
			require.NoError(t, os.WriteFile(file, []byte("agent:\n  name: refund-bot\n  version: \"2.0.0\"\n  tenant_id: acme\n  key:\n    secret_name: refund-bot-talon-key\npolicies:\n  cost_limits: {}\n"), 0o600))
		}, "it does not carry that registration's marker")
	})
	t.Run("a symbolic link at the file's path, to identical content: fails safely", func(t *testing.T) {
		var target string
		failsSafely(t, func(t *testing.T, file string) {
			target = filepath.Join(t.TempDir(), "moved-agent.talon.yaml")
			require.NoError(t, os.Rename(file, target))
			require.NoError(t, os.Symlink(target, file))
		}, "it is a symbolic link, which is never followed or removed")
		require.True(t, pathExists(target), "the link's target was not removed")
	})
	t.Run("the use case's directory is a symbolic link: fails safely", func(t *testing.T) {
		var elsewhere string
		failsSafely(t, func(t *testing.T, file string) {
			elsewhere = filepath.Join(t.TempDir(), "elsewhere")
			require.NoError(t, os.Rename(filepath.Dir(file), elsewhere))
			require.NoError(t, os.Symlink(elsewhere, filepath.Dir(file)))
		}, "is a symbolic link or not a directory, so the path may lead somewhere else")
		require.True(t, pathExists(filepath.Join(elsewhere, "agent.talon.yaml")))
	})
	t.Run("an intent of an earlier version (no marker) proves nothing about a file", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		// A file with exactly the digest that intent recorded.
		file := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
		content := deterministic(t, cfg)
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
		require.NoError(t, os.WriteFile(file, content, 0o600))
		sum := sha256.Sum256(content)
		abs, _ := filepath.Abs(file)
		require.NoError(t, cfg.EnsureDataDir())
		vault, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		own, err := vault.NewOwnership("refund-bot-talon-key")
		require.NoError(t, err)
		require.NoError(t, vault.Close())
		c := registration.Commitments{SecretName: "refund-bot-talon-key", KeyOwnershipToken: own.Token(), AgentFile: abs, FileSHA256: hex.EncodeToString(sum[:])}
		store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
		require.NoError(t, err)
		require.NoError(t, store.Store(ctx, &evidence.Evidence{
			ID: "al_before_markers", CorrelationID: "al_before_markers_corr", TenantID: "acme", AgentID: "refund-bot", Timestamp: time.Now().UTC(),
			InvocationType: registration.TypeIntent, PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: registration.TypeIntent, Reasons: c.Reasons()},
		}))
		require.NoError(t, store.Close())

		var out bytes.Buffer
		err = runAgentsAdd(ctx, &out, cfg, "refund-bot")
		require.ErrorContains(t, err, "NOTHING was changed")
		require.ErrorContains(t, err, "records no registration marker (it was written by an earlier version)")
		noDeletionAdvice(t, err)
		require.Equal(t, content, mustRead(t, file), "a matching digest alone removed nothing")
	})
	t.Run("the limit: a byte-for-byte copy at the same path cannot be told from the original", func(t *testing.T) {
		// Content is all this proof has. A copy made byte for byte, marker
		// included, in a regular file at the committed path is treated as
		// the registration's file. Nothing claims a stronger provenance.
		cfg, agentsDir := crashEnv(t)
		killedAt(t, cfg, stepFilePublished)
		file := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
		raw := mustRead(t, file)
		require.NoError(t, os.Remove(file))
		require.NoError(t, os.WriteFile(file, raw, 0o600))
		var out bytes.Buffer
		require.NoError(t, runAgentsAdd(context.Background(), &out, cfg, "refund-bot"))
		require.NotEqual(t, raw, mustRead(t, file), "the copy was treated as the interrupted registration's file and replaced")
	})
}

func mustRead(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	return raw
}

// Publication of the agent file and the cleanup of its temporary file are
// separate facts (#567 review). Before, a failed removal of the temporary
// file was returned as a failed publication although the agent file had
// already been linked into place: the run did not know it owned the file,
// and a rollback left it published.
func TestAgentsAdd_PublicationIsTrackedApartFromTempFileCleanup(t *testing.T) {
	ctx := context.Background()
	failTempCleanup := func(t *testing.T) {
		t.Helper()
		old := removeTempFile
		removeTempFile = func(string) error { return errors.New("injected: the temporary file cannot be removed") }
		t.Cleanup(func() { removeTempFile = old })
	}
	tempFiles := func(dir string) []string {
		m, _ := filepath.Glob(filepath.Join(dir, ".agent.talon.yaml.*"))
		return m
	}

	t.Run("the cleanup fails: the file IS published and the registration completes", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		failTempCleanup(t)
		var out bytes.Buffer
		require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"), "a leftover temporary file is not a failed publication")
		key := printedKeyRe.FindString(out.String())
		require.NotEmpty(t, key)
		stored, _ := vaultValue(t, cfg, "refund-bot-talon-key")
		require.Equal(t, key, stored)
		require.True(t, registered(t, agentsDir, "refund-bot"))
		dir := filepath.Join(agentsDir, "refund-bot")
		require.Len(t, tempFiles(dir), 1, "the temporary file is still there")
		// The leftover is explicit: in the output and in the signed record.
		require.Contains(t, out.String(), "Leftover")
		require.Contains(t, out.String(), tempFiles(dir)[0])
		recs := registrationRecords(t, cfg, "acme", "refund-bot")
		require.Len(t, recs[registration.TypeRegistered], 1)
		require.Contains(t, strings.Join(recs[registration.TypeRegistered][0].PolicyDecision.Reasons, " | "), "residual: the temporary file "+tempFiles(dir)[0])
		// It is not an agent file: the fleet has exactly the two use cases.
		require.True(t, registered(t, agentsDir, "support"))
	})

	t.Run("the cleanup fails and a later step fails: the rollback removes the published file", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		failTempCleanup(t)
		registrationFault = func(point string) error {
			if point == stepFilePublished {
				return errors.New("injected failure right after publication")
			}
			return nil
		}
		var out bytes.Buffer
		err := runAgentsAdd(ctx, &out, cfg, "refund-bot")
		require.ErrorContains(t, err, "injected failure right after publication")
		require.Empty(t, printedKeyRe.FindString(out.String()+err.Error()))
		dir := filepath.Join(agentsDir, "refund-bot")
		require.False(t, pathExists(filepath.Join(dir, "agent.talon.yaml")), "the published agent file was removed by the rollback")
		require.False(t, registered(t, agentsDir, "refund-bot"), "no use case a server could load")
		_, hasKey := vaultValue(t, cfg, "refund-bot-talon-key")
		require.False(t, hasKey, "no credential is left")
		// The incomplete cleanup is stated, in the error and in evidence.
		require.Len(t, tempFiles(dir), 1)
		require.ErrorContains(t, err, "NOT fully undone")
		require.ErrorContains(t, err, tempFiles(dir)[0])
		require.NotContains(t, err.Error(), "rm -r")
		recs := registrationRecords(t, cfg, "acme", "refund-bot")
		require.Len(t, recs[registration.TypeRolledBack], 1)
		note := strings.Join(recs[registration.TypeRolledBack][0].PolicyDecision.Reasons, " | ")
		require.Contains(t, note, "cleanup: removed the agent file this registration published; removed the key this registration stored")
		require.Contains(t, note, "NOT removed: the temporary file "+tempFiles(dir)[0])
		require.Empty(t, unresolved(t, cfg, "refund-bot"))
		require.True(t, registered(t, agentsDir, "support"))
	})

	t.Run("a file substituted by someone else is never removed by the rollback", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		file := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
		substituted := []byte("agent:\n  name: refund-bot\n  version: \"2.0.0\"\n  tenant_id: acme\n  key:\n    secret_name: someone-elses-key\npolicies:\n  cost_limits: {}\n")
		registrationFault = func(point string) error {
			if point != stepFilePublished {
				return nil
			}
			// Another operator replaces the file between publication and
			// the failure: a different file is now at the path.
			require.NoError(t, os.Remove(file))
			require.NoError(t, os.WriteFile(file, substituted, 0o600))
			return errors.New("injected failure after someone replaced the file")
		}
		var out bytes.Buffer
		err := runAgentsAdd(ctx, &out, cfg, "refund-bot")
		require.ErrorContains(t, err, "NOT fully undone")
		require.ErrorContains(t, err, "is no longer the one this registration published")
		require.ErrorContains(t, err, "left untouched")
		after, rerr := os.ReadFile(file)
		require.NoError(t, rerr, "the substituted file is still there")
		require.Equal(t, substituted, after)
		_, hasKey := vaultValue(t, cfg, "refund-bot-talon-key")
		require.False(t, hasKey, "this registration's own key is removed")
		recs := registrationRecords(t, cfg, "acme", "refund-bot")
		note := strings.Join(recs[registration.TypeRolledBack][0].PolicyDecision.Reasons, " | ")
		require.Contains(t, note, "NOT removed: the file at "+file+" is no longer the one this registration published")
	})
}
