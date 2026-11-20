package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
		c := registration.Commitments{SecretName: "refund-bot-talon-key", KeyOwnershipToken: other.Token(), AgentFile: abs, FileSHA256: strings.Repeat("ab", 32)}
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
		require.Contains(t, note, "was created by something else and was not touched")
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
		require.ErrorContains(t, err, "is NOT the one that registration committed to")
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
		require.Contains(t, out.String(), "leftover")
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
