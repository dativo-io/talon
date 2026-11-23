package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/registration"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// backupInstallation is a small installation: an evidence store, a vault
// whose entries are ALL ACL-restricted (as `talon agents add` creates them),
// a gateway config and one agent file.
func backupInstallation(t *testing.T) *config.Config {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cfg := &config.Config{DataDir: filepath.Join(dir, "data"), SecretsKey: "0123456789abcdef0123456789abcdef", SigningKey: testutil.TestSigningKey, AgentsDir: filepath.Join(dir, "agents")}
	require.NoError(t, cfg.EnsureDataDir())
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	vault, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	require.NoError(t, err)
	for _, uc := range []string{"refund-bot", "hr-copilot"} {
		require.NoError(t, vault.Set(ctx, uc+"-talon-key", []byte("k-"+uc), secrets.ACL{Tenants: []string{"acme"}, Agents: []string{uc}}))
	}
	require.NoError(t, vault.Close())
	gw := filepath.Join(dir, "talon.config.yaml")
	require.NoError(t, os.WriteFile(gw, []byte("gateway:\n  enabled: true\n"), 0o600))
	t.Setenv("TALON_GATEWAY_CONFIG", gw)
	require.NoError(t, os.MkdirAll(filepath.Join(cfg.AgentsDir, "refund-bot"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(cfg.AgentsDir, "refund-bot", "agent.talon.yaml"), []byte("agent:\n  name: refund-bot\n"), 0o600))
	return cfg
}

func rewriteManifest(t *testing.T, dir string, mutate func(m map[string]any)) {
	t.Helper()
	p := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(p)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	mutate(m)
	out, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p, out, 0o600))
}

func TestBackup_CreateAndVerify(t *testing.T) {
	ctx := context.Background()
	cfg := backupInstallation(t)
	dest := filepath.Join(t.TempDir(), "b")
	m, err := createBackup(ctx, cfg, dest, true)
	require.NoError(t, err, "no Talon process is running: --cold is satisfied")
	require.Equal(t, backupModeCold, m.Mode)
	names := []string{}
	for _, f := range m.Files {
		names = append(names, f.Name)
	}
	require.Equal(t, []string{"evidence.db", "secrets.db"}, names)
	require.Equal(t, []string{"memory.db"}, m.Absent, "an absent store is recorded, never silently omitted")
	cfgNames := []string{}
	for _, f := range m.Config {
		cfgNames = append(cfgNames, f.Name)
	}
	require.Equal(t, []string{"config/agents/refund-bot/agent.talon.yaml", "config/talon.config.yaml"}, cfgNames)

	rep, err := verifyBackup(ctx, cfg, dest)
	require.NoError(t, err, rep)
	joined := strings.Join(rep, "\n")
	require.Contains(t, joined, "ok   vault: all 2 entries decrypt", "ACL-restricted entries are verified, not skipped")
	require.Contains(t, joined, "the snapshot carries the recovery hold")
	require.Contains(t, joined, "one coherent recovery point")
	require.NotContains(t, joined, "not checked")

	// The live store carries no hold; only the snapshot does.
	live, err := sql.Open("sqlite3", "file:"+cfg.EvidenceDBPath()+"?mode=ro")
	require.NoError(t, err)
	holds, err := action.ActiveRecoveryHolds(ctx, live)
	require.NoError(t, err)
	require.Empty(t, holds)
	require.NoError(t, live.Close())

	// The same backup under another secrets key: every restricted entry fails.
	other := *cfg
	other.SecretsKey = "fedcba9876543210fedcba9876543210"
	rep, err = verifyBackup(ctx, &other, dest)
	require.Error(t, err)
	require.Contains(t, strings.Join(rep, "\n"), "FAIL vault: 2 of 2 entries do not decrypt")

	// And under another signing key (no records here, so add one first).
	_, err = createBackup(ctx, cfg, dest, false)
	require.ErrorContains(t, err, "not empty", "a backup never overwrites one")
}

func TestBackup_RefusesWithoutAnEvidenceStore(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir(), SecretsKey: "0123456789abcdef0123456789abcdef", SigningKey: testutil.TestSigningKey}
	_, err := createBackup(context.Background(), cfg, filepath.Join(t.TempDir(), "b"), false)
	require.ErrorContains(t, err, "nothing to back up")
}

// A manifest that is malformed, incomplete or inconsistent, or a backup
// directory that carries more or less than its manifest, fails verification.
func TestBackup_VerifyRejectsBadManifestsAndContents(t *testing.T) {
	ctx := context.Background()
	cfg := backupInstallation(t)
	fresh := func(t *testing.T) string {
		t.Helper()
		dest := filepath.Join(t.TempDir(), "b")
		_, err := createBackup(ctx, cfg, dest, false)
		require.NoError(t, err)
		return dest
	}
	files := func(m map[string]any) []any { return m["files"].([]any) }
	cases := map[string]struct {
		mutate func(t *testing.T, dir string)
		want   string
	}{
		"not JSON": {func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{"), 0o600))
		}, "not a valid"},
		"unknown field": {func(t *testing.T, dir string) { rewriteManifest(t, dir, func(m map[string]any) { m["surprise"] = 1 }) }, "not a valid"},
		"other format": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) { m["format"] = "talon-backup/v0" })
		}, "format"},
		"no backup id": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) { m["backup_id"] = "" })
		}, "backup_id"},
		"unknown mode": {func(t *testing.T, dir string) { rewriteManifest(t, dir, func(m map[string]any) { m["mode"] = "warm" }) }, "mode"},
		"required store omitted": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) { m["files"] = files(m)[:1] })
		}, "incomplete"},
		"evidence store marked absent": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) { m["files"] = files(m)[1:]; m["absent"] = []any{"memory.db", "evidence.db"} })
		}, "not allowed"},
		"duplicate store": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) { m["files"] = append(files(m), files(m)[0]) })
		}, "more than once"},
		"store both present and absent": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) { m["absent"] = []any{"memory.db", "secrets.db"} })
		}, "and as absent"},
		"unexpected store name": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) {
				f := files(m)[0].(map[string]any)
				m["files"] = append(files(m), map[string]any{"name": "../evil.db", "sha256": f["sha256"], "bytes": f["bytes"]})
			})
		}, "unexpected store"},
		"configuration path traversal": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) {
				c := m["config"].([]any)
				c[0].(map[string]any)["name"] = "config/../../etc/passwd"
			})
		}, "outside config/"},
		"configuration path outside config": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) {
				c := m["config"].([]any)
				c[0].(map[string]any)["name"] = "evidence.db"
			})
		}, "outside config/"},
		"configuration list changed": {func(t *testing.T, dir string) {
			rewriteManifest(t, dir, func(m map[string]any) { m["config"] = m["config"].([]any)[:1] })
		}, "config_digest"},
		"extra file in the backup": {func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config", "agents", "planted.yaml"), []byte("x"), 0o600))
		}, "does not account for"},
		"configuration file changed": {func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config", "talon.config.yaml"), []byte("gateway:\n  enabled: false\n"), 0o600))
		}, "check(s) failed"},
		"store file missing": {func(t *testing.T, dir string) {
			require.NoError(t, os.Remove(filepath.Join(dir, "secrets.db")))
		}, "check(s) failed"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := fresh(t)
			c.mutate(t, dir)
			rep, err := verifyBackup(ctx, cfg, dir)
			require.Error(t, err, rep)
			require.Contains(t, err.Error()+"\n"+strings.Join(rep, "\n"), c.want)
		})
	}

	t.Run("an evidence snapshot without the recovery hold", func(t *testing.T) {
		dir := fresh(t)
		ev := filepath.Join(dir, "evidence.db")
		db, err := sql.Open("sqlite3", "file:"+ev+"?_journal_mode=DELETE")
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, `DELETE FROM recovery_holds`)
		require.NoError(t, err)
		require.NoError(t, db.Close())
		sum, n, err := fileSHA256(ev)
		require.NoError(t, err)
		rewriteManifest(t, dir, func(m map[string]any) {
			f := files(m)[0].(map[string]any)
			f["sha256"], f["bytes"] = sum, n
		})
		rep, err := verifyBackup(ctx, cfg, dir)
		require.Error(t, err)
		require.Contains(t, strings.Join(rep, "\n"), "does not carry this backup's recovery hold")
	})
}

// After a restore the hold is shown, a resume needs an explicit statement,
// a changed configuration needs an explicit acceptance, and the resume is
// recorded as signed evidence.
func TestBackup_ResumeAfterRestore(t *testing.T) {
	ctx := context.Background()
	cfg := backupInstallation(t)
	dest := filepath.Join(t.TempDir(), "b")
	_, err := createBackup(ctx, cfg, dest, false)
	require.NoError(t, err)
	reset := func() { backupResumeReconciled, backupResumeHoldOps, backupResumeAcceptDrift = false, nil, false }
	reset()
	t.Cleanup(reset)

	var out bytes.Buffer
	require.NoError(t, resumeAfterRestore(ctx, &out, cfg))
	require.Contains(t, out.String(), "No recovery hold", "the live installation was never restored")

	// Restore: the snapshot replaces the live store.
	b, err := os.ReadFile(filepath.Join(dest, "evidence.db"))
	require.NoError(t, err)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(cfg.EvidenceDBPath() + suffix)
	}
	require.NoError(t, os.WriteFile(cfg.EvidenceDBPath(), b, 0o600))

	out.Reset()
	err = resumeAfterRestore(ctx, &out, cfg)
	require.ErrorContains(t, err, "recovery hold is active")
	require.Contains(t, out.String(), "RECOVERY HOLD")
	require.Contains(t, out.String(), "Not resumed")

	// The company policy file changed since the backup: not silently accepted.
	require.NoError(t, os.WriteFile(os.Getenv("TALON_GATEWAY_CONFIG"), []byte("gateway:\n  enabled: true\n  # weakened\n"), 0o600))
	backupResumeReconciled = true
	out.Reset()
	err = resumeAfterRestore(ctx, &out, cfg)
	require.ErrorContains(t, err, "--accept-config-change")
	require.Contains(t, out.String(), "CONFIGURATION CHANGED")

	backupResumeAcceptDrift, backupResumeHoldOps = true, []string{"op-executed-after-backup"}

	// Failure injection: the evidence store refuses the signed record of the
	// resume. The hold must stay active and no operation id may be held:
	// dispatch is never re-enabled without evidence of the decision.
	inject, err := sql.Open("sqlite3", cfg.EvidenceDBPath())
	require.NoError(t, err)
	_, err = inject.ExecContext(ctx, `CREATE TRIGGER fail_resume_evidence BEFORE INSERT ON evidence BEGIN SELECT RAISE(ABORT, 'injected evidence failure'); END`)
	require.NoError(t, err)
	out.Reset()
	err = resumeAfterRestore(ctx, &out, cfg)
	require.ErrorContains(t, err, "the recovery hold is still active")
	require.ErrorContains(t, err, "not resumed by this command")
	require.NotContains(t, out.String(), "Resumed:")
	held, err := action.ActiveRecoveryHolds(ctx, inject)
	require.NoError(t, err)
	require.Len(t, held, 1, "the hold survives a failed evidence write")
	var heldOps int
	require.NoError(t, inject.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_held_operations`).Scan(&heldOps))
	require.Zero(t, heldOps)
	_, err = inject.ExecContext(ctx, `DROP TRIGGER fail_resume_evidence`)
	require.NoError(t, err)
	require.NoError(t, inject.Close())

	out.Reset()
	require.NoError(t, resumeAfterRestore(ctx, &out, cfg))
	require.Contains(t, out.String(), "Resumed: 1 hold(s) ended, 1 operation id(s) held for good")

	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	defer store.Close()
	rows, err := store.List(ctx, "system", "talon-backup", time.Time{}, time.Time{}, 5)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "recovery_resumed", rows[0].InvocationType)
	require.True(t, store.VerifyRecord(&rows[0]))
	// #593: an installation event, not a tenant's activity.
	require.True(t, evidence.IsInstallationEvent(rows[0].TenantID, rows[0].InvocationType))
	inst, err := store.ListInstallationEvents(ctx, 5)
	require.NoError(t, err)
	require.Len(t, inst, 1)
	require.Equal(t, rows[0].ID, inst[0].ID)
	holds, err := action.ActiveRecoveryHolds(ctx, store.DB())
	require.NoError(t, err)
	require.Empty(t, holds)
}

// #568 review. A resume reports a signed record only when it wrote one. Two
// operators resume at the same time: the second one's transaction finds no
// active hold. It must not print an evidence id (the id it prepared was
// never stored), must not say that it resumed, and must say that the
// operation ids it was asked to hold are NOT held. A later repeat is the
// same: nothing changes, nothing is recorded.
func TestBackup_ResumeReportsEvidenceOnlyWhenItWroteIt(t *testing.T) {
	ctx := context.Background()
	cfg := backupInstallation(t)
	dest := filepath.Join(t.TempDir(), "b")
	_, err := createBackup(ctx, cfg, dest, false)
	require.NoError(t, err)
	reset := func() {
		backupResumeReconciled, backupResumeHoldOps, backupResumeAcceptDrift = false, nil, false
		resumeRaceHook = func() {}
	}
	reset()
	t.Cleanup(reset)
	b, err := os.ReadFile(filepath.Join(dest, "evidence.db"))
	require.NoError(t, err)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(cfg.EvidenceDBPath() + suffix)
	}
	require.NoError(t, os.WriteFile(cfg.EvidenceDBPath(), b, 0o600))

	evidenceOfResumes := func() []evidence.Evidence {
		store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
		require.NoError(t, err)
		defer store.Close()
		rows, err := store.List(ctx, "system", "talon-backup", time.Time{}, time.Time{}, 10)
		require.NoError(t, err)
		for i := range rows {
			require.True(t, store.VerifyRecord(&rows[i]))
		}
		return rows
	}
	heldIDs := func() []string {
		db, err := sql.Open("sqlite3", cfg.EvidenceDBPath())
		require.NoError(t, err)
		defer db.Close()
		rows, err := db.QueryContext(ctx, `SELECT operation_id FROM recovery_held_operations ORDER BY operation_id`)
		require.NoError(t, err)
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			require.NoError(t, rows.Scan(&id))
			ids = append(ids, id)
		}
		require.NoError(t, rows.Err())
		return ids
	}

	// Operator B's command has read the active hold. Before its transaction,
	// operator A resumes (holding op-a) and commits.
	var winner bytes.Buffer
	resumeRaceHook = func() {
		resumeRaceHook = func() {}
		mine := backupResumeHoldOps
		backupResumeHoldOps = []string{"op-a"}
		require.NoError(t, resumeAfterRestore(ctx, &winner, cfg))
		backupResumeHoldOps = mine
	}
	backupResumeReconciled, backupResumeHoldOps = true, []string{"op-b"}
	var out bytes.Buffer
	err = resumeAfterRestore(ctx, &out, cfg)
	require.Contains(t, winner.String(), "Resumed: 1 hold(s) ended, 1 operation id(s) held for good. Evidence: rr_")

	require.Error(t, err, "the ids B asked to hold are not held: that is not a success")
	require.ErrorContains(t, err, "were NOT held by this command")
	require.ErrorContains(t, err, "op-b")
	require.Contains(t, out.String(), "Not resumed by this command")
	require.Contains(t, out.String(), "wrote no evidence")
	require.NotContains(t, out.String(), "Resumed:")
	require.NotContains(t, out.String(), "Evidence: rr_", "an evidence id that was never stored:\n%s", out.String())
	records := evidenceOfResumes()
	require.Len(t, records, 1, "exactly one signed record: the winner's")
	require.Contains(t, winner.String(), records[0].ID, "the id the winner printed is the id that is stored")
	require.Equal(t, []string{"op-a"}, heldIDs(), "only the winner's id is held")

	// A repeat, with and without ids to hold: nothing changes, nothing is recorded.
	out.Reset()
	err = resumeAfterRestore(ctx, &out, cfg)
	require.ErrorContains(t, err, "were NOT held by this command")
	require.Contains(t, out.String(), "No recovery hold")
	require.Contains(t, out.String(), "no evidence was written")
	require.NotContains(t, out.String(), "rr_")
	backupResumeHoldOps = nil
	out.Reset()
	require.NoError(t, resumeAfterRestore(ctx, &out, cfg))
	require.Contains(t, out.String(), "No recovery hold")
	require.NotContains(t, out.String(), "rr_")
	require.Len(t, evidenceOfResumes(), 1)
	require.Equal(t, []string{"op-a"}, heldIDs())
}

// #568 review. "Cold" is one coherent recovery point. That no Talon process
// reports running does not establish it: a command can still write. A cold
// backup therefore holds every writer out for the whole snapshot (the
// registration lock, a write lock on every store) and fails when the
// configuration changes meanwhile; it refuses to start while a writer is
// active.
func TestBackup_ColdHoldsEveryWriterOut(t *testing.T) {
	ctx := context.Background()
	cfg := backupInstallation(t)
	t.Cleanup(func() { backupQuiescedHook = func() {} })
	writer := func(name string) *sql.DB {
		db, err := sql.Open("sqlite3", "file:"+filepath.Join(cfg.DataDir, name)+"?_busy_timeout=200")
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		return db
	}

	// A command is writing to the evidence store: no cold backup.
	busy := writer("evidence.db")
	conn, err := busy.Conn(ctx)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE")
	require.NoError(t, err)
	dest := filepath.Join(t.TempDir(), "while-writing")
	_, err = createBackup(ctx, cfg, dest, true)
	require.ErrorContains(t, err, "--cold")
	require.ErrorContains(t, err, "evidence.db is being written")
	require.ErrorContains(t, err, "no backup was taken")
	_, statErr := os.Stat(filepath.Join(dest, "manifest.json"))
	require.True(t, os.IsNotExist(statErr))
	_, err = conn.ExecContext(ctx, "ROLLBACK")
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	// A registration is running (it holds the installation's lock): no cold backup.
	unlock, err := registration.Acquire(ctx, cfg.DataDir, time.Second)
	require.NoError(t, err)
	_, err = createBackup(ctx, cfg, filepath.Join(t.TempDir(), "while-registering"), true)
	require.ErrorContains(t, err, "the registration lock of this installation could not be taken")
	unlock()

	// While a cold backup runs, nobody can commit to a store or register.
	var tried int
	backupQuiescedHook = func() {
		for _, name := range backupStores {
			if _, err := os.Stat(filepath.Join(cfg.DataDir, name)); err != nil {
				continue
			}
			_, werr := writer(name).ExecContext(ctx, "CREATE TABLE IF NOT EXISTS written_during_backup (x)")
			require.Error(t, werr, "a write to %s committed during a cold backup", name)
			require.Contains(t, werr.Error(), "locked")
			tried++
		}
		_, lerr := registration.Acquire(ctx, cfg.DataDir, 100*time.Millisecond)
		require.ErrorIs(t, lerr, registration.ErrLockBusy, "a registration could start during a cold backup")
	}
	good := filepath.Join(t.TempDir(), "cold")
	m, err := createBackup(ctx, cfg, good, true)
	require.NoError(t, err)
	require.Equal(t, backupModeCold, m.Mode)
	require.GreaterOrEqual(t, tried, 1)
	_, err = verifyBackup(ctx, cfg, good)
	require.NoError(t, err)
	// The locks are released: the installation writes again.
	_, err = writer("evidence.db").ExecContext(ctx, "CREATE TABLE IF NOT EXISTS written_after_backup (x)")
	require.NoError(t, err)
	unlock, err = registration.Acquire(ctx, cfg.DataDir, time.Second)
	require.NoError(t, err)
	unlock()

	// A configuration file changes after it was captured and before the
	// backup finished: not one point in time. The backup fails, says why,
	// and leaves no manifest: `talon backup verify` cannot accept it.
	backupQuiescedHook = func() {}
	backupConfigCapturedHook = func() {
		require.NoError(t, os.WriteFile(os.Getenv("TALON_GATEWAY_CONFIG"), []byte("gateway:\n  enabled: true\n  # edited during the backup\n"), 0o600))
	}
	t.Cleanup(func() { backupConfigCapturedHook = func() {} })
	changed := filepath.Join(t.TempDir(), "config-changed")
	_, err = createBackup(ctx, cfg, changed, true)
	require.ErrorContains(t, err, "changed while the backup was taken")
	require.ErrorContains(t, err, "must not be used")
	_, statErr = os.Stat(filepath.Join(changed, "manifest.json"))
	require.True(t, os.IsNotExist(statErr), "an incoherent backup has no manifest")
	_, err = verifyBackup(ctx, cfg, changed)
	require.Error(t, err, "and does not verify")
	backupConfigCapturedHook = func() {}
	// The locks of the failed backup were released too.
	_, err = createBackup(ctx, cfg, filepath.Join(t.TempDir(), "cold-again"), true)
	require.NoError(t, err)
}
