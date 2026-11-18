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
	holds, err := action.ActiveRecoveryHolds(ctx, store.DB())
	require.NoError(t, err)
	require.Empty(t, holds)
}
