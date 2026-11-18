package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func backupTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{DataDir: dir, SecretsKey: "0123456789abcdef0123456789abcdef", SigningKey: testutil.TestSigningKey}
}

func TestBackup_CreateAndVerify(t *testing.T) {
	ctx := context.Background()
	cfg := backupTestConfig(t)
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	vault, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	require.NoError(t, err)
	require.NoError(t, vault.Set(ctx, "uc-talon-key", []byte("k"), secrets.ACL{}))
	require.NoError(t, vault.Close())

	dest := filepath.Join(t.TempDir(), "b")
	m, err := createBackup(ctx, cfg, dest)
	require.NoError(t, err)
	names := []string{}
	for _, f := range m.Files {
		names = append(names, f.Name)
	}
	require.Equal(t, []string{"evidence.db", "secrets.db"}, names, "absent stores are skipped, present ones never")
	raw, err := os.ReadFile(filepath.Join(dest, "manifest.json"))
	require.NoError(t, err)
	var onDisk backupManifest
	require.NoError(t, json.Unmarshal(raw, &onDisk))
	require.Equal(t, backupFormat, onDisk.Format)
	require.NotEmpty(t, onDisk.NotIncluded, "the manifest says what a restore also needs")

	rep, err := verifyBackup(ctx, cfg, dest)
	require.NoError(t, err, rep)

	// The same backup under another secrets key: the vault does not decrypt.
	other := *cfg
	other.SecretsKey = "fedcba9876543210fedcba9876543210"
	rep, err = verifyBackup(ctx, &other, dest)
	require.Error(t, err)
	require.Contains(t, joinLines(rep), "FAIL vault")
}

func TestBackup_RefusesWithoutAnEvidenceStore(t *testing.T) {
	_, err := createBackup(context.Background(), backupTestConfig(t), filepath.Join(t.TempDir(), "b"))
	require.ErrorContains(t, err, "nothing to back up")
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}
