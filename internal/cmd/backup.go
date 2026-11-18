package cmd

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
)

// Single-node backup (#465): a consistent online snapshot of each durable
// SQLite store, taken while `talon serve` keeps running, plus a manifest of
// checksums; and an offline verification of a backup (checksums, SQLite
// integrity, every evidence signature under the configured signing key,
// every vault entry decryptable under the configured secrets key). Restore
// is deliberately a documented stop → copy → start procedure, not a
// command: replacing the stores of a running installation is never done
// behind the operator's back.

// backupFormat versions the manifest.
const backupFormat = "talon-backup/v1"

// backupStores are the durable stores, in restore order. evidence.db holds
// signed evidence, sessions, approver principals and action operations;
// secrets.db is the encrypted vault (agent keys, provider keys); memory.db
// holds agent memory. cache.db (rebuildable) and runtime/ (transient
// heartbeats) are not backed up.
var backupStores = []string{"evidence.db", "secrets.db", "memory.db"}

type backupManifest struct {
	Format       string       `json:"format"`
	TalonVersion string       `json:"talon_version"`
	CreatedAt    time.Time    `json:"created_at"`
	DataDir      string       `json:"data_dir"`
	Files        []backupFile `json:"files"`
	NotIncluded  []string     `json:"not_included"`
}

type backupFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

var backupNotIncluded = []string{
	"TALON_SECRETS_KEY and TALON_SIGNING_KEY: keep them in your secret manager; without the same keys the vault cannot be decrypted and evidence cannot be verified",
	"configuration files (talon.config.yaml, agent files, MCP proxy config): keep them in version control",
	"cache.db: rebuildable semantic cache",
	"runtime/: transient process heartbeats",
}

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Back up and verify this installation's durable state (single-node)",
}

var backupCreateCmd = &cobra.Command{
	Use:   "create <dest-dir>",
	Short: "Take a consistent online snapshot of evidence, vault and memory into a new directory",
	Long: `Take a consistent snapshot of each durable store of this installation into
<dest-dir> (which must not exist or be empty), with a manifest of checksums.

Safe while 'talon serve' runs: each store is copied in one read transaction
(SQLite VACUUM INTO over a read-only connection). The stores are snapshotted one
after another, not in one cross-store transaction. The keys (TALON_SECRETS_KEY,
TALON_SIGNING_KEY) and the configuration files are NOT included: back them up
separately. Verify a backup with 'talon backup verify <dir>'.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		m, err := createBackup(cmd.Context(), cfg, args[0])
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "Backup written to %s\n", args[0])
		for _, f := range m.Files {
			fmt.Fprintf(w, "  %-12s %10d bytes  sha256 %s\n", f.Name, f.Bytes, f.SHA256)
		}
		fmt.Fprintf(w, "Not included (back up separately):\n")
		for _, n := range m.NotIncluded {
			fmt.Fprintf(w, "  - %s\n", n)
		}
		fmt.Fprintf(w, "Verify with: talon backup verify %s\n", args[0])
		return nil
	},
}

var backupVerifyCmd = &cobra.Command{
	Use:   "verify <backup-dir>",
	Short: "Verify a backup offline: checksums, SQLite integrity, evidence signatures, vault decryption",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		rep, err := verifyBackup(cmd.Context(), cfg, args[0])
		w := cmd.OutOrStdout()
		for _, line := range rep {
			fmt.Fprintln(w, line)
		}
		if err != nil {
			fmt.Fprintf(w, "FAIL backup verify: %v\n", err)
			return err
		}
		fmt.Fprintf(w, "PASS backup verify: %s\n", args[0])
		return nil
	},
}

func createBackup(ctx context.Context, cfg *config.Config, dest string) (*backupManifest, error) {
	if entries, err := os.ReadDir(dest); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty; a backup is written into a new or empty directory", dest)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := os.Stat(cfg.EvidenceDBPath()); err != nil {
		return nil, fmt.Errorf("no evidence store at %s: nothing to back up (%w)", cfg.EvidenceDBPath(), err)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, err
	}
	m := &backupManifest{Format: backupFormat, TalonVersion: Version, CreatedAt: time.Now().UTC(), DataDir: cfg.DataDir, NotIncluded: backupNotIncluded}
	for _, name := range backupStores {
		src := filepath.Join(cfg.DataDir, name)
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		}
		dst := filepath.Join(dest, name)
		if err := snapshotSQLite(ctx, src, dst); err != nil {
			return nil, fmt.Errorf("snapshotting %s: %w", name, err)
		}
		sum, n, err := fileSHA256(dst)
		if err != nil {
			return nil, err
		}
		m.Files = append(m.Files, backupFile{Name: name, SHA256: sum, Bytes: n})
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dest, "manifest.json"), append(raw, '\n'), 0o600); err != nil {
		return nil, err
	}
	return m, nil
}

// snapshotSQLite copies one database in a single read transaction. The
// source is opened read-only; a live writer is not blocked beyond SQLite's
// normal reader semantics.
func snapshotSQLite(ctx context.Context, src, dst string) error {
	db, err := sql.Open("sqlite3", "file:"+src+"?mode=ro&_busy_timeout=10000")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

func fileSHA256(path string) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// verifyBackup returns a line per check and a non-nil error when any check
// fails. It reads the backup only; nothing in the data directory is touched.
func verifyBackup(ctx context.Context, cfg *config.Config, dir string) ([]string, error) {
	var rep []string
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return rep, fmt.Errorf("reading manifest: %w", err)
	}
	var m backupManifest
	if err := json.Unmarshal(raw, &m); err != nil || m.Format != backupFormat {
		return rep, fmt.Errorf("manifest.json is not a %s manifest", backupFormat)
	}
	rep = append(rep, fmt.Sprintf("manifest: %s, taken %s by talon %s from %s", m.Format, m.CreatedAt.Format(time.RFC3339), m.TalonVersion, m.DataDir))
	failed := 0
	hasEvidence := false
	for _, f := range m.Files {
		p := filepath.Join(dir, f.Name)
		sum, n, err := fileSHA256(p)
		switch {
		case err != nil:
			rep = append(rep, fmt.Sprintf("FAIL %s: %v", f.Name, err))
			failed++
			continue
		case sum != f.SHA256 || n != f.Bytes:
			rep = append(rep, fmt.Sprintf("FAIL %s: checksum or size differs from the manifest", f.Name))
			failed++
			continue
		}
		if res, err := sqliteIntegrity(ctx, p); err != nil || res != "ok" {
			rep = append(rep, fmt.Sprintf("FAIL %s: integrity_check %q %v", f.Name, res, err))
			failed++
			continue
		}
		rep = append(rep, fmt.Sprintf("ok   %s: checksum and SQLite integrity", f.Name))
		if f.Name == "evidence.db" {
			hasEvidence = true
		}
		line, ok := verifyStoreContent(ctx, cfg, f.Name, p)
		if line != "" {
			rep = append(rep, line)
		}
		if !ok {
			failed++
		}
	}
	if !hasEvidence {
		rep = append(rep, "FAIL evidence.db is not in the backup")
		failed++
	}
	if failed > 0 {
		return rep, fmt.Errorf("%d check(s) failed", failed)
	}
	return rep, nil
}

// verifyStoreContent checks what only the keys can establish: every
// evidence signature, every vault entry's decryption.
func verifyStoreContent(ctx context.Context, cfg *config.Config, name, p string) (line string, ok bool) {
	switch name {
	case "evidence.db":
		total, invalid, err := verifyEvidenceFile(ctx, p, cfg.SigningKey)
		if err != nil || invalid > 0 {
			return fmt.Sprintf("FAIL evidence signatures: %d of %d records do not verify with the configured TALON_SIGNING_KEY %v", invalid, total, errString(err)), false
		}
		return fmt.Sprintf("ok   evidence signatures: %d of %d records verify with the configured TALON_SIGNING_KEY", total, total), true
	case "secrets.db":
		total, undecryptable, unchecked, err := verifyVaultFile(ctx, p, cfg.SecretsKey)
		if err != nil || undecryptable > 0 {
			return fmt.Sprintf("FAIL vault: %d of %d entries cannot be decrypted with the configured TALON_SECRETS_KEY %v", undecryptable, total, errString(err)), false
		}
		return fmt.Sprintf("ok   vault: %d entries decrypt with the configured TALON_SECRETS_KEY (%d not checked: their ACL names specific tenants or agents)", total-unchecked, unchecked), true
	}
	return "", true
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return "(" + err.Error() + ")"
}

func sqliteIntegrity(ctx context.Context, path string) (string, error) {
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer db.Close()
	var res string
	err = db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&res)
	return res, err
}

func verifyEvidenceFile(ctx context.Context, path, signingKey string) (total, invalid int, err error) {
	store, err := evidence.OpenReadOnly(path, signingKey)
	if err != nil {
		return 0, 0, err
	}
	defer store.Close()
	rows, err := store.DB().QueryContext(ctx, `SELECT evidence_json FROM evidence`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return total, invalid, err
		}
		total++
		var ev evidence.Evidence
		if json.Unmarshal([]byte(raw), &ev) != nil || !store.VerifyRecord(&ev) {
			invalid++
		}
	}
	return total, invalid, rows.Err()
}

func verifyVaultFile(ctx context.Context, path, secretsKey string) (total, undecryptable, unchecked int, err error) {
	// The vault opener may create its schema; work on a scratch copy so the
	// backup itself is never written to.
	tmp, err := os.MkdirTemp("", "talon-backup-verify-")
	if err != nil {
		return 0, 0, 0, err
	}
	defer os.RemoveAll(tmp)
	cp := filepath.Join(tmp, "secrets.db")
	if err := copyFile(path, cp); err != nil {
		return 0, 0, 0, err
	}
	store, err := secrets.NewSecretStore(cp, secretsKey)
	if err != nil {
		return 0, 0, 0, err
	}
	defer store.Close()
	all, err := store.ListAll(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	for i := range all {
		total++
		acl := all[i].ACL
		if len(acl.Tenants) > 0 || len(acl.Agents) > 0 {
			unchecked++
			continue
		}
		if _, err := store.Get(ctx, all[i].Name, "default", "backup-verify"); err != nil {
			if errors.Is(err, secrets.ErrSecretUndecryptable) {
				undecryptable++
				continue
			}
			return total, undecryptable, unchecked, err
		}
	}
	return total, undecryptable, unchecked, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func init() {
	backupCmd.AddCommand(backupCreateCmd, backupVerifyCmd)
	rootCmd.AddCommand(backupCmd)
}
