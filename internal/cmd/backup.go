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
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/secrets"
)

// Single-node backup and recovery (#465).
//
// `talon backup create` snapshots each durable SQLite store (one read
// transaction per store), captures the configuration files, and writes a
// manifest of checksums. With no Talon process running the result is one
// coherent recovery point ("cold"); while `talon serve` runs it is a set of
// per-store snapshots taken one after another ("online"), which is useful
// but is NOT a coherent recovery point and is labelled as such.
//
// Every snapshot of the evidence store carries a RECOVERY HOLD (see
// internal/action/recovery.go): an installation started on restored stores
// dispatches no consequential action until an operator has reconciled with
// the downstream systems and runs `talon backup resume`. The restored
// ledger alone does not prove that an action was not executed after the
// backup was taken.
//
// `talon backup verify` checks a backup offline and never writes to it.
// Restore itself stays a documented stop → copy → start: no command
// replaces the stores of a running installation.

// backupFormat versions the manifest.
const backupFormat = "talon-backup/v1"

// backupStores are the durable stores, in restore order. evidence.db holds
// signed evidence, sessions, approver principals and action operations;
// secrets.db is the encrypted vault (agent keys, provider keys); memory.db
// holds agent memory. cache.db (rebuildable) and runtime/ (transient
// heartbeats) are not backed up.
var backupStores = []string{"evidence.db", "secrets.db", "memory.db"}

const (
	backupModeCold   = "cold"
	backupModeOnline = "online"
	backupConfigDir  = "config"
)

type backupManifest struct {
	Format       string    `json:"format"`
	BackupID     string    `json:"backup_id"`
	TalonVersion string    `json:"talon_version"`
	CreatedAt    time.Time `json:"created_at"`
	DataDir      string    `json:"data_dir"`
	// Mode is "cold" (no Talon process was running: one coherent recovery
	// point) or "online" (per-store snapshots taken one after another).
	Mode  string       `json:"mode"`
	Files []backupFile `json:"files"`
	// Absent names the stores that did not exist when the backup was taken,
	// so a store missing from Files is never an unexplained omission.
	Absent []string `json:"absent"`
	// Config lists the captured configuration files (paths under config/).
	Config       []backupFile `json:"config"`
	ConfigDigest string       `json:"config_digest"`
	NotIncluded  []string     `json:"not_included"`
}

type backupFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

var backupNotIncluded = []string{
	"TALON_SECRETS_KEY and TALON_SIGNING_KEY: keep them in your secret manager; without the same keys the vault cannot be decrypted and evidence cannot be verified",
	"cache.db: rebuildable semantic cache",
	"runtime/: transient process heartbeats",
}

var (
	backupRequireCold       bool
	backupResumeReconciled  bool
	backupResumeHoldOps     []string
	backupResumeAcceptDrift bool
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Back up, verify and resume this installation's durable state (single-node)",
}

var backupCreateCmd = &cobra.Command{
	Use:   "create <dest-dir>",
	Short: "Snapshot evidence, vault, memory and configuration into a new directory",
	Long: `Snapshot each durable store of this installation and its configuration files
into <dest-dir> (which must not exist or be empty), with a manifest of checksums.

For a production restore point stop Talon first (or pass --cold, which refuses
while a Talon process is running): the result is then ONE coherent recovery
point. While 'talon serve' runs, each store is still copied consistently (one
read transaction, SQLite VACUUM INTO over a read-only connection), but the
stores are copied one after another: such an "online" backup is labelled as not
being a coherent recovery point.

The snapshot of the evidence store carries a recovery hold: an installation
restored from it dispatches no governed action until 'talon backup resume'.
The keys (TALON_SECRETS_KEY, TALON_SIGNING_KEY) are NOT included.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		m, err := createBackup(cmd.Context(), cfg, args[0], backupRequireCold)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "Backup %s written to %s\n", m.BackupID, args[0])
		fmt.Fprintf(w, "Mode: %s\n", backupModeNote(m.Mode))
		for _, f := range m.Files {
			fmt.Fprintf(w, "  %-12s %10d bytes  sha256 %s\n", f.Name, f.Bytes, f.SHA256)
		}
		fmt.Fprintf(w, "  %d configuration file(s) under %s/\n", len(m.Config), backupConfigDir)
		fmt.Fprintf(w, "Not included (back up separately):\n")
		for _, n := range m.NotIncluded {
			fmt.Fprintf(w, "  - %s\n", n)
		}
		fmt.Fprintf(w, "Verify with: talon backup verify %s\n", args[0])
		return nil
	},
}

func backupModeNote(mode string) string {
	if mode == backupModeCold {
		return "cold — no Talon process was running: one coherent recovery point"
	}
	return "online — a Talon process was running: each store is consistent, but the stores were copied one after another. NOT a coherent recovery point; for a production restore point stop Talon and take a cold backup"
}

var backupVerifyCmd = &cobra.Command{
	Use:   "verify <backup-dir>",
	Short: "Verify a backup offline: manifest, checksums, SQLite integrity, evidence signatures, every vault entry",
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

var backupResumeCmd = &cobra.Command{
	Use:   "resume",
	Short: "After a restore: show the recovery hold and, once reconciled, resume governed-action dispatch",
	Long: `An installation restored from a backup dispatches no governed action: the
restored ledger does not contain what happened after the backup was taken.

Without flags this prints the hold and every operation that was still open in
the backup (with the Idempotency-Key Talon sends for it). Check each one in the
downstream system. Then:

  talon backup resume --reconciled [--hold-operation <operation_id>]...

--hold-operation keeps an operation id held for good (use it for every
operation that the downstream system shows as already executed, and for any you
could not check). All other operations become claimable again.

If the configuration files differ from those captured with the backup, the
resume is refused until you review them and pass --accept-config-change.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		return resumeAfterRestore(cmd.Context(), cmd.OutOrStdout(), cfg)
	},
}

// talonProcessRunning reports whether a Talon process of this installation
// is running (its runtime record is fresh or stale). It answers true as
// well when that cannot be established — the runtime records are unreadable,
// or a record cannot be attributed to this installation — because "cold" is
// a claim about a coherent recovery point and is only made when it is known.
func talonProcessRunning(cfg *config.Config) bool {
	v := runtimestatus.NewReader().Assess(cfg.DataDir, runtimestatus.Fingerprint(cfg.SigningKey), nil, time.Now())
	if v.Err != "" || len(v.Rejected) > 0 {
		return true
	}
	for i := range v.Processes {
		if st := v.Processes[i].Assessed; st == runtimestatus.Running || st == runtimestatus.Stale {
			return true
		}
	}
	return false
}

// configSources lists the configuration files of this installation as
// (name under config/, absolute path): the gateway config that carries the
// company policy and every agent file.
func configSources(ctx context.Context, cfg *config.Config) (map[string]string, error) {
	out := map[string]string{}
	if p := gatewayConfigPath(""); p != "" {
		if _, err := os.Stat(p); err == nil {
			out[backupConfigDir+"/talon.config.yaml"] = p
		}
	}
	if dir := strings.TrimSpace(cfg.AgentsDir); dir != "" {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() || d.Name() != agentcatalog.AgentConfigFilename {
				return nil
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			out[backupConfigDir+"/agents/"+filepath.ToSlash(rel)] = path
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else if cfg.DefaultPolicy != "" {
		if _, err := os.Stat(cfg.DefaultPolicy); err == nil {
			out[backupConfigDir+"/"+agentcatalog.AgentConfigFilename] = cfg.DefaultPolicy
		}
	}
	return out, nil
}

// configDigest identifies a set of configuration files by name and content.
func configDigest(files []backupFile) string {
	sorted := append([]backupFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	h := sha256.New()
	for _, f := range sorted {
		fmt.Fprintf(h, "%s\t%s\n", f.Name, f.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// liveConfigDigest is configDigest over the installation's current files.
func liveConfigDigest(ctx context.Context, cfg *config.Config) (string, error) {
	src, err := configSources(ctx, cfg)
	if err != nil {
		return "", err
	}
	files := make([]backupFile, 0, len(src))
	for name, path := range src {
		sum, n, err := fileSHA256(path)
		if err != nil {
			return "", err
		}
		files = append(files, backupFile{Name: name, SHA256: sum, Bytes: n})
	}
	return configDigest(files), nil
}

func createBackup(ctx context.Context, cfg *config.Config, dest string, requireCold bool) (*backupManifest, error) {
	if entries, err := os.ReadDir(dest); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty; a backup is written into a new or empty directory", dest)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := os.Stat(cfg.EvidenceDBPath()); err != nil {
		return nil, fmt.Errorf("no evidence store at %s: nothing to back up (%w)", cfg.EvidenceDBPath(), err)
	}
	mode := backupModeCold
	if talonProcessRunning(cfg) {
		if requireCold {
			return nil, errors.New("--cold: a Talon process of this installation is running, stopped without a clean shutdown less than a minute ago, or its runtime records cannot be read; stop 'talon serve' and 'talon ui serve' and retry")
		}
		mode = backupModeOnline
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, err
	}
	m := &backupManifest{
		Format: backupFormat, BackupID: "bk_" + uuid.New().String(), TalonVersion: Version, CreatedAt: time.Now().UTC(),
		DataDir: cfg.DataDir, Mode: mode, Absent: []string{}, Config: []backupFile{}, NotIncluded: backupNotIncluded,
	}
	// Configuration first: the hold stamped into the evidence snapshot names
	// the configuration it was taken with.
	if err := captureConfig(ctx, cfg, dest, m); err != nil {
		return nil, err
	}
	if err := snapshotStores(ctx, cfg, dest, m); err != nil {
		return nil, err
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

// captureConfig copies the configuration files into the backup and records
// them, with their digest, in the manifest.
func captureConfig(ctx context.Context, cfg *config.Config, dest string, m *backupManifest) error {
	src, err := configSources(ctx, cfg)
	if err != nil {
		return fmt.Errorf("reading configuration files: %w", err)
	}
	names := make([]string, 0, len(src))
	for name := range src {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		dst := filepath.Join(dest, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := copyFile(src[name], dst); err != nil {
			return fmt.Errorf("copying %s: %w", src[name], err)
		}
		sum, n, err := fileSHA256(dst)
		if err != nil {
			return err
		}
		m.Config = append(m.Config, backupFile{Name: name, SHA256: sum, Bytes: n})
	}
	m.ConfigDigest = configDigest(m.Config)
	return nil
}

// snapshotStores snapshots each durable store that exists and records the
// ones that do not. The evidence snapshot receives the recovery hold.
func snapshotStores(ctx context.Context, cfg *config.Config, dest string, m *backupManifest) error {
	for _, name := range backupStores {
		srcDB := filepath.Join(cfg.DataDir, name)
		if _, err := os.Stat(srcDB); errors.Is(err, os.ErrNotExist) {
			m.Absent = append(m.Absent, name)
			continue
		}
		dst := filepath.Join(dest, name)
		if err := snapshotSQLite(ctx, srcDB, dst); err != nil {
			return fmt.Errorf("snapshotting %s: %w", name, err)
		}
		if name == "evidence.db" {
			if err := stampSnapshotHold(ctx, dst, m); err != nil {
				return fmt.Errorf("stamping the recovery hold into the snapshot: %w", err)
			}
		}
		sum, n, err := fileSHA256(dst)
		if err != nil {
			return err
		}
		m.Files = append(m.Files, backupFile{Name: name, SHA256: sum, Bytes: n})
	}
	return nil
}

// stampSnapshotHold writes the recovery hold into the evidence SNAPSHOT
// (never the live store) and leaves it a single plain database file.
func stampSnapshotHold(ctx context.Context, snapshot string, m *backupManifest) error {
	db, err := sql.Open("sqlite3", "file:"+snapshot+"?_journal_mode=DELETE")
	if err != nil {
		return err
	}
	defer db.Close()
	return action.StampRecoveryHold(ctx, db, m.BackupID, m.CreatedAt, m.ConfigDigest)
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

// readManifest loads and validates a manifest: a backup whose manifest is
// malformed, incomplete or inconsistent is refused before any file is read
// through it.
func readManifest(dir string) (*backupManifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var m backupManifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest.json is not a valid %s manifest: %w", backupFormat, err)
	}
	if m.Format != backupFormat {
		return nil, fmt.Errorf("manifest.json has format %q, want %s", m.Format, backupFormat)
	}
	if !strings.HasPrefix(m.BackupID, "bk_") || m.CreatedAt.IsZero() {
		return nil, errors.New("manifest.json has no backup_id or created_at")
	}
	if m.Mode != backupModeCold && m.Mode != backupModeOnline {
		return nil, fmt.Errorf("manifest.json has unknown mode %q", m.Mode)
	}
	if err := validateManifestStores(&m); err != nil {
		return nil, err
	}
	if err := validateManifestConfig(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// validateManifestStores: every known store is accounted for exactly once,
// as a snapshot or as absent; nothing else is listed.
func validateManifestStores(m *backupManifest) error {
	known := map[string]bool{}
	for _, s := range backupStores {
		known[s] = true
	}
	seen := map[string]string{}
	for _, f := range m.Files {
		if !known[f.Name] {
			return fmt.Errorf("manifest.json lists an unexpected store %q (allowed: %s)", f.Name, strings.Join(backupStores, ", "))
		}
		if seen[f.Name] != "" {
			return fmt.Errorf("manifest.json lists %q more than once", f.Name)
		}
		seen[f.Name] = "file"
	}
	for _, name := range m.Absent {
		if !known[name] || name == "evidence.db" {
			return fmt.Errorf("manifest.json marks %q absent, which is not allowed", name)
		}
		if seen[name] != "" {
			return fmt.Errorf("manifest.json lists %q as %s and as absent", name, seen[name])
		}
		seen[name] = "absent"
	}
	for _, s := range backupStores {
		if seen[s] == "" {
			return fmt.Errorf("manifest.json accounts for neither a snapshot nor the absence of %q: the backup is incomplete", s)
		}
	}
	return nil
}

// validateManifestConfig: configuration paths stay under config/, are
// unique, and match the recorded digest.
func validateManifestConfig(m *backupManifest) error {
	cseen := map[string]bool{}
	for _, f := range m.Config {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(f.Name)))
		if clean != f.Name || !strings.HasPrefix(f.Name, backupConfigDir+"/") || strings.Contains(f.Name, "..") || strings.ContainsAny(f.Name, "\\\x00") || filepath.IsAbs(f.Name) {
			return fmt.Errorf("manifest.json lists a configuration path outside %s/: %q", backupConfigDir, f.Name)
		}
		if cseen[f.Name] {
			return fmt.Errorf("manifest.json lists %q more than once", f.Name)
		}
		cseen[f.Name] = true
	}
	if m.ConfigDigest != configDigest(m.Config) {
		return errors.New("manifest.json config_digest does not match its configuration list")
	}
	return nil
}

// unexpectedFiles lists what is in the backup directory but not in the
// manifest: a backup carries exactly what its manifest accounts for.
func unexpectedFiles(dir string, m *backupManifest) ([]string, error) {
	want := map[string]bool{"manifest.json": true}
	for _, f := range m.Files {
		want[f.Name] = true
	}
	for _, f := range m.Config {
		want[f.Name] = true
	}
	var extra []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel = filepath.ToSlash(rel); !want[rel] {
			extra = append(extra, rel)
		}
		return nil
	})
	sort.Strings(extra)
	return extra, err
}

// verifyBackup returns a line per check and a non-nil error when any check
// fails. It reads the backup only; nothing in it or in the data directory
// is written.
func verifyBackup(ctx context.Context, cfg *config.Config, dir string) ([]string, error) {
	var rep []string
	m, err := readManifest(dir)
	if err != nil {
		return rep, err
	}
	rep = append(rep, fmt.Sprintf("manifest: %s %s, taken %s by talon %s from %s", m.Format, m.BackupID, m.CreatedAt.Format(time.RFC3339), m.TalonVersion, m.DataDir))
	rep = append(rep, "mode: "+backupModeNote(m.Mode))
	failed := 0
	fail := func(format string, a ...any) {
		rep = append(rep, "FAIL "+fmt.Sprintf(format, a...))
		failed++
	}
	extra, err := unexpectedFiles(dir, m)
	if err != nil {
		return rep, err
	}
	if len(extra) > 0 {
		fail("the backup contains files its manifest does not account for: %s", strings.Join(extra, ", "))
	}
	lines, bad := verifyStores(ctx, cfg, dir, m)
	rep = append(rep, lines...)
	failed += bad
	for _, name := range m.Absent {
		rep = append(rep, fmt.Sprintf("note %s did not exist when the backup was taken", name))
	}
	badConfig := 0
	for _, f := range m.Config {
		if !checksumMatches(filepath.Join(dir, filepath.FromSlash(f.Name)), f) {
			fail("%s: missing, or checksum or size differs from the manifest", f.Name)
			badConfig++
		}
	}
	if badConfig == 0 {
		rep = append(rep, fmt.Sprintf("ok   configuration: %d file(s), digest %s", len(m.Config), m.ConfigDigest))
	}
	if live, err := liveConfigDigest(ctx, cfg); err == nil && live != m.ConfigDigest {
		rep = append(rep, "note the configuration files of THIS installation differ from those captured in the backup (company policy or agent files changed, or this is another host); review "+backupConfigDir+"/ before restoring")
	}
	if failed > 0 {
		return rep, fmt.Errorf("%d check(s) failed", failed)
	}
	return rep, nil
}

// verifyStores checks every snapshot: checksum, SQLite integrity, and what
// only the keys can establish.
func verifyStores(ctx context.Context, cfg *config.Config, dir string, m *backupManifest) (rep []string, failed int) {
	for _, f := range m.Files {
		p := filepath.Join(dir, f.Name)
		if !checksumMatches(p, f) {
			rep = append(rep, fmt.Sprintf("FAIL %s: missing, or checksum or size differs from the manifest", f.Name))
			failed++
			continue
		}
		if res, err := sqliteIntegrity(ctx, p); err != nil || res != "ok" {
			rep = append(rep, fmt.Sprintf("FAIL %s: integrity_check %q %s", f.Name, res, errString(err)))
			failed++
			continue
		}
		rep = append(rep, fmt.Sprintf("ok   %s: checksum and SQLite integrity", f.Name))
		line, ok := verifyStoreContent(ctx, cfg, m, f.Name, p)
		if line != "" {
			rep = append(rep, line)
		}
		if !ok {
			failed++
		}
	}
	return rep, failed
}

func checksumMatches(path string, f backupFile) bool {
	sum, n, err := fileSHA256(path)
	return err == nil && sum == f.SHA256 && n == f.Bytes
}

// verifyStoreContent checks what only the keys can establish: every
// evidence signature and every vault entry, and that the evidence snapshot
// carries this backup's recovery hold.
func verifyStoreContent(ctx context.Context, cfg *config.Config, m *backupManifest, name, p string) (line string, ok bool) {
	switch name {
	case "evidence.db":
		if err := snapshotCarriesHold(ctx, p, m.BackupID); err != nil {
			return "FAIL evidence.db: " + err.Error(), false
		}
		total, invalid, err := verifyEvidenceFile(ctx, p, cfg.SigningKey)
		if err != nil || invalid > 0 {
			return fmt.Sprintf("FAIL evidence signatures: %d of %d records do not verify with the configured TALON_SIGNING_KEY %v", invalid, total, errString(err)), false
		}
		return fmt.Sprintf("ok   evidence signatures: %d of %d records verify with the configured TALON_SIGNING_KEY; the snapshot carries the recovery hold", total, total), true
	case "secrets.db":
		rep, err := secrets.VerifyFile(ctx, p, cfg.SecretsKey)
		if err != nil {
			return "FAIL vault: " + err.Error(), false
		}
		if len(rep.Undecryptable) > 0 {
			return fmt.Sprintf("FAIL vault: %d of %d entries do not decrypt with the configured TALON_SECRETS_KEY (%s)", len(rep.Undecryptable), rep.Entries, strings.Join(rep.Undecryptable, ", ")), false
		}
		return fmt.Sprintf("ok   vault: all %d entries decrypt with the configured TALON_SECRETS_KEY (ACL-restricted entries included; no value was read out)", rep.Entries), true
	}
	return "", true
}

func snapshotCarriesHold(ctx context.Context, path, backupID string) error {
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	holds, err := action.ActiveRecoveryHolds(ctx, db)
	if err != nil {
		return err
	}
	for i := range holds {
		if holds[i].BackupID == backupID {
			return nil
		}
	}
	return errors.New("the snapshot does not carry this backup's recovery hold: an installation restored from it would dispatch governed actions without reconciliation")
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

// resumeAfterRestore shows the recovery hold of a restored installation
// and, with --reconciled, ends it.
func resumeAfterRestore(ctx context.Context, out io.Writer, cfg *config.Config) error {
	evStore, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("opening the evidence store: %w", err)
	}
	defer evStore.Close()
	db := evStore.DB()
	holds, err := action.ActiveRecoveryHolds(ctx, db)
	if err != nil {
		return fmt.Errorf("reading recovery state: %w", err)
	}
	if len(holds) == 0 {
		fmt.Fprintln(out, "No recovery hold: this installation is not running on a restored backup (or was already resumed).")
		fmt.Fprintln(out, "Nothing was changed and no evidence was written.")
		return notHeld()
	}
	hold := holds[0]
	fmt.Fprintf(out, "RECOVERY HOLD: this installation runs on backup %s, taken %s.\n", hold.BackupID, hold.BackupCreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintln(out, "No governed action is dispatched. Everything Talon did after that time is missing from its ledger.")
	open, err := action.OpenOperations(ctx, db)
	if err != nil {
		return fmt.Errorf("reading open operations: %w", err)
	}
	if len(open) == 0 {
		fmt.Fprintln(out, "\nNo operation was open in the backup.")
	} else {
		fmt.Fprintf(out, "\n%d operation(s) were open in the backup. Each may have been executed after it was taken; check the downstream system (by the Idempotency-Key Talon sends):\n", len(open))
		for i := range open {
			o := &open[i]
			fmt.Fprintf(out, "  %s  %s/%s  %s  %s  Idempotency-Key %s\n", o.OperationID, o.TenantID, o.AgentID, o.Action, o.Status, o.IdempotencyKey)
		}
	}
	fmt.Fprintln(out, "Operations established after the backup are not listed: Talon no longer knows them. Reconcile those from the downstream system and the calling application.")

	live, err := liveConfigDigest(ctx, cfg)
	if err != nil {
		return fmt.Errorf("reading configuration files: %w", err)
	}
	drift := hold.ConfigDigest != "" && live != hold.ConfigDigest
	if drift {
		fmt.Fprintln(out, "\nCONFIGURATION CHANGED: the company policy or agent files of this installation differ from those captured with the backup. Review them (the backup's copies are under config/ in the backup directory): a restore must not silently change which policy is enforced.")
	}
	if !backupResumeReconciled {
		fmt.Fprintln(out, "\nNot resumed. After reconciling: talon backup resume --reconciled [--hold-operation <operation_id>]...")
		return errors.New("recovery hold is active")
	}
	if drift && !backupResumeAcceptDrift {
		return errors.New("the configuration differs from the backup's: review it, then pass --accept-config-change to resume with the current configuration")
	}
	// The held operation ids, the end of the hold and the signed record of
	// the operator's decision commit in ONE transaction (the evidence
	// store's transactional writer). If the record cannot be written, the
	// hold stays active and dispatch stays refused.
	id := "rr_" + uuid.New().String()[:12]
	w := evStore.NewTxWriter()
	resumeRaceHook()
	ended, err := action.ResumeRecovery(ctx, db, operatorID(), backupResumeHoldOps, time.Now(), func(ctx context.Context, tx *sql.Tx, ended []action.RecoveryHold) error {
		backups := make([]string, 0, len(ended))
		for i := range ended {
			backups = append(backups, ended[i].BackupID+" taken "+ended[i].BackupCreatedAt.UTC().Format(time.RFC3339))
		}
		reasons := []string{"backups: " + strings.Join(backups, "; "), fmt.Sprintf("open operations in the backup: %d", len(open)), "held operation ids: " + strings.Join(backupResumeHoldOps, ","), fmt.Sprintf("configuration changed since the backup: %t", drift)}
		return w.Store(ctx, tx, &evidence.Evidence{
			ID: id, CorrelationID: id, Timestamp: time.Now().UTC(), TenantID: "system", AgentID: "talon-backup",
			InvocationType: "recovery_resumed", RequestSourceID: operatorID(),
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "recovery_resumed", Reasons: reasons},
		})
	})
	if err != nil {
		w.Discard()
		// Say what the state IS, not what it is assumed to be: another
		// command may have ended the hold while this one failed.
		state := "the recovery hold is still active and nothing is dispatched"
		if now, rerr := action.ActiveRecoveryHolds(ctx, db); rerr != nil {
			state = "whether a recovery hold is still active could not be read; check with: talon backup resume"
		} else if len(now) == 0 {
			state = "no recovery hold is active now (another command ended it); this command changed nothing and wrote no evidence"
		}
		return fmt.Errorf("not resumed by this command, %s: %w", state, err)
	}
	if len(ended) == 0 {
		// The hold this command saw was ended by another `talon backup
		// resume` before this command's transaction. Nothing happened here:
		// no state change, no held id, no evidence record. The evidence id
		// prepared above was never written and must not be named.
		w.Discard()
		fmt.Fprintln(out, "\nNot resumed by this command: the recovery hold was ended by another `talon backup resume` in the meantime.")
		fmt.Fprintln(out, "This command changed nothing, held no operation id and wrote no evidence. The other command's record: talon audit list --agent talon-backup")
		return notHeld()
	}
	w.Committed(ctx)
	// The record committed in the transaction that ended the hold. Name it
	// only after reading it back with a valid signature.
	rec, err := evStore.Get(ctx, id)
	if err != nil || rec == nil || !evStore.VerifyRecord(rec) {
		return fmt.Errorf("the recovery hold was ended, but its evidence record %s could not be read back and verified (%v): check the evidence store before relying on it", id, err)
	}
	fmt.Fprintf(out, "\nResumed: %d hold(s) ended, %d operation id(s) held for good. Evidence: %s (signed, recovery_resumed).\n", len(ended), len(backupResumeHoldOps), id)
	return nil
}

// resumeRaceHook runs between a resume's reading of the active hold and its
// transaction. It does nothing; tests use it to let another resume win.
var resumeRaceHook = func() {}

// notHeld is the error of a resume that did not happen although the
// operator named operation ids to hold: those ids are NOT held, and saying
// nothing would let the operator believe they are.
func notHeld() error {
	if len(backupResumeHoldOps) == 0 {
		return nil
	}
	return fmt.Errorf("the operation ids named with --hold-operation were NOT held by this command (no recovery hold was ended by it): %s", strings.Join(backupResumeHoldOps, ", "))
}

func init() {
	backupCreateCmd.Flags().BoolVar(&backupRequireCold, "cold", false, "refuse unless no Talon process of this installation is running (one coherent recovery point)")
	backupResumeCmd.Flags().BoolVar(&backupResumeReconciled, "reconciled", false, "state that the open operations were checked in the downstream systems; ends the recovery hold")
	backupResumeCmd.Flags().StringArrayVar(&backupResumeHoldOps, "hold-operation", nil, "operation_id to keep held for good (repeatable)")
	backupResumeCmd.Flags().BoolVar(&backupResumeAcceptDrift, "accept-config-change", false, "resume although the configuration files differ from those captured with the backup")
	backupCmd.AddCommand(backupCreateCmd, backupVerifyCmd, backupResumeCmd)
	rootCmd.AddCommand(backupCmd)
}
