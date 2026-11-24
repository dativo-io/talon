package doctor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
)

// Onboarding failure modes (#575), each reported accurately, read-only and
// without a secret value in any message.

const (
	keySupport = "tk-support-0123456789abcdef"
	keyHR      = "tk-hr-0123456789abcdef"
)

// onboardingFleet is two use cases under agents_dir, as `talon agents add`
// writes them (tenant default, one key binding each).
func onboardingFleet(t *testing.T) (cfg *config.Config, agentsDir string) {
	t.Helper()
	dataDir := t.TempDir()
	agentsDir = filepath.Join(dataDir, "agents")
	t.Setenv("TALON_DATA_DIR", dataDir)
	t.Setenv("TALON_AGENTS_DIR", agentsDir)
	t.Setenv("TALON_SECRETS_KEY", strings.Repeat("s", 32))
	for _, a := range []struct{ dir, name, secret string }{{"customer-support", "customer-support", "customer-support-talon-key"}, {"hr-copilot", "hr-copilot", "hr-copilot-talon-key"}} {
		d := filepath.Join(agentsDir, a.dir)
		require.NoError(t, os.MkdirAll(d, 0o755))
		y := "agent:\n  name: " + a.name + "\n  version: \"1.0.0\"\n  key:\n    secret_name: " + a.secret + "\npolicies:\n  cost_limits: {}\n"
		require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(y), 0o600))
	}
	cfg, err := config.Load()
	require.NoError(t, err)
	return cfg, agentsDir
}

func storeSecret(t *testing.T, cfg *config.Config, name, value string, acl secrets.ACL) {
	t.Helper()
	store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.Set(context.Background(), name, []byte(value), acl))
}

func byName(results []CheckResult) map[string]CheckResult {
	m := map[string]CheckResult{}
	for _, r := range results {
		m[r.Name] = r
	}
	return m
}

func assertNoSecretValue(t *testing.T, results []CheckResult, values ...string) {
	t.Helper()
	for _, r := range results {
		for _, v := range values {
			assert.NotContains(t, r.Message+r.Fix, v, "%s printed a secret value", r.Name)
		}
	}
}

// vaultFingerprint is the vault's bytes plus its access-log row count: a
// read-only check changes neither.
func vaultFingerprint(t *testing.T, cfg *config.Config) string {
	t.Helper()
	b, err := os.ReadFile(cfg.SecretsDBPath())
	require.NoError(t, err)
	db, err := sql.Open("sqlite3", "file:"+cfg.SecretsDBPath()+"?mode=ro")
	require.NoError(t, err)
	defer db.Close()
	var n, counted int
	require.NoError(t, db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM secret_access_log`).Scan(&n))
	require.NoError(t, db.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(access_count),0) FROM secrets`).Scan(&counted))
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%s log=%d counted=%d", hex.EncodeToString(sum[:]), n, counted)
}

func TestConfigLoadFailure_FixMatchesTheCause(t *testing.T) {
	perm := configLoadFailure(fmt.Errorf("open talon.config.yaml: %w", fs.ErrPermission))
	assert.Equal(t, "fail", perm.Status)
	assert.Contains(t, perm.Fix, "readable")
	assert.NotContains(t, perm.Fix, "YAML")

	parse := configLoadFailure(viper.ConfigParseError{})
	assert.Contains(t, parse.Fix, "YAML")

	missing := configLoadFailure(fmt.Errorf("open x.yaml: %w", fs.ErrNotExist))
	assert.Contains(t, missing.Fix, "--config")
}

// An existing config file that cannot be used is the ONE reported cause: no
// cascade of checks judging the configless defaults instead (the false
// "no LLM provider configured", "agent.talon.yaml not found").
func TestRun_UnusableConfigIsTheOneCause(t *testing.T) {
	t.Setenv("TALON_DATA_DIR", t.TempDir())
	config.RecordFileRead(fmt.Errorf("open talon.config.yaml: %w", fs.ErrPermission))
	t.Cleanup(func() { config.RecordFileRead(nil) })

	report := Run(context.Background(), Options{GatewayConfigPath: "talon.config.yaml", SkipUpstream: true})
	assert.Equal(t, "fail", report.Status)
	got := byName(report.Checks)
	require.Contains(t, got, "config_load")
	assert.Contains(t, got["config_load"].Message, "permission denied")
	for _, absent := range []string{"llm_keys", "policy_valid", "gateway_config_valid", "gateway_agent_identity"} {
		assert.NotContains(t, got, absent, "a check judging defaults must not run while the config file cannot be read")
	}
}

func TestCheckVaultKey_ProvesTheKeyDecryptsTheVault(t *testing.T) {
	cfg, _ := onboardingFleet(t)
	assert.Equal(t, "pass", checkVaultKey(context.Background(), cfg).Status, "no vault yet")

	storeSecret(t, cfg, "customer-support-talon-key", keySupport, secrets.ACL{})
	storeSecret(t, cfg, "hr-copilot-talon-key", keyHR, secrets.ACL{})
	ok := checkVaultKey(context.Background(), cfg)
	assert.Equal(t, "pass", ok.Status)
	assert.Contains(t, ok.Message, "all 2")

	before := vaultFingerprint(t, cfg)
	wrong := *cfg
	wrong.SecretsKey = strings.Repeat("w", 32)
	bad := checkVaultKey(context.Background(), &wrong)
	assert.Equal(t, "fail", bad.Status)
	assert.Contains(t, bad.Message, "decrypts none of the 2")
	assert.Contains(t, bad.Fix, "Restore")
	assert.Contains(t, bad.Fix, "Do not re-set")
	assert.Equal(t, before, vaultFingerprint(t, cfg), "verification reads only")
}

// With two use cases each gets its own verdict: a problem with one never
// hides the other, and each cause has its own fix — never a re-set for a
// secret that exists but does not decrypt.
func TestCheckUseCaseKeys_OneVerdictPerUseCase(t *testing.T) {
	t.Run("both resolve", func(t *testing.T) {
		cfg, _ := onboardingFleet(t)
		storeSecret(t, cfg, "customer-support-talon-key", keySupport, secrets.ACL{})
		storeSecret(t, cfg, "hr-copilot-talon-key", keyHR, secrets.ACL{})
		before := vaultFingerprint(t, cfg)
		res := checkUseCaseKeys(context.Background(), cfg)
		got := byName(res)
		assert.Equal(t, "pass", got["use_case_key:customer-support"].Status)
		assert.Equal(t, "pass", got["use_case_key:hr-copilot"].Status)
		assertNoSecretValue(t, res, keySupport, keyHR)
		assert.Equal(t, before, vaultFingerprint(t, cfg), "no access-log row, no counter, no byte changed")
	})
	t.Run("the second key is missing", func(t *testing.T) {
		cfg, _ := onboardingFleet(t)
		storeSecret(t, cfg, "customer-support-talon-key", keySupport, secrets.ACL{})
		got := byName(checkUseCaseKeys(context.Background(), cfg))
		assert.Equal(t, "pass", got["use_case_key:customer-support"].Status)
		hr := got["use_case_key:hr-copilot"]
		assert.Equal(t, "fail", hr.Status)
		assert.Contains(t, hr.Message, "not in the vault")
		assert.Contains(t, hr.Fix, "talon secrets set hr-copilot-talon-key --tenant default --agent hr-copilot")
	})
	t.Run("ACL scoped to another use case", func(t *testing.T) {
		cfg, _ := onboardingFleet(t)
		storeSecret(t, cfg, "customer-support-talon-key", keySupport, secrets.ACL{})
		storeSecret(t, cfg, "hr-copilot-talon-key", keyHR, secrets.ACL{Agents: []string{"customer-support"}})
		hr := byName(checkUseCaseKeys(context.Background(), cfg))["use_case_key:hr-copilot"]
		assert.Equal(t, "fail", hr.Status)
		assert.Contains(t, hr.Message, "ACL")
		assert.Contains(t, hr.Fix, "Review the stored secret ACL")
		assert.Contains(t, hr.Fix, "do not re-set")
		assert.NotContains(t, hr.Fix, "talon secrets set", "an ACL denial must not lead to a destructive secret overwrite")
	})
	t.Run("secrets key changed", func(t *testing.T) {
		cfg, _ := onboardingFleet(t)
		storeSecret(t, cfg, "customer-support-talon-key", keySupport, secrets.ACL{})
		storeSecret(t, cfg, "hr-copilot-talon-key", keyHR, secrets.ACL{})
		wrong := *cfg
		wrong.SecretsKey = strings.Repeat("w", 32)
		res := checkUseCaseKeys(context.Background(), &wrong)
		for _, name := range []string{"use_case_key:customer-support", "use_case_key:hr-copilot"} {
			r := byName(res)[name]
			assert.Equal(t, "fail", r.Status, name)
			assert.Contains(t, r.Message, "cannot be decrypted")
			assert.Contains(t, r.Fix, "do not re-set")
		}
		assertNoSecretValue(t, res, keySupport, keyHR)
	})
	t.Run("no vault at all is reported, and not created", func(t *testing.T) {
		cfg, _ := onboardingFleet(t)
		res := checkUseCaseKeys(context.Background(), cfg)
		assert.Equal(t, "fail", byName(res)["use_case_key:hr-copilot"].Status)
		_, err := os.Stat(cfg.SecretsDBPath())
		assert.True(t, errors.Is(err, os.ErrNotExist), "doctor never creates a vault")
	})
}

// The identity dry-run reads keys through the read-only vault: running the
// whole doctor leaves the vault byte-identical and logs no access.
func TestRun_LeavesTheVaultUntouched(t *testing.T) {
	cfg, _ := onboardingFleet(t)
	storeSecret(t, cfg, "customer-support-talon-key", keySupport, secrets.ACL{})
	storeSecret(t, cfg, "hr-copilot-talon-key", keyHR, secrets.ACL{})
	storeSecret(t, cfg, "openai-api-key", "sk-provider-0123456789", secrets.ACL{})
	gw := filepath.Join(t.TempDir(), "talon.config.yaml")
	require.NoError(t, os.WriteFile(gw, []byte("gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      secret_name: \"openai-api-key\"\n      base_url: \"http://127.0.0.1:9\"\n"), 0o600))
	before := vaultFingerprint(t, cfg)
	report := Run(context.Background(), Options{GatewayConfigPath: gw, SkipUpstream: true})
	got := byName(report.Checks)
	assert.Equal(t, "pass", got["use_case_key:hr-copilot"].Status)
	assert.Equal(t, "pass", got["gateway_secrets_openai"].Status, got["gateway_secrets_openai"].Message)
	assert.Equal(t, "pass", got["gateway_agent_identity"].Status, got["gateway_agent_identity"].Message)
	assert.Equal(t, before, vaultFingerprint(t, cfg))
	_, _, err := GatewayIdentityPreflight(context.Background())
	require.NoError(t, err)
	assert.Equal(t, before, vaultFingerprint(t, cfg), "the identity dry-run is read-only too")
	assertNoSecretValue(t, report.Checks, keySupport, keyHR, "sk-provider-0123456789")
}

// A declared MCP action source is discovered as talon serve discovers it at
// startup: unreachable → a failure that says serve will not start.
func TestCheckActionSources_DiscoversLikeServe(t *testing.T) {
	cfg, agentsDir := onboardingFleet(t)
	srv := sdk.NewServer(&sdk.Implementation{Name: "crm", Version: "1"}, &sdk.ServerOptions{
		SetCacheable: func(_ context.Context, _ sdk.Request, c *sdk.Cacheable) { c.TTLMs, c.CacheScope = 60000, "private" },
	})
	srv.AddTool(&sdk.Tool{Name: "ticket.lookup", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"ticket_id": map[string]any{"type": "string"}}}},
		func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return &sdk.CallToolResult{}, nil
		})
	up := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, &sdk.StreamableHTTPOptions{Stateless: true}))
	defer up.Close()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := "http://" + ln.Addr().String() + "/mcp"
	require.NoError(t, ln.Close())

	appendSource := func(url string) {
		p := filepath.Join(agentsDir, "customer-support", "agent.talon.yaml")
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		y := strings.Split(string(b), "actions:")[0] + "actions:\n  sources:\n    crm:\n      type: mcp\n      url: \"" + url + "\"\n  definitions:\n    lookup_ticket:\n      source: crm\n      upstream_name: ticket.lookup\n      read_only: true\n      review: {fields: [ticket_id]}\n"
		require.NoError(t, os.WriteFile(p, []byte(y), 0o600))
	}
	appendSource(up.URL)
	got := byName(checkActionSources(context.Background(), cfg))["action_source:customer-support/crm"]
	assert.Equal(t, "pass", got.Status, got.Message)
	assert.Contains(t, got.Message, "1 tool(s)")

	appendSource(closed)
	got = byName(checkActionSources(context.Background(), cfg))["action_source:customer-support/crm"]
	assert.Equal(t, "fail", got.Status)
	assert.Contains(t, got.Message, "talon serve will not start")
}

// treeSnapshot records every entry under root: path, type, mode, size and
// content digest (symlink targets for links). SQLite's own sidecar files of
// a WAL-mode database are left out: the -shm shared-memory index (SQLite
// creates it for ANY connection, read-only included) and an EMPTY -wal file
// (removed when the last connection closes). Neither holds data; every
// database file and every other file is compared byte for byte.
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			snap[rel] = "link->" + target
		case fi.IsDir():
			snap[rel] = "dir " + fi.Mode().String()
		default:
			if strings.HasSuffix(p, "-shm") || (strings.HasSuffix(p, "-wal") && fi.Size() == 0) {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			sum := sha256.Sum256(b)
			snap[rel] = fmt.Sprintf("file %s %d %s", fi.Mode(), fi.Size(), hex.EncodeToString(sum[:8]))
		}
		return nil
	})
	require.NoError(t, err)
	return snap
}

// PR #592 review, finding 1: the old writability probe wrote a fixed-name
// file in the data directory — overwriting and deleting an existing one,
// and following a symlink to overwrite its target. Doctor now asks access(2)
// and writes nothing: both stay exactly as they were.
func TestRun_NeverTouchesAnExistingProbeNameOrItsSymlinkTarget(t *testing.T) {
	cfg, _ := onboardingFleet(t)
	require.NoError(t, os.MkdirAll(cfg.DataDir, 0o700))
	outside := filepath.Join(t.TempDir(), "precious.txt")
	require.NoError(t, os.WriteFile(outside, []byte("operator data"), 0o600))
	for _, name := range []string{".doctor-space-test", ".doctor-cache-write-test"} {
		require.NoError(t, os.WriteFile(filepath.Join(cfg.DataDir, name), []byte("keep me"), 0o600))
	}
	require.NoError(t, os.Symlink(outside, filepath.Join(cfg.DataDir, ".doctor-write-test")))
	enableCache(t)

	before := treeSnapshot(t, cfg.DataDir)
	report := Run(context.Background(), Options{SkipUpstream: true})
	got := byName(report.Checks)
	assert.Equal(t, "pass", got["data_dir_writable"].Status, got["data_dir_writable"].Message)
	assert.Equal(t, before, treeSnapshot(t, cfg.DataDir), "no entry of the data directory changed")
	b, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, "operator data", string(b), "a symlink's target is never written")
}

// enableCache turns the cache on through configuration (the nested
// cache.* keys have no environment-variable form), so the cache check runs.
func enableCache(t *testing.T) {
	t.Helper()
	viper.Set("cache", map[string]any{"enabled": true, "default_ttl": 3600, "similarity_threshold": 0.92, "max_entries_per_tenant": 10000})
	t.Cleanup(func() { viper.Set("cache", nil) })
}

// PR #592 review, finding 2: a doctor run on a FRESH installation creates
// nothing — no data directory, no evidence store, no vault, no cache
// directory — whether the data directory is missing or was created empty by
// the operator, and still reports what talon will create and whether it can.
func TestRun_FreshInstallationStaysEmpty(t *testing.T) {
	for name, precreate := range map[string]bool{"data directory missing": false, "data directory created empty": true} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data")
			if precreate {
				require.NoError(t, os.MkdirAll(dataDir, 0o700))
			}
			t.Setenv("TALON_DATA_DIR", dataDir)
			t.Setenv("TALON_AGENTS_DIR", "")
			t.Setenv("TALON_SECRETS_KEY", strings.Repeat("s", 32))
			enableCache(t)
			prev, _ := os.Getwd()
			require.NoError(t, os.Chdir(root))
			t.Cleanup(func() { _ = os.Chdir(prev) })

			before := treeSnapshot(t, root)
			report := Run(context.Background(), Options{SkipUpstream: true})
			assert.Equal(t, before, treeSnapshot(t, root), "doctor created something on a fresh installation")
			got := byName(report.Checks)
			assert.Equal(t, "pass", got["data_dir_writable"].Status, got["data_dir_writable"].Message)
			assert.Equal(t, "pass", got["evidence_db"].Status, got["evidence_db"].Message)
			assert.Equal(t, "pass", got["cache"].Status, got["cache"].Message)
			if !precreate {
				assert.Contains(t, got["data_dir_writable"].Message, "does not exist yet")
				assert.Contains(t, got["cache"].Message, "does not exist yet")
			}
		})
	}
}

// PR #592 review, finding 2: on an EXISTING installation (vault, evidence
// store, two use cases) every doctor path — config, use cases, system
// statistics, cache — leaves the whole tree byte-identical.
func TestRun_ExistingInstallationUnchanged(t *testing.T) {
	cfg, _ := onboardingFleet(t)
	storeSecret(t, cfg, "customer-support-talon-key", keySupport, secrets.ACL{})
	storeSecret(t, cfg, "hr-copilot-talon-key", keyHR, secrets.ACL{})
	ev, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	require.NoError(t, ev.Store(context.Background(), &evidence.Evidence{ID: "ev-1", CorrelationID: "c-1", TenantID: "default", AgentID: "customer-support", Timestamp: time.Now().UTC(), InvocationType: "gateway", PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"}}))
	require.NoError(t, ev.Close())
	enableCache(t)
	// The store file read-only, as for an operator without write access:
	// a read-only open still reads it, a read-write open (which could
	// migrate it) cannot.
	require.NoError(t, os.Chmod(cfg.EvidenceDBPath(), 0o400))

	before := treeSnapshot(t, cfg.DataDir)
	report := Run(context.Background(), Options{SkipUpstream: true})
	assert.Equal(t, before, treeSnapshot(t, cfg.DataDir), "doctor changed the installation")
	got := byName(report.Checks)
	assert.Equal(t, "pass", got["evidence_stats"].Status, got["evidence_stats"].Message)
	assert.Contains(t, got["evidence_stats"].Message, "1 records")
	assert.Equal(t, "pass", got["disk_space"].Status, got["disk_space"].Message)
}

// PR #592 review, finding 2 (migration): an evidence store with an OLDER
// schema — the original evidence table, before the migrations that added
// columns — is read for statistics and never migrated: a read-write open
// would add the columns and change the file.
func TestRun_NeverMigratesAnOlderEvidenceStore(t *testing.T) {
	cfg, _ := onboardingFleet(t)
	require.NoError(t, os.MkdirAll(cfg.DataDir, 0o700))
	db, err := sql.Open("sqlite3", "file:"+cfg.EvidenceDBPath())
	require.NoError(t, err)
	_, err = db.ExecContext(context.Background(), `CREATE TABLE evidence (
		id TEXT PRIMARY KEY, correlation_id TEXT NOT NULL, timestamp TIMESTAMP NOT NULL,
		tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, invocation_type TEXT NOT NULL,
		evidence_json TEXT NOT NULL, signature TEXT NOT NULL);
		INSERT INTO evidence VALUES ('ev-old', 'c-old', '2026-01-01T00:00:00Z', 'default', 'legacy', 'gateway', '{}', 'sig');`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	before := treeSnapshot(t, cfg.DataDir)
	report := Run(context.Background(), Options{SkipUpstream: true})
	assert.Equal(t, before, treeSnapshot(t, cfg.DataDir), "doctor migrated or otherwise changed an older evidence store")
	got := byName(report.Checks)
	assert.Equal(t, "pass", got["evidence_stats"].Status, got["evidence_stats"].Message)
	assert.Contains(t, got["evidence_stats"].Message, "1 records")
}

// Discovery errors are described from typed facts only: a hostile source
// that echoes the credential doctor presented — in its JSON-RPC error
// message or a header — and adds terminal control sequences gets none of it
// into doctor's output.
func TestCheckActionSources_NeverPrintsUpstreamText(t *testing.T) {
	cfg, agentsDir := onboardingFleet(t)
	const token = "crm-token-0123456789abcdef"
	storeSecret(t, cfg, "crm-mcp-token", token, secrets.ACL{})
	for name, reply := range map[string]func(w http.ResponseWriter, auth string){
		"json-rpc error echoing the token": func(w http.ResponseWriter, auth string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"denied for %s \u001b[2J"}}`, auth)
		},
		"content type echoing the token": func(w http.ResponseWriter, auth string) {
			w.Header().Set("Content-Type", "text/x-"+strings.TrimPrefix(auth, "Bearer "))
			_, _ = w.Write([]byte("nope"))
		},
		"HTTP status": func(w http.ResponseWriter, auth string) {
			http.Error(w, "unauthorized "+auth, http.StatusUnauthorized)
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reply(w, r.Header.Get("Authorization")) }))
			defer srv.Close()
			p := filepath.Join(agentsDir, "customer-support", "agent.talon.yaml")
			b, err := os.ReadFile(p)
			require.NoError(t, err)
			y := strings.Split(string(b), "actions:")[0] + "actions:\n  sources:\n    crm:\n      type: mcp\n      url: \"" + srv.URL + "\"\n      auth:\n        secret_name: crm-mcp-token\n  definitions:\n    lookup_ticket:\n      source: crm\n      upstream_name: ticket.lookup\n      read_only: true\n      review: {fields: [ticket_id]}\n"
			require.NoError(t, os.WriteFile(p, []byte(y), 0o600))

			res := checkActionSources(context.Background(), cfg)
			got := byName(res)["action_source:customer-support/crm"]
			require.Equal(t, "fail", got.Status)
			assertNoSecretValue(t, res, token)
			assert.NotContains(t, got.Message, "\x1b", "no terminal control sequence")
			assert.NotContains(t, got.Message, "denied for", "no upstream text")
		})
	}
}

// Provider upstream checks never print a configured URL beyond scheme and
// host: its userinfo or query can carry a credential (the rule the MCP
// source check follows, and the Console's scheme://host display). Failures
// are typed (refused, timeout, DNS), never the HTTP client's error text,
// which embeds the URL.
func TestCheckUpstream_NeverPrintsCredentialBearingURLParts(t *testing.T) {
	const pw, token = "s3cret-pw-0193", "leak-me-token-7731"
	allText := func(rs []CheckResult) string {
		var b strings.Builder
		for _, r := range rs {
			b.WriteString(r.Message + " | " + r.Fix + "\n")
		}
		return b.String()
	}
	t.Run("connection refused", func(t *testing.T) {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := ln.Addr().String()
		require.NoError(t, ln.Close()) // nothing listens there now
		res := checkUpstream(context.Background(), "openai", "http://user:"+pw+"@"+addr+"/v1?api_key="+token)
		text := allText(res)
		assert.NotContains(t, text, pw)
		assert.NotContains(t, text, token)
		assert.Contains(t, text, "connection refused")
		assert.Contains(t, text, "http://"+addr, "scheme and host identify the endpoint")
	})
	t.Run("reachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		defer srv.Close()
		res := checkUpstream(context.Background(), "openai", strings.Replace(srv.URL, "http://", "http://user:"+pw+"@", 1)+"/?token="+token)
		text := allText(res)
		assert.NotContains(t, text, pw)
		assert.NotContains(t, text, token)
		assert.Equal(t, "pass", byName(res)["gateway_upstream_openai"].Status)
	})
	t.Run("invalid URL", func(t *testing.T) {
		res := checkUpstream(context.Background(), "openai", "http://user:"+pw+"@bad host/?k="+token)
		text := allText(res)
		assert.NotContains(t, text, pw)
		assert.NotContains(t, text, token)
		assert.Equal(t, "fail", res[0].Status)
	})
}

// The MCP source check (140c8411): a source URL can carry a credential in
// its userinfo or query, so neither the URL nor transport error text (which
// embeds it) is ever printed, on success or failure. A URL with userinfo is
// refused by source validation before anything is sent (use
// auth.secret_name); a query is accepted and must still never be echoed.
func TestCheckActionSources_NeverPrintsCredentialBearingSourceURL(t *testing.T) {
	const pw, token = "src-pw-55412", "src-token-90817"
	cfg, agentsDir := onboardingFleet(t)
	srv := sdk.NewServer(&sdk.Implementation{Name: "crm", Version: "1"}, &sdk.ServerOptions{
		SetCacheable: func(_ context.Context, _ sdk.Request, c *sdk.Cacheable) { c.TTLMs, c.CacheScope = 60000, "private" },
	})
	srv.AddTool(&sdk.Tool{Name: "ticket.lookup", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"ticket_id": map[string]any{"type": "string"}}}},
		func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return &sdk.CallToolResult{}, nil
		})
	mcpHandler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, &sdk.StreamableHTTPOptions{Stateless: true})
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mcpHandler.ServeHTTP(w, r)
	}))
	defer up.Close()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := ln.Addr().String()
	require.NoError(t, ln.Close())
	setSource := func(url string) {
		p := filepath.Join(agentsDir, "customer-support", "agent.talon.yaml")
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		y := strings.Split(string(b), "actions:")[0] + "actions:\n  sources:\n    crm:\n      type: mcp\n      url: \"" + url + "\"\n  definitions:\n    lookup_ticket:\n      source: crm\n      upstream_name: ticket.lookup\n      read_only: true\n      review: {fields: [ticket_id]}\n"
		require.NoError(t, os.WriteFile(p, []byte(y), 0o600))
	}
	for _, c := range []struct {
		name, url, status, want string
		noRequest               bool
	}{
		{"userinfo is refused before any request", strings.Replace(up.URL, "http://", "http://user:"+pw+"@", 1) + "/?token=" + token, "fail", "local source configuration or credential error", true},
		{"query, reachable", up.URL + "/?token=" + token, "pass", "1 tool(s)", false},
		{"query, unreachable", "http://" + closedAddr + "/mcp?token=" + token, "fail", "connection refused", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			setSource(c.url)
			before := hits.Load()
			got := byName(checkActionSources(context.Background(), cfg))["action_source:customer-support/crm"]
			if c.noRequest {
				assert.Equal(t, before, hits.Load(), "the credential-bearing URL was never sent")
			}
			require.Equal(t, c.status, got.Status, got.Message)
			text := got.Message + " | " + got.Fix
			assert.Contains(t, text, c.want)
			assert.NotContains(t, text, pw)
			assert.NotContains(t, text, token)
			assert.NotContains(t, text, "127.0.0.1", "the source URL is not printed at all")
		})
	}
}

// transportProblem names a transport failure by type only; an unknown error's
// text (which may embed a URL with a credential) is never echoed.
func TestTransportProblem_TypedOnly(t *testing.T) {
	const secret = "leak-7799"
	refused := &url.Error{Op: "Post", URL: "http://u:" + secret + "@h/x", Err: &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}
	for _, c := range []struct {
		err  error
		want string
	}{
		{refused, "transport error: connection refused"},
		{&url.Error{Op: "Get", URL: "http://h/?k=" + secret, Err: &net.DNSError{Err: "no such host", Name: "h", IsNotFound: true}}, "transport error: DNS lookup failed"},
		{fmt.Errorf("wrapped: %w", context.DeadlineExceeded), "transport error: timeout"},
		{&url.Error{Op: "Get", URL: "http://h/?k=" + secret, Err: timeoutErr{}}, "transport error: timeout"},
		{errors.New("tls: handshake failure at http://u:" + secret + "@h"), "transport error (check address, TLS, DNS and egress)"},
	} {
		got := transportProblem(c.err)
		assert.Equal(t, c.want, got)
		assert.NotContains(t, got, secret)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Review finding (#592, 2026-11-23): a remediation command must never turn a
// configured value into shell syntax. agent.key.secret_name and a provider's
// secret_name accept any non-empty string, so every interpolated value is
// rendered by shellWord. Proof by a real POSIX shell: the word parses back to
// exactly the value, and the canary commands inside the value never run.
var adversarialNames = []string{
	"plain-name_1.2",
	"two words",
	"x; touch pwned",
	"$(touch pwned)",
	"`touch pwned`",
	"x && touch pwned || touch pwned",
	"x | touch pwned > pwned",
	"it's",
	`back\slash "dq" $HOME *`,
	"ключ",
	"-leading-dash",
}

func shellOrSkip(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX sh on PATH")
	}
	return sh
}

func TestShellWord_ParsesBackToTheValueAndRunsNothing(t *testing.T) {
	sh := shellOrSkip(t)
	for _, v := range adversarialNames {
		dir := t.TempDir()
		w, ok := shellWord(v)
		require.True(t, ok, "%q", v)
		cmd := exec.CommandContext(t.Context(), sh, "-c", "printf '%s' "+w)
		cmd.Dir = dir
		out, err := cmd.Output()
		require.NoError(t, err, "%q -> %s", v, w)
		assert.Equal(t, v, string(out), "the shell reads back exactly the value")
		assert.NoFileExists(t, filepath.Join(dir, "pwned"), "nothing in %q ran", v)
	}
	w, _ := shellWord("plain-name_1.2")
	assert.Equal(t, "plain-name_1.2", w, "an ordinary name stays readable")
	w, _ = shellWord("")
	assert.Equal(t, "''", w)
	// A value with a control or format character (an escape sequence, a
	// newline, a bidi override, a tab) is never rendered: raw, it would also
	// reach the terminal.
	for _, v := range []string{"a\nb", "\x1b[31mred", "x\u202ey", "tab\there"} {
		_, ok := shellWord(v)
		assert.False(t, ok, "%q", v)
	}
}

// The doctor's own fix text, end to end: the generated `talon secrets set`
// command is run by sh with `talon` replaced by a function printing its
// argv. The secret name is exactly one argument; the canaries never run.
func TestCheckUseCaseKeys_FixCommandsKeepSecretNameOneShellWord(t *testing.T) {
	sh := shellOrSkip(t)
	argv := func(t *testing.T, fix string) []string {
		t.Helper()
		i := strings.Index(fix, "printf '%s'")
		require.GreaterOrEqual(t, i, 0, "a runnable command: %s", fix)
		dir := t.TempDir()
		cmd := exec.CommandContext(t.Context(), sh, "-c", `talon() { for a; do printf '%s\n' "[$a]"; done; }; `+fix[i:])
		cmd.Dir = dir
		out, err := cmd.Output()
		require.NoError(t, err, fix)
		assert.NoFileExists(t, filepath.Join(dir, "pwned"), "nothing in the secret name ran: %s", fix)
		var args []string
		for _, l := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			args = append(args, strings.TrimSuffix(strings.TrimPrefix(l, "["), "]"))
		}
		return args
	}
	t.Run("a name with an escape sequence gets no command at all", func(t *testing.T) {
		cfg, agentsDir := onboardingFleet(t)
		p := filepath.Join(agentsDir, "hr-copilot", "agent.talon.yaml")
		require.NoError(t, os.WriteFile(p, []byte("agent:\n  name: hr-copilot\n  version: \"1.0.0\"\n  key:\n    secret_name: \"key\\x1b[31mred\"\npolicies:\n  cost_limits: {}\n"), 0o600))
		got := byName(checkUseCaseKeys(context.Background(), cfg))["use_case_key:hr-copilot"]
		require.Equal(t, "fail", got.Status, got.Message)
		assert.Equal(t, unprintableNameFix, got.Fix)
		assert.NotContains(t, got.Message+got.Fix, "\x1b", "no raw escape byte reaches the terminal")
		assert.Contains(t, got.Message, `\x1b[31mred`, "the message shows the name escaped")
	})
	for _, name := range adversarialNames {
		if strings.HasPrefix(name, "-") {
			continue // a flag to the CLI, not a shell problem
		}
		t.Run(name, func(t *testing.T) {
			cfg, agentsDir := onboardingFleet(t)
			p := filepath.Join(agentsDir, "hr-copilot", "agent.talon.yaml")
			yamlName := "'" + strings.ReplaceAll(name, "'", "''") + "'"
			require.NoError(t, os.WriteFile(p, []byte("agent:\n  name: hr-copilot\n  version: \"1.0.0\"\n  key:\n    secret_name: "+yamlName+"\npolicies:\n  cost_limits: {}\n"), 0o600))
			storeSecret(t, cfg, "customer-support-talon-key", keySupport, secrets.ACL{})

			missing := byName(checkUseCaseKeys(context.Background(), cfg))["use_case_key:hr-copilot"]
			require.Equal(t, "fail", missing.Status, missing.Message)
			assert.Equal(t, []string{"secrets", "set", name, "--tenant", "default", "--agent", "hr-copilot"}, argv(t, missing.Fix))

			storeSecret(t, cfg, name, "", secrets.ACL{})
			empty := byName(checkUseCaseKeys(context.Background(), cfg))["use_case_key:hr-copilot"]
			require.Equal(t, "fail", empty.Status, empty.Message)
			require.Contains(t, empty.Message, "empty")
			assert.Equal(t, []string{"secrets", "set", name, "--tenant", "default", "--agent", "hr-copilot"}, argv(t, empty.Fix))
		})
	}
}

// The two older fixes that print a secret name use the same rendering.
func TestGatewayFixes_QuoteTheSecretName(t *testing.T) {
	const name = "openai key; touch pwned"
	_, _ = onboardingFleet(t)
	res := checkGatewaySecrets(context.Background(), &gateway.GatewayConfig{Providers: map[string]gateway.ProviderConfig{
		"openai": {Enabled: true, SecretName: name},
	}})
	require.Len(t, res, 1)
	w, _ := shellWord(name)
	assert.Contains(t, res[0].Fix, "talon secrets set "+w)
	assert.NotContains(t, res[0].Fix, "set "+name)
}
