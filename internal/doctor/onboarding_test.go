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
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
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
