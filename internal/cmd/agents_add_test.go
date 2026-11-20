package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/doctor"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/registration"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

var printedKeyRe = regexp.MustCompile(`talon_uc_[0-9a-f]{48}`)

const addGateway = "gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      secret_name: openai-api-key\n      base_url: \"https://api.openai.com\"\n  organization_policy:\n    defaults:\n      pii_action: block\n      daily_cost: 25\n    constraints:\n      forbidden_tools: [delete_customer]\n"

const supportAgent = "agent:\n  name: support\n  version: \"1.0.0\"\n  key:\n    secret_name: support-talon-key\npolicies:\n  cost_limits: {}\n"

// addEnv prepares an installation directory with one existing use case and
// returns the environment a registration needs. gateway "" means no gateway
// config (no company policy).
func addEnv(t *testing.T, dir, gateway string) map[string]string {
	t.Helper()
	env := map[string]string{
		"TALON_DATA_DIR": filepath.Join(dir, "data"), "TALON_SIGNING_KEY": testutil.TestSigningKey,
		"TALON_SECRETS_KEY": "0123456789abcdef0123456789abcdef", "TALON_AGENTS_DIR": filepath.Join(dir, "agents"),
		"TALON_GATEWAY_CONFIG": filepath.Join(dir, "absent.talon.config.yaml"),
	}
	if gateway != "" {
		env["TALON_GATEWAY_CONFIG"] = filepath.Join(dir, "talon.config.yaml")
		require.NoError(t, os.WriteFile(env["TALON_GATEWAY_CONFIG"], []byte(gateway), 0o600))
	}
	d := filepath.Join(env["TALON_AGENTS_DIR"], "support")
	require.NoError(t, os.MkdirAll(d, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "agent.talon.yaml"), []byte(supportAgent), 0o600))
	return env
}

func setupAddFleet(t *testing.T) (cfg *config.Config, agentsDir string) {
	t.Helper()
	return setupAddFleetWith(t, "")
}

func setupAddFleetWith(t *testing.T, gateway string) (cfg *config.Config, agentsDir string) {
	t.Helper()
	// The data directory is deliberately absent: a first registration creates it.
	env := addEnv(t, t.TempDir(), gateway)
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	require.NoError(t, err)
	return cfg, env["TALON_AGENTS_DIR"]
}

func resetAgentsAddFlags(t *testing.T) {
	t.Helper()
	// setupAddFleet has no gateway config: these registrations state that on purpose.
	agentsAddTenant, agentsAddDescription, agentsAddOwner, agentsAddDryRun, agentsAddNoCompanyPolicy = "default", "", "", false, true
	t.Cleanup(func() {
		agentsAddTenant, agentsAddDescription, agentsAddOwner, agentsAddDryRun, agentsAddNoCompanyPolicy = "default", "", "", false, false
		registrationFault = func(string) error { return nil }
	})
}

func vaultValue(t *testing.T, cfg *config.Config, name string) (string, bool) {
	t.Helper()
	if _, err := os.Stat(cfg.SecretsDBPath()); os.IsNotExist(err) {
		return "", false // nothing was ever written: no vault
	}
	store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	require.NoError(t, err)
	defer store.Close()
	if _, err := store.Metadata(context.Background(), name); errors.Is(err, secrets.ErrSecretNotFound) {
		return "", false
	}
	s, err := store.Get(context.Background(), name, tenantOf(name), agentOf(name))
	require.NoError(t, err)
	return string(s.Value), true
}

// The vault ACL binds a generated key to its use case and tenant; the test
// fleet registers everything in tenant acme.
func tenantOf(string) string { return "acme" }

func agentOf(secret string) string { return strings.TrimSuffix(secret, "-talon-key") }

// registrationRecords returns the registration lifecycle records of a use
// case by type, each verified.
func registrationRecords(t *testing.T, cfg *config.Config, tenant, name string) map[string][]evidence.Evidence {
	t.Helper()
	out := map[string][]evidence.Evidence{}
	if _, err := os.Stat(cfg.EvidenceDBPath()); err != nil {
		return out
	}
	st, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	require.NoError(t, err)
	defer st.Close()
	rows, err := st.List(context.Background(), tenant, name, time.Time{}, time.Time{}, 100)
	require.NoError(t, err)
	for i := range rows {
		require.True(t, st.VerifyRecord(&rows[i]), "every registration record is signed")
		out[rows[i].InvocationType] = append(out[rows[i].InvocationType], rows[i])
	}
	return out
}

// unresolved returns the registrations of name whose signed intent has no
// terminal record, as a complete lookup.
func unresolved(t *testing.T, cfg *config.Config, name string) []registration.Unresolved {
	t.Helper()
	lookup, err := unresolvedRegistrations(context.Background(), cfg, name)
	require.NoError(t, err)
	require.True(t, lookup.Complete)
	return lookup.Unresolved
}

// checkRegistrationsForTest is `talon doctor`'s agent_registrations check.
func checkRegistrationsForTest(t *testing.T, cfg *config.Config) doctor.CheckResult {
	t.Helper()
	return doctor.CheckRegistrations(cfg)
}

func registered(t *testing.T, agentsDir, name string) bool {
	t.Helper()
	scan, err := agentcatalog.DiscoverAgents(context.Background(), agentsDir)
	require.NoError(t, err)
	for i := range scan.Agents {
		if scan.Agents[i].Name == name {
			return true
		}
	}
	return false
}

func TestAgentsAdd_FirstAndSecondUseCase(t *testing.T) {
	cfg, agentsDir := setupAddFleetWith(t, addGateway)
	resetAgentsAddFlags(t)
	agentsAddNoCompanyPolicy = false
	ctx := context.Background()
	gwBefore, err := os.ReadFile(os.Getenv("TALON_GATEWAY_CONFIG"))
	require.NoError(t, err)
	supportBefore, err := os.ReadFile(filepath.Join(agentsDir, "support", "agent.talon.yaml"))
	require.NoError(t, err)

	var out bytes.Buffer
	agentsAddTenant, agentsAddOwner, agentsAddDescription = "acme", "support-engineering", "AI customer support assistant"
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "customer-support"))
	text := out.String()
	key1 := printedKeyRe.FindString(text)
	require.NotEmpty(t, key1, text)
	stored, ok := vaultValue(t, cfg, "customer-support-talon-key")
	require.True(t, ok)
	require.Equal(t, key1, stored, "the printed key is the stored key")

	// The output, in order: identity and owner, configuration location,
	// credential, inherited policy from the canonical projection,
	// activation, how to connect, how to verify, what is not verified —
	// and the secret last, in a block of its own.
	order := []string{
		`Registered AI use case "customer-support"`, "tenant:      acme", "owner:       support-engineering",
		"config:      " + filepath.Join(agentsDir, "customer-support", "agent.talon.yaml"),
		`key:         generated, vault secret "customer-support-talon-key"`, "evidence:", "signed completion record",
		"Company policy this use case runs under", "daily_cost", "25", "from organization.defaults", "pii_action", "block", "the use case can only tighten it",
		"forbidden_tools", "delete_customer", "no layer can remove a tool another forbids",
		"Activation (configuration is not activation)", "NOT PROVEN ACTIVE", "NOT ACTIVE — no Talon process of this installation is running",
		"Connect the application", "<talon-url>/v1/proxy/openai/v1", "Authorization: Bearer <the Talon key>", "TALON_USE_CASE_KEY", "docs/guides/choosing-integration-path.md",
		"Verify the first request", "talon agents show customer-support --effective", "talon audit verify",
		"Not verified by this command", "only requests sent to a Talon endpoint are governed",
		"SECRET — shown once", key1,
	}
	at := 0
	for _, want := range order {
		i := strings.Index(text[at:], want)
		require.GreaterOrEqual(t, i, 0, "%q missing or out of order in:\n%s", want, text)
		at += i + len(want)
	}
	require.Equal(t, 1, strings.Count(text, key1), "the key is printed exactly once")
	above, _, found := strings.Cut(text, "SECRET — shown once")
	require.True(t, found)
	require.NotContains(t, above, "talon_uc_", "nothing above the secret block is secret")
	require.NotContains(t, text, "WARNING")
	require.NotContains(t, text, "Runtime: ACTIVE", "configured is not active: nothing runs here")

	content, err := os.ReadFile(filepath.Join(agentsDir, "customer-support", "agent.talon.yaml"))
	require.NoError(t, err)
	require.Contains(t, string(content), `tenant_id: "acme"`)
	require.Contains(t, string(content), `secret_name: "customer-support-talon-key"`)
	require.Contains(t, string(content), `owner: "support-engineering"`)
	require.Contains(t, string(content), `description: "AI customer support assistant"`)
	require.Contains(t, string(content), "cost_limits: {}", "no budget of its own: the company defaults apply")
	require.NotContains(t, string(content), key1, "the key never lands in the file")
	require.NotContains(t, string(content), "pii_action", "company policy is inherited, not copied into the use case's file")

	// The key is readable only as this use case in its tenant.
	vault, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	require.NoError(t, err)
	_, err = vault.Get(ctx, "customer-support-talon-key", "acme", "support")
	require.Error(t, err, "another use case cannot resolve this key")
	_, err = vault.Get(ctx, "customer-support-talon-key", "other-tenant", "customer-support")
	require.Error(t, err, "another tenant cannot resolve this key")
	require.NoError(t, vault.Close())

	// Signed intent and completion, one correlation, no key in either.
	recs := registrationRecords(t, cfg, "acme", "customer-support")
	require.Len(t, recs[registration.TypeIntent], 1)
	require.Len(t, recs[registration.TypeRegistered], 1)
	require.Empty(t, recs[registration.TypeRolledBack])
	require.Equal(t, recs[registration.TypeIntent][0].CorrelationID, recs[registration.TypeRegistered][0].CorrelationID)
	require.True(t, recs[registration.TypeIntent][0].Timestamp.Before(recs[registration.TypeRegistered][0].Timestamp) || recs[registration.TypeIntent][0].Timestamp.Equal(recs[registration.TypeRegistered][0].Timestamp))
	for _, list := range recs {
		for i := range list {
			require.NotContains(t, strings.Join(list[i].PolicyDecision.Reasons, " "), key1)
			require.Equal(t, evidence.ClassOperatorEvent, evidence.RecordClassOf(list[i].InvocationType), "a registration record is an operator event, never traffic")
		}
	}

	// No secret leakage: the key is nowhere in the evidence database, the
	// agent files or the company configuration, and the vault holds it
	// encrypted, not in clear text.
	for _, path := range []string{cfg.EvidenceDBPath(), cfg.EvidenceDBPath() + "-wal", cfg.SecretsDBPath(), cfg.SecretsDBPath() + "-wal", os.Getenv("TALON_GATEWAY_CONFIG")} {
		raw, rerr := os.ReadFile(path)
		if os.IsNotExist(rerr) {
			continue
		}
		require.NoError(t, rerr)
		require.NotContains(t, string(raw), key1, "the key in clear text in %s", path)
	}

	// A second, unrelated use case: same command, same company policy, no
	// policy copied, nothing of the first one or of the company changed.
	out.Reset()
	agentsAddTenant, agentsAddOwner, agentsAddDescription = "acme", "people-ops", "HR policy assistant"
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "hr-copilot"))
	key2 := printedKeyRe.FindString(out.String())
	require.NotEmpty(t, key2)
	require.NotEqual(t, key1, key2)
	require.Contains(t, out.String(), "from organization.defaults")
	stored, _ = vaultValue(t, cfg, "customer-support-talon-key")
	require.Equal(t, key1, stored, "the first use case's key is untouched")

	scan, err := agentcatalog.DiscoverAgents(ctx, agentsDir)
	require.NoError(t, err, "the fleet validates with both new use cases")
	names := []string{}
	for i := range scan.Agents {
		names = append(names, scan.Agents[i].Name)
	}
	require.ElementsMatch(t, []string{"support", "customer-support", "hr-copilot"}, names)
	gwAfter, _ := os.ReadFile(os.Getenv("TALON_GATEWAY_CONFIG"))
	require.Equal(t, gwBefore, gwAfter, "a registration never changes the company policy")
	supportAfter, _ := os.ReadFile(filepath.Join(agentsDir, "support", "agent.talon.yaml"))
	require.Equal(t, supportBefore, supportAfter, "an existing use case's file is untouched")
}

func TestAgentsAdd_RefusesWithoutWriting(t *testing.T) {
	ctx := context.Background()

	t.Run("an existing name", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		before, _ := os.ReadFile(filepath.Join(agentsDir, "support", "agent.talon.yaml"))
		err := runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "support")
		require.ErrorContains(t, err, "already registered")
		after, _ := os.ReadFile(filepath.Join(agentsDir, "support", "agent.talon.yaml"))
		require.Equal(t, before, after)
		_, ok := vaultValue(t, cfg, "support-talon-key")
		require.False(t, ok, "no key minted for a refused registration")
		require.Empty(t, registrationRecords(t, cfg, "default", "support"), "a refusal in planning writes no evidence")
	})
	t.Run("an existing secret is never replaced or bound", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		require.NoError(t, cfg.EnsureDataDir())
		store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		require.NoError(t, store.Set(ctx, "refund-bot-talon-key", []byte("in-use-key-0001"), secrets.ACL{}))
		require.NoError(t, store.Close())
		var out bytes.Buffer
		err = runAgentsAdd(ctx, &out, cfg, "refund-bot")
		require.ErrorContains(t, err, "already exists")
		require.ErrorContains(t, err, "talon secrets delete refund-bot-talon-key")
		require.NotContains(t, err.Error()+out.String(), "in-use-key-0001")
		_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
		require.True(t, os.IsNotExist(statErr))
		v, _ := vaultValue(t, cfg, "refund-bot-talon-key")
		require.Equal(t, "in-use-key-0001", v)
		// The unreleased --use-existing-key option is gone (#567 review).
		require.Nil(t, agentsAddCmd.Flags().Lookup("use-existing-key"))
	})
	t.Run("an invalid existing fleet", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		bad := filepath.Join(agentsDir, "broken")
		require.NoError(t, os.MkdirAll(bad, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(bad, "agent.talon.yaml"), []byte("agent:\n  name: broken\n  typo_field: 1\n"), 0o600))
		err := runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot")
		require.ErrorContains(t, err, "does not validate")
		_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
		require.True(t, os.IsNotExist(statErr))
		_, ok := vaultValue(t, cfg, "refund-bot-talon-key")
		require.False(t, ok)
	})
	t.Run("no agents_dir", func(t *testing.T) {
		cfg, _ := setupAddFleet(t)
		resetAgentsAddFlags(t)
		cfg.AgentsDir = ""
		require.ErrorContains(t, runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot"), "agents_dir is not configured")
	})
	t.Run("an invalid name", func(t *testing.T) {
		cfg, _ := setupAddFleet(t)
		resetAgentsAddFlags(t)
		for _, n := range []string{"Refund", "../escape", "a b", "", "-x"} {
			require.ErrorContains(t, runAgentsAdd(ctx, &bytes.Buffer{}, cfg, n), "invalid use case name", n)
		}
	})
	t.Run("an invalid company policy", func(t *testing.T) {
		cfg, agentsDir := setupAddFleetWith(t, "gateway:\n  enabled: true\n  not_a_key: 1\n")
		resetAgentsAddFlags(t)
		require.ErrorContains(t, runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot"), "present but invalid")
		_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
		require.True(t, os.IsNotExist(statErr))
	})
}

// An ordinary failure at any step removes exactly what the registration
// created, records a signed rollback that says what happened, prints no
// key, leaves the existing use case alone, and a later registration of the
// same name works.
func TestAgentsAdd_FailureAtEveryStepIsRolledBack(t *testing.T) {
	ctx := context.Background()
	for _, step := range []string{stepIntentRecorded, stepKeyStored, stepFilePublished, stepFleetValidated} {
		t.Run(step, func(t *testing.T) {
			cfg, agentsDir := setupAddFleet(t)
			resetAgentsAddFlags(t)
			agentsAddTenant = "acme"
			var seen []string
			registrationFault = func(s string) error {
				if strings.HasPrefix(s, "fail:") {
					return nil
				}
				seen = append(seen, s)
				if s == step {
					if s == stepFilePublished || s == stepFleetValidated {
						// What a running server's reload would load in this window.
						require.True(t, registered(t, agentsDir, "refund-bot"))
					}
					return errors.New("injected failure after " + s)
				}
				return nil
			}
			var out bytes.Buffer
			err := runAgentsAdd(ctx, &out, cfg, "refund-bot")
			require.ErrorContains(t, err, "injected failure after "+step)
			require.ErrorContains(t, err, "nothing of this registration was left behind")
			require.Equal(t, step, seen[len(seen)-1], "the registration stopped at the failed step")
			require.Empty(t, printedKeyRe.FindString(out.String()+err.Error()), "no key is shown for a failed registration")

			_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
			require.True(t, os.IsNotExist(statErr), "no agent file or directory is left")
			_, ok := vaultValue(t, cfg, "refund-bot-talon-key")
			require.False(t, ok, "no key is left")
			require.False(t, registered(t, agentsDir, "refund-bot"))
			require.True(t, registered(t, agentsDir, "support"), "the existing use case is untouched")

			recs := registrationRecords(t, cfg, "acme", "refund-bot")
			require.Len(t, recs[registration.TypeIntent], 1)
			require.Empty(t, recs[registration.TypeRegistered], "no completion record")
			require.Len(t, recs[registration.TypeRolledBack], 1)
			reasons := strings.Join(recs[registration.TypeRolledBack][0].PolicyDecision.Reasons, " | ")
			require.Contains(t, reasons, "cause: injected failure after "+step)
			switch step {
			case stepIntentRecorded:
				require.Contains(t, reasons, "cleanup: nothing had been created")
			case stepKeyStored:
				require.Contains(t, reasons, "cleanup: removed the key this registration stored")
			default:
				require.Contains(t, reasons, "removed the agent file this registration published; removed the key this registration stored")
			}
			require.Empty(t, unresolved(t, cfg, "refund-bot"), "a rolled-back registration is terminal, not unresolved")

			registrationFault = func(string) error { return nil }
			out.Reset()
			require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
			require.NotEmpty(t, printedKeyRe.FindString(out.String()))
		})
	}

	// After the completion record the registration IS complete: a failure
	// to show the key is reported as that, and nothing is rolled back.
	t.Run(stepCompleted, func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		registrationFault = func(s string) error {
			if s == stepCompleted {
				return errors.New("terminal closed")
			}
			return nil
		}
		var out bytes.Buffer
		err := runAgentsAdd(ctx, &out, cfg, "refund-bot")
		require.ErrorContains(t, err, "completed")
		require.ErrorContains(t, err, "talon secrets set refund-bot-talon-key")
		require.Empty(t, printedKeyRe.FindString(out.String()+err.Error()))
		require.True(t, registered(t, agentsDir, "refund-bot"))
		recs := registrationRecords(t, cfg, "acme", "refund-bot")
		require.Len(t, recs[registration.TypeRegistered], 1)
		require.Empty(t, recs[registration.TypeRolledBack])
	})
}

// A step ITSELF fails (the intent cannot be recorded, the vault refuses the
// write, the file cannot be published, the fleet check fails, the
// completion record cannot be written): nothing usable is left, the signed
// rollback says what was cleaned up, and no key is shown. When even the
// rollback record cannot be written, the artifacts are still removed, the
// error says so, and the dangling intent is detected and closed by the
// next registration.
func TestAgentsAdd_AStepItselfFails(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		step    string
		cleanup string // what the rollback record says; "" = no rollback record at all
	}{
		{stepIntentRecorded, ""},
		{stepKeyStored, "cleanup: nothing had been created"},
		{stepFilePublished, "cleanup: removed the key this registration stored"},
		{stepFleetValidated, "cleanup: removed the agent file this registration published; removed the key this registration stored"},
		{stepCompleted, "cleanup: removed the agent file this registration published; removed the key this registration stored"},
	} {
		t.Run(tc.step, func(t *testing.T) {
			cfg, agentsDir := setupAddFleet(t)
			resetAgentsAddFlags(t)
			agentsAddTenant = "acme"
			registrationFault = func(point string) error {
				if point == "fail:"+tc.step {
					return errors.New("injected: " + tc.step + " itself failed")
				}
				return nil
			}
			var out bytes.Buffer
			err := runAgentsAdd(ctx, &out, cfg, "refund-bot")
			require.ErrorContains(t, err, "injected: "+tc.step+" itself failed")
			require.Empty(t, printedKeyRe.FindString(out.String()+err.Error()))
			_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
			require.True(t, os.IsNotExist(statErr), "no agent file or directory is left")
			_, ok := vaultValue(t, cfg, "refund-bot-talon-key")
			require.False(t, ok, "no key is left")
			require.True(t, registered(t, agentsDir, "support"))

			recs := registrationRecords(t, cfg, "acme", "refund-bot")
			require.Empty(t, recs[registration.TypeRegistered], "no completion record")
			if tc.cleanup == "" {
				// The intent itself could not be recorded: nothing was written anywhere.
				require.ErrorContains(t, err, "nothing else was written")
				require.Empty(t, recs)
			} else {
				require.ErrorContains(t, err, "nothing of this registration was left behind")
				require.Len(t, recs[registration.TypeIntent], 1)
				require.Len(t, recs[registration.TypeRolledBack], 1)
				reasons := strings.Join(recs[registration.TypeRolledBack][0].PolicyDecision.Reasons, " | ")
				require.Contains(t, reasons, "cause: ")
				require.Contains(t, reasons, tc.cleanup)
			}
			require.Empty(t, unresolved(t, cfg, "refund-bot"))
		})
	}

	t.Run("neither the completion nor the rollback record can be written", func(t *testing.T) {
		cfg, agentsDir := setupAddFleet(t)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		registrationFault = func(point string) error {
			if point == "fail:"+stepCompleted || point == "fail:"+stepRollbackRecord {
				return errors.New("evidence store unavailable")
			}
			return nil
		}
		var out bytes.Buffer
		err := runAgentsAdd(ctx, &out, cfg, "refund-bot")
		require.ErrorContains(t, err, "what this registration created was removed (removed the agent file this registration published; removed the key this registration stored)")
		require.ErrorContains(t, err, "the rollback could not be recorded as evidence")
		require.ErrorContains(t, err, "talon doctor")
		require.NotContains(t, err.Error(), "nothing of this registration was left behind", "an unrecorded rollback is not reported as a clean one")
		require.Empty(t, printedKeyRe.FindString(out.String()+err.Error()))
		_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
		require.True(t, os.IsNotExist(statErr))
		_, ok := vaultValue(t, cfg, "refund-bot-talon-key")
		require.False(t, ok)

		// The signed intent has no terminal record: detected, and closed by
		// the next registration, which works because nothing was left.
		require.Len(t, unresolved(t, cfg, "refund-bot"), 1)
		registrationFault = func(string) error { return nil }
		out.Reset()
		require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
		require.Contains(t, out.String(), "left nothing of its own and is now recorded as rolled back")
		require.NotEmpty(t, printedKeyRe.FindString(out.String()))
		require.Empty(t, unresolved(t, cfg, "refund-bot"))
	})
}

// A rollback removes only this registration's own key version: a key someone
// else stored under the name in the meantime survives, and the rollback
// record says so.
func TestAgentsAdd_RollbackRemovesOnlyItsOwnKey(t *testing.T) {
	ctx := context.Background()
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	agentsAddTenant = "acme"
	registrationFault = func(s string) error {
		if s != stepKeyStored {
			return nil
		}
		// Someone replaces the secret between this registration's steps.
		store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		require.NoError(t, err)
		defer store.Close()
		require.NoError(t, store.Set(ctx, "refund-bot-talon-key", []byte("replaced-by-someone-else"), secrets.ACL{}))
		return os.ErrPermission
	}
	err := runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot")
	require.ErrorContains(t, err, "nothing of this registration was left behind")
	got, ok := vaultValue(t, cfg, "refund-bot-talon-key")
	require.True(t, ok)
	require.Equal(t, "replaced-by-someone-else", got)
	_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
	require.True(t, os.IsNotExist(statErr))
	recs := registrationRecords(t, cfg, "acme", "refund-bot")
	require.Contains(t, strings.Join(recs[registration.TypeRolledBack][0].PolicyDecision.Reasons, " | "), "the key this registration stored was already gone")
}

// Of concurrent registrations of one name exactly one completes; the
// others are refused, never overwrite the winner's file or key, and clean
// up nothing that is the winner's.
func TestAgentsAdd_ConcurrentRegistrationsOneWinner(t *testing.T) {
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	agentsAddTenant = "acme"
	const n = 6
	var wg sync.WaitGroup
	start := make(chan struct{})
	outs := make([]bytes.Buffer, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = runAgentsAdd(context.Background(), &outs[i], cfg, "refund-bot")
		}(i)
	}
	close(start)
	wg.Wait()
	winners, key := 0, ""
	for i := 0; i < n; i++ {
		if errs[i] == nil {
			winners++
			key = printedKeyRe.FindString(outs[i].String())
		} else {
			require.Empty(t, printedKeyRe.FindString(outs[i].String()+errs[i].Error()), "a refused registration shows no key")
		}
	}
	require.Equal(t, 1, winners, "errors: %v", errs)
	require.NotEmpty(t, key)
	stored, ok := vaultValue(t, cfg, "refund-bot-talon-key")
	require.True(t, ok, "the winner's key survives every loser's cleanup")
	require.Equal(t, key, stored)
	require.True(t, registered(t, agentsDir, "refund-bot"))
	recs := registrationRecords(t, cfg, "acme", "refund-bot")
	require.Len(t, recs[registration.TypeRegistered], 1)
	require.Empty(t, unresolved(t, cfg, "refund-bot"), "no registration is left without a terminal record")
	// The registrations ran one at a time: every loser found the name
	// registered and wrote nothing, so there is exactly one intent and no
	// rollback.
	require.Len(t, recs[registration.TypeIntent], 1)
	require.Empty(t, recs[registration.TypeRolledBack])
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			require.ErrorContains(t, errs[i], "already registered")
		}
	}
}

// TestAgentsAdd_CrashHelper is not a test of its own: the abrupt-death test
// re-executes the test binary with TALON_TEST_CRASH_STEP set, and this
// function then runs one registration and SIGKILLs its own process at that
// step. No deferred function, rollback or terminal record runs.
func TestAgentsAdd_CrashHelper(t *testing.T) {
	step := os.Getenv("TALON_TEST_CRASH_STEP")
	if step == "" {
		return
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	agentsAddTenant, agentsAddNoCompanyPolicy = "acme", true
	registrationFault = func(s string) error {
		if s == step {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	_ = runAgentsAdd(context.Background(), os.Stdout, cfg, "refund-bot")
	os.Exit(3) // not reached when the step exists
}

// The process dies abruptly at each step, while it holds the registration
// lock. The kernel releases the lock, so nothing has to be unlocked by hand.
// Whatever the process left, nobody has seen a key. `talon doctor` reports
// the registration as INTERRUPTED (not in progress: the lock is free). The
// next registration of the name proves from the signed intent which
// artifacts that registration created, removes exactly those, records it as
// rolled back and registers. The existing use case is never affected.
func TestAgentsAdd_AbruptProcessDeathAtEveryStep(t *testing.T) {
	ctx := context.Background()
	const supportKey = "talon_uc_the_existing_application_key_000000000000001"
	for _, tc := range []struct {
		step      string
		key, file bool
		recovery  string // what the rollback record says was done
	}{
		{stepIntentRecorded, false, false, "observed now: neither the key version nor the agent file its signed intent committed to exists"},
		{stepKeyStored, true, false, "recovery: removed the key version (its vault ownership token equals the one in the signed intent; the key was never shown)"},
		{stepFilePublished, true, true, "recovery: removed the agent file (its SHA-256 equals the one in the signed intent); removed the key version"},
		{stepFleetValidated, true, true, "recovery: removed the agent file (its SHA-256 equals the one in the signed intent); removed the key version"},
	} {
		t.Run(tc.step, func(t *testing.T) {
			dir := t.TempDir()
			env := addEnv(t, dir, "")
			for k, v := range env {
				t.Setenv(k, v)
			}
			cfg, err := config.Load()
			require.NoError(t, err)
			agentsDir := env["TALON_AGENTS_DIR"]
			resetAgentsAddFlags(t)
			agentsAddTenant = "acme"
			// The existing application has its key in the vault, as in a
			// running installation.
			require.NoError(t, cfg.EnsureDataDir())
			seed, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
			require.NoError(t, err)
			require.NoError(t, seed.Set(ctx, "support-talon-key", []byte(supportKey), secrets.ACL{}))
			require.NoError(t, seed.Close())
			// An unrelated file an operator keeps next to the agent files.
			note := filepath.Join(agentsDir, "refund-bot", "NOTES.md")

			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAgentsAdd_CrashHelper$")
			child.Env = append(os.Environ(), "TALON_TEST_CRASH_STEP="+tc.step)
			var childOut bytes.Buffer
			child.Stdout, child.Stderr = &childOut, &childOut
			err = child.Run()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			ws, _ := exit.Sys().(syscall.WaitStatus)
			require.True(t, ws.Signaled() && ws.Signal() == syscall.SIGKILL, "the helper must die by SIGKILL at the step: %v\n%s", err, childOut.String())
			require.Empty(t, printedKeyRe.FindString(childOut.String()), "a key is never printed before completion")

			// What it left. The lock is not among it.
			require.Equal(t, registration.LockFree, registration.Probe(cfg.DataDir), "a killed registration leaves no lock")
			leftKey, hasKey := vaultValue(t, cfg, "refund-bot-talon-key")
			require.Equal(t, tc.key, hasKey)
			_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml"))
			require.Equal(t, tc.file, statErr == nil)
			require.True(t, registered(t, agentsDir, "support"), "the existing use case is untouched and the fleet still validates")
			recs := registrationRecords(t, cfg, "acme", "refund-bot")
			require.Len(t, recs[registration.TypeIntent], 1)
			require.Empty(t, recs[registration.TypeRegistered])
			require.Empty(t, recs[registration.TypeRolledBack], "an abrupt death writes no terminal record")
			in := unresolved(t, cfg, "refund-bot")
			require.Len(t, in, 1, "the unfinished registration is found from its signed intent")
			require.True(t, in[0].Verified)
			require.NotEmpty(t, in[0].Commitments.KeyOwnershipToken, "the intent committed to the key version before storing it")
			require.NotEmpty(t, in[0].Commitments.FileSHA256)
			intentText := strings.Join(recs[registration.TypeIntent][0].PolicyDecision.Reasons, " | ")
			if hasKey {
				require.NotContains(t, intentText, leftKey, "the intent commits to the key VERSION, never to the key")
			}

			// `talon doctor`: interrupted, because no registration is running.
			check := checkRegistrationsForTest(t, cfg)
			require.Equal(t, "warn", check.Status)
			require.Contains(t, check.Message, "INTERRUPTED")
			require.Contains(t, check.Message, in[0].IntentID)
			require.NotContains(t, check.Fix, "rm ")
			require.Contains(t, check.Fix, "Do not delete files or secrets by hand")

			// A restart of `talon serve` after the interruption: the start-up
			// identity registry (the function serve calls) builds, the
			// existing application's key still authenticates as itself, and
			// whatever the interrupted registration left is served only under
			// a key nobody has ever seen.
			ids := serveIdentities(t, cfg)
			require.Equal(t, "support", ids[supportKey], "the existing application keeps working across a restart")
			require.Equal(t, tc.file, hasIdentity(ids, "refund-bot"), "a half-registered use case is served exactly when its file was published")

			// A dry run reads only: it reports the unfinished registration
			// and changes nothing.
			if tc.file {
				require.NoError(t, os.WriteFile(note, []byte("ours"), 0o600))
			}
			before := registrationRecords(t, cfg, "acme", "refund-bot")
			agentsAddDryRun = true
			var dry bytes.Buffer
			require.NoError(t, runAgentsAdd(ctx, &dry, cfg, "refund-bot"))
			agentsAddDryRun = false
			require.Contains(t, dry.String(), "no registration is running now")
			require.Contains(t, dry.String(), in[0].IntentID)
			require.Equal(t, before, registrationRecords(t, cfg, "acme", "refund-bot"), "a dry run writes no record")
			_, stillKey := vaultValue(t, cfg, "refund-bot-talon-key")
			require.Equal(t, tc.key, stillKey, "a dry run removes nothing")

			// The next registration recovers by proof and registers.
			var out bytes.Buffer
			require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
			key := printedKeyRe.FindString(out.String())
			require.NotEmpty(t, key)
			require.NotEqual(t, leftKey, key, "the interrupted registration's key was removed, not adopted")
			require.Contains(t, out.String(), "is now recorded as rolled back")
			stored, _ := vaultValue(t, cfg, "refund-bot-talon-key")
			require.Equal(t, key, stored)
			if tc.file {
				raw, rerr := os.ReadFile(note)
				require.NoError(t, rerr, "an unrelated file in the directory is never removed")
				require.Equal(t, "ours", string(raw))
			}

			recs = registrationRecords(t, cfg, "acme", "refund-bot")
			require.Len(t, recs[registration.TypeIntent], 2)
			require.Len(t, recs[registration.TypeRegistered], 1)
			require.Len(t, recs[registration.TypeRolledBack], 1)
			rb := recs[registration.TypeRolledBack][0]
			require.Equal(t, in[0].Correlation, rb.CorrelationID, "the terminal record closes the interrupted registration")
			reasons := strings.Join(rb.PolicyDecision.Reasons, " | ")
			require.Contains(t, reasons, "its process is not running: the registration lock was free")
			require.Contains(t, reasons, tc.recovery)
			require.Empty(t, unresolved(t, cfg, "refund-bot"))
			require.Equal(t, "pass", checkRegistrationsForTest(t, cfg).Status)

			// After the recovery a restart serves both applications, the new
			// one under the key that was just shown.
			ids = serveIdentities(t, cfg)
			require.Equal(t, "support", ids[supportKey])
			require.Equal(t, "refund-bot", ids[key])
		})
	}

	// Death after the completion record, before the key was shown: the
	// registration IS complete (it is not "interrupted"), the use case is
	// registered, and its key was never seen by anyone. The operator
	// replaces the key (the lost-key procedure); nothing is rolled back.
	t.Run(stepCompleted, func(t *testing.T) {
		env := addEnv(t, t.TempDir(), "")
		for k, v := range env {
			t.Setenv(k, v)
		}
		cfg, err := config.Load()
		require.NoError(t, err)
		resetAgentsAddFlags(t)
		agentsAddTenant = "acme"
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAgentsAdd_CrashHelper$")
		child.Env = append(os.Environ(), "TALON_TEST_CRASH_STEP="+stepCompleted)
		var childOut bytes.Buffer
		child.Stdout, child.Stderr = &childOut, &childOut
		err = child.Run()
		var exit *exec.ExitError
		require.ErrorAs(t, err, &exit)
		ws, _ := exit.Sys().(syscall.WaitStatus)
		require.True(t, ws.Signaled() && ws.Signal() == syscall.SIGKILL, "%v\n%s", err, childOut.String())
		require.Empty(t, printedKeyRe.FindString(childOut.String()), "the key is printed only after the completion step returned")

		require.True(t, registered(t, env["TALON_AGENTS_DIR"], "refund-bot"))
		_, hasKey := vaultValue(t, cfg, "refund-bot-talon-key")
		require.True(t, hasKey)
		recs := registrationRecords(t, cfg, "acme", "refund-bot")
		require.Len(t, recs[registration.TypeRegistered], 1)
		require.Empty(t, unresolved(t, cfg, "refund-bot"), "a completed registration is not an unresolved one")
		require.Equal(t, registration.LockFree, registration.Probe(cfg.DataDir), "the killed process left no lock")
		err = runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot")
		require.ErrorContains(t, err, "already registered")
	})
}

// serveIdentities builds the identity registry exactly as `talon serve`
// does at start for an agents_dir fleet and returns key → use case for
// every key in the vault that authenticates.
func serveIdentities(t *testing.T, cfg *config.Config) map[string]string {
	t.Helper()
	ctx := context.Background()
	store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	require.NoError(t, err)
	defer store.Close()
	reg, _, err := buildServeIdentityRegistryFromDir(ctx, cfg.AgentsDir, store, "")
	require.NoError(t, err, "serve must be able to start")
	out := map[string]string{}
	for _, id := range reg.Identities() {
		// The key itself is in the vault under the use case's binding; read
		// it as that use case to map it back.
		sec, gerr := store.Get(ctx, id.Name+"-talon-key", id.TenantID, id.Name)
		require.NoError(t, gerr)
		resolved, ok := reg.ResolveKey(string(sec.Value))
		require.True(t, ok)
		out[string(sec.Value)] = resolved.Name
	}
	return out
}

func hasIdentity(ids map[string]string, name string) bool {
	for _, n := range ids {
		if n == name {
			return true
		}
	}
	return false
}

func TestAgentsAdd_DryRunWritesNothing(t *testing.T) {
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	agentsAddDryRun = true
	var out bytes.Buffer
	require.NoError(t, runAgentsAdd(context.Background(), &out, cfg, "refund-bot"))
	require.Contains(t, out.String(), "Dry run")
	require.Empty(t, printedKeyRe.FindString(out.String()))
	_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
	require.True(t, os.IsNotExist(statErr))
	_, ok := vaultValue(t, cfg, "refund-bot-talon-key")
	require.False(t, ok)
}

// A registration without any company policy is refused unless the operator
// states it; with one, the policy actually in force is reported.
func TestAgentsAdd_CompanyPolicyIsRequiredAndReported(t *testing.T) {
	ctx := context.Background()
	cfg, agentsDir := setupAddFleet(t)
	resetAgentsAddFlags(t)
	agentsAddNoCompanyPolicy = false
	err := runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "refund-bot")
	require.ErrorContains(t, err, "no company policy: no gateway config at")
	require.ErrorContains(t, err, "--no-company-policy")
	_, statErr := os.Stat(filepath.Join(agentsDir, "refund-bot"))
	require.True(t, os.IsNotExist(statErr))
	_, ok := vaultValue(t, cfg, "refund-bot-talon-key")
	require.False(t, ok)

	gw := filepath.Join(t.TempDir(), "talon.config.yaml")
	require.NoError(t, os.WriteFile(gw, []byte(addGateway), 0o600))
	t.Setenv("TALON_GATEWAY_CONFIG", gw)
	var out bytes.Buffer
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
	require.Contains(t, out.String(), "company policy: configured in "+gw+" — pii_action block, daily cost 25.00")
	require.Contains(t, out.String(), "1 forbidden tool/action pattern(s)")
	// Configured is not active: nothing runs here, and the output says so.
	require.Contains(t, out.String(), "Runtime: NOT PROVEN ACTIVE")
	require.NotContains(t, out.String(), "Runtime: ACTIVE")
	require.NotContains(t, out.String(), "WARNING")

	// A gateway config that exists but declares no organization policy is
	// not a company policy: the loader's built-in defaults were chosen by nobody.
	bare := filepath.Join(t.TempDir(), "talon.config.yaml")
	require.NoError(t, os.WriteFile(bare, []byte("gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      secret_name: openai-api-key\n      base_url: \"https://api.openai.com\"\n"), 0o600))
	t.Setenv("TALON_GATEWAY_CONFIG", bare)
	err = runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "hr-copilot")
	require.ErrorContains(t, err, "has no gateway.organization_policy block")
	require.ErrorContains(t, err, "--no-company-policy")
	_, statErr = os.Stat(filepath.Join(agentsDir, "hr-copilot"))
	require.True(t, os.IsNotExist(statErr))
	agentsAddNoCompanyPolicy = true
	out.Reset()
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "hr-copilot"))
	require.Contains(t, out.String(), "WARNING: registered WITHOUT a company policy")

	// No gateway config at all: the endpoint is not claimed.
	t.Setenv("TALON_GATEWAY_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	out.Reset()
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "ops-bot"))
	require.Contains(t, out.String(), "no enabled provider is configured in the gateway config this command read, so no model endpoint can be named")
	require.NotContains(t, out.String(), "/v1/proxy/openai/v1")
}

// A dry run writes nothing at all, on an installation that does not exist yet.
func TestAgentsAdd_DryRunOnAFreshInstallationCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TALON_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("TALON_SIGNING_KEY", testutil.TestSigningKey)
	t.Setenv("TALON_SECRETS_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("TALON_GATEWAY_CONFIG", filepath.Join(dir, "absent.yaml"))
	t.Setenv("TALON_AGENTS_DIR", filepath.Join(dir, "agents"))
	cfg, err := config.Load()
	require.NoError(t, err)
	resetAgentsAddFlags(t)
	agentsAddDryRun = true
	var out bytes.Buffer
	require.NoError(t, runAgentsAdd(context.Background(), &out, cfg, "refund-bot"))
	require.Contains(t, out.String(), "Dry run: nothing was written")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries, "no data directory, no agents_dir, no vault, no evidence store")
}

// A dry run leaves an existing vault and evidence store byte-identical.
func TestAgentsAdd_DryRunLeavesExistingStoresUntouched(t *testing.T) {
	ctx := context.Background()
	cfg, _ := setupAddFleet(t)
	resetAgentsAddFlags(t)
	// A real registration first, so both stores exist with content.
	require.NoError(t, runAgentsAdd(ctx, &bytes.Buffer{}, cfg, "first-one"))
	checkpoint := func(path string) {
		rw, err := sql.Open("sqlite3", path)
		require.NoError(t, err)
		_, err = rw.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
		require.NoError(t, err)
		require.NoError(t, rw.Close())
	}
	checkpoint(cfg.SecretsDBPath())
	checkpoint(cfg.EvidenceDBPath())
	digest := func(path string) [32]byte {
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		return sha256.Sum256(b)
	}
	vaultBefore, evBefore := digest(cfg.SecretsDBPath()), digest(cfg.EvidenceDBPath())

	agentsAddDryRun = true
	var out bytes.Buffer
	require.NoError(t, runAgentsAdd(ctx, &out, cfg, "refund-bot"))
	require.Contains(t, out.String(), "Dry run: nothing was written")
	require.Equal(t, vaultBefore, digest(cfg.SecretsDBPath()), "the vault file is unchanged by a dry run")
	require.Equal(t, evBefore, digest(cfg.EvidenceDBPath()), "the evidence store is unchanged by a dry run")

	// A vault file without a secrets table (never initialized) is treated as empty, read-only.
	empty := *cfg
	empty.DataDir = t.TempDir()
	e, err := sql.Open("sqlite3", empty.SecretsDBPath())
	require.NoError(t, err)
	_, err = e.ExecContext(ctx, `CREATE TABLE unrelated (x INTEGER)`)
	require.NoError(t, err)
	require.NoError(t, e.Close())
	_, err = secrets.MetadataReadOnly(ctx, empty.SecretsDBPath(), "refund-bot-talon-key")
	require.ErrorIs(t, err, secrets.ErrSecretNotFound)
}
