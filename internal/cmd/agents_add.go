package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

// `talon agents add` (#472): register one more AI use case in an existing
// agents_dir installation without hand-editing YAML. The new agent file
// declares only identity and ownership: every policy — budgets, PII,
// models, tools, forbidden actions, approval rules and amount limits — is
// the company's organization policy until the use case's own file adds a
// restriction. Order is fail-safe: nothing is written when the fleet is
// invalid or the name is taken; the key is stored BEFORE the file appears,
// so a running server never reloads a use case whose key is missing; a
// failed file write removes the key it just stored; an existing key is
// never regenerated.

var (
	agentsAddTenant      string
	agentsAddDescription string
	agentsAddOwner       string
	agentsAddUseExisting bool
	agentsAddDryRun      bool
)

var agentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

const agentsAddTemplate = `# AI use case {{ printf "%q" .Name }} — registered with 'talon agents add'.
# Every policy not set here is the company's organization policy
# (talon.config.yaml gateway.organization_policy): budgets, PII handling,
# models, tools, forbidden actions, approval rules and amount limits.
# Add a block below only to tighten it for this use case; company
# constraints and denials cannot be lifted from this file.
agent:
  name: {{ printf "%q" .Name }}
  description: {{ printf "%q" .Description }}
  version: 1.0.0
  tenant_id: {{ printf "%q" .Tenant }}
  # The Talon key this use case presents (vault secret NAME, never the value).
  key:
    secret_name: {{ printf "%q" .SecretName }}

policies:
  cost_limits: {}   # inherit organization_policy.defaults daily_cost / monthly_cost
{{- if .Owner }}

metadata:
  owner: {{ printf "%q" .Owner }}
{{- end }}
`

var agentsAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Register a new AI use case under the company policy and issue its Talon key",
	Long: `Register a new AI use case in the agents_dir of this installation.

Creates <agents_dir>/<name>/agent.talon.yaml declaring only the use case's
identity, tenant and key binding: every policy is inherited from the company's
organization policy until this file adds a restriction. Generates a new Talon
key, stores it in the encrypted vault as <name>-talon-key and prints it ONCE.

Refuses, writing nothing, when agents_dir is not configured, the existing fleet
is invalid, the name is already registered, or the key secret already exists
(pass --use-existing-key to bind the existing secret instead of generating one).
A running 'talon serve' picks the new use case up within agents_reload_interval.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		return runAgentsAdd(cmd.Context(), cmd.OutOrStdout(), cfg, args[0])
	},
}

type agentsAddPlan struct {
	Name, Tenant, Description, Owner, SecretName string
	Dir, Path                                    string
	Content                                      []byte
	CreatedAgentsDir                             bool
	// NoOrganizationPolicy: no gateway config was found, so nothing is
	// inherited and the new use case has no budget cap of its own.
	NoOrganizationPolicy bool
	EvidenceID           string
}

func runAgentsAdd(ctx context.Context, out io.Writer, cfg *config.Config, name string) error {
	plan, err := planAgentsAdd(ctx, cfg, name)
	if err != nil {
		return err
	}
	store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	if err != nil {
		return fmt.Errorf("opening the secrets vault: %w", err)
	}
	defer store.Close()
	exists, err := secretExists(ctx, store, plan.SecretName)
	if err != nil {
		return fmt.Errorf("reading the secrets vault: %w", err)
	}
	if exists && !agentsAddUseExisting {
		return fmt.Errorf("vault secret %q already exists; refusing to overwrite a key that may be in use. Pass --use-existing-key to bind it, or remove it deliberately with 'talon secrets delete %s'", plan.SecretName, plan.SecretName)
	}
	if !exists && agentsAddUseExisting {
		return fmt.Errorf("--use-existing-key: vault secret %q does not exist", plan.SecretName)
	}
	if agentsAddDryRun {
		fmt.Fprintf(out, "Dry run: would create %s and %s the key secret %q.\n\n%s", plan.Path, map[bool]string{true: "bind", false: "generate"}[exists], plan.SecretName, plan.Content)
		return nil
	}

	key, err := commitAgentsAdd(ctx, cfg, store, plan, exists)
	if err != nil {
		return err
	}
	printAgentsAddResult(out, plan, key)
	return nil
}

// commitAgentsAdd stores a new key (unless one exists and is bound), then
// writes the file, then re-scans the fleet; each failure undoes what this
// call wrote. It returns the generated key ("" when an existing one is bound).
func commitAgentsAdd(ctx context.Context, cfg *config.Config, store *secrets.SecretStore, plan *agentsAddPlan, exists bool) (string, error) {
	var key string
	if !exists {
		var err error
		key, err = newAgentKey()
		if err != nil {
			return "", err
		}
		// Readable only as this use case in its tenant: another use case's
		// identity can never resolve this key.
		acl := secrets.ACL{Tenants: []string{plan.Tenant}, Agents: []string{plan.Name}}
		if err := store.Set(ctx, plan.SecretName, []byte(key), acl); err != nil {
			return "", fmt.Errorf("storing the key in the vault (nothing else was written): %w", err)
		}
	}
	if err := writeAgentFileAtomically(plan); err != nil {
		if !exists {
			if derr := store.Delete(ctx, plan.SecretName); derr != nil {
				return "", fmt.Errorf("%w; ALSO failed to remove the key just stored as %q (remove it with 'talon secrets delete %s'): %v", err, plan.SecretName, plan.SecretName, derr)
			}
		}
		return "", err
	}
	if err := verifyFleetAfterAdd(ctx, cfg, plan); err != nil {
		_ = os.Remove(plan.Path)
		_ = os.Remove(plan.Dir)
		if !exists {
			_ = store.Delete(ctx, plan.SecretName)
		}
		return "", fmt.Errorf("the fleet does not validate with the new use case, so it was removed again: %w", err)
	}
	// The registration is an operator event like enable/disable: one signed
	// record in the use case's tenant. A registration that cannot be
	// recorded is undone.
	if err := recordAgentRegistered(ctx, cfg, plan, exists); err != nil {
		_ = os.Remove(plan.Path)
		_ = os.Remove(plan.Dir)
		if !exists {
			_ = store.Delete(ctx, plan.SecretName)
		}
		return "", fmt.Errorf("recording the registration as signed evidence failed, so it was removed again: %w", err)
	}
	return key, nil
}

func recordAgentRegistered(ctx context.Context, cfg *config.Config, plan *agentsAddPlan, boundExisting bool) error {
	evStore, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return err
	}
	defer evStore.Close()
	keyNote := "key: generated, vault secret " + plan.SecretName
	if boundExisting {
		keyNote = "key: bound to existing vault secret " + plan.SecretName
	}
	id := "al_" + uuid.New().String()[:12]
	plan.EvidenceID = id
	return evStore.Store(ctx, &evidence.Evidence{
		ID: id, CorrelationID: id, Timestamp: time.Now().UTC(), TenantID: plan.Tenant, AgentID: plan.Name,
		InvocationType: "agent_registered", RequestSourceID: operatorID(),
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "agent_registered", Reasons: []string{"config: " + plan.Path, keyNote}},
	})
}

// planAgentsAdd validates everything that needs no write: the installation
// mode, the existing fleet, the name, and the rendered file.
func planAgentsAdd(ctx context.Context, cfg *config.Config, name string) (*agentsAddPlan, error) {
	if !agentNameRe.MatchString(name) {
		return nil, fmt.Errorf("invalid use case name %q: lower-case letters, digits, '-' and '_', starting with a letter or digit, at most 63 characters", name)
	}
	if strings.TrimSpace(cfg.AgentsDir) == "" {
		return nil, errors.New("agents_dir is not configured: 'talon agents add' registers use cases in an agents_dir fleet. Set agents_dir in talon.config.yaml (or TALON_AGENTS_DIR), move an existing agent.talon.yaml to <agents_dir>/<name>/agent.talon.yaml, then retry")
	}
	created := false
	if _, err := os.Stat(cfg.AgentsDir); os.IsNotExist(err) {
		// The first registration of a new agents_dir installation.
		if err := os.MkdirAll(cfg.AgentsDir, 0o755); err != nil {
			return nil, fmt.Errorf("creating agents_dir %s: %w", cfg.AgentsDir, err)
		}
		created = true
	}
	scan, err := agentcatalog.DiscoverAgents(ctx, cfg.AgentsDir)
	if err != nil {
		return nil, fmt.Errorf("the existing fleet under %s does not validate, so nothing was added (fix it first; 'talon validate --dir %s'): %w", cfg.AgentsDir, cfg.AgentsDir, err)
	}
	for i := range scan.Agents {
		if scan.Agents[i].Name == name {
			return nil, fmt.Errorf("use case %q is already registered (%s)", name, scan.Agents[i].Path)
		}
	}
	tenant := strings.TrimSpace(agentsAddTenant)
	if tenant == "" {
		tenant = "default"
	}
	desc := strings.TrimSpace(agentsAddDescription)
	if desc == "" {
		desc = "AI use case " + name
	}
	plan := &agentsAddPlan{
		Name: name, Tenant: tenant, Description: desc, Owner: strings.TrimSpace(agentsAddOwner), SecretName: name + "-talon-key",
		Dir: filepath.Join(cfg.AgentsDir, name), CreatedAgentsDir: created,
	}
	plan.Path = filepath.Join(plan.Dir, agentcatalog.AgentConfigFilename)
	if _, err := os.Stat(plan.Path); err == nil {
		return nil, fmt.Errorf("%s already exists", plan.Path)
	}
	var b strings.Builder
	if err := template.Must(template.New("agent").Parse(agentsAddTemplate)).Execute(&b, plan); err != nil {
		return nil, err
	}
	plan.Content = []byte(b.String())
	if _, err := os.Stat(gatewayConfigPath("")); errors.Is(err, os.ErrNotExist) {
		plan.NoOrganizationPolicy = true
	}
	if err := validateAgentContent(ctx, plan.Content); err != nil {
		return nil, fmt.Errorf("the generated agent file does not validate (nothing was written): %w", err)
	}
	return plan, nil
}

// validateAgentContent runs the strict loader and the effective action
// policy compiler with the company policy over the rendered bytes.
func validateAgentContent(ctx context.Context, content []byte) error {
	dir, err := os.MkdirTemp("", "talon-agents-add-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, agentcatalog.AgentConfigFilename)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		return err
	}
	pol, err := policy.LoadPolicy(ctx, agentcatalog.AgentConfigFilename, false, dir) // the mode fleet discovery loads with
	if err != nil {
		return err
	}
	if err := policy.ValidateNoUnknownFields(p); err != nil {
		return err
	}
	offline, err := offlineServeContextFromGateway()
	if err != nil {
		return err
	}
	_, err = action.CompileEffectiveActionPolicy(pol, offline.Company)
	return err
}

func writeAgentFileAtomically(plan *agentsAddPlan) error {
	if err := os.MkdirAll(plan.Dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", plan.Dir, err)
	}
	tmp, err := os.CreateTemp(plan.Dir, ".agent.talon.yaml.*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", plan.Path, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(plan.Content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", plan.Path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", plan.Path, err)
	}
	//nolint:gosec // G302: agent files hold no secret (key binding is a vault NAME) and must be readable by the serving process
	if err := os.Chmod(tmpName, 0o644); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// os.Link refuses an existing target, so a concurrent add of the same
	// name cannot overwrite the winner's file.
	if err := os.Link(tmpName, plan.Path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("creating %s: %w", plan.Path, err)
	}
	return os.Remove(tmpName)
}

func verifyFleetAfterAdd(ctx context.Context, cfg *config.Config, plan *agentsAddPlan) error {
	scan, err := agentcatalog.DiscoverAgents(ctx, cfg.AgentsDir)
	if err != nil {
		return err
	}
	for i := range scan.Agents {
		if scan.Agents[i].Name == plan.Name {
			return nil
		}
	}
	return fmt.Errorf("use case %q not found by the fleet scan after writing %s", plan.Name, plan.Path)
}

func secretExists(ctx context.Context, store *secrets.SecretStore, name string) (bool, error) {
	all, err := store.ListAll(ctx)
	if err != nil {
		return false, err
	}
	for i := range all {
		if all[i].Name == name {
			return true, nil
		}
	}
	return false, nil
}

// newAgentKey returns a fresh 192-bit Talon key.
func newAgentKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating a key: %w", err)
	}
	return "talon_uc_" + hex.EncodeToString(b), nil
}

func printAgentsAddResult(out io.Writer, plan *agentsAddPlan, key string) {
	if plan.CreatedAgentsDir {
		fmt.Fprintf(out, "Created agents_dir %s (it did not exist).\n", filepath.Dir(plan.Dir))
	}
	fmt.Fprintf(out, "Registered AI use case %q (tenant %s)\n", plan.Name, plan.Tenant)
	fmt.Fprintf(out, "  config:  %s\n", plan.Path)
	fmt.Fprintf(out, "  key:     vault secret %q\n", plan.SecretName)
	fmt.Fprintf(out, "  evidence: %s (signed, agent_registered)\n", plan.EvidenceID)
	if plan.NoOrganizationPolicy {
		fmt.Fprintf(out, "\nWARNING: no gateway config (%s) was found, so there is no organization policy to inherit: this use case has NO budget cap and no company constraints until you add an organization_policy or set policies.cost_limits in its file.\n", gatewayConfigPath(""))
	}
	if key != "" {
		fmt.Fprintf(out, "\nTalon key (shown ONCE; store it in the application's secret manager, never in source):\n  %s\n", key)
	} else {
		fmt.Fprintf(out, "\nBound to the EXISTING vault secret %q; no key was generated or printed.\n", plan.SecretName)
	}
	fmt.Fprintf(out, `
Connect the application (it presents the key as a bearer token):
  LLM gateway (talon serve --gateway; OpenAI-compatible):
                                    base URL <talon-url>/v1/proxy/<provider>/v1
                                    header   Authorization: Bearer <key>
  Business actions (needs actions.definitions in the use case's file):
                                    POST <talon-url>/v1/action-operations
                                    header   Authorization: Bearer <key>

Next:
  talon agents show %[1]s --effective   # the company policy this use case now runs under, with rule provenance
  talon validate                        # the whole fleet, as 'talon serve' will load it
A running 'talon serve' loads the new use case within agents_reload_interval (default %[2]s) or on restart.
`, plan.Name, config.DefaultAgentsReloadInterval)
}

func init() {
	agentsAddCmd.Flags().StringVar(&agentsAddTenant, "tenant", "default", "tenant the use case belongs to")
	agentsAddCmd.Flags().StringVar(&agentsAddDescription, "description", "", "what the use case is for")
	agentsAddCmd.Flags().StringVar(&agentsAddOwner, "owner", "", "accountable owner (identifier or contact)")
	agentsAddCmd.Flags().BoolVar(&agentsAddUseExisting, "use-existing-key", false, "bind the existing vault secret <name>-talon-key instead of generating a key")
	agentsAddCmd.Flags().BoolVar(&agentsAddDryRun, "dry-run", false, "validate and print the file that would be written; write nothing")
	agentsCmd.AddCommand(agentsAddCmd)
}
