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
	"github.com/dativo-io/talon/internal/gateway"
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
	// agentsAddNoCompanyPolicy permits a registration when no gateway config
	// (and so no organization policy) exists.
	agentsAddNoCompanyPolicy bool
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
	// AgentsDirMissing: agents_dir does not exist yet; a real registration
	// creates it, a dry run does not.
	AgentsDirMissing bool
	// CompanyPolicy states the company policy in force (or its absence).
	CompanyPolicy string
	// NoOrganizationPolicy: no gateway config was found, so nothing is
	// inherited and the new use case has no budget cap of its own.
	NoOrganizationPolicy bool
	EvidenceID           string
}

func runAgentsAdd(ctx context.Context, out io.Writer, cfg *config.Config, name string) error {
	// Planning reads only: nothing below this call has been written yet.
	plan, err := planAgentsAdd(ctx, cfg, name)
	if err != nil {
		return err
	}
	if agentsAddDryRun {
		return dryRunAgentsAdd(ctx, out, cfg, plan)
	}
	if plan.AgentsDirMissing {
		// The first registration of a new agents_dir installation.
		if err := os.MkdirAll(cfg.AgentsDir, 0o755); err != nil {
			return fmt.Errorf("creating agents_dir %s: %w", cfg.AgentsDir, err)
		}
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return fmt.Errorf("creating the data directory %s: %w", cfg.DataDir, err)
	}
	store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
	if err != nil {
		return fmt.Errorf("opening the secrets vault: %w", err)
	}
	defer store.Close()
	key, err := commitAgentsAdd(ctx, cfg, store, plan)
	if err != nil {
		return err
	}
	printAgentsAddResult(out, plan, key)
	return nil
}

// dryRunAgentsAdd reports what a registration would do. It creates no
// directory, no vault and no evidence store, on a fresh installation too.
func dryRunAgentsAdd(ctx context.Context, out io.Writer, cfg *config.Config, plan *agentsAddPlan) error {
	keyState := "generate"
	if _, statErr := os.Stat(cfg.SecretsDBPath()); statErr == nil {
		store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		if err != nil {
			return fmt.Errorf("opening the secrets vault: %w", err)
		}
		defer store.Close()
		meta, err := store.Metadata(ctx, plan.SecretName)
		switch {
		case err == nil && !agentsAddUseExisting:
			return existingKeyError(plan)
		case err == nil:
			if aclErr := existingKeyPermits(meta, plan); aclErr != nil {
				return aclErr
			}
			keyState = "bind the existing"
		case !errors.Is(err, secrets.ErrSecretNotFound):
			return fmt.Errorf("reading the secrets vault: %w", err)
		}
	}
	if keyState == "generate" && agentsAddUseExisting {
		return fmt.Errorf("--use-existing-key: vault secret %q does not exist", plan.SecretName)
	}
	fmt.Fprintf(out, "Dry run: nothing was written. A registration would create %s and %s key secret %q.\n", plan.Path, keyState, plan.SecretName)
	fmt.Fprintf(out, "Company policy: %s\n\n%s", plan.CompanyPolicy, plan.Content)
	return nil
}

func existingKeyError(plan *agentsAddPlan) error {
	return fmt.Errorf("vault secret %q already exists (a key that may be in use, or another registration of %q in progress); refusing to overwrite it. Pass --use-existing-key to bind it, or remove it deliberately with 'talon secrets delete %s'", plan.SecretName, plan.Name, plan.SecretName)
}

// existingKeyPermits checks that the ACL of a key bound with
// --use-existing-key lets this use case, in this tenant, resolve it:
// otherwise the registration would validate now and fail at serve.
func existingKeyPermits(meta *secrets.SecretMetadata, plan *agentsAddPlan) error {
	if meta.ACL.CheckAccess(plan.Tenant, plan.Name) {
		return nil
	}
	return fmt.Errorf("--use-existing-key: the ACL of vault secret %q does not permit use case %q in tenant %q; set it deliberately with 'talon secrets set %s <key> --tenants %s --agents %s'", plan.SecretName, plan.Name, plan.Tenant, plan.SecretName, plan.Tenant, plan.Name)
}

// commitAgentsAdd performs the registration. Order and ownership:
//
//  1. the key: a NEW key is created atomically (create-if-absent; of
//     concurrent registrations of one name exactly one gets past this
//     step), or an existing one is bound after its ACL is checked;
//  2. a signed intent record;
//  3. the agent file, created without overwriting;
//  4. the fleet re-scan;
//  5. the signed completion record.
//
// A failure undoes only what THIS call created: its own key version (never a
// key someone else stored under the name) and its own file. A running server
// may have loaded the use case between steps 3 and a rollback; it drops it
// on its next reload, and the rollback is recorded.
func commitAgentsAdd(ctx context.Context, cfg *config.Config, store *secrets.SecretStore, plan *agentsAddPlan) (key string, err error) {
	var own secrets.Ownership
	if agentsAddUseExisting {
		meta, merr := store.Metadata(ctx, plan.SecretName)
		if errors.Is(merr, secrets.ErrSecretNotFound) {
			return "", fmt.Errorf("--use-existing-key: vault secret %q does not exist", plan.SecretName)
		}
		if merr != nil {
			return "", fmt.Errorf("reading the secrets vault: %w", merr)
		}
		if aclErr := existingKeyPermits(meta, plan); aclErr != nil {
			return "", aclErr
		}
	} else {
		key, err = newAgentKey()
		if err != nil {
			return "", err
		}
		// Readable only as this use case in its tenant.
		acl := secrets.ACL{Tenants: []string{plan.Tenant}, Agents: []string{plan.Name}}
		own, err = store.Create(ctx, plan.SecretName, []byte(key), acl)
		if errors.Is(err, secrets.ErrSecretExists) {
			return "", existingKeyError(plan)
		}
		if err != nil {
			return "", fmt.Errorf("storing the key in the vault (nothing else was written): %w", err)
		}
	}
	evStore, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return "", undoAgentsAdd(ctx, store, nil, plan, own, false, fmt.Errorf("opening the evidence store: %w", err))
	}
	defer evStore.Close()
	correlation := "al_" + uuid.New().String()[:12]
	keyNote := "key: generated, vault secret " + plan.SecretName
	if agentsAddUseExisting {
		keyNote = "key: bound to existing vault secret " + plan.SecretName
	}
	record := func(kind string, extra ...string) (string, error) {
		id := "al_" + uuid.New().String()[:12]
		reasons := append([]string{"config: " + plan.Path, keyNote, "company policy: " + plan.CompanyPolicy}, extra...)
		return id, evStore.Store(ctx, &evidence.Evidence{
			ID: id, CorrelationID: correlation, Timestamp: time.Now().UTC(), TenantID: plan.Tenant, AgentID: plan.Name,
			InvocationType: kind, RequestSourceID: operatorID(),
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: kind, Reasons: reasons},
		})
	}
	undo := func(fileCreated bool, cause error) error {
		return undoAgentsAdd(ctx, store, record, plan, own, fileCreated, cause)
	}
	if _, err := record("agent_registration_intent"); err != nil {
		return "", undo(false, fmt.Errorf("recording the registration intent as signed evidence: %w", err))
	}
	if err := writeAgentFileAtomically(plan); err != nil {
		return "", undo(false, err)
	}
	if err := verifyFleetAfterAdd(ctx, cfg, plan); err != nil {
		return "", undo(true, fmt.Errorf("the fleet does not validate with the new use case: %w", err))
	}
	id, err := record("agent_registered")
	if err != nil {
		return "", undo(true, fmt.Errorf("recording the registration as signed evidence: %w", err))
	}
	plan.EvidenceID = id
	return key, nil
}

// undoAgentsAdd removes what this registration created and reports, in the
// returned error, anything it could not remove: a failed registration never
// leaves an undisclosed key or file behind.
func undoAgentsAdd(ctx context.Context, store *secrets.SecretStore, record func(string, ...string) (string, error), plan *agentsAddPlan, own secrets.Ownership, fileCreated bool, cause error) error {
	var left []string
	if fileCreated {
		if err := os.Remove(plan.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			left = append(left, fmt.Sprintf("the agent file %s could not be removed (%v): remove it by hand, a running server will otherwise load it", plan.Path, err))
		}
		_ = os.Remove(plan.Dir) // only when empty
	}
	if _, err := store.DeleteOwned(ctx, own); err != nil {
		left = append(left, fmt.Sprintf("the key stored as vault secret %q could not be removed (%v): remove it with 'talon secrets delete %s'", plan.SecretName, err, plan.SecretName))
	}
	if record != nil {
		if _, err := record("agent_registration_rolled_back", "cause: "+cause.Error()); err != nil {
			left = append(left, fmt.Sprintf("the rollback could not be recorded as evidence (%v)", err))
		}
	}
	if len(left) > 0 {
		return fmt.Errorf("%w; the registration was NOT fully undone: %s", cause, strings.Join(left, "; "))
	}
	return fmt.Errorf("%w; nothing of this registration was left behind", cause)
}

// planAgentsAdd validates everything that needs no write: the installation
// mode, the existing fleet, the name, the company policy in force and the
// rendered file. It creates nothing.
func planAgentsAdd(ctx context.Context, cfg *config.Config, name string) (*agentsAddPlan, error) {
	if !agentNameRe.MatchString(name) {
		return nil, fmt.Errorf("invalid use case name %q: lower-case letters, digits, '-' and '_', starting with a letter or digit, at most 63 characters", name)
	}
	if strings.TrimSpace(cfg.AgentsDir) == "" {
		return nil, errors.New("agents_dir is not configured: 'talon agents add' registers use cases in an agents_dir fleet. Set agents_dir in talon.config.yaml (or TALON_AGENTS_DIR), move an existing agent.talon.yaml to <agents_dir>/<name>/agent.talon.yaml, then retry")
	}
	missing := false
	if _, err := os.Stat(cfg.AgentsDir); os.IsNotExist(err) {
		missing = true // a first registration: no fleet to validate yet
	} else {
		scan, err := agentcatalog.DiscoverAgents(ctx, cfg.AgentsDir)
		if err != nil {
			return nil, fmt.Errorf("the existing fleet under %s does not validate, so nothing was added (fix it first; 'talon validate --dir %s'): %w", cfg.AgentsDir, cfg.AgentsDir, err)
		}
		for i := range scan.Agents {
			if scan.Agents[i].Name == name {
				return nil, fmt.Errorf("use case %q is already registered (%s)", name, scan.Agents[i].Path)
			}
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
		Dir: filepath.Join(cfg.AgentsDir, name), AgentsDirMissing: missing,
	}
	plan.Path = filepath.Join(plan.Dir, agentcatalog.AgentConfigFilename)
	if _, err := os.Stat(plan.Path); err == nil {
		return nil, fmt.Errorf("%s already exists", plan.Path)
	}
	summary, present, err := companyPolicySummary()
	if err != nil {
		return nil, err
	}
	plan.CompanyPolicy, plan.NoOrganizationPolicy = summary, !present
	if !present && !agentsAddNoCompanyPolicy {
		return nil, fmt.Errorf("no company policy is active: %s. A use case registered now would inherit nothing (no budget cap, no PII rule, no forbidden actions, no approval rules). Create the gateway config with an organization_policy (starter: examples/pilot/talon.config.yaml) or point TALON_GATEWAY_CONFIG at it; to register without any company policy on purpose, pass --no-company-policy", summary)
	}
	var b strings.Builder
	if err := template.Must(template.New("agent").Parse(agentsAddTemplate)).Execute(&b, plan); err != nil {
		return nil, err
	}
	plan.Content = []byte(b.String())
	if err := validateAgentContent(ctx, plan.Content); err != nil {
		return nil, fmt.Errorf("the generated agent file does not validate (nothing was written): %w", err)
	}
	return plan, nil
}

// companyPolicySummary states which company policy a registration would run
// under, read from the gateway config `talon serve` loads. present is false
// when that file does not exist; a present but invalid file is an error.
func companyPolicySummary() (summary string, present bool, err error) {
	path := gatewayConfigPath("")
	gw, err := gateway.LoadGatewayConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		return "none (no gateway config at " + path + ")", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("gateway config %s is present but invalid: %w — fix it first (serve refuses to start on this file)", path, err)
	}
	org := gw.OrganizationPolicy
	return fmt.Sprintf("%s — pii_action %s, daily cost %.2f / monthly %.2f per use case, %d forbidden tool/action pattern(s), %s",
		path, org.Defaults.PIIAction, org.Defaults.DailyCost, org.Defaults.MonthlyCost, len(org.Constraints.ForbiddenTools), companyApprovalSummary(org.Constraints.ActionApprovals)), true, nil
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
	if plan.AgentsDirMissing {
		fmt.Fprintf(out, "Created agents_dir %s (it did not exist).\n", filepath.Dir(plan.Dir))
	}
	fmt.Fprintf(out, "Registered AI use case %q (tenant %s)\n", plan.Name, plan.Tenant)
	fmt.Fprintf(out, "  config:  %s\n", plan.Path)
	fmt.Fprintf(out, "  key:     vault secret %q\n", plan.SecretName)
	fmt.Fprintf(out, "  evidence: %s (signed, agent_registered)\n", plan.EvidenceID)
	fmt.Fprintf(out, "  company policy: %s\n", plan.CompanyPolicy)
	if plan.NoOrganizationPolicy {
		fmt.Fprintf(out, "\nWARNING: registered WITHOUT a company policy (--no-company-policy): this use case has NO budget cap and no company constraints until you add an organization_policy or set policies.cost_limits in its file.\n")
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
	agentsAddCmd.Flags().BoolVar(&agentsAddNoCompanyPolicy, "no-company-policy", false, "register although no gateway config with an organization policy exists (the use case then inherits nothing)")
	agentsCmd.AddCommand(agentsAddCmd)
}

// companyApprovalSummary counts the company approval requirements.
func companyApprovalSummary(aa *gateway.ActionApprovalsConstraint) string {
	if aa == nil {
		return "0 approval rule(s)"
	}
	return fmt.Sprintf("%d approval rule(s), %d amount limit(s)", len(aa.Rules), len(aa.AmountLimits))
}
