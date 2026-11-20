package cmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/registration"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// `talon agents add` (#472): register an existing AI application as one AI
// use case of this installation, without hand-editing YAML, and tell the
// operator how to connect it and how to verify its first request. This file
// is the command: flags and rendering. The registration itself is in
// agents_registration.go.

var (
	agentsAddTenant      string
	agentsAddDescription string
	agentsAddOwner       string
	agentsAddDryRun      bool
	// agentsAddNoCompanyPolicy permits a registration when no gateway config
	// (and so no organization policy) exists.
	agentsAddNoCompanyPolicy bool
)

var agentsAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Register an existing AI application as a use case under the company policy and issue its Talon key",
	Long: `Register one AI use case in the agents_dir of this installation.

Creates <agents_dir>/<name>/agent.talon.yaml declaring only the use case's
identity, owner, tenant and key binding: every policy is the company's
organization policy until this file adds a restriction. Generates a new Talon
key, stores it in the encrypted vault as <name>-talon-key and prints it ONCE,
after the registration has completed.

Refuses, writing nothing, when agents_dir is not configured, the existing fleet
is invalid, the name is already registered or a vault secret of that name
already exists.

Registrations of one installation run one at a time (a lock in the data
directory). When an earlier registration of the name never finished, this
command removes only what that registration's signed intent proves it created,
records it as rolled back and then registers; anything else under the name is
left untouched and named.

The command does not start or change a running process. A running 'talon
serve' re-scans agents_dir every agents_reload_interval; whether it has loaded
the new use case, and whether the application's requests arrive under the
expected policy, is shown by 'talon agents show <name> --effective'.`,
	Example: `  talon agents add customer-support --owner support-engineering --description "AI customer support assistant"
  talon agents add customer-support --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		return runAgentsAdd(cmd.Context(), cmd.OutOrStdout(), cfg, args[0])
	},
}

// printDryRun reports what a registration would do. It reads without the
// registration lock and creates nothing, so it judges the name only when no
// registration is running: what exists under the name while one runs may be
// that registration's work in progress.
func printDryRun(ctx context.Context, out io.Writer, cfg *config.Config, plan *agentsAddPlan) error {
	lock := registration.Probe(cfg.DataDir)
	if len(plan.Unresolved) == 0 {
		if err := nameOccupied(ctx, cfg, plan); err != nil {
			if lock == registration.LockHeld {
				return fmt.Errorf("a registration is running now (the registration lock is held): what exists under the name %q may be its work in progress, so the name is not judged. Nothing was written; run the command again when it has finished", plan.Name)
			}
			return err
		}
	}
	fmt.Fprintf(out, "Dry run: nothing was written. A registration would create %s and generate key secret %q.\n", plan.Path, plan.SecretName)
	if len(plan.Unresolved) > 0 {
		state := map[string]string{
			registration.LockHeld:    "a registration is running now (the registration lock is held), so this may be in progress",
			registration.LockFree:    "no registration is running now (the registration lock is free)",
			registration.LockUnknown: "whether a registration is running now could not be established",
		}[lock]
		for i := range plan.Unresolved {
			in := &plan.Unresolved[i]
			fmt.Fprintf(out, "An earlier registration of this name has no completion or rollback record (signed intent %s of %s); %s. A real run decides under the registration lock and removes only what that intent proves it created.\n", in.IntentID, in.At.UTC().Format(time.RFC3339), state)
		}
	}
	fmt.Fprintf(out, "Company policy: %s\n\n%s", plan.CompanyPolicy, plan.Content)
	return nil
}

func runAgentsAdd(ctx context.Context, out io.Writer, cfg *config.Config, name string) error {
	req := registrationRequest{
		Name: name, Tenant: agentsAddTenant, Description: agentsAddDescription, Owner: agentsAddOwner, AllowNoCompanyPolicy: agentsAddNoCompanyPolicy,
	}
	// Planning reads only: nothing below this call has been written yet.
	// Before the lock it validates what does not depend on another
	// registration's progress (the name's form, the fleet, the company
	// policy, the generated file). Whether the NAME is free is not decided
	// here: a key or a file under it may be the work in progress of a
	// registration that is running right now.
	plan, err := planRegistration(ctx, cfg, req, false)
	if err != nil {
		return err
	}
	if agentsAddDryRun {
		return printDryRun(ctx, out, cfg, plan)
	}
	// The execution takes the registration lock, plans again under it and
	// decides there whether the name is free.
	plan, res, err := executeRegistration(ctx, cfg, req)
	if err != nil {
		return err
	}
	printAgentsAddResult(ctx, out, cfg, plan, res)
	return nil
}

// registrationReport builds the canonical effective-policy report of the
// new use case: the projection `talon agents show --effective` and the
// console use, so the registration output interprets no policy of its own.
func registrationReport(ctx context.Context, cfg *config.Config, plan *agentsAddPlan) (*effective.Report, error) {
	in := effective.Inputs{AgentsDir: cfg.AgentsDir, GatewayConfig: gatewayConfigPath(""), Name: plan.Name, Tenant: plan.Tenant, Now: time.Now().UTC(), SecretsDB: cfg.SecretsDBPath()}
	v := runtimestatus.NewReader().Assess(cfg.DataDir, runtimestatus.Fingerprint(cfg.SigningKey), nil, time.Now())
	in.Runtime, in.RuntimeReadable = &v, v.Err == ""
	if ro, err := evidence.OpenReadOnly(cfg.EvidenceDBPath(), cfg.SigningKey); err == nil {
		defer ro.Close()
		in.Evidence = ro
	}
	return effective.Build(ctx, in)
}

// printAgentsAddResult answers, briefly and in this order: what was
// registered, which company controls apply, whether a running Talon serves
// it yet, where to point the application, how to verify the first request,
// and last, in a block of its own, the key. Everything above the key block
// is safe to copy into a ticket. The full policy with its provenance, and
// every fact behind these lines, is `talon agents show <name> --effective`;
// this output states nothing that report does not hold.
func printAgentsAddResult(ctx context.Context, out io.Writer, cfg *config.Config, plan *agentsAddPlan, res *registrationResult) {
	row := func(k, v string) { fmt.Fprintf(out, "  %-9s %s\n", k, v) }
	if plan.AgentsDirMissing {
		fmt.Fprintf(out, "Created agents_dir %s (it did not exist).\n", filepath.Dir(plan.Dir))
	}
	fmt.Fprintf(out, "Registered %s (tenant %s)\n", plan.Name, plan.Tenant)
	if plan.Owner != "" {
		row("Owner", plan.Owner)
	} else {
		row("Owner", "not given (--owner)")
	}
	if plan.Purpose != "" {
		row("Purpose", plan.Purpose)
	}
	row("File", plan.Path)
	row("Record", fmt.Sprintf("%s (signed; check it with: talon audit verify %s)", res.EvidenceID, res.EvidenceID))
	for _, msg := range res.Recovered {
		row("Recovered", msg)
	}
	for _, msg := range res.Residual {
		row("Leftover", msg+" (also in the signed record)")
	}

	report, rerr := registrationReport(ctx, cfg, plan)
	fmt.Fprintln(out)
	printInheritedPolicy(out, plan, report, rerr)

	fmt.Fprintf(out, "\nRuntime\n  %s\n", registrationRuntimeLine(cfg, report, rerr))
	if warn := companyPolicyNotLoaded(cfg, report); warn != "" {
		fmt.Fprintf(out, "  %s\n", warn)
	}

	fmt.Fprintf(out, "\nConnect your application\n")
	printConnectionRecipe(out, report)

	fmt.Fprintf(out, "\nVerify\n  Send one request from the application, then:\n    talon agents show %s\n", plan.Name)

	fmt.Fprintf(out, "\nApplication key — SECRET — shown once\n")
	fmt.Fprintf(out, "  %s\n", res.Key)
	fmt.Fprintf(out, "  Store it in the application's secret manager, never in source, YAML, a ticket or a shell argument.\n  It cannot be shown again; a lost key is replaced (docs/guides/operate-ai-use-cases.md).\n")
}

// companyPolicyNotLoaded returns a warning when a gateway of this
// installation is running with ANOTHER gateway config than the one on disk:
// the company policy shown above is then not the one in force until
// `talon serve` restarts (it reads the gateway config at start). "" when no
// gateway runs or the running one loaded the current file.
func companyPolicyNotLoaded(cfg *config.Config, report *effective.Report) string {
	if report == nil || report.CurrentFiles.GatewayConfig == nil || report.CurrentFiles.GatewayConfig.Digest == "" {
		return ""
	}
	view, readable := installationRuntime(cfg, time.Now().UTC())
	proof := runtimestatus.ProveGatewayConfig(view, readable, report.CurrentFiles.GatewayConfig.Digest)
	if proof.State != runtimestatus.LoadedDiffersFromFile {
		return ""
	}
	return "WARNING: the running Talon gateway has not loaded the current gateway config (" + proof.Reason + "). The company policy above takes effect when `talon serve` restarts."
}

// registrationRuntimeLine says whether a running Talon serves the new use
// case yet, from the processes' own records. A file that was written is not
// a use case that is served.
func registrationRuntimeLine(cfg *config.Config, report *effective.Report, rerr error) string {
	if rerr != nil || report == nil || report.Verification == nil {
		return "Not confirmed: " + fleetActivation(cfg)
	}
	if report.Loaded.State == runtimestatus.LoadedMatchesFile {
		return "Active: the running Talon process has loaded this use case."
	}
	switch next := report.Verification.Next; next.Code {
	case effective.NextStartRuntime:
		return "Not active: no Talon process of this installation is running. `talon serve` loads this use case when it starts."
	case effective.NextWaitReload:
		return fmt.Sprintf("Not active yet: the running Talon process loads it at its next re-scan of agents_dir (agents_reload_interval, default %s). No restart is needed.", config.DefaultAgentsReloadInterval)
	default:
		return "Not active. " + next.Text
	}
}

// printInheritedPolicy states the company controls the new use case runs
// under, from the canonical projection, in two groups: the company's
// defaults and what always binds. The layer that wins each rule and its
// precedence are in the full report.
func printInheritedPolicy(out io.Writer, plan *agentsAddPlan, report *effective.Report, rerr error) {
	if plan.NoOrganizationPolicy {
		fmt.Fprintf(out, "Company policy: NONE (--no-company-policy)\n")
		fmt.Fprintf(out, "  WARNING: this use case has no budget cap and no company constraints until you add gateway.organization_policy\n  to the gateway config or set policies.cost_limits in its file.\n")
		return
	}
	fmt.Fprintf(out, "Company policy: inherited (nothing is copied into the use case's file)\n")
	if rerr != nil {
		fmt.Fprintf(out, "  It could not be compiled for display (%v). See: talon agents show %s --effective\n", rerr, plan.Name)
		return
	}
	var defaults, always, own []string
	for i := range report.Effective.Rules {
		rule := &report.Effective.Rules[i]
		if strings.TrimSpace(rule.Effective) == "" {
			continue
		}
		item := rule.Rule + " " + rule.Effective
		switch {
		case strings.HasPrefix(rule.Winner, "organization.defaults"):
			defaults = append(defaults, item)
		case strings.HasPrefix(rule.Winner, "organization.constraints"), rule.Winner == "union", strings.HasPrefix(rule.Winner, "provider"):
			always = append(always, item)
		case strings.HasPrefix(rule.Winner, "use_case"):
			own = append(own, item)
		}
	}
	line := func(label string, items []string) {
		if len(items) > 0 {
			fmt.Fprintf(out, "  %-16s %s\n", label, strings.Join(items, " · "))
		}
	}
	line("defaults", defaults)
	line("always enforced", always)
	line("own file", own)
	if len(defaults)+len(always)+len(own) == 0 {
		fmt.Fprintf(out, "  The company policy sets no budget, PII or tool rule.\n")
	}
	fmt.Fprintf(out, "  The use case's own file can only tighten these. Why each rule applies: talon agents show %s --effective\n", plan.Name)
}

// printConnectionRecipe states the endpoint only as far as it is
// established: the gateway path per provider the configuration enables.
//
// The address is never named. A Talon server that answers at some address is
// not thereby the gateway of the installation this application was
// registered in: another installation on the same host answers the same
// way, and no existing contract says whose a server is. Printing a
// discovered address would send the application to a gateway that may not
// hold its key or its policy (#567 review). The operator supplies the
// address of the gateway that serves this installation.
func printConnectionRecipe(out io.Writer, r *effective.Report) {
	var providers []string
	if r != nil {
		for _, p := range r.Effective.Providers {
			if p.Enabled {
				providers = append(providers, p.Name)
			}
		}
	}
	if len(providers) == 0 {
		fmt.Fprintf(out, "  No model provider is enabled in the gateway config this command read, so no endpoint can be named.\n")
		fmt.Fprintf(out, "  Add gateway.providers (docs/guides/add-talon-to-existing-app.md); the endpoint is then <talon-url>/v1/proxy/<provider>/v1\n")
		return
	}
	for _, p := range providers {
		fmt.Fprintf(out, "  Base URL  <talon-url>/v1/proxy/%s/v1   (<talon-url>: the address of the Talon gateway that serves this installation; you supply it)\n", p)
	}
	fmt.Fprintf(out, "  API key   the application key below (never the provider's key)\n")
	fmt.Fprintf(out, "  Set these two in the application's OpenAI-compatible SDK. Other ways to connect: docs/guides/choosing-integration-path.md\n")
}

// renderEffectiveRules prints the effective rules with their winning layer
// and precedence: the lines `talon agents show --effective` prints.
func renderEffectiveRules(w io.Writer, r *effective.Report, indent string) {
	for _, rule := range r.Effective.Rules {
		val := rule.Effective
		if val == "" {
			val = "(none)"
		}
		fmt.Fprintf(w, "%s%-19s %-28s from %s\n", indent, rule.Rule, val, rule.Winner)
		fmt.Fprintf(w, "%s%-19s precedence: %s\n", indent, "", rule.Precedence)
	}
	if strings.TrimSpace(r.Effective.Basis) != "" && len(r.Effective.Rules) == 0 {
		fmt.Fprintf(w, "%s(no rule to show: %s)\n", indent, r.Effective.Basis)
	}
}

func init() {
	agentsAddCmd.Flags().StringVar(&agentsAddTenant, "tenant", "default", "tenant the use case belongs to")
	agentsAddCmd.Flags().StringVar(&agentsAddDescription, "description", "", "what the use case is for")
	agentsAddCmd.Flags().StringVar(&agentsAddOwner, "owner", "", "accountable owner (identifier or contact)")
	agentsAddCmd.Flags().BoolVar(&agentsAddDryRun, "dry-run", false, "validate and print the file that would be written; write nothing")
	agentsAddCmd.Flags().BoolVar(&agentsAddNoCompanyPolicy, "no-company-policy", false, "register although no gateway config with an organization policy exists (the use case then inherits nothing)")
	agentsCmd.AddCommand(agentsAddCmd)
}
