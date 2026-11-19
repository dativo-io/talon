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
is invalid, the name is already registered, a vault secret of that name already
exists, or an earlier registration of the name was interrupted (the message
names what it left and how to remove it).

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

func runAgentsAdd(ctx context.Context, out io.Writer, cfg *config.Config, name string) error {
	// Planning reads only: nothing below this call has been written yet.
	plan, err := planRegistration(ctx, cfg, registrationRequest{
		Name: name, Tenant: agentsAddTenant, Description: agentsAddDescription, Owner: agentsAddOwner, AllowNoCompanyPolicy: agentsAddNoCompanyPolicy,
	})
	if err != nil {
		return err
	}
	if agentsAddDryRun {
		fmt.Fprintf(out, "Dry run: nothing was written. A registration would create %s and generate key secret %q.\n", plan.Path, plan.SecretName)
		fmt.Fprintf(out, "Company policy: %s\n\n%s", plan.CompanyPolicy, plan.Content)
		return nil
	}
	res, err := executeRegistration(ctx, cfg, plan)
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
	in := effective.Inputs{AgentsDir: cfg.AgentsDir, GatewayConfig: gatewayConfigPath(""), Name: plan.Name, Tenant: plan.Tenant, Now: time.Now().UTC()}
	v := runtimestatus.NewReader().Assess(cfg.DataDir, runtimestatus.Fingerprint(cfg.SigningKey), nil, time.Now())
	in.Runtime, in.RuntimeReadable = &v, v.Err == ""
	if ro, err := evidence.OpenReadOnly(cfg.EvidenceDBPath(), cfg.SigningKey); err == nil {
		defer ro.Close()
		in.Evidence = ro
	}
	return effective.Build(ctx, in)
}

// printAgentsAddResult prints, in this order: what was registered, the
// company policy the use case runs under (from the canonical projection),
// what is and is not active, how to connect the application, how to verify
// its first request, what this command did not verify — and only then, in a
// block of its own, the secret. Everything above the secret block is safe
// to copy into a ticket or a chat.
func printAgentsAddResult(ctx context.Context, out io.Writer, cfg *config.Config, plan *agentsAddPlan, res *registrationResult) {
	if plan.AgentsDirMissing {
		fmt.Fprintf(out, "Created agents_dir %s (it did not exist).\n", filepath.Dir(plan.Dir))
	}
	fmt.Fprintf(out, "Registered AI use case %q\n", plan.Name)
	row := func(k, v string) { fmt.Fprintf(out, "  %-12s %s\n", k+":", v) }
	row("tenant", plan.Tenant)
	if plan.Owner != "" {
		row("owner", plan.Owner)
	} else {
		row("owner", "not given (--owner; set metadata.owner in the file)")
	}
	row("config", plan.Path)
	row("key", fmt.Sprintf("generated, vault secret %q; one active key per use case; the value is shown once, at the end", plan.SecretName))
	row("evidence", fmt.Sprintf("%s (signed completion record; intent %s). Verify: talon audit verify %s", res.EvidenceID, res.IntentID, res.EvidenceID))
	for _, in := range plan.Superseded {
		row("recovered", fmt.Sprintf("the interrupted registration of %s (intent %s) is now recorded as rolled back", in.At.UTC().Format(time.RFC3339), in.IntentID))
	}

	report, rerr := registrationReport(ctx, cfg, plan)
	fmt.Fprintf(out, "\nCompany policy this use case runs under\n")
	if plan.NoOrganizationPolicy {
		fmt.Fprintf(out, "  WARNING: registered WITHOUT a company policy (--no-company-policy): this use case has NO budget cap and no company constraints until you add a gateway.organization_policy or set policies.cost_limits in its file.\n")
	}
	if rerr != nil {
		fmt.Fprintf(out, "  could not be compiled for display (%v); run: talon agents show %s --effective\n", rerr, plan.Name)
	} else {
		fmt.Fprintf(out, "  Compiled from the current files by the resolver the gateway enforces with. Each rule names the layer that won and its precedence:\n  a company default is replaced by this use case's own file only where the precedence says so; company ceilings, floors and\n  forbidden lists always bind and cannot be lifted from that file.\n")
		renderEffectiveRules(out, report, "  ")
	}

	fmt.Fprintf(out, "\nActivation (configuration is not activation)\n")
	fmt.Fprintf(out, "  company policy: %s\n", plan.CompanyPolicy)
	if rerr == nil {
		fmt.Fprintf(out, "  this use case:  %s — %s\n", report.Loaded.State, report.Loaded.Reason)
	}
	fmt.Fprintf(out, "  %s\n", fleetActivation(cfg))

	fmt.Fprintf(out, "\nConnect the application\n")
	printConnectionRecipe(out, report)

	fmt.Fprintf(out, `
Verify the first request
  talon agents show %[1]s --effective   # section 2: loaded by a running process; section 5: authenticated traffic observed, and under which policy
  talon audit verify <evidence-id>      # the signature of the record section 5 names
  talon agents show %[1]s               # health, spend and requests

Not verified by this command
  - that a running Talon process has loaded this use case (see Activation above)
  - that the application is configured with the endpoint and the key
  - that any request of the application reaches Talon: only requests sent to a Talon endpoint are governed and recorded
`, plan.Name)

	fmt.Fprintf(out, "\n==================== SECRET — shown once, do not copy with the text above ====================\n")
	fmt.Fprintf(out, "Talon key of %q (store it in the application's secret manager; never in source, YAML, a shell argument or a ticket):\n  %s\n", plan.Name, res.Key)
	fmt.Fprintf(out, "Lost it? It cannot be shown again: replace it (docs/guides/add-talon-to-existing-app.md, \"Replace or revoke a key\").\n")
}

// printConnectionRecipe states the endpoint only as far as the gateway
// configuration proves it: one line per provider the gateway config
// enables, or the reason none can be named. <talon-url> is never guessed.
func printConnectionRecipe(out io.Writer, r *effective.Report) {
	var providers []string
	if r != nil {
		for _, p := range r.Effective.Providers {
			if p.Enabled {
				providers = append(providers, p.Name)
			}
		}
	}
	fmt.Fprintf(out, "  The application presents its Talon key, never the provider's key (Talon holds that in its vault).\n")
	if len(providers) == 0 {
		fmt.Fprintf(out, "  LLM gateway: no enabled provider is configured in the gateway config this command read, so no model endpoint can be named.\n")
		fmt.Fprintf(out, "               Add gateway.providers (docs/guides/add-talon-to-existing-app.md) and start 'talon serve --gateway'; the endpoint is then\n")
		fmt.Fprintf(out, "               <talon-url>/v1/proxy/<provider>/v1\n")
	} else {
		fmt.Fprintf(out, "  LLM gateway (needs a running 'talon serve --gateway'; <talon-url> is where it listens, http://localhost:8080 by default):\n")
		for _, p := range providers {
			fmt.Fprintf(out, "    base URL  <talon-url>/v1/proxy/%s/v1\n", p)
		}
		fmt.Fprintf(out, "    header    Authorization: Bearer <the Talon key>\n")
		fmt.Fprintf(out, "    OpenAI SDK (Node):   new OpenAI({ baseURL: process.env.TALON_URL + \"/v1/proxy/%s/v1\", apiKey: process.env.TALON_USE_CASE_KEY })\n", providers[0])
		fmt.Fprintf(out, "    OpenAI SDK (Python): OpenAI(base_url=os.environ[\"TALON_URL\"] + \"/v1/proxy/%s/v1\", api_key=os.environ[\"TALON_USE_CASE_KEY\"])\n", providers[0])
	}
	fmt.Fprintf(out, "  Other supported paths (coding agents, MCP proxy, HTTP Action Gateway, n8n, OpenShell): docs/guides/choosing-integration-path.md\n")
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
