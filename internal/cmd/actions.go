package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/action/mcpsource"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/secrets"
)

// talon actions (#427): operator inspection of one AI use case's trusted
// action catalog over the ONE shared projection (action.CatalogView) the
// runtime generation is built from. The CLI compiles a CANDIDATE catalog
// in this process — it reads the agent file and discovers the trusted MCP
// sources now — and says so: it cannot know which generation a running
// server has active (GET /v1/agents/fleet reports that). It never prints
// secret values, sealed payloads or protected data.

var (
	actionsAgent       string
	actionsPolicyPath  string
	actionsJSON        bool
	actionsValidateFor string
	actionsValidateIn  string
)

var actionsCmd = &cobra.Command{
	Use:   "actions",
	Short: "Inspect an AI use case's trusted action catalog (explicit and MCP-discovered definitions)",
}

var actionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the catalog: canonical name, source, upstream identity, digests, verdict and matching approval rules",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Minute)
		defer cancel()
		cc, err := cliActionCatalog(ctx, actionsAgent, actionsPolicyPath)
		if err != nil {
			return err
		}
		view := cc.catalog.View(cc.approvals)
		if actionsJSON {
			return writeActionsJSON(cmd.OutOrStdout(), map[string]any{"candidate": cc.candidateLabel(), "catalog": view})
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "%s\n", cc.candidateLabel())
		fmt.Fprintf(w, "Catalog digest: %s\n", view.Digest)
		if len(view.Sources) > 0 {
			fmt.Fprintln(w, "\nSources:")
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "  ID\tTYPE\tURL\tGENERATION\tTOOLS\tEXCLUDED\tSERVER (informational)\tREFRESH AT")
			for _, s := range view.Sources {
				fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n", s.ID, s.Type, s.URL, shortGeneration(s.Generation), s.ToolCount, len(s.Excluded), strings.TrimSpace(s.ServerInfo.Name+" "+s.ServerInfo.Version), s.RefreshAt.UTC().Format(time.RFC3339))
			}
			_ = tw.Flush()
		}
		fmt.Fprintln(w, "\nActions:")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  ACTION\tSOURCE\tUPSTREAM\tSCHEMA\tDEFINITION\tVERDICT\tRULES")
		for _, a := range view.Actions {
			src := a.Source.Type
			if a.Source.ID != "" {
				src += ":" + a.Source.ID
			}
			rules := make([]string, 0, len(a.ApprovalRules))
			for _, r := range a.ApprovalRules {
				rules = append(rules, r.ID)
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.Name, src, orDash(a.UpstreamName), shortGeneration(a.SchemaDigest), shortGeneration(a.DefinitionDigest), a.Verdict, orDash(strings.Join(rules, ",")))
		}
		return tw.Flush()
	},
}

var actionsShowCmd = &cobra.Command{
	Use:   "show <action>",
	Short: "Show one definition: source and upstream identity, schema and digests, reviewer classification, binding, destination reference, approval rules",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Minute)
		defer cancel()
		cc, err := cliActionCatalog(ctx, actionsAgent, actionsPolicyPath)
		if err != nil {
			return err
		}
		dv, ok := cc.catalog.DefinitionView(args[0], cc.approvals)
		if !ok {
			return fmt.Errorf("action %q is not in agent %q's catalog (actions: %s)", args[0], cc.agent.Name, strings.Join(cc.catalog.Names(), ", "))
		}
		if actionsJSON {
			return writeActionsJSON(cmd.OutOrStdout(), map[string]any{"candidate": cc.candidateLabel(), "action": dv})
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "%s\n\n", cc.candidateLabel())
		fmt.Fprintf(w, "Action:             %s\n", dv.Name)
		if dv.Description != "" {
			fmt.Fprintf(w, "Description:        %s\n", dv.Description)
		}
		fmt.Fprintf(w, "Source:             %s", dv.Source.Type)
		if dv.Source.ID != "" {
			fmt.Fprintf(w, " %s (config %s, generation %s)", dv.Source.ID, shortGeneration(dv.Source.ConfigDigest), shortGeneration(dv.Source.Generation))
		}
		fmt.Fprintln(w)
		if dv.UpstreamName != "" {
			fmt.Fprintf(w, "Upstream action:    %s\n", dv.UpstreamName)
		}
		fmt.Fprintf(w, "Schema digest:      %s\n", dv.SchemaDigest)
		fmt.Fprintf(w, "Properties:         %s\n", orDash(strings.Join(dv.Properties, ", ")))
		fmt.Fprintf(w, "Review fields:      %s\n", orDash(strings.Join(dv.Review.Fields, ", ")))
		fmt.Fprintf(w, "Non-material:       %s\n", orDash(strings.Join(dv.Review.NonMaterial, ", ")))
		fmt.Fprintf(w, "Projection digest:  %s\n", dv.ProjectionDigest)
		fmt.Fprintf(w, "Binding profile:    %s\n", dv.BindingProfile)
		fmt.Fprintf(w, "Execution profile:  %s\n", dv.ExecutionProfile)
		fmt.Fprintf(w, "Destination:        %s %s %s\n", dv.Destination.Type, dv.Destination.Method, dv.Destination.URL)
		if len(dv.Destination.SuccessStatusCodes) > 0 {
			fmt.Fprintf(w, "Success statuses:   %v\n", dv.Destination.SuccessStatusCodes)
		}
		fmt.Fprintf(w, "Destination id:     %s\n", dv.DestinationID)
		fmt.Fprintf(w, "Definition digest:  %s\n", dv.DefinitionDigest)
		fmt.Fprintf(w, "Metadata digest:    %s\n", dv.MetadataDigest)
		if len(dv.MirroredParams) > 0 {
			fmt.Fprintln(w, "Mirrored params (x-mcp-header, protocol metadata only):")
			for _, m := range dv.MirroredParams {
				fmt.Fprintf(w, "  Mcp-Param-%s <- %s (%s)\n", m.Header, strings.Join(m.Path, "."), orDash(m.Type))
			}
		}
		fmt.Fprintf(w, "Verdict:            %s\n", dv.Verdict)
		for _, r := range dv.ApprovalRules {
			fmt.Fprintf(w, "Approval rule:      %s (groups: %s)\n", r.ID, strings.Join(r.ApproverGroups, ", "))
		}
		fmt.Fprintf(w, "Schema:             %s\n", string(dv.Schema))
		return nil
	},
}

// actionsValidateResult is the --json shape of `talon actions validate`.
type actionsValidateResult struct {
	Candidate        string                     `json:"candidate"`
	Action           string                     `json:"action"`
	Valid            bool                       `json:"valid"`
	Error            string                     `json:"error,omitempty"`
	DefinitionDigest string                     `json:"definition_digest"`
	ArgumentsDigest  string                     `json:"arguments_digest,omitempty"`
	Review           map[string]json.RawMessage `json:"review,omitempty"`
	Verdict          string                     `json:"verdict"`
	MatchedRuleID    string                     `json:"matched_rule_id,omitempty"`
}

var actionsValidateCmd = &cobra.Command{
	Use:   "validate --action <name> --input <file>",
	Short: "Validate an argument document against one definition and show its canonical digest, reviewer projection and verdict (no operation is created)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		if actionsValidateFor == "" || actionsValidateIn == "" {
			return fmt.Errorf("--action and --input are required")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Minute)
		defer cancel()
		raw, err := readBoundedInput(actionsValidateIn)
		if err != nil {
			return err
		}
		cc, err := cliActionCatalog(ctx, actionsAgent, actionsPolicyPath)
		if err != nil {
			return err
		}
		def, ok := cc.catalog.Lookup(actionsValidateFor)
		if !ok {
			return fmt.Errorf("action %q is not in agent %q's catalog (actions: %s)", actionsValidateFor, cc.agent.Name, strings.Join(cc.catalog.Names(), ", "))
		}
		res := actionsValidateResult{Candidate: cc.candidateLabel(), Action: def.Name, DefinitionDigest: def.DefinitionDigest}
		verdict := cc.approvals.Evaluate(def.Name)
		res.Verdict, res.MatchedRuleID = verdict.Outcome, verdict.RuleID
		canonical, err := action.Canonicalize(raw)
		if err == nil {
			err = def.ValidateArguments(canonical)
		}
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Valid = true
			res.ArgumentsDigest = action.Digest(canonical)
			res.Review = def.ReviewProjection(canonical)
		}
		if actionsJSON {
			if werr := writeActionsJSON(cmd.OutOrStdout(), res); werr != nil {
				return werr
			}
		} else {
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s\n\n", res.Candidate)
			fmt.Fprintf(w, "Action:             %s\n", res.Action)
			fmt.Fprintf(w, "Definition digest:  %s\n", res.DefinitionDigest)
			if res.Valid {
				fmt.Fprintf(w, "Arguments:          valid\n")
				fmt.Fprintf(w, "Arguments digest:   %s\n", res.ArgumentsDigest)
				fmt.Fprintf(w, "Reviewer projection (shown fields, exact values):\n")
				keys := make([]string, 0, len(res.Review))
				for k := range res.Review {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Fprintf(w, "  %s: %s\n", k, string(res.Review[k]))
				}
			} else {
				fmt.Fprintf(w, "Arguments:          INVALID — %s\n", res.Error)
			}
			fmt.Fprintf(w, "Verdict:            %s", res.Verdict)
			if res.MatchedRuleID != "" {
				fmt.Fprintf(w, " (rule %s)", res.MatchedRuleID)
			}
			fmt.Fprintln(w)
		}
		if !res.Valid {
			return fmt.Errorf("arguments do not satisfy the trusted definition of %q", def.Name)
		}
		return nil
	},
}

// cliCatalog is a candidate catalog compiled by this CLI process.
type cliCatalog struct {
	agent     *agentcatalog.CatalogAgent
	catalog   *action.Catalog
	approvals *action.ApprovalPolicy
	at        time.Time
}

func (c *cliCatalog) candidateLabel() string {
	return fmt.Sprintf("Candidate catalog for agent %q compiled by this CLI from %s at %s (trusted sources discovered now). A running `talon serve` applies the catalog of its ACTIVE runtime generation, which may differ — see GET /v1/agents/fleet.",
		c.agent.Name, c.agent.Path, c.at.Format(time.RFC3339))
}

// cliActionCatalog scans the fleet source, resolves the agent, discovers
// its trusted sources (vault-backed auth through the same secret store
// serve uses) and compiles the catalog with the same compiler.
func cliActionCatalog(ctx context.Context, agentName, policyPath string) (*cliCatalog, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	scan, err := cliAgentScan(ctx, cfg, policyPath)
	if err != nil {
		return nil, err
	}
	ca, err := resolveCatalogAgent(scan, agentName)
	if err != nil {
		return nil, err
	}
	if ca.Policy == nil || ca.Policy.Actions == nil || len(ca.Policy.Actions.Definitions) == 0 {
		return nil, fmt.Errorf("agent %q (%s) declares no actions (agent.talon.yaml actions.definitions)", ca.Name, ca.Path)
	}
	var getter mcpsource.SecretGetter
	if sourcesNeedAuth(ca) {
		if cfg.SecretsKey == "" {
			return nil, fmt.Errorf("agent %q declares an MCP source with auth.secret_name; TALON_SECRETS_KEY (or secrets_key) is required to resolve it", ca.Name)
		}
		store, err := secrets.NewSecretStore(cfg.SecretsDBPath(), cfg.SecretsKey)
		if err != nil {
			return nil, fmt.Errorf("opening secrets store: %w", err)
		}
		defer store.Close()
		getter = store
	}
	disc := mcpsource.New(getter)
	disc.Version = resolvedVersion()
	snapshots, err := disc.DiscoverSources(ctx, normalizedTenant(ca.TenantID), ca.Name, ca.Policy.Actions)
	if err != nil {
		return nil, fmt.Errorf("discovering trusted action sources: %w", err)
	}
	cat, err := action.CompileCatalog(ca.Policy.Actions, snapshots)
	if err != nil {
		return nil, fmt.Errorf("action catalog: %w", err)
	}
	ap, err := action.CompileApprovalPolicy(ca.Policy)
	if err != nil {
		return nil, fmt.Errorf("action approval policy: %w", err)
	}
	return &cliCatalog{agent: ca, catalog: cat, approvals: ap, at: time.Now().UTC()}, nil
}

func sourcesNeedAuth(ca *agentcatalog.CatalogAgent) bool {
	for _, s := range ca.Policy.Actions.Sources {
		if s.Auth != nil {
			return true
		}
	}
	return false
}

// readBoundedInput reads an argument document ("-" = stdin), bounded by the
// catalog's own argument limit.
func readBoundedInput(path string) ([]byte, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path) //nolint:gosec // operator-provided path on the operator's own machine
		if err != nil {
			return nil, fmt.Errorf("reading --input: %w", err)
		}
		defer f.Close()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, action.MaxArgumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading --input: %w", err)
	}
	if len(raw) > action.MaxArgumentBytes {
		return nil, fmt.Errorf("--input exceeds %d bytes", action.MaxArgumentBytes)
	}
	return raw, nil
}

func writeActionsJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func init() {
	for _, c := range []*cobra.Command{actionsListCmd, actionsShowCmd, actionsValidateCmd} {
		c.Flags().StringVar(&actionsAgent, "agent", "default", "Agent name (\"default\" resolves when exactly one agent is discovered)")
		c.Flags().StringVar(&actionsPolicyPath, "policy", "", "Path to agent.talon.yaml (default: agents_dir or the default policy file)")
		c.Flags().BoolVar(&actionsJSON, "json", false, "Machine-readable output (the shared catalog projection)")
	}
	actionsValidateCmd.Flags().StringVar(&actionsValidateFor, "action", "", "Canonical action name")
	actionsValidateCmd.Flags().StringVar(&actionsValidateIn, "input", "", "JSON argument document (\"-\" for stdin)")
	actionsCmd.AddCommand(actionsListCmd, actionsShowCmd, actionsValidateCmd)
	rootCmd.AddCommand(actionsCmd)
}
