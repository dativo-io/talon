package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/dativo-io/talon/internal/compliance"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/llm"
	_ "github.com/dativo-io/talon/internal/llm/providers"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/sovereignty"
)

var (
	complianceFramework string
	complianceFormat    string
	complianceTenant    string
	complianceAgent     string
	complianceFrom      string
	complianceTo        string
	complianceOutput    string
)

var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Generate compliance reports",
}

var complianceReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate framework-mapped compliance report",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
		defer cancel()

		store, err := openEvidenceStore()
		if err != nil {
			return fmt.Errorf("initializing evidence store: %w", err)
		}
		defer store.Close()

		from, to, err := parseAuditDateRange(complianceFrom, complianceTo)
		if err != nil {
			return err
		}
		list, err := store.List(ctx, complianceTenant, complianceAgent, from, to, 200000)
		if err != nil {
			return fmt.Errorf("querying evidence: %w", err)
		}

		report := compliance.BuildReport(complianceFramework, complianceTenant, complianceAgent, complianceFrom, complianceTo, list)
		var out []byte
		switch strings.ToLower(complianceFormat) {
		case "json":
			out, err = compliance.RenderJSON(report)
		case "html":
			out, err = compliance.RenderHTML(report)
		default:
			return fmt.Errorf("unsupported --format %q; use html or json", complianceFormat)
		}
		if err != nil {
			return fmt.Errorf("rendering report: %w", err)
		}
		if complianceOutput == "" {
			_, _ = cmd.OutOrStdout().Write(out)
			if len(out) == 0 || out[len(out)-1] != '\n' {
				_, _ = cmd.OutOrStdout().Write([]byte("\n"))
			}
			return nil
		}
		return os.WriteFile(complianceOutput, out, 0o600)
	},
}

var complianceRopaCmd = &cobra.Command{
	Use:   "ropa",
	Short: "Generate a GDPR Art. 30 Record of Processing Activities (supporting records, not a legal filing)",
	Long: `Generate a Record of Processing Activities (RoPA) shaped after GDPR Art. 30(1).

Declared facts (controller identity, purposes, retention) are read from
talon.config.yaml (compliance.controller) and the agent policy file
(compliance.declarations). Runtime facts (recipients, observed identifiers,
third-country transfers) come from the signed evidence store.

Missing declarations are reported as warnings and rendered as flagged
placeholder sections — fill them in with your DPO and regenerate.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runAuditorDocument(cmd, generateRoPADocument)
	},
}

var complianceAnnexIVCmd = &cobra.Command{
	Use:   "annex-iv",
	Short: "Generate an EU AI Act Annex IV technical-documentation pack (supporting records, not a legal filing)",
	Long: `Generate a technical-documentation pack shaped after EU AI Act Annex IV.

Declared facts (system description, intended purpose, oversight arrangements)
are read from the agent policy file (compliance.declarations.system). Runtime
facts (models and providers observed, policy denials, human-oversight events,
risk-control outcomes) come from the signed evidence store.

Annex IV items Talon cannot document (model development process, performance
metrics, declaration of conformity) are listed for your organisation and the
model provider to complete. Missing declarations are reported as warnings and
rendered as flagged placeholder sections.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runAuditorDocument(cmd, generateAnnexIVDocument)
	},
}

var complianceSovereigntyCmd = &cobra.Command{
	Use:   "sovereignty",
	Short: "Generate a sovereignty posture report (configured mode + observed egress)",
	Long: `Generate a sovereignty posture report for security review.

Declared facts (data_sovereignty_mode, deployment_mode, gateway providers,
LLM registry allowlist) come from talon.config.yaml. Runtime facts (observed
destinations, egress denials, routing rejections) come from the signed evidence
store.

This is supporting evidence for data-residency posture — not a compliance
determination.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runSovereigntyPosture(cmd)
	},
}

func generateAnnexIVDocument(ctx context.Context, decl compliance.Declarations, list []evidence.Evidence) (compliance.Document, error) {
	return compliance.GenerateAnnexIV(ctx, decl, list, compliance.AnnexIVOptions{
		TenantID: complianceTenant,
		AgentID:  complianceAgent,
		From:     complianceFrom,
		To:       complianceTo,
	})
}

// auditorDocumentGenerator builds one auditor document from declarations and evidence.
type auditorDocumentGenerator func(ctx context.Context, decl compliance.Declarations, list []evidence.Evidence) (compliance.Document, error)

func generateRoPADocument(ctx context.Context, decl compliance.Declarations, list []evidence.Evidence) (compliance.Document, error) {
	return compliance.GenerateRoPA(ctx, decl, list, compliance.RoPAOptions{
		TenantID: complianceTenant,
		AgentID:  complianceAgent,
		From:     complianceFrom,
		To:       complianceTo,
	})
}

// runAuditorDocument is the shared CLI wrapper for auditor-document
// subcommands (ropa, annex-iv): load declarations, query evidence, generate,
// render, write.
func runAuditorDocument(cmd *cobra.Command, generate auditorDocumentGenerator) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
	defer cancel()

	decl := loadDeclarations(ctx, cmd)

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	from, to, err := parseAuditDateRange(complianceFrom, complianceTo)
	if err != nil {
		return err
	}
	list, err := store.List(ctx, complianceTenant, complianceAgent, from, to, 200000)
	if err != nil {
		return fmt.Errorf("querying evidence: %w", err)
	}

	doc, err := generate(ctx, decl, list)
	if err != nil {
		return fmt.Errorf("generating document: %w", err)
	}
	for _, w := range doc.Warnings {
		fmt.Fprintln(cmd.ErrOrStderr(), "WARNING:", w)
	}

	var out []byte
	switch strings.ToLower(complianceFormat) {
	case "json":
		out, err = compliance.RenderDocumentJSON(doc)
	case "html":
		out, err = compliance.RenderDocumentHTML(doc)
	default:
		return fmt.Errorf("unsupported --format %q; use html or json", complianceFormat)
	}
	if err != nil {
		return fmt.Errorf("rendering document: %w", err)
	}
	if complianceOutput == "" {
		_, _ = cmd.OutOrStdout().Write(out)
		if len(out) == 0 || out[len(out)-1] != '\n' {
			_, _ = cmd.OutOrStdout().Write([]byte("\n"))
		}
		return nil
	}
	return os.WriteFile(complianceOutput, out, 0o600)
}

// loadDeclarations gathers declared facts for the compliance CLI commands.
func loadDeclarations(ctx context.Context, cmd *cobra.Command) compliance.Declarations {
	return loadComplianceDeclarations(ctx, compliancePolicyFile, cmd.ErrOrStderr())
}

// loadComplianceDeclarations gathers declared facts: controller identity from
// operator config, processing/system declarations from the agent policy file.
// Both are optional — missing declarations surface as document warnings, not
// errors. Shared by the compliance CLI and the `talon serve` compliance API.
// Load warnings are written to warn (use io.Discard to suppress).
func loadComplianceDeclarations(ctx context.Context, policyFile string, warn io.Writer) compliance.Declarations {
	var decl compliance.Declarations

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(warn, "WARNING: could not load talon.config.yaml:", err)
	} else {
		decl.Controller = cfg.ControllerDeclarations()
	}

	policyPath := policyFile
	if policyPath == "" && cfg != nil {
		policyPath = cfg.DefaultPolicy
	}
	if _, statErr := os.Stat(policyPath); statErr != nil {
		// No agent policy in the working directory — fine for org-wide exports.
		return decl
	}
	pol, err := policy.LoadPolicy(ctx, policyPath, false, filepath.Dir(policyPath))
	if err != nil {
		fmt.Fprintf(warn, "WARNING: could not load agent policy %s: %v\n", policyPath, err)
		return decl
	}
	if pol.Compliance != nil {
		decl = decl.MergeAgentDeclarations(pol.Compliance.Declarations)
		decl.DataResidency = pol.Compliance.DataResidency
	}
	return decl
}

func runSovereigntyPosture(cmd *cobra.Command) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
	defer cancel()

	opCfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	postureCfg, cfgWarnings, err := resolveSovereigntyPostureConfig(ctx, opCfg)
	if err != nil {
		return err
	}

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	from, to, err := parseAuditDateRange(complianceFrom, complianceTo)
	if err != nil {
		return err
	}
	list, err := store.List(ctx, complianceTenant, complianceAgent, from, to, 200000)
	if err != nil {
		return fmt.Errorf("querying evidence: %w", err)
	}

	doc, err := compliance.GenerateSovereigntyPosture(ctx, postureCfg, list, compliance.SovereigntyPostureOptions{
		TenantID: complianceTenant,
		AgentID:  complianceAgent,
		From:     complianceFrom,
		To:       complianceTo,
	})
	if err != nil {
		return fmt.Errorf("generating sovereignty posture report: %w", err)
	}
	doc.Warnings = append(cfgWarnings, doc.Warnings...)
	for _, w := range doc.Warnings {
		fmt.Fprintln(cmd.ErrOrStderr(), "WARNING:", w)
	}

	var out []byte
	switch strings.ToLower(complianceFormat) {
	case "json":
		out, err = compliance.RenderDocumentJSON(doc)
	case "html":
		out, err = compliance.RenderDocumentHTML(doc)
	default:
		return fmt.Errorf("unsupported --format %q; use html or json", complianceFormat)
	}
	if err != nil {
		return fmt.Errorf("rendering document: %w", err)
	}
	if complianceOutput == "" {
		_, _ = cmd.OutOrStdout().Write(out)
		if len(out) == 0 || out[len(out)-1] != '\n' {
			_, _ = cmd.OutOrStdout().Write([]byte("\n"))
		}
		return nil
	}
	return os.WriteFile(complianceOutput, out, 0o600)
}

// resolveSovereigntyPostureConfig resolves the effective sovereignty posture for
// the report. Sovereignty (air_gap / eu_strict) commonly lives in the
// --gateway-config file, so it merges any gateway-declared block into the
// operator config fail-safe (stronger posture wins) — the same resolution the
// gateway and `talon doctor` use — before building the posture config. An
// explicitly provided --gateway-config that cannot be loaded is a hard error so
// an auditor-facing report never silently renders "no providers".
func resolveSovereigntyPostureConfig(ctx context.Context, opCfg *config.Config) (compliance.SovereigntyPostureConfig, []string, error) {
	gwPath := complianceGatewayConfig
	if gwPath == "" {
		gwPath = viper.ConfigFileUsed()
	}
	if gwPath != "" {
		if err := config.ResolveSovereigntyForGateway(opCfg, gwPath); err != nil {
			return compliance.SovereigntyPostureConfig{}, nil, fmt.Errorf("resolving sovereignty config: %w", err)
		}
	}
	postureCfg, warnings := buildSovereigntyPostureConfig(ctx, opCfg, gwPath, complianceGatewayConfig != "")
	if complianceGatewayConfig != "" && postureCfg.GatewayConfigError != "" {
		return compliance.SovereigntyPostureConfig{}, nil, fmt.Errorf("loading gateway config %s: %s", complianceGatewayConfig, postureCfg.GatewayConfigError)
	}
	return postureCfg, warnings, nil
}

func buildSovereigntyPostureConfig(ctx context.Context, opCfg *config.Config, gatewayConfigPath string, gatewayExplicit bool) (cfg compliance.SovereigntyPostureConfig, warnings []string) {
	cfg.DataSovereigntyMode = opCfg.EffectiveSovereigntyMode()
	if opCfg.Sovereignty != nil {
		cfg.DeploymentMode = opCfg.Sovereignty.Mode()
		cfg.AirGapEgressGuard = opCfg.Sovereignty.AirGapEnabled()
		cfg.AllowedEgressHosts = append([]string(nil), opCfg.Sovereignty.AllowedEgressHosts...)
	}
	gwCfg, gwWarnings := loadGatewayProvidersForPosture(gatewayConfigPath, gatewayExplicit)
	warnings = append(warnings, gwWarnings...)
	cfg.GatewayProviders = gwCfg.providers
	cfg.GatewayConfigError = gwCfg.loadError

	excludedGateway, excludedLLM := sovereigntyExclusionMaps(sovereignty.EvaluateSovereignty(opCfg, gwCfg.cfg))
	applyGatewayPostureLabels(cfg.GatewayProviders, excludedGateway)
	cfg.LLMProviders = buildLLMProviderRowsForPosture(ctx, opCfg, cfg.DataSovereigntyMode, excludedLLM)
	return cfg, warnings
}

type postureGatewayLoad struct {
	cfg       *gateway.GatewayConfig
	providers []compliance.SovereigntyGatewayProvider
	loadError string
}

func loadGatewayProvidersForPosture(gatewayConfigPath string, gatewayExplicit bool) (loaded postureGatewayLoad, warnings []string) {
	if gatewayConfigPath == "" {
		return postureGatewayLoad{}, nil
	}
	gwCfg, err := gateway.LoadGatewayConfig(gatewayConfigPath)
	switch {
	case err != nil && gatewayExplicit:
		return postureGatewayLoad{loadError: err.Error()},
			[]string{fmt.Sprintf("could not load gateway config %s: %v", gatewayConfigPath, err)}
	case err != nil:
		return postureGatewayLoad{},
			[]string{fmt.Sprintf("active config %s has no usable gateway block (%v); gateway providers section will be empty", gatewayConfigPath, err)}
	default:
		out := postureGatewayLoad{cfg: gwCfg}
		for name := range gwCfg.Providers {
			p := gwCfg.Providers[name]
			out.providers = append(out.providers, compliance.SovereigntyGatewayProvider{
				Name: name, Region: p.Region, Enabled: p.Enabled,
			})
		}
		return out, nil
	}
}

func sovereigntyExclusionMaps(eval sovereignty.Evaluation) (gateway, llm map[string]bool) {
	gateway = make(map[string]bool)
	llm = make(map[string]bool)
	for _, ex := range eval.Excluded {
		switch ex.Scope {
		case sovereignty.ExclusionScopeGateway:
			gateway[ex.Provider] = true
		case sovereignty.ExclusionScopeEnv, sovereignty.ExclusionScopeLLMProviders:
			llm[ex.Provider] = true
		}
	}
	return gateway, llm
}

func applyGatewayPostureLabels(providers []compliance.SovereigntyGatewayProvider, excluded map[string]bool) {
	for i := range providers {
		switch {
		case !providers[i].Enabled:
			providers[i].Posture = "disabled"
		case excluded[providers[i].Name]:
			providers[i].Posture = "excluded"
		default:
			providers[i].Posture = "allowed"
		}
	}
}

func buildLLMProviderRowsForPosture(ctx context.Context, opCfg *config.Config, mode string, excludedLLM map[string]bool) []compliance.SovereigntyLLMProvider {
	if mode == "" {
		mode = "global"
	}
	declaredRegions := sovereignty.DeclaredOperatorRegions(opCfg)
	pol := &policy.Policy{VersionTag: "v1", Policies: policy.PoliciesConfig{}}
	eng, err := policy.NewEngine(ctx, pol)
	if err != nil {
		return nil
	}
	list := llm.ListForWizard(false)
	rows := make([]compliance.SovereigntyLLMProvider, 0, len(list))
	for i := range list {
		meta := list[i]
		// Use the operator-declared configured region when present. Never
		// substitute metadata EURegions[0] for region-aware providers — that
		// would misreport e.g. AWS_REGION=us-east-1 as an EU-routed Bedrock.
		region := declaredRegions[meta.ID]
		row := compliance.SovereigntyLLMProvider{ID: meta.ID}
		dec, evalErr := eng.EvaluateRouting(ctx, &policy.RoutingInput{
			SovereigntyMode:      mode,
			ProviderID:           meta.ID,
			ProviderJurisdiction: meta.Jurisdiction,
			ProviderRegion:       region,
			DataTier:             0,
		})
		switch {
		case evalErr != nil:
			row.Reason = evalErr.Error()
		case excludedLLM[meta.ID]:
			row.Status = "excluded_declared"
			row.Reason = "declared but excluded under eu_strict"
		case dec.Allowed:
			row.Allowed = true
			row.Status = "allowed"
		default:
			row.Status = "not_allowed"
			row.Reason = strings.Join(dec.Reasons, "; ")
		}
		rows = append(rows, row)
	}
	return rows
}

var (
	compliancePolicyFile    string
	complianceGatewayConfig string
)

func init() {
	complianceReportCmd.Flags().StringVar(&complianceFramework, "framework", "", "Framework filter: gdpr, eu-ai-act, nis2, dora, iso-27001")
	complianceReportCmd.Flags().StringVar(&complianceFormat, "format", "html", "Output format: html or json")
	complianceReportCmd.Flags().StringVar(&complianceTenant, "tenant", "", "Filter by tenant ID")
	complianceReportCmd.Flags().StringVar(&complianceAgent, "agent", "", "Filter by agent ID")
	complianceReportCmd.Flags().StringVar(&complianceFrom, "from", "", "Start date (YYYY-MM-DD)")
	complianceReportCmd.Flags().StringVar(&complianceTo, "to", "", "End date (YYYY-MM-DD)")
	complianceReportCmd.Flags().StringVar(&complianceOutput, "output", "", "Write report to file")

	complianceRopaCmd.Flags().StringVar(&complianceFormat, "format", "html", "Output format: html or json")
	complianceRopaCmd.Flags().StringVar(&complianceTenant, "tenant", "", "Filter by tenant ID")
	complianceRopaCmd.Flags().StringVar(&complianceAgent, "agent", "", "Filter by agent ID")
	complianceRopaCmd.Flags().StringVar(&complianceFrom, "from", "", "Start date (YYYY-MM-DD)")
	complianceRopaCmd.Flags().StringVar(&complianceTo, "to", "", "End date (YYYY-MM-DD)")
	complianceRopaCmd.Flags().StringVar(&complianceOutput, "output", "", "Write document to file")
	complianceRopaCmd.Flags().StringVar(&compliancePolicyFile, "policy", "", "Agent policy file for declarations (default: from talon.config.yaml)")

	complianceAnnexIVCmd.Flags().StringVar(&complianceFormat, "format", "html", "Output format: html or json")
	complianceAnnexIVCmd.Flags().StringVar(&complianceTenant, "tenant", "", "Filter by tenant ID")
	complianceAnnexIVCmd.Flags().StringVar(&complianceAgent, "agent", "", "Filter by agent ID")
	complianceAnnexIVCmd.Flags().StringVar(&complianceFrom, "from", "", "Start date (YYYY-MM-DD)")
	complianceAnnexIVCmd.Flags().StringVar(&complianceTo, "to", "", "End date (YYYY-MM-DD)")
	complianceAnnexIVCmd.Flags().StringVar(&complianceOutput, "output", "", "Write document to file")
	complianceAnnexIVCmd.Flags().StringVar(&compliancePolicyFile, "policy", "", "Agent policy file for declarations (default: from talon.config.yaml)")

	complianceSovereigntyCmd.Flags().StringVar(&complianceFormat, "format", "html", "Output format: html or json")
	complianceSovereigntyCmd.Flags().StringVar(&complianceTenant, "tenant", "", "Filter by tenant ID")
	complianceSovereigntyCmd.Flags().StringVar(&complianceAgent, "agent", "", "Filter by agent ID")
	complianceSovereigntyCmd.Flags().StringVar(&complianceFrom, "from", "", "Start date (YYYY-MM-DD)")
	complianceSovereigntyCmd.Flags().StringVar(&complianceTo, "to", "", "End date (YYYY-MM-DD)")
	complianceSovereigntyCmd.Flags().StringVar(&complianceOutput, "output", "", "Write document to file")
	complianceSovereigntyCmd.Flags().StringVar(&complianceGatewayConfig, "gateway-config", "", "Gateway config path for declared upstream providers (default: active config file)")

	complianceCmd.AddCommand(complianceReportCmd)
	complianceCmd.AddCommand(complianceRopaCmd)
	complianceCmd.AddCommand(complianceAnnexIVCmd)
	complianceCmd.AddCommand(complianceSovereigntyCmd)
	rootCmd.AddCommand(complianceCmd)
}
