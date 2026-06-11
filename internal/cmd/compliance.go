package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/compliance"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
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

// loadDeclarations gathers declared facts: controller identity from operator
// config, processing/system declarations from the agent policy file. Both are
// optional — missing declarations surface as document warnings, not errors.
func loadDeclarations(ctx context.Context, cmd *cobra.Command) compliance.Declarations {
	var decl compliance.Declarations

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: could not load talon.config.yaml:", err)
	} else {
		decl.Controller = cfg.ControllerDeclarations()
	}

	policyPath := compliancePolicyFile
	if policyPath == "" && cfg != nil {
		policyPath = cfg.DefaultPolicy
	}
	if _, statErr := os.Stat(policyPath); statErr != nil {
		// No agent policy in the working directory — fine for org-wide exports.
		return decl
	}
	pol, err := policy.LoadPolicy(ctx, policyPath, false, filepath.Dir(policyPath))
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: could not load agent policy %s: %v\n", policyPath, err)
		return decl
	}
	if pol.Compliance != nil {
		decl = decl.MergeAgentDeclarations(pol.Compliance.Declarations)
		decl.DataResidency = pol.Compliance.DataResidency
	}
	return decl
}

var compliancePolicyFile string

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

	complianceCmd.AddCommand(complianceReportCmd)
	complianceCmd.AddCommand(complianceRopaCmd)
	complianceCmd.AddCommand(complianceAnnexIVCmd)
	rootCmd.AddCommand(complianceCmd)
}
