package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/compliance"
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

func init() {
	complianceReportCmd.Flags().StringVar(&complianceFramework, "framework", "", "Framework filter: gdpr, eu-ai-act, nis2, dora, iso-27001")
	complianceReportCmd.Flags().StringVar(&complianceFormat, "format", "html", "Output format: html or json")
	complianceReportCmd.Flags().StringVar(&complianceTenant, "tenant", "", "Filter by tenant ID")
	complianceReportCmd.Flags().StringVar(&complianceAgent, "agent", "", "Filter by agent ID")
	complianceReportCmd.Flags().StringVar(&complianceFrom, "from", "", "Start date (YYYY-MM-DD)")
	complianceReportCmd.Flags().StringVar(&complianceTo, "to", "", "End date (YYYY-MM-DD)")
	complianceReportCmd.Flags().StringVar(&complianceOutput, "output", "", "Write report to file")

	complianceCmd.AddCommand(complianceReportCmd)
	rootCmd.AddCommand(complianceCmd)
}
