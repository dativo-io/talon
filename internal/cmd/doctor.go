package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/doctor"
)

var (
	doctorFormat        string
	doctorGatewayConfig string
	doctorSkipUpstream  bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run health checks (config, gateway, system)",
	Long:  "Verifies configuration, gateway connectivity, secrets, and system health.",
	RunE:  runDoctor,
}

func init() {
	doctorCmd.Flags().StringVar(&doctorFormat, "format", "text", "Output format: text or json")
	doctorCmd.Flags().StringVar(&doctorGatewayConfig, "gateway-config", "", "Gateway config path (auto-detected if empty)")
	doctorCmd.Flags().BoolVar(&doctorSkipUpstream, "skip-upstream", false, "Skip upstream connectivity checks")
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	gwConfig := doctorGatewayConfig
	if gwConfig == "" {
		if _, err := os.Stat("talon.config.yaml"); err == nil {
			gwConfig = "talon.config.yaml"
		}
	}

	opts := doctor.Options{
		GatewayConfigPath: gwConfig,
		SkipUpstream:      doctorSkipUpstream,
	}
	report := doctor.Run(ctx, opts)

	out := cmd.OutOrStdout()
	if doctorFormat == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encoding doctor report: %w", err)
		}
	} else {
		renderDoctorText(out, report)
	}

	if report.Status == "fail" {
		return fmt.Errorf("doctor checks failed")
	}
	return nil
}

func renderDoctorText(w io.Writer, report *doctor.Report) {
	currentCategory := ""
	for _, c := range report.Checks {
		if c.Category != currentCategory {
			currentCategory = c.Category
			fmt.Fprintf(w, "\n%s\n", categoryTitle(currentCategory))
		}
		icon := "✓"
		switch c.Status {
		case "warn":
			icon = "⚠"
		case "fail":
			icon = "✗"
		}
		fmt.Fprintf(w, "  %s %-30s %s\n", icon, c.Name, c.Message)
		if c.Fix != "" && c.Status != "pass" {
			fmt.Fprintf(w, "    → %s\n", c.Fix)
		}
	}
	fmt.Fprintf(w, "\nResult: %d passed, %d warnings, %d failures\n",
		report.Summary.Pass, report.Summary.Warn, report.Summary.Fail)
}

func categoryTitle(cat string) string {
	switch cat {
	case "config":
		return "Configuration"
	case "gateway":
		return "Gateway"
	case "system":
		return "System"
	default:
		return cat
	}
}
