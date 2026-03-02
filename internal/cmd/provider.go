package cmd

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/llm"
	_ "github.com/dativo-io/talon/internal/llm/providers"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/pricing"
)

var providerCmd = &cobra.Command{
	Use:   "provider",
	Short: "List and inspect LLM providers (registry, compliance metadata)",
}

var providerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered providers with compliance columns",
	RunE:  runProviderList,
}

var providerInfoCmd = &cobra.Command{
	Use:   "info [type]",
	Short: "Show detailed compliance info for a provider",
	Args:  cobra.ExactArgs(1),
	RunE:  runProviderInfo,
}

var providerAllowedCmd = &cobra.Command{
	Use:   "allowed",
	Short: "List providers allowed under current data sovereignty mode (from config)",
	RunE:  runProviderAllowed,
}

func init() {
	providerCmd.AddCommand(providerListCmd)
	providerCmd.AddCommand(providerInfoCmd)
	providerCmd.AddCommand(providerAllowedCmd)
	rootCmd.AddCommand(providerCmd)
}

func runProviderList(cmd *cobra.Command, _ []string) error {
	list := llm.ListForWizard(false)
	if len(list) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No providers registered.")
		return nil
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tDisplay Name\tJurisdiction\tGDPR\tEU Regions\tDPA")
	for i := range list {
		m := &list[i]
		euRegions := strings.Join(m.EURegions, ", ")
		if euRegions == "" {
			euRegions = "-"
		}
		gdpr := "no"
		if m.GDPRCompliant {
			gdpr = "yes"
		}
		dpa := "no"
		if m.DPAAvailable {
			dpa = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", m.ID, m.DisplayName, m.Jurisdiction, gdpr, euRegions, dpa)
	}
	return tw.Flush()
}

func runProviderInfo(cmd *cobra.Command, args []string) error {
	providerType := strings.ToLower(strings.TrimSpace(args[0]))
	p, err := llm.NewProvider(providerType, nil)
	if err != nil {
		return fmt.Errorf("provider %q: %w", providerType, err)
	}
	meta := p.Metadata()
	fmt.Fprintf(cmd.OutOrStdout(), "ID:           %s\n", meta.ID)
	fmt.Fprintf(cmd.OutOrStdout(), "Display Name: %s\n", meta.DisplayName)
	fmt.Fprintf(cmd.OutOrStdout(), "Jurisdiction: %s\n", meta.Jurisdiction)
	fmt.Fprintf(cmd.OutOrStdout(), "GDPR:         %v\n", meta.GDPRCompliant)
	fmt.Fprintf(cmd.OutOrStdout(), "DPA:          %v\n", meta.DPAAvailable)
	fmt.Fprintf(cmd.OutOrStdout(), "EU Regions:   %s\n", strings.Join(meta.EURegions, ", "))
	fmt.Fprintf(cmd.OutOrStdout(), "AI Act:       %s\n", meta.AIActScope)
	fmt.Fprintf(cmd.OutOrStdout(), "Data Retention: %s\n", meta.DataRetention)
	fmt.Fprintf(cmd.OutOrStdout(), "SOC2:         %v  ISO27001: %v\n", meta.SOC2, meta.ISO27001)
	if meta.Wizard.Suffix != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Wizard suffix: %s\n", meta.Wizard.Suffix)
	}
	// Pricing status from config-driven table (same path as run/serve)
	pricingPath := config.DefaultPricingFile
	if cfg, _ := config.Load(); cfg != nil && cfg.LLM != nil && cfg.LLM.PricingFile != "" {
		pricingPath = cfg.LLM.PricingFile
	}
	pt := pricing.LoadOrDefault(pricingPath)
	if n := pt.ModelCount(providerType); n > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Pricing:       available (%d models configured)\n", n)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Pricing:       not configured\n")
	}
	return nil
}

func runProviderAllowed(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	mode := "global"
	if cfg.LLM != nil && cfg.LLM.Routing != nil && cfg.LLM.Routing.DataSovereigntyMode != "" {
		mode = cfg.LLM.Routing.DataSovereigntyMode
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Data sovereignty mode: %s\n\n", mode)

	ctx := context.Background()
	pol := &policy.Policy{VersionTag: "v1", Policies: policy.PoliciesConfig{}}
	eng, err := policy.NewEngine(ctx, pol)
	if err != nil {
		return fmt.Errorf("creating policy engine: %w", err)
	}

	list := llm.ListForWizard(false)
	if len(list) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No providers registered.")
		return nil
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tAllowed\tReason")
	for i := range list {
		m := &list[i]
		region := ""
		if len(m.EURegions) > 0 {
			region = m.EURegions[0]
		}
		dec, err := eng.EvaluateRouting(ctx, &policy.RoutingInput{
			SovereigntyMode:      mode,
			ProviderID:           m.ID,
			ProviderJurisdiction: m.Jurisdiction,
			ProviderRegion:       region,
			DataTier:             0,
			RequireEURouting:     false,
		})
		var allowed, reason string
		switch {
		case err != nil:
			reason = err.Error()
		case dec.Allowed:
			allowed = "yes"
		default:
			reason = strings.Join(dec.Reasons, "; ")
		}
		if allowed == "" {
			allowed = "no"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", m.ID, allowed, reason)
	}
	return tw.Flush()
}
