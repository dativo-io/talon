package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/policy"
)

var intentCmd = &cobra.Command{
	Use:   "intent",
	Short: "Inspect tool intent classification and risk classes",
}

var intentClassifyCmd = &cobra.Command{
	Use:   "classify <tool-name> [params-json]",
	Short: "Classify a tool invocation into operation class and risk level",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		toolName := strings.TrimSpace(args[0])
		var params []byte
		if len(args) == 2 {
			params = []byte(strings.TrimSpace(args[1]))
			if len(params) > 0 && !json.Valid(params) {
				return fmt.Errorf("params-json must be valid JSON")
			}
		}

		classification := agent.ClassifyToolIntent(toolName, params, loadPlanReviewConfig(cmd.Context()))
		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			out, err := json.MarshalIndent(classification, "", "  ")
			if err != nil {
				return fmt.Errorf("encoding JSON output: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Tool:            %s\n", classification.ToolName)
		fmt.Fprintf(cmd.OutOrStdout(), "Operation class: %s\n", classification.OperationClass)
		fmt.Fprintf(cmd.OutOrStdout(), "Risk level:      %s\n", classification.RiskLevel)
		fmt.Fprintf(cmd.OutOrStdout(), "Bulk detected:   %t\n", classification.IsBulk)
		fmt.Fprintf(cmd.OutOrStdout(), "Plan review:     %t\n", classification.RequiresReview)
		fmt.Fprintf(cmd.OutOrStdout(), "Reason:          %s\n", classification.Reason)
		return nil
	},
}

var intentClassesCmd = &cobra.Command{
	Use:   "classes",
	Short: "Show available operation classes and example tool names",
	RunE: func(cmd *cobra.Command, _ []string) error {
		catalog := agent.IntentClassCatalog()
		sort.Slice(catalog, func(i, j int) bool {
			return catalog[i].Class < catalog[j].Class
		})
		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			out, err := json.MarshalIndent(catalog, "", "  ")
			if err != nil {
				return fmt.Errorf("encoding JSON output: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		}

		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "Class\tDefault risk\tDescription\tExamples")
		for _, classDef := range catalog {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
				classDef.Class,
				classDef.DefaultRisk,
				classDef.Description,
				strings.Join(classDef.Examples, ", "),
			)
		}
		return tw.Flush()
	},
}

func init() {
	intentClassifyCmd.Flags().Bool("json", false, "output in JSON format")
	intentClassesCmd.Flags().Bool("json", false, "output in JSON format")

	intentCmd.AddCommand(intentClassifyCmd)
	intentCmd.AddCommand(intentClassesCmd)
	rootCmd.AddCommand(intentCmd)
}

func loadPlanReviewConfig(ctx context.Context) *agent.PlanReviewConfig {
	cfg, err := config.Load()
	if err != nil {
		return nil
	}
	pol, err := policy.LoadPolicy(ctx, cfg.DefaultPolicy, false, ".")
	if err != nil || pol == nil || pol.Compliance == nil || pol.Compliance.PlanReview == nil {
		return nil
	}
	return &agent.PlanReviewConfig{
		RequireForTools: pol.Compliance.PlanReview.RequireForTools,
		RequireForTier:  pol.Compliance.PlanReview.RequireForTier,
		CostThreshold:   pol.Compliance.PlanReview.CostThreshold,
		TimeoutMinutes:  pol.Compliance.PlanReview.TimeoutMinutes,
		NotifyWebhook:   pol.Compliance.PlanReview.NotifyWebhook,
		Mode:            pol.Compliance.PlanReview.Mode,
	}
}
