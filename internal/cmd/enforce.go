package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
)

var (
	enforceGatewayConfig string
	enforceFrom          string
	enforceTo            string
	enforceFormat        string
	enforceForce         bool
)

var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "Manage gateway enforcement mode (shadow ↔ enforce migration)",
}

var enforceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current gateway enforcement mode",
	RunE:  enforceStatus,
}

var enforceReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show shadow mode violation summary",
	RunE:  enforceReport,
}

var enforceEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Switch gateway to enforce mode (blocks violations)",
	RunE:  enforceEnable,
}

var enforceDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Switch gateway back to shadow mode (log only)",
	RunE:  enforceDisable,
}

func init() {
	enforceCmd.PersistentFlags().StringVar(&enforceGatewayConfig, "gateway-config", "talon.config.yaml", "Gateway config file path")
	enforceReportCmd.Flags().StringVar(&enforceFrom, "from", "", "Start date (YYYY-MM-DD); default: 24h ago")
	enforceReportCmd.Flags().StringVar(&enforceTo, "to", "", "End date (YYYY-MM-DD); default: now")
	enforceReportCmd.Flags().StringVar(&enforceFormat, "format", "text", "Output format: text or json")
	enforceEnableCmd.Flags().BoolVar(&enforceForce, "force", false, "Skip doctor safety checks")

	enforceCmd.AddCommand(enforceStatusCmd)
	enforceCmd.AddCommand(enforceReportCmd)
	enforceCmd.AddCommand(enforceEnableCmd)
	enforceCmd.AddCommand(enforceDisableCmd)
	rootCmd.AddCommand(enforceCmd)
}

func enforceStatus(cmd *cobra.Command, _ []string) error {
	cfg, err := gateway.LoadGatewayConfig(enforceGatewayConfig)
	if err != nil {
		return fmt.Errorf("loading gateway config: %w", err)
	}

	out := cmd.OutOrStdout()
	switch cfg.Mode {
	case gateway.ModeShadow:
		fmt.Fprintln(out, "Gateway mode: shadow (log only — violations are recorded but not blocked)")
		fmt.Fprintln(out, "Run 'talon enforce report' to review shadow violations.")
	case gateway.ModeEnforce:
		fmt.Fprintln(out, "Gateway mode: enforce (active — violations are blocked)")
	case gateway.ModeLogOnly:
		fmt.Fprintln(out, "Gateway mode: log_only (evidence only — no policy evaluation)")
	default:
		fmt.Fprintf(out, "Gateway mode: %s (unknown)\n", cfg.Mode)
	}
	return nil
}

func enforceReport(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
	defer cancel()

	store, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("initializing evidence store: %w", err)
	}
	defer store.Close()

	from, to, err := parseEnforceTimeRange()
	if err != nil {
		return err
	}

	list, err := store.List(ctx, "", "", from, to, 50000)
	if err != nil {
		return fmt.Errorf("querying evidence: %w", err)
	}

	counts := map[string]int{
		"pii_block":        0,
		"policy_deny":      0,
		"tool_block":       0,
		"rate_limit":       0,
		"attachment_block": 0,
	}
	total := 0
	for i := range list {
		ev := &list[i]
		if !ev.ObservationModeOverride || len(ev.ShadowViolations) == 0 {
			continue
		}
		for _, sv := range ev.ShadowViolations {
			counts[sv.Type]++
			total++
		}
	}

	out := cmd.OutOrStdout()
	if enforceFormat == "json" {
		return renderEnforceReportJSON(out, from, to, counts, total)
	}
	return renderEnforceReportText(out, from, to, counts, total)
}

func renderEnforceReportText(w io.Writer, from, to time.Time, counts map[string]int, total int) error {
	period := fmt.Sprintf("%s to %s", from.Format("2006-01-02 15:04"), to.Format("2006-01-02 15:04"))
	fmt.Fprintf(w, "Shadow Mode Violation Report (%s)\n", period)
	fmt.Fprintln(w, strings.Repeat("-", 50))
	fmt.Fprintf(w, "PII blocked:          %4d (would have been blocked)\n", counts["pii_block"])
	fmt.Fprintf(w, "Policy denied:        %4d (would have been blocked)\n", counts["policy_deny"])
	fmt.Fprintf(w, "Forbidden tools:      %4d (would have been stripped/blocked)\n", counts["tool_block"])
	fmt.Fprintf(w, "Rate limit exceeded:  %4d (would have been blocked)\n", counts["rate_limit"])
	fmt.Fprintf(w, "Attachment violations:%4d (would have been blocked)\n", counts["attachment_block"])
	fmt.Fprintln(w, strings.Repeat("-", 50))
	fmt.Fprintf(w, "Total: %d violations logged, 0 blocked (shadow mode)\n", total)
	if total > 0 {
		fmt.Fprintln(w, "\nRun 'talon enforce enable' to start blocking violations.")
	}
	return nil
}

func renderEnforceReportJSON(w io.Writer, from, to time.Time, counts map[string]int, total int) error {
	report := struct {
		Period struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"period"`
		Violations map[string]int `json:"violations"`
		Total      int            `json:"total"`
	}{
		Violations: counts,
		Total:      total,
	}
	report.Period.From = from.Format(time.RFC3339)
	report.Period.To = to.Format(time.RFC3339)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func enforceEnable(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	cfg, err := gateway.LoadGatewayConfig(enforceGatewayConfig)
	if err != nil {
		return fmt.Errorf("loading gateway config: %w", err)
	}
	if cfg.Mode == gateway.ModeEnforce {
		fmt.Fprintln(cmd.OutOrStdout(), "Gateway is already in enforce mode.")
		return nil
	}

	if !enforceForce {
		if doctorErr := runQuickDoctorChecks(); doctorErr != nil {
			return fmt.Errorf("doctor checks failed (use --force to override): %w", doctorErr)
		}
	}

	from := cfg.Mode
	if err := updateGatewayMode(enforceGatewayConfig, "enforce"); err != nil {
		return fmt.Errorf("updating config: %w", err)
	}

	if err := recordModeChangeEvidence(ctx, string(from), "enforce"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to record mode change evidence: %v\n", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Gateway mode updated to: enforce")
	fmt.Fprintln(cmd.OutOrStdout(), "Restart 'talon serve' to apply the change.")
	return nil
}

func enforceDisable(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	cfg, err := gateway.LoadGatewayConfig(enforceGatewayConfig)
	if err != nil {
		return fmt.Errorf("loading gateway config: %w", err)
	}
	if cfg.Mode == gateway.ModeShadow {
		fmt.Fprintln(cmd.OutOrStdout(), "Gateway is already in shadow mode.")
		return nil
	}

	from := cfg.Mode
	if err := updateGatewayMode(enforceGatewayConfig, "shadow"); err != nil {
		return fmt.Errorf("updating config: %w", err)
	}

	if err := recordModeChangeEvidence(ctx, string(from), "shadow"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to record mode change evidence: %v\n", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Gateway mode updated to: shadow")
	fmt.Fprintln(cmd.OutOrStdout(), "Restart 'talon serve' to apply the change.")
	return nil
}

func parseEnforceTimeRange() (from, to time.Time, err error) {
	to = time.Now().UTC()
	from = to.Add(-24 * time.Hour)

	if enforceFrom != "" {
		from, err = time.ParseInLocation("2006-01-02", enforceFrom, time.UTC)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid --from: %w", err)
		}
	}
	if enforceTo != "" {
		to, err = time.ParseInLocation("2006-01-02", enforceTo, time.UTC)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid --to: %w", err)
		}
		to = to.Add(24 * time.Hour)
	}
	return from, to, nil
}

// updateGatewayMode reads the YAML config, replaces the mode value, and writes back.
// Uses simple string replacement to preserve comments and formatting.
func updateGatewayMode(path, newMode string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	content := string(data)
	for _, old := range []string{
		`mode: "shadow"`, `mode: "enforce"`, `mode: "log_only"`,
		`mode: shadow`, `mode: enforce`, `mode: log_only`,
	} {
		if strings.Contains(content, old) {
			// Preserve the quoting style of the original
			replacement := fmt.Sprintf(`mode: "%s"`, newMode)
			content = strings.Replace(content, old, replacement, 1)
			return os.WriteFile(path, []byte(content), 0o600)
		}
	}
	return fmt.Errorf("could not find mode field in %s", path)
}

func recordModeChangeEvidence(ctx context.Context, fromMode, toMode string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return err
	}
	defer store.Close()

	ev := &evidence.Evidence{
		ID:              "mc_" + uuid.New().String()[:12],
		CorrelationID:   "mc_" + uuid.New().String()[:12],
		Timestamp:       time.Now(),
		TenantID:        "system",
		AgentID:         "talon-cli",
		InvocationType:  "mode_change",
		RequestSourceID: "cli",
		PolicyDecision:  evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution: evidence.Execution{
			ModelUsed: fmt.Sprintf("mode_change:%s->%s", fromMode, toMode),
		},
	}
	return store.Store(ctx, ev)
}

// runQuickDoctorChecks runs minimal doctor checks before enabling enforcement.
func runQuickDoctorChecks() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("evidence store: %w", err)
	}
	_ = store.Close()

	if _, gwErr := gateway.LoadGatewayConfig(enforceGatewayConfig); gwErr != nil {
		return fmt.Errorf("gateway config: %w", gwErr)
	}
	return nil
}
