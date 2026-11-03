package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/trigger"
)

var (
	validateFile   string
	validateDir    string
	validateStrict bool
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate agent policy and configuration",
	Long: "Validates agent policy (.talon.yaml) against schema and runs policy compilation checks. " +
		"With --dir (or agents_dir in talon.config.yaml), validates every agent.talon.yaml under the directory (#267). " +
		"To check infrastructure config (talon.config.yaml, including cache), run 'talon doctor'.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		_, span := tracer.Start(ctx, "validate")
		defer span.End()

		// Resolution order: explicit -f wins → explicit --dir → agents_dir
		// from talon.config.yaml → the default single file. A config-load
		// failure only degrades to single-file mode; it never blocks
		// validating an explicit target.
		rules := offlineTriggerRules()
		file := validateFile
		if file == "" {
			dir := validateDir
			if dir == "" {
				if cfg, err := config.Load(); err == nil {
					dir = cfg.AgentsDir
				} else {
					log.Warn().Err(err).Msg("operator config unavailable; validating the default single policy file")
				}
			}
			if dir != "" {
				return runValidateDir(ctx, dir, rules)
			}
			file = "agent.talon.yaml"
		}

		baseDir := "."
		if filepath.IsAbs(filepath.Clean(file)) {
			baseDir = filepath.Dir(filepath.Clean(file))
		}
		pol, err := policy.LoadPolicy(ctx, file, validateStrict, baseDir)
		if err != nil {
			log.Error().
				Err(err).
				Str("file", file).
				Bool("strict", validateStrict).
				Msg("Policy validation failed")
			fmt.Fprintf(os.Stderr, "✗ Validation failed: %s\n", file)
			return fmt.Errorf("validation failed: %w", err)
		}

		if err := deepValidatePolicy(ctx, pol, rules); err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %s\n", file, err)
			return err
		}

		log.Info().
			Str("file", file).
			Str("version", pol.VersionTag).
			Bool("strict", validateStrict).
			Msg("Policy validated successfully")

		fmt.Printf("✓ Policy valid: %s\n", file)
		fmt.Printf("  Agent: %s v%s\n", pol.Agent.Name, pol.Agent.Version)
		fmt.Printf("  Version: %s\n", pol.VersionTag)
		if validateStrict {
			fmt.Println("  Mode: strict")
		}

		return nil
	},
}

// offlineTriggerRules derives the trigger serve rules `talon validate` can
// determine without running serve (#479). A gateway config that exists and
// is enabled (TALON_GATEWAY_CONFIG, default talon.config.yaml) means the
// deployment serves a gateway, so trigger definitions are refused exactly as
// `talon serve --gateway` refuses them. Without a gateway config validate
// cannot know whether serve will be started with --gateway and applies the
// definition rules only (secret_name present, require_approval unset); a
// present but invalid gateway config is doctor's finding, not validate's.
func offlineTriggerRules() trigger.ServeRules {
	path := strings.TrimSpace(os.Getenv("TALON_GATEWAY_CONFIG"))
	if path == "" {
		path = "talon.config.yaml"
	}
	gwCfg, err := gateway.LoadGatewayConfig(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warn().Err(err).Str("path", path).Msg("gateway config present but invalid; trigger definitions validated with native-only rules (run 'talon doctor')")
		}
		return trigger.ServeRules{}
	}
	return trigger.ServeRules{GatewayServed: gwCfg.Enabled}
}

// deepValidatePolicy runs the compilation-level checks beyond schema load:
// the Rego engine (compiles all policies), the PII scanner built from
// data_classification and the trigger definition rules serve applies at
// startup (#479). Shared by single-file and directory validation so the two
// modes cannot drift.
func deepValidatePolicy(ctx context.Context, pol *policy.Policy, rules trigger.ServeRules) error {
	if _, err := policy.NewEngine(ctx, pol); err != nil {
		return fmt.Errorf("policy engine initialization failed: %w", err)
	}
	if err := trigger.ValidatePolicyTriggers(pol, rules); err != nil {
		return fmt.Errorf("triggers: %w", err)
	}
	if _, err := policy.NewPIIScannerForPolicy(pol, ""); err != nil {
		return fmt.Errorf("PII scanner from policy: %w", err)
	}
	// The action catalog compiles with the same fail-closed rules serve
	// applies (closed 2020-12 schema, exact reviewer projection, trusted
	// destination), so a catalog serve would refuse is refused here first.
	// Trusted MCP sources are not discovered here (validate is offline and
	// makes no network call): their static configuration and mapping are
	// checked, and the undiscovered sources are reported truthfully —
	// `talon actions list --agent <name>` discovers and compiles them.
	if pol.Actions != nil && len(pol.Actions.Definitions) > 0 {
		if _, err := action.CompileCatalog(pol.Actions, nil); err != nil {
			var undiscovered *action.SourceNotDiscoveredError
			if !errors.As(err, &undiscovered) {
				return fmt.Errorf("action catalog: %w", err)
			}
			log.Info().Strs("sources", undiscovered.IDs).Msg("action_sources_not_discovered_offline")
		}
		if _, err := action.CompileApprovalPolicy(pol); err != nil {
			return fmt.Errorf("action approval policy: %w", err)
		}
	}
	return nil
}

// runValidateDir validates every agent.talon.yaml under dir (#267): the same
// recursive scan and strict per-file pipeline serve startup runs, plus the
// deep checks single-file validate applies. One ✓/✗ line per file; any
// failure (or an empty directory) exits non-zero.
func runValidateDir(ctx context.Context, dir string, rules trigger.ServeRules) error {
	scan, scanErr := agentcatalog.DiscoverAgents(ctx, dir)
	if scanErr != nil && len(scan.Files) == 0 {
		fmt.Fprintf(os.Stderr, "✗ %s\n", scanErr)
		return scanErr
	}
	if len(scan.Files) == 0 {
		return fmt.Errorf("no %s found under %s — one directory per AI use case, one %s per directory (#267)",
			agentcatalog.AgentConfigFilename, dir, agentcatalog.AgentConfigFilename)
	}

	failures := 0
	for _, f := range scan.Files {
		if f.Err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "✗ %s: %s\n", f.Path, f.Err)
			continue
		}
		pol := f.Agent.Policy
		if validateStrict {
			var strictErr error
			pol, strictErr = policy.LoadPolicy(ctx, filepath.Base(f.Path), true, filepath.Dir(f.Path))
			if strictErr != nil {
				failures++
				fmt.Fprintf(os.Stderr, "✗ %s: strict validation: %s\n", f.Path, strictErr)
				continue
			}
		}
		if err := deepValidatePolicy(ctx, pol, rules); err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "✗ %s: %s\n", f.Path, err)
			continue
		}
		fmt.Printf("✓ %s — agent %s v%s\n", f.Path, pol.Agent.Name, pol.Agent.Version)
	}

	if failures > 0 {
		return fmt.Errorf("agents_dir validation failed: %d of %d file(s) invalid under %s", failures, len(scan.Files), dir)
	}
	fmt.Printf("✓ %d agent(s) valid under %s\n", len(scan.Agents), dir)
	return nil
}

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.Flags().StringVarP(&validateFile, "file", "f", "", "policy file to validate (default: agent.talon.yaml)")
	validateCmd.Flags().StringVar(&validateDir, "dir", "", "validate every agent.talon.yaml under a directory (defaults to agents_dir from talon.config.yaml when set)")
	validateCmd.Flags().BoolVar(&validateStrict, "strict", false, "enable strict validation")
}
