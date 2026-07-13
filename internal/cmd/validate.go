package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/policy"
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
				return runValidateDir(ctx, dir)
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

		if err := deepValidatePolicy(ctx, pol); err != nil {
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

// deepValidatePolicy runs the compilation-level checks beyond schema load:
// the Rego engine (compiles all policies) and the PII scanner built from
// data_classification. Shared by single-file and directory validation so the
// two modes cannot drift.
func deepValidatePolicy(ctx context.Context, pol *policy.Policy) error {
	if _, err := policy.NewEngine(ctx, pol); err != nil {
		return fmt.Errorf("policy engine initialization failed: %w", err)
	}
	if _, err := policy.NewPIIScannerForPolicy(pol, ""); err != nil {
		return fmt.Errorf("PII scanner from policy: %w", err)
	}
	return nil
}

// runValidateDir validates every agent.talon.yaml under dir (#267): the same
// recursive scan and strict per-file pipeline serve startup runs, plus the
// deep checks single-file validate applies. One ✓/✗ line per file; any
// failure (or an empty directory) exits non-zero.
func runValidateDir(ctx context.Context, dir string) error {
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
		if err := deepValidatePolicy(ctx, pol); err != nil {
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
