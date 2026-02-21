package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Talon configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "config.show")
		defer span.End()

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		out := cmd.OutOrStdout()

		// Data directory
		dataDir := cfg.DataDir
		dataDirExists := dirExists(dataDir)
		fmt.Fprintf(out, "Data directory:    %s", dataDir)
		if dataDirExists {
			fmt.Fprintln(out, " (exists)")
		} else {
			fmt.Fprintln(out, " (missing)")
		}

		// Secrets key
		if cfg.UsingDefaultSecretsKey() {
			fmt.Fprintln(out, "Secrets key:        default (generated) — set TALON_SECRETS_KEY for production")
		} else {
			fmt.Fprintln(out, "Secrets key:        configured")
		}

		// Signing key
		if cfg.UsingDefaultSigningKey() {
			fmt.Fprintln(out, "Signing key:        default (generated) — set TALON_SIGNING_KEY for production")
		} else {
			fmt.Fprintln(out, "Signing key:        configured")
		}

		// Default policy path and existence
		policyPath := cfg.DefaultPolicy
		if !filepath.IsAbs(policyPath) {
			cwd, _ := os.Getwd()
			policyPath = filepath.Join(cwd, cfg.DefaultPolicy)
		}
		policyExists := fileExists(policyPath)
		fmt.Fprintf(out, "Default policy:     %s", cfg.DefaultPolicy)
		if policyExists {
			fmt.Fprintf(out, " → %s (exists)\n", policyPath)
		} else {
			fmt.Fprintf(out, " → %s (missing)\n", policyPath)
		}

		// DB paths
		fmt.Fprintln(out, "Secrets DB:         ", cfg.SecretsDBPath())
		fmt.Fprintln(out, "Evidence DB:        ", cfg.EvidenceDBPath())
		fmt.Fprintln(out, "Memory DB:          ", cfg.MemoryDBPath())

		// LLM provider keys (env only; vault keys are not listed here for security)
		fmt.Fprintln(out, "LLM keys (env):     ", maskEnvKeys())
		return nil
	},
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// maskEnvKeys returns a short summary of which provider env keys are set (masked).
func maskEnvKeys() string {
	keys := []struct{ env, label string }{
		{"OPENAI_API_KEY", "openai"},
		{"ANTHROPIC_API_KEY", "anthropic"},
		{"AWS_ACCESS_KEY_ID", "bedrock"},
	}
	var set []string
	for _, k := range keys {
		if v := os.Getenv(k.env); v != "" {
			set = append(set, k.label+"=***")
		} else {
			set = append(set, k.label+"=missing")
		}
	}
	return strings.Join(set, ", ")
}

func init() {
	configCmd.AddCommand(configShowCmd)
	rootCmd.AddCommand(configCmd)
}
