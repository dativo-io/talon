package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run preflight checks (data dir, policy, LLM key, SQLite)",
	Long:  "Verifies data directory is writable, default policy is valid, at least one LLM key is available, and evidence DB is usable.",
	RunE:  runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

//nolint:gocyclo // preflight runs a linear sequence of independent checks
func runDoctor(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	out := cmd.OutOrStdout()
	ok := true

	// 1. Data directory writable
	dataDir := cfg.DataDir
	if err := cfg.EnsureDataDir(); err != nil {
		fmt.Fprintf(out, "\u2717 Data directory: %s — %v\n", dataDir, err)
		ok = false
	} else {
		// Check writable
		testFile := filepath.Join(dataDir, ".doctor-write-test")
		if err := os.WriteFile(testFile, []byte("ok"), 0o600); err != nil {
			fmt.Fprintf(out, "\u2717 Data directory: %s not writable — %v\n", dataDir, err)
			ok = false
		} else {
			_ = os.Remove(testFile)
			fmt.Fprintf(out, "\u2713 Data directory: %s (writable)\n", dataDir)
		}
	}

	// 2. Default policy valid
	policyPath := cfg.DefaultPolicy
	if _, err := os.Stat(policyPath); err != nil {
		fmt.Fprintf(out, "\u2717 Policy: %s — file not found\n", policyPath)
		ok = false
	} else {
		pol, err := policy.LoadPolicy(ctx, policyPath, false)
		if err != nil {
			fmt.Fprintf(out, "\u2717 Policy: %s — %v\n", policyPath, err)
			ok = false
		} else {
			fmt.Fprintf(out, "\u2713 Policy: %s (agent %s)\n", policyPath, pol.Agent.Name)
		}
	}

	// 3. LLM key present (env fallback or vault)
	hasOpenAI := os.Getenv("OPENAI_API_KEY") != ""
	hasAnthropic := os.Getenv("ANTHROPIC_API_KEY") != ""
	hasAWS := os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_PROFILE") != ""
	if !hasOpenAI && !hasAnthropic && !hasAWS {
		fmt.Fprintf(out, "\u2717 LLM key: no OPENAI_API_KEY, ANTHROPIC_API_KEY, or AWS credentials found (set one for talon run)\n")
		ok = false
	} else {
		var keys []string
		if hasOpenAI {
			keys = append(keys, "openai")
		}
		if hasAnthropic {
			keys = append(keys, "anthropic")
		}
		if hasAWS {
			keys = append(keys, "aws")
		}
		fmt.Fprintf(out, "\u2713 LLM key: %v (env)\n", keys)
	}

	// 4. Crypto keys (warn if default)
	if cfg.UsingDefaultSecretsKey() {
		fmt.Fprintf(out, "\u26a0 Secrets key: using generated default — set TALON_SECRETS_KEY for production\n")
	} else {
		fmt.Fprintf(out, "\u2713 Secrets key: configured\n")
	}
	if cfg.UsingDefaultSigningKey() {
		fmt.Fprintf(out, "\u26a0 Signing key: using generated default — set TALON_SIGNING_KEY for production\n")
	} else {
		fmt.Fprintf(out, "\u2713 Signing key: configured\n")
	}

	// 5. SQLite evidence store
	store, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		fmt.Fprintf(out, "\u2717 Evidence DB: %v\n", err)
		ok = false
	} else {
		_ = store.Close()
		fmt.Fprintf(out, "\u2713 Evidence DB: %s\n", cfg.EvidenceDBPath())
	}

	if !ok {
		return fmt.Errorf("preflight checks failed")
	}
	fmt.Fprintf(out, "\nAll checks passed.\n")
	return nil
}
