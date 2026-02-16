package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/policy"
)

var (
	validateFile   string
	validateStrict bool
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate agent policy and configuration",
	Long:  "Validates .talon.yaml against schema and runs policy compilation checks",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		_, span := tracer.Start(ctx, "validate")
		defer span.End()

		if validateFile == "" {
			validateFile = "agent.talon.yaml"
		}

		pol, err := policy.LoadPolicy(ctx, validateFile, validateStrict)
		if err != nil {
			log.Error().
				Err(err).
				Str("file", validateFile).
				Bool("strict", validateStrict).
				Msg("Policy validation failed")
			fmt.Fprintf(os.Stderr, "✗ Validation failed: %s\n", validateFile)
			return fmt.Errorf("validation failed: %w", err)
		}

		// Creating the engine compiles all Rego policies, verifying correctness
		_, err = policy.NewEngine(ctx, pol)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ Policy compilation failed: %s\n", validateFile)
			return fmt.Errorf("policy engine initialization failed: %w", err)
		}

		log.Info().
			Str("file", validateFile).
			Str("version", pol.VersionTag).
			Bool("strict", validateStrict).
			Msg("Policy validated successfully")

		fmt.Printf("✓ Policy valid: %s\n", validateFile)
		fmt.Printf("  Agent: %s v%s\n", pol.Agent.Name, pol.Agent.Version)
		fmt.Printf("  Version: %s\n", pol.VersionTag)
		if validateStrict {
			fmt.Println("  Mode: strict")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.Flags().StringVarP(&validateFile, "file", "f", "", "policy file to validate (default: agent.talon.yaml)")
	validateCmd.Flags().BoolVar(&validateStrict, "strict", false, "enable strict validation")
}
