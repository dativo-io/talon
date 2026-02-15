package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage secrets vault (set, list, rotate, audit)",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "secrets")
		defer span.End()

		log.Info().Msg("talon secrets - coming in Prompt 4")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(secretsCmd)
}
