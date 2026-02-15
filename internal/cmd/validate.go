package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate agent policy and configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "validate")
		defer span.End()

		log.Info().Msg("talon validate - coming in Prompt 2")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
}
