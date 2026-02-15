package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run an agent with a query",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "run")
		defer span.End()

		log.Info().Msg("talon run - coming in Prompt 3/4")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
