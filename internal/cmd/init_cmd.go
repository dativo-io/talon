package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new Talon project",
	Long:  "Creates agent.talon.yaml and talon.config.yaml from templates",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "init")
		defer span.End()

		log.Info().Msg("talon init - coming in Prompt 1 (Days 3-4)")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
