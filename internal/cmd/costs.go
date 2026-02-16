package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var costsCmd = &cobra.Command{
	Use:   "costs",
	Short: "Show cost and budget usage",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "costs")
		defer span.End()

		log.Info().Msg("talon costs - coming in Prompt 4")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(costsCmd)
}
