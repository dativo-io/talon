package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var memoryCmd = &cobra.Command{
	Use:   "memory",
	Short: "Manage agent memory / soul directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "memory")
		defer span.End()

		log.Info().Msg("talon memory - coming in Prompt 5")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(memoryCmd)
}
