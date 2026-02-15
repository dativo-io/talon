package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start Talon server (API + MCP + dashboard)",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "serve")
		defer span.End()

		log.Info().Msg("talon serve - coming in Prompt 6")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
