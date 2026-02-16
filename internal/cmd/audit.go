package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Query and export audit trail (evidence)",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "audit")
		defer span.End()

		log.Info().Msg("talon audit - coming in Prompt 4")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
