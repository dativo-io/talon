package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "version")
		defer span.End()

		version := Version
		if version == "dev" {
			if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
				version = info.Main.Version
			}
		}
		fmt.Printf("Talon %s\n", version)
		fmt.Printf("Commit: %s\n", Commit)
		fmt.Printf("Built:  %s\n", BuildDate)
		fmt.Printf("Go:     %s\n", runtime.Version())

		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
