package cmd

import (
	"embed"
	"fmt"
	"os"
	"text/template"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

//go:embed templates/init/*.tmpl
var initTemplates embed.FS

var (
	initName  string
	initOwner string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new Talon project",
	Long:  "Creates agent.talon.yaml and talon.config.yaml from templates",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "init")
		defer span.End()

		if err := initializeProject(); err != nil {
			return fmt.Errorf("initializing project: %w", err)
		}

		log.Info().
			Str("name", initName).
			Msg("Initialized Talon project")

		fmt.Println("Initialized Talon project")
		fmt.Println()
		fmt.Println("Created files:")
		fmt.Println("  - agent.talon.yaml (agent policy)")
		fmt.Println("  - talon.config.yaml (global config)")
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("  1. Review and edit agent.talon.yaml")
		fmt.Println("  2. Set LLM provider API key:")
		fmt.Println("     export OPENAI_API_KEY=sk-your-key")
		fmt.Println("  3. Validate configuration:")
		fmt.Println("     talon validate")
		fmt.Println("  4. Run your agent:")
		fmt.Println("     talon run \"your query\"")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringVar(&initName, "name", "my-agent", "agent name")
	initCmd.Flags().StringVar(&initOwner, "owner", "", "agent owner email")
}

func initializeProject() error {
	if _, err := os.Stat("agent.talon.yaml"); err == nil {
		return fmt.Errorf("agent.talon.yaml already exists")
	}

	data := map[string]interface{}{
		"Name":  initName,
		"Owner": initOwner,
		"Date":  time.Now().Format(time.RFC3339),
	}

	if err := renderTemplate("templates/init/agent.talon.yaml.tmpl", "agent.talon.yaml", data); err != nil {
		return fmt.Errorf("creating agent.talon.yaml: %w", err)
	}

	if err := renderTemplate("templates/init/talon.config.yaml.tmpl", "talon.config.yaml", data); err != nil {
		return fmt.Errorf("creating talon.config.yaml: %w", err)
	}

	return nil
}

func renderTemplate(tmplPath, outPath string, data interface{}) error {
	tmplContent, err := initTemplates.ReadFile(tmplPath)
	if err != nil {
		return fmt.Errorf("reading template %s: %w", tmplPath, err)
	}

	tmpl, err := template.New(outPath).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer out.Close()

	if err := tmpl.Execute(out, data); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return nil
}
