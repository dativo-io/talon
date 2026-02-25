package cmd

import (
	"embed"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

//go:embed templates/init/*.tmpl
var initTemplates embed.FS

var (
	initName    string
	initOwner   string
	initMinimal bool
	initPack    string
)

// supportedPacks are the allowed values for --pack (industry starter packs).
var supportedPacks = []string{"fintech-eu", "ecommerce-eu", "saas-eu", "telecom-eu", "openclaw"}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new Talon project",
	Long:  "Creates agent.talon.yaml and talon.config.yaml from templates. Use --minimal for a short config, or --pack for an industry starter.",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, span := tracer.Start(cmd.Context(), "init")
		defer span.End()

		if err := initializeProject(); err != nil {
			return fmt.Errorf("initializing project: %w", err)
		}

		log.Info().
			Str("name", initName).
			Bool("minimal", initMinimal).
			Str("pack", initPack).
			Msg("Initialized Talon project")

		fmt.Println("Initialized Talon project")
		fmt.Println()
		fmt.Println("Created files:")
		fmt.Println("  - agent.talon.yaml (agent policy)")
		fmt.Println("  - talon.config.yaml (global config)")
		fmt.Println()
		if initPack == "openclaw" {
			printOpenClawNextSteps()
		} else {
			fmt.Println("Next steps:")
			fmt.Println("  1. Review and edit agent.talon.yaml")
			fmt.Println("  2. Set LLM provider API key:")
			fmt.Println("     export OPENAI_API_KEY=sk-your-key")
			fmt.Println("  3. Validate configuration:")
			fmt.Println("     talon validate")
			fmt.Println("  4. Run your agent:")
			fmt.Println("     talon run \"your query\"")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringVar(&initName, "name", "my-agent", "agent name")
	initCmd.Flags().StringVar(&initOwner, "owner", "", "agent owner email")
	initCmd.Flags().BoolVar(&initMinimal, "minimal", false, "generate minimal agent.talon.yaml (fewer options, faster to edit)")
	initCmd.Flags().StringVar(&initPack, "pack", "", "starter pack: openclaw, fintech-eu, ecommerce-eu, saas-eu, telecom-eu (overrides default template)")
}

func printOpenClawNextSteps() {
	fmt.Println("Next steps (OpenClaw gateway):")
	fmt.Println("  1. Store your real OpenAI key in the vault:")
	fmt.Println("     talon secrets set openai-api-key \"sk-your-key\"")
	fmt.Println("  2. Start the gateway:")
	fmt.Println("     talon serve --gateway")
	fmt.Println("  3. Point OpenClaw at Talon:")
	fmt.Println("     Base URL:  http://localhost:8080/v1/proxy/openai/v1  (trailing /v1 required for correct paths)")
	fmt.Println("     API key:   talon-gw-openclaw-001")
	fmt.Println("  4. Send a message through OpenClaw, then check the audit trail:")
	fmt.Println("     talon audit list")
	fmt.Println()
	fmt.Println("  The gateway starts in shadow mode (log only, no blocking).")
	fmt.Println("  Switch to enforce mode in talon.config.yaml when ready.")
}

func initializeProject() error {
	if _, err := os.Stat("agent.talon.yaml"); err == nil {
		return fmt.Errorf("agent.talon.yaml already exists")
	}

	if initPack != "" && initMinimal {
		return fmt.Errorf("cannot use both --pack and --minimal; choose one")
	}

	data := map[string]interface{}{
		"Name":  initName,
		"Owner": initOwner,
		"Date":  time.Now().Format(time.RFC3339),
	}

	agentTmpl := "templates/init/agent.talon.yaml.tmpl"
	switch {
	case initPack != "":
		ok := false
		for _, p := range supportedPacks {
			if p == initPack {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("unsupported --pack %q; use one of: %s", initPack, strings.Join(supportedPacks, ", "))
		}
		agentTmpl = "templates/init/pack_" + strings.ReplaceAll(initPack, "-", "_") + ".talon.yaml.tmpl"
	case initMinimal:
		agentTmpl = "templates/init/agent.talon.yaml.minimal.tmpl"
	}

	if err := renderTemplate(agentTmpl, "agent.talon.yaml", data); err != nil {
		return fmt.Errorf("creating agent.talon.yaml: %w", err)
	}

	configTmpl := "templates/init/talon.config.yaml.tmpl"
	if initPack != "" {
		packConfig := "templates/init/pack_" + strings.ReplaceAll(initPack, "-", "_") + ".config.yaml.tmpl"
		if _, err := initTemplates.ReadFile(packConfig); err == nil {
			configTmpl = packConfig
		}
	}

	if err := renderTemplate(configTmpl, "talon.config.yaml", data); err != nil {
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
