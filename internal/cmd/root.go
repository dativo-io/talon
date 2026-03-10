package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/dativo-io/talon/internal/otel"
)

func init() {
	initBuildInfo()
}

// initBuildInfo fills Version, Commit, and BuildDate from Go's embedded VCS
// metadata when they were not set via ldflags (i.e. still at defaults).
// This covers `go install ...@tag` and plain `go build` from a git checkout.
func initBuildInfo() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	if Version == "dev" {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			Version = v
		}
	}

	settings := make(map[string]string, len(info.Settings))
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}

	if Commit == "none" {
		if rev, ok := settings["vcs.revision"]; ok && len(rev) >= 7 {
			short := rev[:7]
			if settings["vcs.modified"] == "true" {
				short += "-dirty"
			}
			Commit = short
		}
	}

	if BuildDate == "unknown" {
		if t, ok := settings["vcs.time"]; ok {
			BuildDate = t
		}
	}
}

// resolvedVersion returns the current Version string (already resolved by initBuildInfo).
func resolvedVersion() string {
	return Version
}

// tracer is the package-level tracer for all CLI commands
var tracer = otel.Tracer("github.com/dativo-io/talon/internal/cmd")

var (
	// otelShutdown holds the OTel shutdown function, called from Execute()
	otelShutdown func(context.Context) error

	// Version info injected via ldflags at build time
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"

	// Global flags
	cfgFile   string
	verbose   bool
	logLevel  string
	logFormat string
	otelFlag  bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "talon",
	Short: "Policy-as-code for AI agents",
	Long: `Talon is a compliance-first AI orchestration platform for European SMBs.

It enforces policies on AI agent execution with:
- Cost control and budgets
- PII detection and data classification
- Audit trail with HMAC-signed evidence
- Multi-tenant isolation
- MCP-native tool integration`,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize logging
		setupLogging()

		// Initialize OpenTelemetry when --otel, -v, or TALON_OTEL_ENABLED=true
		otelEnabled := otelFlag || verbose || os.Getenv("TALON_OTEL_ENABLED") == "true"
		shutdown, err := otel.Setup("dativo-talon", resolvedVersion(), otelEnabled)
		if err != nil {
			return fmt.Errorf("initializing OpenTelemetry: %w", err)
		}

		// Store shutdown for call on exit from Execute()
		otelShutdown = shutdown

		return nil
	},
}

func setupLogging() {
	// Parse log level
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// All structured logs go to stderr so stdout stays clean for piping (e.g. talon costs | jq).
	if logFormat == "json" {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	} else {
		log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
			With().
			Timestamp().
			Logger()
	}

	if verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "infrastructure config file (default: ./talon.config.yaml or ~/.talon/talon.config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "console", "log format (console, json)")
	rootCmd.PersistentFlags().BoolVar(&otelFlag, "otel", false, "enable OpenTelemetry (traces and metrics to stdout)")

	// Bind to viper
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("otel", rootCmd.PersistentFlags().Lookup("otel"))
	_ = viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("log_format", rootCmd.PersistentFlags().Lookup("log-format"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Search in ~/.talon/ and current directory
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home + "/.talon")
		}
		viper.AddConfigPath(".")
		viper.SetConfigName("talon.config")
		viper.SetConfigType("yaml")
	}

	// Environment variables with TALON_ prefix
	viper.SetEnvPrefix("TALON")
	viper.AutomaticEnv()

	// Read config (ignore errors - file may not exist yet)
	_ = viper.ReadInConfig()
}

// Execute runs the root command and flushes OTel on exit
func Execute() error {
	err := rootCmd.Execute()
	if otelShutdown != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = otelShutdown(ctx)
	}
	return err
}
