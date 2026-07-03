package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
)

// The documented --config default is "./talon.config.yaml or
// ~/.talon/talon.config.yaml": the project-local config must win over a
// machine-wide one, or per-project settings (sovereignty mode, cache,
// compliance declarations) are silently overridden by whatever happens to
// live in the operator's home directory.
func TestInitConfig_CurrentDirWinsOverHomeConfig(t *testing.T) {
	homeDir := t.TempDir()
	workDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(homeDir, ".talon"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(homeDir, ".talon", "talon.config.yaml"),
		[]byte("log_level: error\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "talon.config.yaml"),
		[]byte("log_level: debug\n"), 0o644))

	t.Setenv("HOME", homeDir)
	oldWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(workDir))
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	oldCfgFile := cfgFile
	cfgFile = ""
	t.Cleanup(func() {
		cfgFile = oldCfgFile
		// viper.Reset wipes the init()-time registrations of the config and
		// cmd packages; restore them for later tests in this binary (same
		// pattern as internal/config/config_test.go).
		viper.Reset()
		viper.SetEnvPrefix("TALON")
		viper.AutomaticEnv()
		viper.SetDefault(config.KeyDefaultPolicy, config.DefaultPolicy)
		viper.SetDefault(config.KeyMaxAttachmentMB, config.DefaultMaxAttachMB)
		viper.SetDefault(config.KeyOllamaBaseURL, config.DefaultOllamaURL)
		_ = viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
		_ = viper.BindPFlag("log_format", rootCmd.PersistentFlags().Lookup("log-format"))
	})

	initConfig()
	require.Equal(t, "debug", viper.GetString("log_level"),
		"project-local talon.config.yaml must take precedence over ~/.talon")
}
