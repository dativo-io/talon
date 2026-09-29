package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const postureBaseGateway = `
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: "openai-api-key"
`

func loadPostureConfig(t *testing.T, yamlDoc string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "talon.config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlDoc), 0o600))
	_, err := LoadGatewayConfig(path)
	return err
}

// TestLoadGatewayConfig_RejectsLegacyMode pins the #442 migration contract:
// the removed gateway.mode key fails with a tailored message for EVERY value
// (including the now-redundant "enforce"), and no alias form smuggles it in.
func TestLoadGatewayConfig_RejectsLegacyMode(t *testing.T) {
	cases := map[string]string{
		"shadow":          postureBaseGateway + "  mode: shadow\n",
		"log_only":        postureBaseGateway + "  mode: log_only\n",
		"enforce":         postureBaseGateway + "  mode: \"enforce\"\n",
		"yaml alias":      "posture: &m shadow\n" + postureBaseGateway + "  mode: *m\n",
		"empty value":     postureBaseGateway + "  mode: \"\"\n",
		"root-level mode": "mode: shadow\n" + postureBaseGateway,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			err := loadPostureConfig(t, doc)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "mode")
			if name != "root-level mode" {
				assert.Contains(t, err.Error(), "gateway.mode")
				assert.Contains(t, err.Error(), "#442")
				assert.Contains(t, err.Error(), "talon doctor")
			}
		})
	}
}

func TestLoadGatewayConfig_UnknownNestedPostureKeysRejected(t *testing.T) {
	for name, doc := range map[string]string{
		"enforcement_mode": postureBaseGateway + "  enforcement_mode: shadow\n",
		"enforce bool":     postureBaseGateway + "  enforce: false\n",
		"nested block":     postureBaseGateway + "  enforcement:\n    mode: shadow\n",
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, loadPostureConfig(t, doc), "no alternative spelling may select a posture")
		})
	}
}

func TestLoadGatewayConfig_NoModeKeyIsEnforced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "talon.config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(postureBaseGateway), 0o600))
	cfg, err := LoadGatewayConfig(path)
	require.NoError(t, err)
	assert.True(t, cfg.Enabled)
}

// TestQuickstartConfig_RejectsRemovedModeEnv pins the #442 adversarial
// contract for the environment surface: the removed TALON_QUICKSTART_MODE
// selector fails closed for EVERY non-empty value (a stale "shadow" must not
// silently become an enforcing gateway, and "enforce" is not a valid knob
// either) with the shared migration guidance.
func TestQuickstartConfig_RejectsRemovedModeEnv(t *testing.T) {
	for _, v := range []string{"shadow", "enforce", "log_only", "bogus", " shadow "} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("TALON_QUICKSTART_MODE", v)
			cfg, err := QuickstartConfig(QuickstartOptions{})
			require.Error(t, err)
			assert.Nil(t, cfg)
			assert.Contains(t, err.Error(), "TALON_QUICKSTART_MODE")
			assert.Contains(t, err.Error(), "#442")
			assert.Contains(t, err.Error(), "talon doctor")
		})
	}
	t.Run("unset builds an enforcing quickstart", func(t *testing.T) {
		t.Setenv("TALON_QUICKSTART_MODE", "")
		cfg, err := QuickstartConfig(QuickstartOptions{})
		require.NoError(t, err)
		assert.True(t, cfg.Enabled)
	})
}
