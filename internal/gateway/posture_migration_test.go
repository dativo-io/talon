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

func TestQuickstartConfig_IgnoresRemovedShadowEnv(t *testing.T) {
	t.Setenv("TALON_QUICKSTART_MODE", "shadow")
	cfg, err := QuickstartConfig(QuickstartOptions{})
	require.NoError(t, err)
	assert.True(t, cfg.Enabled, "the removed env selector must have no effect")
}
