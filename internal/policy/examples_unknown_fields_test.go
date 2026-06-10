package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestShippedExamplesHaveNoUnknownFields walks the repo examples and pack
// overlays and asserts that every agent policy YAML contains only keys the
// loader actually parses, so users never see unknown-key warnings from files
// Talon itself ships. Proxy configs (agent.type: mcp_proxy) use a different
// struct and are skipped.
func TestShippedExamplesHaveNoUnknownFields(t *testing.T) {
	roots := []string{
		filepath.Join("..", "..", "examples"),
		filepath.Join("..", "pack", "templates"),
	}
	checked := 0
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			if !strings.HasSuffix(path, ".talon.yaml") && filepath.Base(path) != "agent.talon.yaml" {
				return nil
			}
			// Infra configs and proxy policies are different schemas.
			if strings.Contains(filepath.Base(path), "config") || strings.Contains(filepath.Base(path), "proxy") {
				return nil
			}
			content, readErr := os.ReadFile(path)
			require.NoError(t, readErr, path)
			if strings.Contains(string(content), "mcp_proxy") || strings.Contains(string(content), "\nproxy:") {
				return nil
			}
			checked++
			require.NoError(t, detectUnknownFields(content),
				"%s contains keys the policy loader does not parse", path)
			return nil
		})
		require.NoError(t, err)
	}
	require.Greater(t, checked, 0, "expected to find example policies to check")
}
