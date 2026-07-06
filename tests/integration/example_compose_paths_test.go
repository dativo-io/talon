//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Host paths that example compose files bind-mount but that are created at
// runtime rather than tracked in git. Keep this list short and justified:
// every entry is a fresh-clone landmine unless a script provably creates it.
var composePathAllowlist = map[string]string{
	"examples/shortlist-demo/out": "created by demo.sh; .gitkeep tracked inside",
}

// TestExampleComposeHostPathsAreTracked guards against the #236 failure mode:
// .gitignore swallowing files that example compose stacks bind-mount, so a
// fresh clone breaks while every local checkout works. For each tracked
// compose file, every relative host path in volumes: must be tracked in git —
// as a file, or as a directory containing at least one tracked file.
func TestExampleComposeHostPathsAreTracked(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)

	tracked := gitTrackedFiles(t, repoRoot)

	composeFiles := composeFilesIn(tracked)
	require.NotEmpty(t, composeFiles, "no tracked compose files found — glob out of date?")

	for _, composePath := range composeFiles {
		t.Run(composePath, func(t *testing.T) {
			for _, hostPath := range composeHostVolumePaths(t, repoRoot, composePath) {
				rel, err := filepath.Rel(repoRoot, hostPath)
				require.NoError(t, err)
				rel = filepath.ToSlash(rel)

				if reason, ok := composePathAllowlist[rel]; ok {
					t.Logf("allowlisted: %s (%s)", rel, reason)
					continue
				}
				require.True(t, isTracked(tracked, rel),
					"%s mounts %q, which is not tracked in git — a fresh clone cannot start this stack (see #236; check .gitignore)",
					composePath, rel)
			}
		})
	}
}

// gitTrackedFiles returns all git-tracked paths (slash-separated, repo-relative).
func gitTrackedFiles(t *testing.T, repoRoot string) map[string]bool {
	t.Helper()
	out, err := exec.Command("git", "-C", repoRoot, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("git ls-files unavailable (%v) — guard requires a git checkout", err)
	}
	tracked := make(map[string]bool)
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			tracked[p] = true
		}
	}
	return tracked
}

// composeFilesIn selects tracked compose files under examples/ and docs/.
func composeFilesIn(tracked map[string]bool) []string {
	var files []string
	for p := range tracked {
		if !strings.HasPrefix(p, "examples/") && !strings.HasPrefix(p, "docs/") {
			continue
		}
		base := filepath.Base(p)
		switch base {
		case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
			files = append(files, p)
		}
	}
	return files
}

// isTracked reports whether rel is a tracked file or a directory prefix of one.
func isTracked(tracked map[string]bool, rel string) bool {
	if tracked[rel] {
		return true
	}
	prefix := rel + "/"
	for p := range tracked {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// composeHostVolumePaths parses a compose file and returns the absolute host
// paths of every relative bind mount in services.*.volumes (short string form
// "./src:/dst[:mode]" and long form {type: bind, source: ./src, ...}).
// Named volumes and absolute host paths are ignored.
func composeHostVolumePaths(t *testing.T, repoRoot, composePath string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, composePath))
	require.NoError(t, err, "reading %s", composePath)

	var doc struct {
		Services map[string]struct {
			Volumes []yaml.Node `yaml:"volumes"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(data, &doc), "parsing %s", composePath)

	composeDir := filepath.Dir(filepath.Join(repoRoot, composePath))
	var paths []string
	for _, svc := range doc.Services {
		for _, vol := range svc.Volumes {
			src := volumeHostSource(t, composePath, vol)
			if !strings.HasPrefix(src, "./") && !strings.HasPrefix(src, "../") {
				continue // named volume or absolute path
			}
			paths = append(paths, filepath.Join(composeDir, filepath.FromSlash(src)))
		}
	}
	return paths
}

// volumeHostSource extracts the host-side source of one volumes: entry.
func volumeHostSource(t *testing.T, composePath string, vol yaml.Node) string {
	t.Helper()
	switch vol.Kind {
	case yaml.ScalarNode:
		var s string
		require.NoError(t, vol.Decode(&s), "decoding volume entry in %s", composePath)
		// Short syntax: source:target[:mode]. The source never contains a
		// colon in these repo-relative mounts.
		if i := strings.Index(s, ":"); i > 0 {
			return s[:i]
		}
		return s
	case yaml.MappingNode:
		var long struct {
			Type   string `yaml:"type"`
			Source string `yaml:"source"`
		}
		require.NoError(t, vol.Decode(&long), "decoding long-form volume in %s", composePath)
		if long.Type == "bind" || strings.HasPrefix(long.Source, ".") {
			return long.Source
		}
		return ""
	default:
		return ""
	}
}
