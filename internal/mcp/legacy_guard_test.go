package mcp

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoLegacyMCPLifecycleVocabulary guards the clean cutover: current docs,
// examples, tests and scripts must not teach or depend on the removed
// handshake/session lifecycle. CHANGELOG.md is history and is exempt.
func TestNoLegacyMCPLifecycleVocabulary(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`notifications/initialized`),
		regexp.MustCompile(`"method"\s*:\s*"initialize"`),
		regexp.MustCompile(`(?i)mcp-session-id`),
		regexp.MustCompile(`\b2025-06-18\b`),
		regexp.MustCompile(`\b2025-03-26\b`),
		regexp.MustCompile(`\b2025-11-25\b`),
	}
	allowed := map[string]bool{
		"CHANGELOG.md": true,
	}
	var hits []string
	for _, dir := range []string{"docs", "examples", "tests", "scripts", "internal/mcp", "README.md", "LIMITATIONS.md", "ROADMAP.md"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			// Go tests legitimately carry legacy fixtures to prove they are
			// rejected; everything that teaches or ships the protocol may not.
			if allowed[rel] || strings.HasSuffix(rel, "_test.go") || strings.HasSuffix(rel, ".log") {
				return nil
			}
			switch filepath.Ext(path) {
			case ".md", ".go", ".sh", ".yaml", ".yml", ".json", ".py", ".ts", ".js":
			default:
				return nil
			}
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for i, line := range strings.Split(string(raw), "\n") {
				if negates(line) {
					continue // "X is ignored / not supported / rejected": documents the cut, does not depend on it
				}
				for _, p := range patterns {
					if p.MatchString(line) {
						hits = append(hits, rel+":"+itoa(i+1)+": "+strings.TrimSpace(line))
					}
				}
			}
			return nil
		})
	}
	if len(hits) > 0 {
		t.Fatalf("legacy MCP lifecycle vocabulary must not return to current code/docs/tests:\n  %s", strings.Join(hits, "\n  "))
	}
}

func negates(line string) bool {
	l := strings.ToLower(line)
	for _, w := range []string{"ignored", "not supported", "never", "no longer", "removed", "rejected", "unsupported", "not part of"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
