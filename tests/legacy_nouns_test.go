package tests

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoLegacyCallerNouns is the #266 grep guard: the caller identity model
// was deleted, and its vocabulary must not leak back into user-facing
// surfaces (docs, templates, examples, schemas). A line is permitted only
// when it references the breaking change explicitly ("#266") — e.g. a
// "renamed from default_policy (#266)" note — or lives in an allowlisted
// historical file (CHANGELOG, recorded demo casts, ADRs).
func TestNoLegacyCallerNouns(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "."))

	scanRoots := []string{
		"README.md",
		"ROADMAP.md",
		"LIMITATIONS.md",
		"docs",
		"examples",
		"schemas",
		filepath.Join("internal", "cmd", "templates"),
		filepath.Join("internal", "pack", "templates"),
		filepath.Join("tests", "smoke_lib.sh"),
		filepath.Join("tests", "smoke_test.sh"),
		filepath.Join("tests", "smoke_sections"),
	}

	// Legacy vocabulary that must not describe the current product.
	patterns := []string{
		"tenant_key",
		"gateway.callers",
		"require_caller_id",
		"per_caller_requests",
		"per-caller",
		"trusted_proxy_cidrs",
		"identify_by: source_ip",
		"CallerConfig",
		"CallerPolicyOverrides",
		"caller_max_",
		"caller_name",
		"caller_allowed_models",
		"caller_blocked_models",
		"tenant key",
	}

	allowlisted := func(path string) bool {
		rel := filepath.ToSlash(path)
		switch {
		case strings.HasSuffix(rel, "CHANGELOG.md"):
			return true // release history is historical by definition
		case strings.Contains(rel, "docs/adr/"):
			return true // ADRs are point-in-time records
		case strings.Contains(rel, "docs/assets/"):
			return true // recorded demo casts
		case strings.HasSuffix(rel, "tests/legacy_nouns_test.go"):
			return true
		}
		return false
	}

	scannableExt := func(path string) bool {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".md", ".yaml", ".yml", ".tmpl", ".sh", ".json", ".rego", ".py", ".ipynb", ".go":
			return true
		}
		return false
	}

	var violations []string
	for _, root := range scanRoots {
		abs := filepath.Join(repoRoot, root)
		info, err := os.Stat(abs)
		if err != nil {
			continue // optional surface (e.g. a smoke file moved)
		}
		walk := func(path string) {
			if allowlisted(path) || !scannableExt(path) {
				return
			}
			violations = append(violations, scanFileForLegacyNouns(t, repoRoot, path, patterns)...)
		}
		if info.IsDir() {
			_ = filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				walk(path)
				return nil
			})
		} else {
			walk(abs)
		}
	}

	if len(violations) > 0 {
		shown := len(violations)
		if shown > 40 {
			shown = 40
		}
		t.Errorf("legacy caller vocabulary leaked into %d user-facing line(s) (#266 cutover guard). Fix or annotate with an explicit #266 breaking-change note:\n%s",
			len(violations), strings.Join(violations[:shown], "\n"))
	}
}

// scanFileForLegacyNouns returns "path:line: text" for every line matching a
// legacy pattern, except lines carrying an explicit "#266" breaking-change note.
func scanFileForLegacyNouns(t *testing.T, repoRoot, path string, patterns []string) []string {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- repo-local test walk
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if strings.Contains(line, "#266") {
			continue // explicit breaking-change note
		}
		lower := strings.ToLower(line)
		for _, p := range patterns {
			if strings.Contains(lower, strings.ToLower(p)) {
				rel, _ := filepath.Rel(repoRoot, path)
				out = append(out, rel+":"+itoa(lineNo)+": "+strings.TrimSpace(line))
				break
			}
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
