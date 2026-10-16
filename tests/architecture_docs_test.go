package tests

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The #424 architecture authority is one ADR plus one living reference. This
// guard keeps that pair real: both files exist, each links the other, both
// are indexed, and public docs do not reintroduce two statements the ADR
// rejects — a `consumed` approval status and an exactly-once execution claim.
// It is deliberately small; implementation contracts stay with their issues.

const (
	archADR       = "docs/contributor/adr/ADR-004-modular-control-plane-and-runtime-boundaries.md"
	archReference = "docs/reference/control-plane-boundaries.md"
)

func TestArchitectureADRAndReferenceAreCrossLinkedAndIndexed(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "."))
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(repoRoot, rel)) // #nosec G304 -- repo-local test read
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}
	adr := read(archADR)
	ref := read(archReference)

	if !strings.Contains(adr, "../../reference/control-plane-boundaries.md") {
		t.Errorf("%s must link the living reference", archADR)
	}
	if !strings.Contains(ref, "../contributor/adr/ADR-004-modular-control-plane-and-runtime-boundaries.md") {
		t.Errorf("%s must link ADR-004", archReference)
	}
	for _, want := range []string{"**Status:** Accepted", "## Decision", "## Alternatives rejected", "## Consequences", "## Non-goals", "## Current-versus-target status"} {
		if !strings.Contains(adr, want) {
			t.Errorf("%s lacks the required section %q", archADR, want)
		}
	}
	// The three diagrams #424 requires and the disposition table.
	for _, want := range []string{"## 2. Component ownership (diagram 1)", "## 8. Native sequence (diagram 2)", "## 9. External and MCP sequence (diagram 3)", "## 15. Current-surface disposition", "visible ≠ proposed ≠ attempted ≠ authorized ≠ dispatched ≠ succeeded"} {
		if !strings.Contains(ref, want) {
			t.Errorf("%s lacks %q", archReference, want)
		}
	}
	for rel, want := range map[string]string{
		"docs/README.md":     "reference/control-plane-boundaries.md",
		"docs/adr/README.md": "ADR-004-modular-control-plane-and-runtime-boundaries.md",
		"ROADMAP.md":         "docs/reference/control-plane-boundaries.md",
	} {
		if !strings.Contains(read(rel), want) {
			t.Errorf("%s must index %s", rel, want)
		}
	}
}

// TestNoRejectedArchitectureClaims scans public docs for two claims ADR-004
// rejects. A line is permitted when it negates the claim (the ADR and the
// reference state the rejection in words such as "no `consumed` state").
func TestNoRejectedArchitectureClaims(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "."))
	consumed := regexp.MustCompile(`(?i)approval[^.\n]{0,60}\bconsumed\b|\bconsumed\b[^.\n]{0,30}approval|consumed (approval )?stat(e|us)`)
	exactlyOnce := regexp.MustCompile(`(?i)exactly[- ]once (execution|delivery|dispatch|semantics|guarantee)|(execut|dispatch|deliver)[a-z]* exactly[- ]once`)
	negation := regexp.MustCompile(`(?i)\bno\b|\bnot\b|never|rejected|does not|do not|without|instead of|at most once`)

	var violations []string
	roots := []string{"README.md", "ROADMAP.md", "LIMITATIONS.md", "docs", "examples"}
	for _, root := range roots {
		_ = filepath.Walk(filepath.Join(repoRoot, root), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".md") {
				return nil
			}
			rel := filepath.ToSlash(strings.TrimPrefix(path, repoRoot+string(os.PathSeparator)))
			if strings.HasSuffix(rel, "CHANGELOG.md") || strings.Contains(rel, "docs/assets/") {
				return nil
			}
			f, err := os.Open(path) // #nosec G304 -- repo-local test walk
			if err != nil {
				return nil
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1024*1024), 1024*1024)
			n := 0
			for sc.Scan() {
				n++
				line := sc.Text()
				if negation.MatchString(line) {
					continue
				}
				if consumed.MatchString(line) || exactlyOnce.MatchString(line) {
					violations = append(violations, rel+":"+itoa(n)+": "+strings.TrimSpace(line))
				}
			}
			return nil
		})
	}
	if len(violations) > 0 {
		t.Errorf("public docs state a claim ADR-004 rejects (a `consumed` approval status or exactly-once execution); negate it or rewrite:\n%s", strings.Join(violations, "\n"))
	}
}
