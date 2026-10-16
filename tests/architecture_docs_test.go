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
	// The three diagrams #424 requires, the disposition table, and the
	// terminal frames that make denied and unusable paths structurally
	// distinct from dispatch in both sequence diagrams.
	for _, want := range []string{
		"## 2. Component ownership (diagram 1)",
		"## 8. Native sequence (diagram 2)",
		"## 9. External and MCP sequence (diagram 3)",
		"## 15. Current-surface disposition",
		"visible ≠ proposed ≠ attempted ≠ authorized ≠ dispatched ≠ succeeded",
		"break DENY — terminal",
		"break rejected / expired / cancelled / invalidated — terminal",
		"break honest non-execution — terminal",
	} {
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

// Prohibited positive claims, matched narrowly. Each match is then checked
// for a negation inside its own clause, not anywhere on the line, so an
// unrelated negation earlier in the sentence cannot launder the claim.
var (
	rejectedClaimPatterns = []*regexp.Regexp{
		// a `consumed` approval status
		regexp.MustCompile("(?i)approval[^.;\\n]{0,40}\\bconsumed\\b|\\bconsumed\\b[^.;\\n]{0,30}approval|\\bconsumed\\b[` ]*(approval )?stat(e|us)"),
		// universal exactly-once execution
		regexp.MustCompile(`(?i)exactly[- ]once (execution|delivery|dispatch|semantics|guarantee)|(execut|dispatch|deliver|guarantee)[a-z]* exactly[- ]once`),
	}
	claimNegation    = regexp.MustCompile(`(?i)\bno\b|\bnot\b|\bnever\b|\bwithout\b|\brejected\b|\binstead of\b|\bneither\b|\bnor\b|\bat most once\b`)
	clauseSeparators = []string{",", ";", ":", " and ", " but ", " while ", " whereas "}
)

// rejectedClaim reports whether line asserts one of the prohibited claims
// without negating it in the same clause.
func rejectedClaim(line string) bool {
	for _, re := range rejectedClaimPatterns {
		for _, loc := range re.FindAllStringIndex(line, -1) {
			clause := line[:loc[0]]
			cut := -1
			for _, sep := range clauseSeparators {
				if i := strings.LastIndex(clause, sep); i > cut {
					cut = i + len(sep)
				}
			}
			if cut > 0 {
				clause = clause[cut:]
			}
			if len(clause) > 48 {
				clause = clause[len(clause)-48:]
			}
			if !claimNegation.MatchString(clause + line[loc[0]:loc[1]]) {
				return true
			}
		}
	}
	return false
}

func TestRejectedClaimDetector(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"There is no consumed approval state", false},
		{"There is no `consumed` state.", false},
		{"Talon does not guarantee exactly-once execution", false},
		{"Talon claims at most one effect per operation, not universal exactly-once execution.", false},
		{"Approval becomes consumed after approval", true},
		{"Talon guarantees exactly-once execution", true},
		{"There is no session state machine, and the approval becomes consumed after the decision.", true},
		{"No transport session is kept; dispatch is executed exactly once per operation.", true},
		{"every top-level field must be classified exactly once", false},
	}
	for _, tc := range cases {
		if got := rejectedClaim(tc.line); got != tc.want {
			t.Errorf("rejectedClaim(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestNoRejectedArchitectureClaims scans public docs for the prohibited
// claims. ADRs are point-in-time records that describe rejected alternatives
// by name and are allowlisted, like the other vocabulary guards do.
func TestNoRejectedArchitectureClaims(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "."))
	var violations []string
	roots := []string{"README.md", "ROADMAP.md", "LIMITATIONS.md", "docs", "examples"}
	for _, root := range roots {
		_ = filepath.Walk(filepath.Join(repoRoot, root), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".md") {
				return nil
			}
			rel := filepath.ToSlash(strings.TrimPrefix(path, repoRoot+string(os.PathSeparator)))
			if strings.HasSuffix(rel, "CHANGELOG.md") || strings.Contains(rel, "docs/assets/") ||
				strings.Contains(rel, "docs/adr/") || strings.Contains(rel, "docs/contributor/adr/") {
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
				if rejectedClaim(sc.Text()) {
					violations = append(violations, rel+":"+itoa(n)+": "+strings.TrimSpace(sc.Text()))
				}
			}
			return nil
		})
	}
	if len(violations) > 0 {
		t.Errorf("public docs state a claim ADR-004 rejects (a `consumed` approval status or exactly-once execution); negate it in the same clause or rewrite:\n%s", strings.Join(violations, "\n"))
	}
}
