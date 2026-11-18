package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReleaseCapabilities_ConsoleApplicability pins the applicability
// contract of the console release gates (#533): a release before v1.17.0
// has no operations console, so an audit of it reports NOT APPLICABLE; from
// v1.17.0 on (candidates included) the gates are mandatory; a tag that is
// not a release tag is an error, never a skip.
func TestReleaseCapabilities_ConsoleApplicability(t *testing.T) {
	script := filepath.Join("..", "scripts", "release-capabilities.sh")
	for tag, want := range map[string]string{
		"v1.15.4":      "console=false",
		"v1.16.1":      "console=false",
		"v1.16.9-rc.3": "console=false",
		"v1.17.0-rc.1": "console=true",
		"v1.17.0":      "console=true",
		"v1.20.3":      "console=true",
		"v2.0.0":       "console=true",
	} {
		out, err := exec.Command("bash", script, tag).Output()
		if err != nil {
			t.Fatalf("%s: %v", tag, err)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%s: %s, want %s", tag, got, want)
		}
	}
	for _, tag := range []string{"latest", "1.17.0", "v1.17", "main", "v1.17.0 ", ""} {
		if out, err := exec.Command("bash", script, tag).Output(); err == nil {
			t.Errorf("%q must be refused, got %q", tag, out)
		}
	}
}

// TestReleaseWorkflows_ConsoleGatesFollowTheApplicabilityRule: every console
// acceptance step in the release and install-smoke workflows is conditioned
// on the version rule and on nothing else, and takes its fixtures from the
// release's own tag. A gate conditioned on a file's existence (hashFiles, a
// `[ -f` test) could silently skip on a console-enabled release.
func TestReleaseWorkflows_ConsoleGatesFollowTheApplicabilityRule(t *testing.T) {
	for _, rel := range []string{".github/workflows/release.yml", ".github/workflows/install-smoke.yml"} {
		raw, err := os.ReadFile(filepath.Join("..", rel))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		gates := 0
		for i, line := range lines {
			if !strings.Contains(line, "bash ") || !(strings.Contains(line, "console-compose-smoke.sh") || strings.Contains(line, "published-console-acceptance.sh")) {
				continue
			}
			gates++
			// Walk back to the step header and require the version condition.
			guarded := false
			for j := i; j >= 0 && !strings.HasPrefix(strings.TrimSpace(lines[j]), "- name:"); j-- {
				if strings.TrimSpace(lines[j]) == "if: steps.cap.outputs.console == 'true'" {
					guarded = true
				}
			}
			if !guarded {
				t.Errorf("%s:%d: console gate is not conditioned on steps.cap.outputs.console", rel, i+1)
			}
		}
		if gates != 2 {
			t.Errorf("%s: expected 2 console gates (Compose image, released binary), found %d", rel, gates)
		}
		text := string(raw)
		if strings.Count(text, "bash scripts/release-capabilities.sh") != 2 {
			t.Errorf("%s: each console job must compute applicability with scripts/release-capabilities.sh", rel)
		}
		if strings.Contains(text, "hashFiles('scripts/console") || strings.Contains(text, "[ -f scripts/") || strings.Contains(text, "continue-on-error: true") {
			t.Errorf("%s: a console gate must not be skipped because a file is missing or allowed to fail", rel)
		}
		if strings.Count(text, "ref: refs/tags/") < 2 {
			t.Errorf("%s: console fixtures must be checked out from the release's own tag", rel)
		}
	}
}
