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
// not a release tag is an error, never a skip. The published-image
// quickstart (#463) and the pilot acceptance (#561) follow the same rule.
func TestReleaseCapabilities_ConsoleApplicability(t *testing.T) {
	script := filepath.Join("..", "scripts", "release-capabilities.sh")
	for tag, want := range map[string]string{
		"v1.15.4":      "console=false\nquickstart=false\ntoolchain=false\npilot=false",
		"v1.16.1":      "console=false\nquickstart=false\ntoolchain=false\npilot=false",
		"v1.16.9-rc.3": "console=false\nquickstart=false\ntoolchain=false\npilot=false",
		"v1.17.0-rc.1": "console=true\nquickstart=true\ntoolchain=true\npilot=true",
		"v1.17.0":      "console=true\nquickstart=true\ntoolchain=true\npilot=true",
		"v1.20.3":      "console=true\nquickstart=true\ntoolchain=true\npilot=true",
		"v2.0.0":       "console=true\nquickstart=true\ntoolchain=true\npilot=true",
	} {
		out, err := exec.CommandContext(t.Context(), "bash", script, tag).Output()
		if err != nil {
			t.Fatalf("%s: %v", tag, err)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%s: %s, want %s", tag, got, want)
		}
	}
	for _, tag := range []string{"latest", "1.17.0", "v1.17", "main", "v1.17.0 ", ""} {
		if out, err := exec.CommandContext(t.Context(), "bash", script, tag).Output(); err == nil {
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
		text := string(raw)
		lines := strings.Split(text, "\n")
		gates := 0
		for i, line := range lines {
			if !isConsoleGate(line) {
				continue
			}
			gates++
			if !stepIsVersionGuarded(lines, i) {
				t.Errorf("%s:%d: console gate is not conditioned on steps.cap.outputs.console", rel, i+1)
			}
		}
		if gates != 2 {
			t.Errorf("%s: expected 2 console gates (Compose image, released binary), found %d", rel, gates)
		}
		if strings.Count(text, "bash scripts/release-capabilities.sh") < 2 {
			t.Errorf("%s: each console job must compute applicability with scripts/release-capabilities.sh", rel)
		}
		// The published-image quickstart (#463) follows the same rule.
		if !strings.Contains(text, "if: steps.cap.outputs.quickstart == 'true'") {
			t.Errorf("%s: the quickstart gate must be conditioned on steps.cap.outputs.quickstart", rel)
		}
		for _, skip := range []string{"hashFiles('scripts/console", "[ -f scripts/", "continue-on-error: true"} {
			if strings.Contains(text, skip) {
				t.Errorf("%s: a console gate must not be skipped because a file is missing or allowed to fail (%q)", rel, skip)
			}
		}
		if strings.Count(text, "ref: refs/tags/") < 2 {
			t.Errorf("%s: console fixtures must be checked out from the release's own tag", rel)
		}
	}
}

// isConsoleGate reports whether a workflow line runs a console acceptance script.
func isConsoleGate(line string) bool {
	if !strings.Contains(line, "bash ") {
		return false
	}
	return strings.Contains(line, "console-compose-smoke.sh") || strings.Contains(line, "published-console-acceptance.sh")
}

// stepIsVersionGuarded walks back from line i to its step header and
// requires the version condition on the way.
func stepIsVersionGuarded(lines []string, i int) bool {
	for j := i; j >= 0; j-- {
		l := strings.TrimSpace(lines[j])
		if l == "if: steps.cap.outputs.console == 'true'" {
			return true
		}
		if strings.HasPrefix(l, "- name:") {
			return false
		}
	}
	return false
}

// The released executable is also the system under test of the
// conditional-action acceptance (#205, #564): the release gate runs it, and
// the script refuses a run in which the test did not execute or did not use
// the binary it was given.
func TestReleaseAcceptance_RunsConditionalActionsOnTheReleasedBinary(t *testing.T) {
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join("..", rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	gate := read("scripts/published-console-acceptance.sh")
	if !strings.Contains(gate, `export TALON_BINARY="$BIN" TALON_E2E_BINARY="$BIN"`) || !strings.Contains(gate, "\nbash scripts/action-evidence-live.sh\n") {
		t.Error("published-console-acceptance.sh must run scripts/action-evidence-live.sh with TALON_E2E_BINARY set to the released binary")
	}
	live := read("scripts/action-evidence-live.sh")
	for _, want := range []string{
		"-run '^TestE2E_ActionGateway_ArgumentRules$'",
		"'^--- PASS: TestE2E_ActionGateway_ArgumentRules '",
		"'^--- SKIP'",
		`"e2e: binary under test is $TALON_E2E_BINARY "`,
	} {
		if !strings.Contains(live, want) {
			t.Errorf("action-evidence-live.sh must require actual execution on the given binary; missing %q", want)
		}
	}
}

// The pilot acceptance (#561) follows the applicability rule of the console
// gates: from v1.17.0 on it is mandatory, it runs on the release's own tree
// (pilot-acceptance.sh refuses a binary from another commit), and it is
// never skipped because a file is missing.
func TestReleaseWorkflows_PilotGateFollowsTheApplicabilityRule(t *testing.T) {
	for _, rel := range []string{".github/workflows/release.yml", ".github/workflows/install-smoke.yml"} {
		raw, err := os.ReadFile(filepath.Join("..", rel))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		gates := 0
		for i, line := range lines {
			if !strings.Contains(line, "bash scripts/pilot-acceptance.sh") {
				continue
			}
			gates++
			guarded := false
			for j := i; j >= 0; j-- {
				l := strings.TrimSpace(lines[j])
				if l == "if: steps.cap.outputs.pilot == 'true'" {
					guarded = true
					break
				}
				if strings.HasPrefix(l, "- name:") {
					break
				}
			}
			if !guarded {
				t.Errorf("%s:%d: the pilot gate is not conditioned on steps.cap.outputs.pilot", rel, i+1)
			}
		}
		if gates != 1 {
			t.Errorf("%s: expected 1 pilot gate, found %d", rel, gates)
		}
		if !strings.Contains(string(raw), "grep -q '^pilot=true$'") {
			t.Errorf("%s: the pilot job must compute applicability with scripts/release-capabilities.sh", rel)
		}
	}
}
