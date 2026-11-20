package tests

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// onboardingStepRe is the marker the onboarding acceptance extracts the
// guide's commands by (tests/e2e, documentedStepRe).
var onboardingStepRe = regexp.MustCompile("(?s)<!-- onboarding-acceptance: ([a-z-]+) -->\n```[a-z]*\n(.*?)\n```")

// onboardingSteps returns the guide's marked blocks and fails when one the
// acceptance executes is missing.
func onboardingSteps(t *testing.T, guide string) map[string]string {
	t.Helper()
	steps := map[string]string{}
	for _, m := range onboardingStepRe.FindAllStringSubmatch(guide, -1) {
		steps[m[1]] = m[2]
	}
	for _, name := range []string{"keys", "load", "config", "provider-key", "register", "start", "check"} {
		if strings.TrimSpace(steps[name]) == "" {
			t.Fatalf("the guide has no block marked <!-- onboarding-acceptance: %s -->: the acceptance would not execute that step", name)
		}
	}
	return steps
}

// The onboarding guide's commands are executed as written by the onboarding
// acceptance (tests/e2e, TestE2E_Onboarding_DocumentedSecureStartup), which
// needs real processes and runs in its own CI step. This guard runs with the
// unit tests and fails as soon as an edit of the guide drops what makes the
// documented startup secure (#472, #567 review): the admin key is
// provisioned into a file only the operator can read, no key is typed as a
// command-line argument, and the server is bound to this machine.
func TestOnboardingGuide_DocumentedStartupIsSecure(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "guides", "add-talon-to-existing-app.md"))
	if err != nil {
		t.Fatal(err)
	}
	guide := string(raw)
	steps := onboardingSteps(t, guide)

	keys := steps["keys"]
	if !strings.HasPrefix(keys, "umask 077\n") {
		t.Errorf("the key file must be created under umask 077 (mode 0600), got:\n%s", keys)
	}
	for _, name := range []string{"TALON_SECRETS_KEY", "TALON_SIGNING_KEY", "TALON_ADMIN_KEY"} {
		if !strings.Contains(keys, name+"=$(openssl rand -hex 32)") {
			t.Errorf("the key step must generate %s into the file", name)
		}
	}
	if start := steps["start"]; !strings.Contains(start, "--host 127.0.0.1") {
		t.Errorf("the documented start must bind this machine only (--host 127.0.0.1), got: %s", start)
	}
	if check := steps["check"]; !strings.Contains(check, "X-Talon-Admin-Key") || !strings.Contains(check, "/v1/secrets") {
		t.Errorf("the documented check must call an administrative route without and with the admin key, got:\n%s", check)
	}
	// The guide states the boundary it relies on.
	for _, must := range []string{
		"Without `TALON_ADMIN_KEY`, `talon serve` runs in development mode",
		"does not terminate TLS",
		"## Three credentials, three owners",
	} {
		if !strings.Contains(guide, must) {
			t.Errorf("the guide no longer states: %q", must)
		}
	}
}

// No command of the guide takes a key as an argument or sets one inline
// (values come from the key file, from stdin or from a variable), and every
// documented server start binds the listener.
func TestOnboardingGuide_NoCommandExposesAKeyOrAnOpenListener(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "guides", "add-talon-to-existing-app.md"))
	if err != nil {
		t.Fatal(err)
	}
	fence := regexp.MustCompile("(?s)```(?:bash|sh)\n(.*?)\n```")
	inline := regexp.MustCompile(`(?:TALON_(?:ADMIN|SECRETS|SIGNING)_KEY|OPENAI_API_KEY)=["']?[A-Za-z0-9]`)
	argument := regexp.MustCompile(`talon secrets set \S+ +["']?[A-Za-z0-9]`)
	lines := 0
	for _, m := range fence.FindAllStringSubmatch(string(raw), -1) {
		for _, line := range strings.Split(m[1], "\n") {
			lines++
			if inline.MatchString(line) {
				t.Errorf("a command sets a key inline (it would be in the shell history): %s", line)
			}
			if argument.MatchString(line) {
				t.Errorf("a secret is passed as a command-line argument (visible in the process list): %s", line)
			}
			if strings.HasPrefix(strings.TrimSpace(line), "talon serve") && !strings.Contains(line, "--host 127.0.0.1") {
				t.Errorf("a documented server start does not bind the listener: %s", line)
			}
		}
	}
	if lines == 0 {
		t.Fatal("the guide has no shell block: the check read nothing")
	}
}
