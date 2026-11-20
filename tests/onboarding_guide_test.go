package tests

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

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
	// The same marker the acceptance extracts by.
	re := regexp.MustCompile("(?s)<!-- onboarding-acceptance: ([a-z-]+) -->\n```[a-z]*\n(.*?)\n```")
	steps := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(guide, -1) {
		steps[m[1]] = m[2]
	}
	for _, name := range []string{"keys", "load", "config", "provider-key", "register", "start", "check"} {
		if strings.TrimSpace(steps[name]) == "" {
			t.Fatalf("the guide has no block marked <!-- onboarding-acceptance: %s -->: the acceptance would not execute that step", name)
		}
	}

	keys := steps["keys"]
	if !strings.HasPrefix(keys, "umask 077\n") {
		t.Errorf("the key file must be created under umask 077 (mode 0600), got:\n%s", keys)
	}
	for _, name := range []string{"TALON_SECRETS_KEY", "TALON_SIGNING_KEY", "TALON_ADMIN_KEY"} {
		if !strings.Contains(keys, name+"=$(openssl rand -hex 32)") {
			t.Errorf("the key step must generate %s into the file", name)
		}
	}

	start := steps["start"]
	if !strings.Contains(start, "--host 127.0.0.1") {
		t.Errorf("the documented start must bind this machine only (--host 127.0.0.1), got: %s", start)
	}
	if !strings.Contains(steps["check"], "X-Talon-Admin-Key") || !strings.Contains(steps["check"], "/v1/secrets") {
		t.Errorf("the documented check must call an administrative route without and with the admin key, got:\n%s", steps["check"])
	}

	// No command of the guide takes a key as an argument or exports one
	// inline: values come from the key file, from stdin or from a variable.
	fence := regexp.MustCompile("(?s)```(?:bash|sh)\n(.*?)\n```")
	inline := regexp.MustCompile(`(?:TALON_(?:ADMIN|SECRETS|SIGNING)_KEY|OPENAI_API_KEY)=["']?[A-Za-z0-9]`)
	argument := regexp.MustCompile(`talon secrets set \S+ +["']?[A-Za-z0-9]`)
	for _, m := range fence.FindAllStringSubmatch(guide, -1) {
		for _, line := range strings.Split(m[1], "\n") {
			if inline.MatchString(line) {
				t.Errorf("a command sets a key inline (it would be in the shell history): %s", line)
			}
			if argument.MatchString(line) && !strings.Contains(line, "--") {
				t.Errorf("a secret is passed as a command-line argument (visible in the process list): %s", line)
			}
			if strings.HasPrefix(strings.TrimSpace(line), "talon serve") && !strings.Contains(line, "--host 127.0.0.1") {
				t.Errorf("a documented server start does not bind the listener: %s", line)
			}
		}
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
