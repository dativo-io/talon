//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Self-service registration (#472, #561) over the built binary: the first
// and second AI use case are registered with `talon agents add` into an
// agents_dir installation; the second is added WHILE `talon serve` runs and
// its new key authenticates after the safe reload, without a restart and
// without disturbing the first; nothing authenticates an unknown key.
func TestE2E_AgentsAdd_SecondUseCaseWhileServing(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	env := map[string]string{"TALON_AGENTS_DIR": agentsDir}
	keyRe := regexp.MustCompile(`talon_uc_[0-9a-f]{48}`)

	out, stderr, code := RunTalon(t, dir, env, "agents", "add", "support-bot", "--tenant", "acme", "--owner", "support-ops")
	if code != 0 {
		t.Fatalf("agents add support-bot: %d\n%s\n%s", code, out, stderr)
	}
	firstKey := keyRe.FindString(out)
	if firstKey == "" || !strings.Contains(out, "Created agents_dir") {
		t.Fatalf("first registration output:\n%s", out)
	}
	if out, stderr, code = RunTalon(t, dir, env, "agents", "add", "support-bot"); code == 0 || !strings.Contains(stderr, "already registered") {
		t.Fatalf("a duplicate must be refused: %d\n%s\n%s", code, out, stderr)
	}

	port := freePort(t)
	stop := startServeWithEnv(t, dir, port, map[string]string{
		"TALON_AGENTS_DIR": agentsDir, "TALON_ADMIN_KEY": "admin-e2e-agents-add-0001", "TALON_AGENTS_RELOAD_INTERVAL": "1s",
	})
	defer stop()
	status := func(key string) int {
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/action-operations", port), strings.NewReader(`{"operation_id":"op-1","action":"x","arguments":{}}`))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Authenticated use case without a catalog: 404 action_not_found. Unknown key: 401.
	if st := status(firstKey); st != http.StatusNotFound {
		t.Fatalf("first use case's key: %d, want 404 (authenticated, no catalog)", st)
	}
	if st := status("talon_uc_" + strings.Repeat("0", 48)); st != http.StatusUnauthorized {
		t.Fatalf("an unknown key: %d, want 401", st)
	}

	out, stderr, code = RunTalon(t, dir, env, "agents", "add", "refund-bot", "--tenant", "acme")
	if code != 0 {
		t.Fatalf("agents add refund-bot: %d\n%s\n%s", code, out, stderr)
	}
	secondKey := keyRe.FindString(out)
	if secondKey == "" || secondKey == firstKey {
		t.Fatalf("second key: %q", secondKey)
	}
	deadline := time.Now().Add(20 * time.Second)
	for status(secondKey) != http.StatusNotFound {
		if time.Now().After(deadline) {
			t.Fatalf("the second use case's key was not authenticated after the reload")
		}
		time.Sleep(250 * time.Millisecond)
	}
	if st := status(firstKey); st != http.StatusNotFound {
		t.Fatalf("the first use case after adding the second: %d", st)
	}
	if out, stderr, code = RunTalon(t, dir, env, "agents", "show", "refund-bot", "--effective"); code != 0 {
		t.Fatalf("the effective policy of the new use case: %d\n%s\n%s", code, out, stderr)
	}
	t.Logf("effective policy of refund-bot:\n%s", out)
	if out, stderr, code = RunTalon(t, dir, env, "validate"); code != 0 {
		t.Fatalf("talon validate after two registrations: %d\n%s\n%s", code, out, stderr)
	}
}
