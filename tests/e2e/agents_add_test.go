//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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

	out, stderr, code := RunTalon(t, dir, env, "agents", "add", "support-bot", "--tenant", "acme", "--owner", "support-ops", "--no-company-policy")
	if code != 0 {
		t.Fatalf("agents add support-bot: %d\n%s\n%s", code, out, stderr)
	}
	// Without a company policy and without the explicit flag, nothing is registered.
	if o2, stderr2, code2 := RunTalon(t, dir, env, "agents", "add", "ungoverned"); code2 == 0 || !strings.Contains(stderr2, "no company policy: no gateway config at") {
		t.Fatalf("a registration without any company policy must be refused: %d\n%s\n%s", code2, o2, stderr2)
	}
	if !strings.Contains(out, "activation: NOT ACTIVE — no Talon process of this installation is running") {
		t.Fatalf("a registration with nothing running must say so:\n%s", out)
	}
	firstKey := keyRe.FindString(out)
	if firstKey == "" || !strings.Contains(out, "Created agents_dir") {
		t.Fatalf("first registration output:\n%s", out)
	}
	if out, stderr, code = RunTalon(t, dir, env, "agents", "add", "support-bot", "--no-company-policy"); code == 0 || !strings.Contains(stderr, "already registered") {
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

	out, stderr, code = RunTalon(t, dir, env, "agents", "add", "refund-bot", "--tenant", "acme", "--no-company-policy")
	if code != 0 {
		t.Fatalf("agents add refund-bot: %d\n%s\n%s", code, out, stderr)
	}
	if !strings.Contains(out, "activation: NOT YET ACTIVE — a Talon process is running") {
		t.Fatalf("a registration while serving must not claim the use case is active:\n%s", out)
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

// The runtime side of a rolled-back registration with --use-existing-key
// (#567 review). A failed registration removes its agent file; a running
// server that loaded the use case while the file existed must drop it on its
// next reload, and the existing key, which the registration never owned,
// stays in the vault. The command's own rollback is proven in
// TestAgentsAdd_ExistingKeyFailureAfterTheFileIsWritten; here the file is
// removed exactly as that rollback removes it, against a real `talon serve`.
// Until the reload the key still authenticates: that window is the bounded
// limitation documented for --use-existing-key.
func TestE2E_AgentsAdd_RolledBackUseCaseIsDroppedOnReload(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	env := map[string]string{"TALON_AGENTS_DIR": agentsDir}
	if out, stderr, code := RunTalon(t, dir, env, "agents", "add", "support-bot", "--tenant", "acme", "--no-company-policy"); code != 0 {
		t.Fatalf("agents add support-bot: %d\n%s\n%s", code, out, stderr)
	}
	const existingKey = "talon_uc_existing_key_of_the_application_0001"
	if out, stderr, code := RunTalon(t, dir, env, "secrets", "set", "refund-bot-talon-key", existingKey, "--tenant", "acme", "--agent", "refund-bot"); code != 0 {
		t.Fatalf("secrets set: %d\n%s\n%s", code, out, stderr)
	}
	port := freePort(t)
	stop := startServeWithEnv(t, dir, port, map[string]string{
		"TALON_AGENTS_DIR": agentsDir, "TALON_ADMIN_KEY": "admin-e2e-agents-add-0002", "TALON_AGENTS_RELOAD_INTERVAL": "1s",
	})
	defer stop()
	status := func() int {
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/action-operations", port), strings.NewReader(`{"operation_id":"op-1","action":"x","arguments":{}}`))
		req.Header.Set("Authorization", "Bearer "+existingKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	waitFor := func(want int, what string) time.Duration {
		start := time.Now()
		for status() != want {
			if time.Since(start) > 20*time.Second {
				t.Fatalf("%s: still HTTP %d after 20s, want %d", what, status(), want)
			}
			time.Sleep(200 * time.Millisecond)
		}
		return time.Since(start)
	}
	if st := status(); st != http.StatusUnauthorized {
		t.Fatalf("a key in the vault without a registered use case must not authenticate: %d", st)
	}

	out, stderr, code := RunTalon(t, dir, env, "agents", "add", "refund-bot", "--tenant", "acme", "--use-existing-key", "--no-company-policy")
	if code != 0 || strings.Contains(out, existingKey) {
		t.Fatalf("agents add --use-existing-key (must succeed and print no key): %d\n%s\n%s", code, out, stderr)
	}
	waitFor(http.StatusNotFound, "the server loads the use case bound to the existing key") // authenticated, no catalog

	// The rollback's effect on disk: the agent file and its directory go.
	agentFile := filepath.Join(agentsDir, "refund-bot", "agent.talon.yaml")
	if err := os.Remove(agentFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(agentFile)); err != nil {
		t.Fatal(err)
	}
	window := waitFor(http.StatusUnauthorized, "the server drops the rolled-back use case on its next reload")
	t.Logf("the existing key kept authenticating for %s after the file was removed (reload interval 1s)", window.Round(100*time.Millisecond))

	// The existing key is still in the vault, and the other use case still validates.
	if out, stderr, code := RunTalon(t, dir, env, "secrets", "list"); code != 0 || !strings.Contains(out, "refund-bot-talon-key") {
		t.Fatalf("the existing key must stay in the vault: %d\n%s\n%s", code, out, stderr)
	}
	if out, stderr, code := RunTalon(t, dir, env, "validate"); code != 0 {
		t.Fatalf("talon validate after the rollback: %d\n%s\n%s", code, out, stderr)
	}
}

// Concurrent registrations of ONE name, as separate processes (#567 review):
// exactly one succeeds; the losers change nothing; the winner's printed key
// is the key in the vault, its file validates, and it authenticates.
func TestE2E_AgentsAdd_ConcurrentProcessesOneWinner(t *testing.T) {
	dir := t.TempDir()
	agentsDir := filepath.Join(dir, "agents")
	env := map[string]string{"TALON_AGENTS_DIR": agentsDir}
	keyRe := regexp.MustCompile(`talon_uc_[0-9a-f]{48}`)
	// The installation exists (a first use case), so the race is on the new name only.
	if out, stderr, code := RunTalon(t, dir, env, "agents", "add", "first", "--tenant", "acme", "--no-company-policy"); code != 0 {
		t.Fatalf("setup: %d\n%s\n%s", code, out, stderr)
	}

	const n = 8
	type result struct {
		out, stderr string
		code        int
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			o, e, c := RunTalon(t, dir, env, "agents", "add", "raced-bot", "--tenant", "acme", "--no-company-policy")
			results[i] = result{o, e, c}
		}(i)
	}
	close(start)
	wg.Wait()

	var winnerKey string
	wins := 0
	for _, r := range results {
		if r.code == 0 {
			wins++
			winnerKey = keyRe.FindString(r.out)
			continue
		}
		if !strings.Contains(r.stderr, "already") {
			t.Errorf("a losing registration must say why: %s", r.stderr)
		}
		if strings.Contains(r.stderr, "NOT fully undone") {
			t.Errorf("a losing registration left something behind: %s", r.stderr)
		}
	}
	if wins != 1 || winnerKey == "" {
		for _, r := range results {
			t.Logf("code=%d stderr=%s", r.code, r.stderr)
		}
		t.Fatalf("want exactly one successful registration, got %d", wins)
	}
	if out, stderr, code := RunTalon(t, dir, env, "validate"); code != 0 {
		t.Fatalf("the fleet after the race: %d\n%s\n%s", code, out, stderr)
	}

	// The winner's key is the one the server authenticates; no loser's key works.
	port := freePort(t)
	stop := startServeWithEnv(t, dir, port, map[string]string{"TALON_AGENTS_DIR": agentsDir, "TALON_ADMIN_KEY": "admin-e2e-agents-race-0001"})
	defer stop()
	status := func(key string) int {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/action-operations/none", port), nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if st := status(winnerKey); st == http.StatusUnauthorized {
		t.Fatalf("the winning registration's key does not authenticate (%d): it was overwritten or removed by a loser", st)
	}
	for _, r := range results {
		if k := keyRe.FindString(r.out); r.code != 0 && k != "" {
			t.Errorf("a losing registration printed a key")
		}
	}
}
