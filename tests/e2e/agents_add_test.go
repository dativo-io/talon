//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
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
