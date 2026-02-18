//go:build e2e

package e2e

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dativo-io/talon/internal/testutil"
)

func TestE2E_CostsShowsSpend(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "cost-agent")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	server := testutil.NewOpenAICompatibleServer("cost test", 10, 20)
	defer server.Close()
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": strings.TrimSuffix(server.URL, "/"),
	}
	_, _, code = RunTalon(t, dir, env, "run", "--policy", policyPath, "hello")
	if code != 0 {
		t.Fatalf("talon run failed: %d", code)
	}
	stdout, stderr, code := RunTalon(t, dir, nil, "costs")
	if code != 0 {
		t.Fatalf("talon costs exited %d\nstderr: %s", code, stderr)
	}
	// Doc-promised: cost summary with Agent, Today, Month (README CLI reference)
	if !regexp.MustCompile(`Agent|Today|Month|Total`).MatchString(stdout) {
		t.Errorf("costs output should contain table headers, got: %s", stdout)
	}
	// Costs are shown in EUR (€)
	if !strings.Contains(stdout, "€") {
		t.Errorf("costs output should show euro amounts (doc promise), got: %s", stdout)
	}
}
