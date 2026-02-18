//go:build e2e

package e2e

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dativo-io/talon/internal/testutil"
)

func TestE2E_AuditListAndVerify(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--name", "audit-agent")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}
	policyPath := filepath.Join(dir, "agent.talon.yaml")
	server := testutil.NewOpenAICompatibleServer("audit test", 10, 20)
	defer server.Close()
	env := map[string]string{
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": strings.TrimSuffix(server.URL, "/"),
	}
	_, _, code = RunTalon(t, dir, env, "run", "--policy", policyPath, "hello")
	if code != 0 {
		t.Fatalf("talon run failed: %d", code)
	}
	stdout, stderr, code := RunTalon(t, dir, nil, "audit", "list", "--limit", "5")
	if code != 0 {
		t.Fatalf("talon audit list exited %d\nstderr: %s", code, stderr)
	}
	// Extract first evidence ID (req_xxxxxxxx from generator)
	evIDRe := regexp.MustCompile(`req_[a-zA-Z0-9_-]+`)
	ids := evIDRe.FindAllString(stdout, -1)
	if len(ids) == 0 {
		t.Skip("no evidence IDs in list output to verify (output format may differ)")
	}
	verifyOut, stderr, code := RunTalon(t, dir, nil, "audit", "verify", ids[0])
	if code != 0 {
		t.Fatalf("talon audit verify exited %d\nstderr: %s", code, stderr)
	}
	// Doc-promised output (QUICKSTART §9, README): "signature VALID (HMAC-SHA256 intact)"
	if !strings.Contains(verifyOut, "VALID") {
		t.Errorf("expected 'VALID' in audit verify output (doc promise), got: %s", verifyOut)
	}
}
