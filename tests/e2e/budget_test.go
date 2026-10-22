//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// TestE2E_Budget_PreventiveAtTheGateway is the black-box proof of the
// agent daily cap on the built binary: a request that would exceed the cap
// is denied 403 budget_exceeded with the provider never reached, a model the
// pricing table does not know is denied 403 pricing_unavailable under the
// same cap, and both denials are signed evidence that verifies. The provider
// is a fixture that counts every dispatch — the denial is proven by that
// counter, not by the status code.
func TestE2E_Budget_PreventiveAtTheGateway(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// 2000 in + 1000 out on gpt-4o-mini = 0.0009 USD: one answer spends
		// past the 0.0005 cap below, so the SECOND request is denied.
		_, _ = w.Write([]byte(`{"id":"cmpl-1","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":2000,"completion_tokens":1000}}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	const agentName = "budget-e2e"
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", agentName); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	agentPath := filepath.Join(dir, "agent.talon.yaml")
	agentYAML, err := os.ReadFile(agentPath)
	if err != nil {
		t.Fatal(err)
	}
	dailyRe := regexp.MustCompile(`(?m)^(\s*daily:\s*)[0-9.]+`)
	if !dailyRe.Match(agentYAML) {
		t.Fatalf("scaffold changed; expected a cost_limits.daily line:\n%s", agentYAML)
	}
	// The pre-request estimate (500 in + 500 out on gpt-4o-mini) is 0.000375:
	// the first request fits, the first answer (0.0009) exhausts the cap.
	agentYAML = dailyRe.ReplaceAll(agentYAML, []byte("${1}0.0005"))
	if err := os.WriteFile(agentPath, agentYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	cfg, _ := os.ReadFile(cfgPath)
	cfg = append(cfg, []byte(fmt.Sprintf(`
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: %q
  organization_policy:
    defaults:
      pii_action: "warn"
      daily_cost: 100.00
`, upstream.URL))...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", "openai-api-key", "sk-fixture-never-checked"); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}
	const agentKey = "talon-gw-budget-e2e-0001"
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", agentName+"-talon-key", agentKey); code != 0 {
		t.Fatalf("secrets set: %d\n%s", code, stderr)
	}

	port := freePort(t)
	stop := startServe(t, dir, port)
	defer stop()
	url := fmt.Sprintf("http://127.0.0.1:%d/v1/proxy/openai/v1/chat/completions", port)
	post := func(model string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(`{"model":"`+model+`","messages":[{"role":"user","content":"hello"}]}`))
		req.Header.Set("Authorization", "Bearer "+agentKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", url, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// 1. Under the cap: dispatched once, settled from the answer's usage.
	if status, body := post("gpt-4o-mini"); status != http.StatusOK {
		t.Fatalf("first request: want 200, got %d: %s", status, body)
	}
	if calls.Load() != 1 {
		t.Fatalf("first request must reach the provider once, got %d", calls.Load())
	}
	// 2. The settled spend exhausted the cap: denied before dispatch.
	status, body := post("gpt-4o-mini")
	if status != http.StatusForbidden || !strings.Contains(body, `"type":"budget_exceeded"`) {
		t.Fatalf("second request: want 403 budget_exceeded, got %d: %s", status, body)
	}
	// 3. A model the pricing table does not know cannot be priced under the
	//    cap: denied with its own code, naming the remediation.
	status, body = post("gpt-unpriced-e2e")
	if status != http.StatusForbidden || !strings.Contains(body, `"type":"pricing_unavailable"`) || !strings.Contains(body, "pricing/models.yaml") {
		t.Fatalf("unpriced model: want 403 pricing_unavailable naming pricing/models.yaml, got %d: %s", status, body)
	}
	if calls.Load() != 1 {
		t.Fatalf("denied requests must never reach the provider; dispatches=%d", calls.Load())
	}

	// 4. Both denials are signed records that verify, with distinct reasons.
	stop()
	out, stderr, code := RunTalon(t, dir, nil, "audit", "list", "--limit", "10")
	if code != 0 {
		t.Fatalf("audit list: %d\n%s", code, stderr)
	}
	ids := regexp.MustCompile(`gw_[A-Za-z0-9_-]+`).FindAllString(out, -1)
	if len(ids) < 3 {
		t.Fatalf("expected three gateway records, got %v in:\n%s", ids, out)
	}
	var shown strings.Builder
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		s, stderr, code := RunTalon(t, dir, nil, "audit", "show", id)
		if code != 0 {
			t.Fatalf("audit show %s: %d\n%s", id, code, stderr)
		}
		shown.WriteString(s)
		if v, _, vcode := RunTalon(t, dir, nil, "audit", "verify", id); vcode != 0 || !strings.Contains(v, "VALID") {
			t.Fatalf("audit verify %s: %d\n%s", id, vcode, v)
		}
	}
	for _, want := range []string{"budget_exceeded", "pricing unavailable"} {
		if !strings.Contains(shown.String(), want) {
			t.Fatalf("signed records must carry %q; audit show output:\n%s", want, shown.String())
		}
	}
}
