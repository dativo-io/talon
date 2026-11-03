//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingProvider is an OpenAI-compatible chat endpoint that counts how
// often the real talon binary reached it. The forbidden side effect of an
// unauthenticated webhook is a provider call, so the count is the proof.
type countingProvider struct {
	srv   *httptest.Server
	calls atomic.Int32
}

func startCountingProvider(t *testing.T) *countingProvider {
	t.Helper()
	p := &countingProvider{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "chatcmpl-webhook",
			"object": "chat.completion",
			"model":  "gpt-4",
			"choices": []map[string]any{{
				"index":         0,
				"finish_reason": "stop",
				"message":       map[string]any{"role": "assistant", "content": "Ticket summarized."},
			}},
			"usage": map[string]any{"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
		})
	}))
	t.Cleanup(p.srv.Close)
	return p
}

const (
	whAgent      = "support-triage"
	whName       = "support-incoming"
	whSecretName = "support-incoming-webhook"
	whSecret     = "whsec-e2e-4f3b2a1c9d8e7f60"
	whAdminKey   = "admin-e2e-webhook-key"
)

func writeWebhookAgent(t *testing.T, dir, keyBlock string) string {
	t.Helper()
	y := fmt.Sprintf(`agent:
  name: %q
  version: "1.0.0"
%striggers:
  webhooks:
    - name: %q
      source: zendesk
      secret_name: %q
      prompt_template: "Summarize this ticket and suggest a reply: {{.payload.description}}"
policies:
  cost_limits:
    per_request: 10.0
    daily: 100.0
    monthly: 1000.0
  model_routing:
    tier_0:
      primary: "gpt-4"
    tier_1:
      primary: "gpt-4"
    tier_2:
      primary: "gpt-4"
`, whAgent, keyBlock, whName, whSecretName)
	path := filepath.Join(dir, "agent.talon.yaml")
	if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// webhookPost sends payload to the webhook with the request decorated by set.
func webhookPost(t *testing.T, base string, payload []byte, set func(*http.Request)) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/v1/triggers/"+whName, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	set(req)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST webhook: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var ticketPayload = []byte(`{"description":"customer cannot log in since the password reset"}`)

func triggerHistoryCount(t *testing.T, base string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/v1/triggers/"+whName+"/history", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Talon-Admin-Key", whAdminKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("trigger history: %d %s", resp.StatusCode, b)
	}
	var out struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return len(out.Entries)
}

// assertNothingDispatched is the preventive-control proof at every boundary
// the real binary exposes: provider calls, signed evidence rows, trigger
// history.
func assertNothingDispatched(t *testing.T, what string, provider *countingProvider, dbPath, base string) {
	t.Helper()
	if n := provider.calls.Load(); n != 0 {
		t.Fatalf("%s: reached the provider %d time(s)", what, n)
	}
	if n := countRecords(t, dbPath); n != 0 {
		t.Fatalf("%s: left %d evidence record(s)", what, n)
	}
	if n := triggerHistoryCount(t, base); n != 0 {
		t.Fatalf("%s: appears in the trigger history (%d)", what, n)
	}
}

// TestE2E_WebhookTrigger_RequiresSecret (#479) runs the REAL binary in the
// supported configuration — native-only serve, admin key set, the webhook's
// secret minted in the vault with `talon secrets set` — and proves at the
// provider boundary that only the webhook secret starts a run: every other
// request is 401 with zero provider calls, zero evidence rows and an empty
// trigger history; the authorized request reaches the provider exactly once
// and leaves a signed record attributed to the declaring agent under the
// webhook invocation type.
func TestE2E_WebhookTrigger_RequiresSecret(t *testing.T) {
	provider := startCountingProvider(t)
	dir := t.TempDir()
	writeWebhookAgent(t, dir, "")

	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", whSecretName, whSecret); code != 0 {
		t.Fatalf("talon secrets set: %d\n%s", code, stderr)
	}
	// validate applies the same definition rules serve does.
	if _, stderr, code := RunTalon(t, dir, nil, "validate", "-f", "agent.talon.yaml"); code != 0 {
		t.Fatalf("talon validate rejected a secret-bound webhook: %d\n%s", code, stderr)
	}

	port := freePort(t)
	stop := startServeWithEnv(t, dir, port, map[string]string{
		"TALON_ADMIN_KEY": whAdminKey,
		"OPENAI_API_KEY":  "test-key",
		"OPENAI_BASE_URL": strings.TrimSuffix(provider.srv.URL, "/"),
	})
	defer stop()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	dbPath := filepath.Join(dir, "evidence.db")

	denied := map[string]func(*http.Request){
		"no credential":       func(*http.Request) {},
		"wrong secret":        func(r *http.Request) { r.Header.Set("Authorization", "Bearer whsec-wrong") },
		"admin key header":    func(r *http.Request) { r.Header.Set("X-Talon-Admin-Key", whAdminKey) },
		"admin key as bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+whAdminKey) },
	}
	for name, set := range denied {
		status, body := webhookPost(t, base, ticketPayload, set)
		if status != http.StatusUnauthorized {
			t.Fatalf("%s: want 401, got %d %s", name, status, body)
		}
		if !strings.Contains(body, `"error":"unauthorized"`) {
			t.Fatalf("%s: body lacks the unauthorized code: %s", name, body)
		}
	}
	assertNothingDispatched(t, "denied webhooks", provider, dbPath, base)

	// Oversized payload from an authorized sender: refused before parsing, no run.
	big := []byte(`{"description":"` + strings.Repeat("x", 600*1024) + `"}`)
	status, body := webhookPost(t, base, big, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+whSecret) })
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized payload: want 413, got %d %s", status, body)
	}
	assertNothingDispatched(t, "oversized payload", provider, dbPath, base)

	status, body = webhookPost(t, base, ticketPayload, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+whSecret) })
	if status != http.StatusOK {
		logs, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
		t.Fatalf("authorized webhook: want 200, got %d %s\nserve log:\n%s", status, body, logs)
	}
	if n := provider.calls.Load(); n != 1 {
		t.Fatalf("authorized webhook reached the provider %d time(s), want 1", n)
	}
	if n := countRecords(t, dbPath); n < 1 {
		t.Fatalf("authorized webhook left no evidence")
	}
	if n := triggerHistoryCount(t, base); n < 1 {
		t.Fatalf("authorized webhook is missing from the trigger history (invocation_type webhook:%s)", whName)
	}
}

// TestE2E_WebhookTrigger_FailsClosedAtStartup (#479): the real binary
// refuses to serve a webhook whose secret is not in the vault, and refuses
// every trigger when a gateway is served (trigger runs bypass
// gateway.organization_policy). `talon validate` says so first.
func TestE2E_WebhookTrigger_FailsClosedAtStartup(t *testing.T) {
	t.Run("secret_name missing from the file", func(t *testing.T) {
		dir := t.TempDir()
		path := writeWebhookAgent(t, dir, "")
		raw, _ := os.ReadFile(path)
		stripped := strings.Replace(string(raw), fmt.Sprintf("      secret_name: %q\n", whSecretName), "", 1)
		if err := os.WriteFile(path, []byte(stripped), 0o600); err != nil {
			t.Fatal(err)
		}
		_, stderr, code := RunTalon(t, dir, nil, "validate", "-f", "agent.talon.yaml")
		if code == 0 {
			t.Fatalf("validate accepted a webhook without secret_name")
		}
		if !strings.Contains(stderr, "secret_name") {
			t.Fatalf("validate did not name secret_name:\n%s", stderr)
		}
	})

	t.Run("secret not minted in the vault", func(t *testing.T) {
		dir := t.TempDir()
		writeWebhookAgent(t, dir, "")
		_, stderr, code := RunTalon(t, dir, map[string]string{"TALON_ADMIN_KEY": whAdminKey}, "serve", "--port", fmt.Sprintf("%d", freePort(t)))
		if code == 0 {
			t.Fatalf("serve started with an unminted webhook secret")
		}
		if !strings.Contains(stderr, whSecretName) || !strings.Contains(stderr, "talon secrets set") {
			t.Fatalf("serve did not point at the missing secret:\n%s", stderr)
		}
	})

	t.Run("gateway served", gatewayRefusesTriggers)
}

// gatewayRefusesTriggers: an enabled gateway config next to a keyed agent
// that declares a webhook. validate applies the gateway rule because it sees
// the enabled config; serve --gateway refuses to start.
func gatewayRefusesTriggers(t *testing.T) {
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", whAgent); code != 0 {
		t.Fatalf("talon init: %d\n%s", code, stderr)
	}
	writeWebhookAgent(t, dir, fmt.Sprintf("  key:\n    secret_name: %q\n", whAgent+"-talon-key"))
	for _, kv := range [][2]string{{whAgent + "-talon-key", "tk-" + whAgent}, {whSecretName, whSecret}, {"openai-api-key", "sk-test"}} {
		if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", kv[0], kv[1]); code != 0 {
			t.Fatalf("talon secrets set %s: %d\n%s", kv[0], code, stderr)
		}
	}
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	cfg, _ := os.ReadFile(cfgPath)
	cfg = append(cfg, []byte(`
gateway:
  enabled: true
  listen_prefix: "/v1/proxy"
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "https://api.openai.com"
  organization_policy:
    defaults:
      pii_action: "redact"
      daily_cost: 100.00
`)...)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := RunTalon(t, dir, nil, "validate", "-f", "agent.talon.yaml")
	if code == 0 {
		t.Fatalf("validate accepted triggers next to an enabled gateway config")
	}
	if !strings.Contains(stderr, "gateway.organization_policy") {
		t.Fatalf("validate did not explain the gateway rule:\n%s", stderr)
	}
	_, stderr, code = RunTalon(t, dir, map[string]string{"TALON_ADMIN_KEY": whAdminKey}, "serve", "--port", fmt.Sprintf("%d", freePort(t)), "--gateway", "--gateway-config", "talon.config.yaml")
	if code == 0 {
		t.Fatalf("serve --gateway started an agent that declares triggers")
	}
	if !strings.Contains(stderr, "declares triggers") || !strings.Contains(stderr, "gateway.organization_policy") {
		t.Fatalf("serve --gateway did not refuse the triggers with the documented cause:\n%s", stderr)
	}
}
