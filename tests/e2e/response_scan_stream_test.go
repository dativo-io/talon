//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Black-box adoption proof for #476 against the real `talon` binary and a
// deterministic in-test SSE provider: under `response_pii_action: warn` the
// client receives the first chunk while the provider is still generating,
// the delivered stream is the provider's stream (PII split across chunks
// included), and `talon audit list/show/verify` show a signed record that
// says the response was delivered and the PII observed after delivery. The
// same scenario under `redact` shows the preventive path: buffered until
// the verdict, PII never delivered. Designed to be consumable by the
// published-artifact onboarding CI (#473) once that harness exists.

// pacedSSEProvider emits its head event, blocks until released (or until a
// bounded fallback), then emits the tail. Seeing the head before release
// proves the gateway did not buffer the stream.
type pacedSSEProvider struct {
	head, tail string
	release    chan struct{}
	done       chan struct{}
	server     *httptest.Server
	relOnce    sync.Once
	mu         sync.Mutex
	headTS     time.Time
	tailTS     time.Time
}

// unblock releases the tail (idempotent). Preventive actions hold even the
// response headers until the verdict, so the harness releases on a timer as
// well as on first-event arrival.
func (p *pacedSSEProvider) unblock() { p.relOnce.Do(func() { close(p.release) }) }

func (p *pacedSSEProvider) headAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.headTS
}

func (p *pacedSSEProvider) tailAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tailTS
}

func newPacedSSEProvider(t *testing.T, head, tail string) *pacedSSEProvider {
	t.Helper()
	p := &pacedSSEProvider{head: head, tail: tail, release: make(chan struct{}), done: make(chan struct{})}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		defer close(p.done)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, p.head)
		flusher.Flush()
		p.mu.Lock()
		p.headTS = time.Now()
		p.mu.Unlock()
		select {
		case <-p.release:
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
			t.Log("provider release fallback fired: the gateway never released the stream")
		}
		_, _ = io.WriteString(w, p.tail)
		flusher.Flush()
		p.mu.Lock()
		p.tailTS = time.Now()
		p.mu.Unlock()
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *pacedSSEProvider) completed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func e2eChatDelta(content string) string {
	return `data: {"id":"chatcmpl-e2e","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"` + content + `"},"finish_reason":null}]}` + "\n\n"
}

const e2eChatTerminal = `data: {"id":"chatcmpl-e2e","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":9,"total_tokens":17}}` + "\n\n" + "data: [DONE]\n\n"

const e2eAgentKey = "talon-gw-e2e-stream-0001"

// prepareGatewayDir scaffolds an agent, appends a gateway block with the
// given response action, and binds the agent traffic key and a fake provider
// key in the vault — the documented `talon init` → `talon secrets set` →
// `talon serve --gateway` path.
func prepareGatewayDir(t *testing.T, responseAction, upstreamURL string) string {
	t.Helper()
	dir := t.TempDir()
	if _, stderr, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", "stream-e2e"); code != 0 {
		t.Fatalf("talon init failed: %d\n%s", code, stderr)
	}
	cfgPath := filepath.Join(dir, "talon.config.yaml")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read scaffolded config: %v", err)
	}
	if strings.Contains(string(cfg), "\ngateway:") {
		t.Fatalf("scaffold unexpectedly ships a gateway block; the test appends its own")
	}
	gatewayBlock := fmt.Sprintf(`
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
      response_pii_action: %q
      daily_cost: 100.00
`, upstreamURL, responseAction)
	if err := os.WriteFile(cfgPath, append(cfg, []byte(gatewayBlock)...), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", "openai-api-key", "sk-fake-e2e-provider-key"); code != 0 {
		t.Fatalf("secrets set provider key: %d\n%s", code, stderr)
	}
	if _, stderr, code := RunTalon(t, dir, nil, "secrets", "set", "stream-e2e-talon-key", e2eAgentKey); code != 0 {
		t.Fatalf("secrets set agent key: %d\n%s", code, stderr)
	}
	return dir
}

func startGatewayServe(t *testing.T, dir string, port int) func() {
	t.Helper()
	cmd := exec.Command(binaryPath, "serve", "--port", fmt.Sprintf("%d", port), "--gateway", "--gateway-config", filepath.Join(dir, "talon.config.yaml"))
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"TALON_DATA_DIR="+dir,
		"TALON_SECRETS_KEY="+testSecretsKey,
		"TALON_SIGNING_KEY="+testSigningKey,
	)
	logPath := filepath.Join(dir, "serve.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create serve log: %v", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	stop := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return stop
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	stop()
	logs, _ := os.ReadFile(logPath)
	t.Fatalf("gateway serve not healthy within 15s; log:\n%s", logs)
	return nil
}

// streamThroughGateway sends one streaming chat request and returns whether
// the first SSE event arrived before the provider finished, plus the full
// body and status. The wait is a failure bound, not pacing: on the passing
// path the read returns as soon as the gateway flushes the event.
func streamThroughGateway(t *testing.T, port int, provider *pacedSSEProvider, wait time.Duration) (bool, int, string) {
	t.Helper()
	body := `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"who is the contact?"}]}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/v1/proxy/openai/v1/chat/completions", port), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+e2eAgentKey)
	req.Header.Set("Content-Type", "application/json")
	timer := time.AfterFunc(wait, provider.unblock)
	defer timer.Stop()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	defer resp.Body.Close()

	// One reader goroutine: first event as soon as it arrives, full body at
	// the end (never two readers on one bufio.Reader).
	firstCh := make(chan string, 1)
	doneCh := make(chan string, 1)
	var firstAt, lastAt time.Time
	go func() {
		br := bufio.NewReader(resp.Body)
		var all, ev strings.Builder
		events := 0
		for {
			line, err := br.ReadString('\n')
			all.WriteString(line)
			ev.WriteString(line)
			if line == "\n" || (err != nil && ev.Len() > 0) {
				if events == 0 {
					firstAt = time.Now()
					firstCh <- ev.String()
				}
				events++
				lastAt = time.Now()
				ev.Reset()
			}
			if err != nil {
				if events == 0 {
					firstCh <- ""
				}
				doneCh <- all.String()
				return
			}
		}
	}()
	early := false
	select {
	case ev := <-firstCh:
		early = ev != "" && !provider.completed()
	case <-time.After(wait):
	}
	provider.unblock()
	var full string
	select {
	case full = <-doneCh:
	case <-time.After(30 * time.Second):
		t.Fatal("stream did not end")
	}
	t.Logf("timing: upstream_first=%s downstream_first=%s upstream_terminal=%s downstream_terminal=%s early=%v",
		provider.headAt().Format(time.RFC3339Nano), firstAt.Format(time.RFC3339Nano),
		provider.tailAt().Format(time.RFC3339Nano), lastAt.Format(time.RFC3339Nano), early)
	return early, resp.StatusCode, full
}

var gwEvidenceIDRe = regexp.MustCompile(`gw_[a-zA-Z0-9_-]+`)

func auditTrail(t *testing.T, dir string) (listOut, showOut, verifyOut string) {
	t.Helper()
	listOut, stderr, code := RunTalon(t, dir, nil, "audit", "list", "--limit", "5")
	if code != 0 {
		t.Fatalf("audit list exited %d\n%s", code, stderr)
	}
	ids := gwEvidenceIDRe.FindAllString(listOut, -1)
	if len(ids) == 0 {
		t.Fatalf("no gateway evidence id in audit list output:\n%s", listOut)
	}
	showOut, stderr, code = RunTalon(t, dir, nil, "audit", "show", ids[0])
	if code != 0 {
		t.Fatalf("audit show exited %d\n%s", code, stderr)
	}
	verifyOut, stderr, code = RunTalon(t, dir, nil, "audit", "verify", ids[0])
	if code != 0 {
		t.Fatalf("audit verify exited %d\n%s", code, stderr)
	}
	return listOut, showOut, verifyOut
}

func TestE2E_StreamingWarn_DeliversBeforeCompletionAndRecordsObservation(t *testing.T) {
	head := e2eChatDelta("Contact ")
	tail := e2eChatDelta("jan.kowalski") + e2eChatDelta("@gmail.com for details") + e2eChatTerminal
	provider := newPacedSSEProvider(t, head, tail)
	dir := prepareGatewayDir(t, "warn", provider.server.URL)
	port := freePort(t)
	stop := startGatewayServe(t, dir, port)
	defer stop()

	early, status, got := streamThroughGateway(t, port, provider, 5*time.Second)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", status, got)
	}
	if !early {
		t.Fatalf("first chunk did not reach the client before the provider completed: warn buffered the stream\nbody=%s", got)
	}
	if got != head+tail {
		t.Fatalf("warn must deliver the provider stream byte-identically\nwant=%q\n got=%q", head+tail, got)
	}

	_, showOut, verifyOut := auditTrail(t, dir)
	for _, want := range []string{
		"Allowed:       true",
		"Response Scan: action=warn | observed after delivery (not preventive) | complete",
		"Output PII:    email",
	} {
		if !strings.Contains(showOut, want) {
			t.Errorf("audit show missing %q:\n%s", want, showOut)
		}
	}
	if strings.Contains(showOut, "Request blocked") {
		t.Errorf("a delivered warn response must not be explained as blocked:\n%s", showOut)
	}
	if !strings.Contains(verifyOut, "signature VALID") {
		t.Errorf("audit verify must report a valid signature:\n%s", verifyOut)
	}
}

func TestE2E_StreamingRedact_RemainsPreventive(t *testing.T) {
	head := e2eChatDelta("Contact ")
	tail := e2eChatDelta("jan.kowalski") + e2eChatDelta("@gmail.com for details") + e2eChatTerminal
	provider := newPacedSSEProvider(t, head, tail)
	dir := prepareGatewayDir(t, "redact", provider.server.URL)
	port := freePort(t)
	stop := startGatewayServe(t, dir, port)
	defer stop()

	early, status, got := streamThroughGateway(t, port, provider, 500*time.Millisecond)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", status, got)
	}
	if early {
		t.Fatalf("redact is preventive and must hold the stream until the verdict; it released a chunk early")
	}
	if strings.Contains(got, "jan.kowalski@gmail.com") {
		t.Fatalf("redact must never deliver the raw PII:\n%s", got)
	}
	if !strings.Contains(got, "Contact") || !strings.Contains(got, "[DONE]") {
		t.Fatalf("redacted stream must still carry the non-PII content and terminate:\n%s", got)
	}

	_, showOut, verifyOut := auditTrail(t, dir)
	if !strings.Contains(showOut, "Response Scan: action=redact | preventive | complete") {
		t.Errorf("audit show must state the preventive path:\n%s", showOut)
	}
	if !strings.Contains(verifyOut, "signature VALID") {
		t.Errorf("audit verify must report a valid signature:\n%s", verifyOut)
	}
}

// allow keeps streaming directly through the served gateway (no response
// scan at all). This also pins the serve-side flush contract: every
// middleware between the listener and the gateway must propagate Flush.
func TestE2E_StreamingAllow_DeliversBeforeCompletion(t *testing.T) {
	head := e2eChatDelta("Contact ")
	tail := e2eChatDelta("jan.kowalski@gmail.com") + e2eChatTerminal
	provider := newPacedSSEProvider(t, head, tail)
	dir := prepareGatewayDir(t, "allow", provider.server.URL)
	port := freePort(t)
	stop := startGatewayServe(t, dir, port)
	defer stop()

	early, status, got := streamThroughGateway(t, port, provider, 5*time.Second)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", status, got)
	}
	if !early {
		t.Fatalf("allow must stream directly; first chunk arrived only after provider completion\nbody=%s", got)
	}
	if got != head+tail {
		t.Fatalf("allow must deliver the provider stream byte-identically\nwant=%q\n got=%q", head+tail, got)
	}
	_, showOut, _ := auditTrail(t, dir)
	if strings.Contains(showOut, "Response Scan:") {
		t.Errorf("allow performs no response scan:\n%s", showOut)
	}
}
