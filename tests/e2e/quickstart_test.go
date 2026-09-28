//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	openai "github.com/sashabaranov/go-openai"
)

func TestE2E_Quickstart_OpenAISDKChatAndFallback(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", "quickstart-e2e")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}

	var upstreamAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/chat/completions"):
			_, _ = w.Write([]byte(`{"id":"chatcmpl_1","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"quickstart ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		case strings.HasPrefix(r.URL.Path, "/v1/responses"):
			_, _ = w.Write([]byte(`{"id":"resp_1","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	port := freePort(t)
	stdErr, stop := startQuickstartServe(t, dir, port, map[string]string{
		"TALON_QUICKSTART_OPENAI_BASE_URL": strings.TrimSuffix(upstream.URL, "/"),
		"OPENAI_API_KEY":                   "sk-env-fallback-e2e",
	})
	defer stop()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	cfg := openai.DefaultConfig("sk-client-e2e")
	cfg.BaseURL = baseURL + "/v1"
	client := openai.NewClientWithConfig(cfg)
	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: "hello"},
		},
	})
	if err != nil {
		t.Fatalf("CreateChatCompletion error: %v", err)
	}
	if got := resp.Choices[0].Message.Content; got != "quickstart ok" {
		t.Fatalf("unexpected chat response: %q", got)
	}
	if upstreamAuth != "Bearer sk-client-e2e" {
		t.Fatalf("expected upstream client bearer, got %q", upstreamAuth)
	}

	// No Authorization header: should fall back to OPENAI_API_KEY env.
	rawResp, err := http.Post(baseURL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatalf("raw fallback request error: %v", err)
	}
	defer rawResp.Body.Close()
	if rawResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rawResp.Body)
		t.Fatalf("expected 200 for env fallback, got %d body=%s", rawResp.StatusCode, string(body))
	}
	if upstreamAuth != "Bearer sk-env-fallback-e2e" {
		t.Fatalf("expected env fallback bearer upstream, got %q", upstreamAuth)
	}

	if !strings.Contains(stdErr.String(), "openai_base_url") {
		t.Fatalf("expected startup quickstart banner in stderr, got: %s", stdErr.String())
	}
}

func TestE2E_Quickstart_NoKeyReturns401_AndNonLoopbackDenied(t *testing.T) {
	dir := t.TempDir()
	_, _, code := RunTalon(t, dir, nil, "init", "--scaffold", "--name", "quickstart-e2e")
	if code != 0 {
		t.Fatalf("talon init failed: %d", code)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called when no key is provided")
	}))
	defer upstream.Close()

	port := freePort(t)
	stdErr, stop := startQuickstartServe(t, dir, port, map[string]string{
		"TALON_QUICKSTART_OPENAI_BASE_URL": strings.TrimSuffix(upstream.URL, "/"),
	})
	defer stop()
	_ = stdErr

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	noKeyResp, err := http.Post(baseURL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatalf("no-key request error: %v", err)
	}
	defer noKeyResp.Body.Close()
	if noKeyResp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(noKeyResp.Body)
		t.Fatalf("expected 401 with no key, got %d body=%s", noKeyResp.StatusCode, string(body))
	}

	port2 := freePort(t)
	exitCode, stderr := runCommand(t, dir, 5*time.Second, map[string]string{
		"TALON_QUICKSTART_OPENAI_BASE_URL": strings.TrimSuffix(upstream.URL, "/"),
	}, "serve", "--proxy-quickstart", "--host", "0.0.0.0", "--port", fmt.Sprintf("%d", port2))
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for non-loopback quickstart without --unsafe-listen")
	}
	if !strings.Contains(stderr, "--unsafe-listen") {
		t.Fatalf("expected unsafe-listen guidance in stderr, got: %s", stderr)
	}
}

func startQuickstartServe(t *testing.T, dir string, port int, env map[string]string) (*bytes.Buffer, func()) {
	t.Helper()
	args := []string{"serve", "--proxy-quickstart", "--port", fmt.Sprintf("%d", port)}
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"TALON_DATA_DIR="+dir,
		"TALON_SECRETS_KEY="+testSecretsKey,
		"TALON_SIGNING_KEY="+testSigningKey,
	)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start quickstart serve: %v", err)
	}
	waitForHealth(t, fmt.Sprintf("http://127.0.0.1:%d/health", port), 10*time.Second, &stderr)
	stop := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	return &stderr, stop
}

func waitForHealth(t *testing.T, url string, timeout time.Duration, stderr *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("serve not healthy within %s; stderr:\n%s", timeout, stderr.String())
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func runCommand(t *testing.T, dir string, timeout time.Duration, env map[string]string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"TALON_DATA_DIR="+dir,
		"TALON_SECRETS_KEY="+testSecretsKey,
		"TALON_SIGNING_KEY="+testSigningKey,
	)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	err := cmd.Run()
	if err == nil {
		return 0, stderr.String()
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), stderr.String()
	}
	return -1, stderr.String()
}

// TestE2E_Quickstart_LegacyModeEnvFailsStartup pins the #442 environment
// contract at the real binary boundary: the removed TALON_QUICKSTART_MODE
// selector must fail `talon serve --proxy-quickstart` before a listener
// exists, for a stale "shadow" as well as for "enforce" and unknown values,
// and the failure must carry the migration guidance. A ready governed
// runtime is never reachable through the legacy env.
func TestE2E_Quickstart_LegacyModeEnvFailsStartup(t *testing.T) {
	for _, legacy := range []string{"shadow", "enforce", "bogus"} {
		t.Run(legacy, func(t *testing.T) {
			dir := t.TempDir()
			port := freePort(t)
			code, out := runCommand(t, dir, 20*time.Second,
				map[string]string{"TALON_QUICKSTART_MODE": legacy},
				"serve", "--proxy-quickstart", "--port", fmt.Sprintf("%d", port))
			if code == 0 {
				t.Fatalf("serve must fail startup with TALON_QUICKSTART_MODE=%q; output:\n%s", legacy, out)
			}
			if code == -1 {
				t.Fatalf("serve did not exit on its own with TALON_QUICKSTART_MODE=%q (killed at timeout): a listener may have started; output:\n%s", legacy, out)
			}
			for _, want := range []string{"TALON_QUICKSTART_MODE", "#442", "talon doctor"} {
				if !strings.Contains(out, want) {
					t.Fatalf("startup failure must carry %q; output:\n%s", want, out)
				}
			}
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("port %d is listening: the legacy env must never reach a ready runtime", port)
			}
		})
	}
}
