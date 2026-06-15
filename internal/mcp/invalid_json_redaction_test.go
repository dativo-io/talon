package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/dativo-io/talon/internal/agent/tools"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jsonBreakingRedactionScanner redacts quoted email values including JSON
// delimiters, producing invalid JSON while VerifyEgress still passes.
func jsonBreakingRedactionScanner(t *testing.T) *classifier.Scanner {
	t.Helper()
	score := 0.95
	s, err := classifier.NewScanner(classifier.WithCustomRecognizers([]classifier.RecognizerConfig{
		{
			Name:            "Quoted Email",
			SupportedEntity: "EMAIL_ADDRESS",
			Patterns: []classifier.PatternConfig{
				{Name: "quoted-email", Regex: `"[^"]*@[^"]*"`, Score: &score},
			},
		},
	}))
	require.NoError(t, err)

	argStr := `{"email":"user@example.com"}`
	ctx := context.Background()
	redacted := s.Redact(ctx, argStr)
	require.NotEqual(t, argStr, redacted, "fixture must change payload on redaction")
	require.False(t, json.Valid([]byte(redacted)), "fixture must produce invalid JSON")
	require.NoError(t, s.VerifyEgress(ctx, redacted), "fixture must pass egress verification")

	return s
}

type capturingTool struct {
	name string
	mu   sync.Mutex
	args json.RawMessage
}

func (c *capturingTool) Name() string                 { return c.name }
func (c *capturingTool) Description() string          { return "captures executed arguments" }
func (c *capturingTool) InputSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (c *capturingTool) Execute(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
	c.mu.Lock()
	c.args = append(json.RawMessage(nil), args...)
	c.mu.Unlock()
	return json.RawMessage(`{"ok":true}`), nil
}

func (c *capturingTool) executedArgs() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.args)
}

func TestMCPProxy_InvalidJSONAfterRedaction_FailClosed(t *testing.T) {
	rawEmail := "user@example.com"
	var forwardedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]interface{}{"ok": true},
		})
	}))
	t.Cleanup(upstream.Close)

	h := proxyHandlerWithScanner(t, upstream.URL, jsonBreakingRedactionScanner(t))
	resp := callProxyTool(t, h, `{"email":"`+rawEmail+`"}`)
	require.NotNil(t, resp.Error, "invalid JSON after redaction must fail closed")
	assert.Contains(t, resp.Error.Message, "invalid JSON")
	assert.NotContains(t, string(forwardedBody), rawEmail, "raw PII must not be forwarded when redaction breaks JSON")
}

func TestMCPServer_InvalidJSONAfterRedaction_FailClosed(t *testing.T) {
	rawEmail := "user@example.com"
	scanner := jsonBreakingRedactionScanner(t)
	tool := &capturingTool{name: "capture"}

	store, err := evidence.NewStore(t.TempDir()+"/e.db", testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	pol := &policy.Policy{
		Agent:        policy.AgentConfig{Name: "test", Version: "1.0"},
		VersionTag:   "v1",
		Capabilities: &policy.CapabilitiesConfig{AllowedTools: []string{"capture"}},
	}
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	reg := tools.NewRegistry()
	reg.Register(tool)
	h := NewHandler(reg, engine, store, scanner)

	resp := serverToolsCall(t, h, "capture", `{"email":"`+rawEmail+`"}`)
	require.NotNil(t, resp.Error, "invalid JSON after redaction must fail closed")
	assert.Contains(t, resp.Error.Message, "invalid JSON")
	assert.NotContains(t, tool.executedArgs(), rawEmail, "tool must not execute with original PII when redaction breaks JSON")
}
