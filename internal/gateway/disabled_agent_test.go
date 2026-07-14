package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// disabledIdentity is testIdentity with the kill switch thrown (#268).
func disabledIdentity(name, tenant, key string) *ResolvedIdentity {
	id := testIdentity(name, tenant, key, nil)
	id.Enabled = false
	return id
}

func setupDisabledAgentGateway(t *testing.T, mode Mode) (*Gateway, *evidence.Store) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":4}}`))
	}))
	t.Cleanup(upstream.Close)
	dir := t.TempDir()

	cfg := &GatewayConfig{
		Enabled: true, ListenPrefix: "/v1/proxy", Mode: mode,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstream.URL, SecretName: "openai-api-key"},
		},
		OrganizationPolicy: OrganizationPolicy{Defaults: OrgDefaults{PIIAction: "warn", DailyCost: 100, MonthlyCost: 2000}},
		Timeouts:           TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.ApplyDefaults())

	registry := testRegistry(
		disabledIdentity("stopped-agent", "acme", "tk-stopped"),
		testIdentity("running-agent", "acme", "tk-running", nil),
	)
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "openai-api-key",
		[]byte("sk-upstream"), secrets.ACL{Tenants: []string{"acme"}, Agents: []string{"*"}}))

	gw, err := NewGateway(cfg, NewRegistryHolder(registry), classifier.MustNewScanner(), evStore, secStore, nil, nil)
	require.NoError(t, err)
	return gw, evStore
}

// TestGateway_DisabledAgentDenied (#268): enabled: false is a hard PLATFORM
// boundary — the resolved agent is denied with an attributed 403 and signed
// evidence in EVERY mode (an operator kill switch is never shadow-bypassed),
// while an enabled sibling keeps serving.
func TestGateway_DisabledAgentDenied(t *testing.T) {
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`

	for _, mode := range []Mode{ModeEnforce, ModeShadow, ModeLogOnly} {
		t.Run(string(mode), func(t *testing.T) {
			gw, evStore := setupDisabledAgentGateway(t, mode)

			w := makeGatewayRequestWithKey(gw, "/v1/proxy/openai/v1/chat/completions", body, "tk-stopped")
			require.Equal(t, http.StatusForbidden, w.Code, "disabled agent must be denied in mode %s", mode)

			// Machine-readable error code on the OpenAI wire.
			var openaiErr struct {
				Error struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &openaiErr))
			assert.Equal(t, "agent_disabled", openaiErr.Error.Type)
			assert.NotContains(t, openaiErr.Error.Message, t.TempDir()[:5], "no server paths in the client body")

			// The denial is ATTRIBUTED to the agent in signed evidence.
			records, err := evStore.List(context.Background(), "acme", "stopped-agent", time.Time{}, time.Time{}, 5)
			require.NoError(t, err)
			require.NotEmpty(t, records)
			assert.False(t, records[0].PolicyDecision.Allowed)
			assert.Contains(t, records[0].PolicyDecision.Reasons[0], "agent disabled")
			assert.True(t, evStore.VerifyRecord(&records[0]))

			// The enabled sibling is untouched.
			w = makeGatewayRequestWithKey(gw, "/v1/proxy/openai/v1/chat/completions", body, "tk-running")
			assert.Equal(t, http.StatusOK, w.Code, "the sibling agent keeps serving")
		})
	}
}

// TestGateway_DisabledAgentDenied_AnthropicWire (#268): the same machine code
// on the Anthropic wire format.
func TestGateway_DisabledAgentDenied_AnthropicWire(t *testing.T) {
	gw, _ := setupDisabledAgentGateway(t, ModeEnforce)
	w := makeGatewayRequestWithKey(gw, "/v1/proxy/openai/v1/messages",
		`{"model":"gpt-4o-mini","max_tokens":10,"messages":[{"role":"user","content":"Hello"}]}`, "tk-stopped")
	require.Equal(t, http.StatusForbidden, w.Code)
	var anthErr struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &anthErr))
	assert.Equal(t, "agent_disabled", anthErr.Error.Type)
}
