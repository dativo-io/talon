package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/trigger"
)

// countingTriggerRunner is the preventive-control probe: the forbidden side
// effect of an unauthenticated webhook is a run, so the proof is this count.
type countingTriggerRunner struct {
	mu    sync.Mutex
	calls []string
}

func (c *countingTriggerRunner) RunFromTrigger(_ context.Context, agentName, prompt, invocationType string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, agentName+"|"+invocationType+"|"+prompt)
	return nil
}

func (c *countingTriggerRunner) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

type staticSecrets map[string]string

func (s staticSecrets) Get(_ context.Context, name, _, _ string) (*secrets.Secret, error) {
	v, ok := s[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return &secrets.Secret{Name: name, Value: []byte(v)}, nil
}

// TestWebhookRoute_RequiresWebhookSecret (#479) proves, through the REAL
// router, that POST /v1/triggers/{name} starts a run for exactly one
// credential — the webhook's own vault-bound secret — and for nothing else
// Talon knows: no credential, a wrong secret, the declaring agent's agent key,
// the admin key (as header or bearer), or dev mode with no keys configured
// anywhere. The runner count is the proof that nothing was dispatched.
func TestWebhookRoute_RequiresWebhookSecret(t *testing.T) {
	const webhookSecret = "whsec-0123456789abcdef"
	pol := minimalPolicy()
	engine, err := policy.NewEngine(context.Background(), pol)
	require.NoError(t, err)
	agentIDs := map[string]requestctx.AgentIdentity{"k_support": {AgentID: "support-triage", TenantID: "acme"}}

	newHandler := func(t *testing.T) (*trigger.WebhookHandler, *countingTriggerRunner) {
		t.Helper()
		runner := &countingTriggerRunner{}
		h := trigger.NewWebhookHandler(runner, staticSecrets{"support-incoming-webhook": webhookSecret})
		require.NoError(t, h.Register(context.Background(), &policy.Policy{
			Agent: policy.AgentConfig{Name: "support-triage", TenantID: "acme"},
			Triggers: &policy.TriggersConfig{Webhooks: []policy.WebhookTrigger{{
				Name: "support-incoming", Source: "zendesk", SecretName: "support-incoming-webhook",
				PromptTemplate: "Summarize: {{.payload.description}}",
			}}},
		}))
		return h, runner
	}

	post := func(r http.Handler, set func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/triggers/support-incoming", strings.NewReader(`{"description":"printer on fire"}`))
		req.Header.Set("Content-Type", "application/json")
		set(req)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	t.Run("admin and agent keys configured: only the webhook secret dispatches", func(t *testing.T) {
		h, runner := newHandler(t)
		srv := NewServer(nil, nil, h, engine, pol, "", nil, "admin-secret", nil, WithAgentIdentities(agentIDs))
		r := srv.Routes()

		denied := map[string]func(*http.Request){
			"no credential":                 func(*http.Request) {},
			"wrong secret":                  func(q *http.Request) { q.Header.Set("Authorization", "Bearer whsec-wrong") },
			"declaring agent's own key":     func(q *http.Request) { q.Header.Set("Authorization", "Bearer k_support") },
			"admin key header":              func(q *http.Request) { q.Header.Set("X-Talon-Admin-Key", "admin-secret") },
			"admin key as bearer":           func(q *http.Request) { q.Header.Set("Authorization", "Bearer admin-secret") },
			"secret in a non-bearer header": func(q *http.Request) { q.Header.Set("X-Talon-Webhook-Secret", webhookSecret) },
		}
		for name, set := range denied {
			rec := post(r, set)
			assert.Equalf(t, http.StatusUnauthorized, rec.Code, "%s must be denied: %s", name, rec.Body.String())
			assert.Contains(t, rec.Body.String(), `"error":"unauthorized"`)
		}
		assert.Equal(t, 0, runner.count(), "no denied request may start a run")

		rec := post(r, func(q *http.Request) { q.Header.Set("Authorization", "Bearer "+webhookSecret) })
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, 1, runner.count())
		assert.Equal(t, "support-triage|webhook:support-incoming|Summarize: printer on fire", runner.calls[0],
			"the run is attributed to the declaring agent with the webhook invocation type")
	})

	t.Run("no keys configured anywhere: webhooks never dev-open", func(t *testing.T) {
		h, runner := newHandler(t)
		srv := NewServer(nil, nil, h, engine, pol, "", nil, "", nil)
		r := srv.Routes()
		// The native run route is dev-open in this configuration (documented
		// in TestNativeExecutionRoutesRequireAdminWhenGatewayServed); the
		// webhook route is not: it faces the sender's network, not localhost.
		rec := post(r, func(*http.Request) {})
		assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		assert.Equal(t, 0, runner.count())
		rec = post(r, func(q *http.Request) { q.Header.Set("Authorization", "Bearer "+webhookSecret) })
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, 1, runner.count())
	})

	t.Run("unknown webhook name is 404 regardless of credential", func(t *testing.T) {
		h, runner := newHandler(t)
		srv := NewServer(nil, nil, h, engine, pol, "", nil, "admin-secret", nil, WithAgentIdentities(agentIDs))
		r := srv.Routes()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/triggers/nope", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+webhookSecret)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, 0, runner.count())
	})
}
