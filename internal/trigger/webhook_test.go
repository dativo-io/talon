package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

// mapSecrets is a SecretResolver over a map; it records the scope each
// lookup was made under so tests can assert the vault is read as the
// declaring agent.
type mapSecrets struct {
	values map[string]string
	scopes []string
}

func (m *mapSecrets) Get(_ context.Context, name, tenantID, agentID string) (*secrets.Secret, error) {
	m.scopes = append(m.scopes, tenantID+"/"+agentID+"/"+name)
	v, ok := m.values[name]
	if !ok {
		return nil, errors.New("secret not found: " + name)
	}
	return &secrets.Secret{Name: name, Value: []byte(v)}, nil
}

const testWebhookSecret = "whsec-5f1c0e3d-test-7a9b2c4d6e8f0a1b3c5d"

func testSecrets() *mapSecrets {
	return &mapSecrets{values: map[string]string{"deploy-webhook": testWebhookSecret, "ticket-webhook": "other-" + testWebhookSecret}}
}

func webhookRouter(handler *WebhookHandler) *chi.Mux {
	r := chi.NewRouter()
	r.Post("/v1/triggers/{name}", handler.HandleWebhook)
	return r
}

func webhookPolicy(agent string, hooks ...policy.WebhookTrigger) *policy.Policy {
	return &policy.Policy{
		Agent:    policy.AgentConfig{Name: agent},
		Triggers: &policy.TriggersConfig{Webhooks: hooks},
	}
}

// postWebhook sends body to /v1/triggers/<name>; bearer "" sends no
// Authorization header at all.
func postWebhook(router http.Handler, name, bearer string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/triggers/"+name, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestHandleWebhook_RendersTemplate(t *testing.T) {
	runner := &mockRunner{}
	handler := NewWebhookHandler(runner, testSecrets())
	require.NoError(t, handler.Register(context.Background(), webhookPolicy("deploy-bot",
		policy.WebhookTrigger{Name: "deploy", Source: "github", SecretName: "deploy-webhook", PromptTemplate: "Deploy event: {{.payload.action}}"})))
	router := webhookRouter(handler)

	body, _ := json.Marshal(map[string]string{"action": "completed"})
	w := postWebhook(router, "deploy", testWebhookSecret, body)

	assert.Equal(t, http.StatusOK, w.Code)
	require.Len(t, runner.calls, 1)
	assert.Contains(t, runner.calls[0], "Deploy event: completed")
	assert.Contains(t, runner.calls[0], "webhook:deploy")
}

func TestHandleWebhook_UnknownTrigger(t *testing.T) {
	runner := &mockRunner{}
	handler := NewWebhookHandler(runner, testSecrets())
	require.NoError(t, handler.Register(context.Background(), &policy.Policy{Agent: policy.AgentConfig{Name: "bot"}}))
	router := webhookRouter(handler)

	body, _ := json.Marshal(map[string]string{"action": "test"})
	w := postWebhook(router, "unknown", "", body)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestHandleWebhook_RequiresSecret (#479): the webhook's vault-bound secret
// is the ONLY credential. Anything else — no header, a wrong value, another
// webhook's secret, a non-bearer scheme, an empty bearer — is 401 and the
// runner is never called. The body is not read before authentication, so
// invalid JSON from an unauthenticated sender is still 401, not 400.
func TestHandleWebhook_RequiresSecret(t *testing.T) {
	runner := &mockRunner{}
	handler := NewWebhookHandler(runner, testSecrets())
	require.NoError(t, handler.Register(context.Background(), webhookPolicy("deploy-bot",
		policy.WebhookTrigger{Name: "deploy", Source: "github", SecretName: "deploy-webhook", PromptTemplate: "{{.payload}}"})))
	require.NoError(t, handler.Register(context.Background(), webhookPolicy("support",
		policy.WebhookTrigger{Name: "ticket", Source: "zendesk", SecretName: "ticket-webhook", PromptTemplate: "{{.payload}}"})))
	router := webhookRouter(handler)
	body, _ := json.Marshal(map[string]string{"action": "completed"})

	cases := map[string]func(*http.Request){
		"no credential":           func(*http.Request) {},
		"wrong secret":            func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") },
		"another webhook secret":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer other-"+testWebhookSecret) },
		"empty bearer":            func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"basic scheme":            func(r *http.Request) { r.SetBasicAuth("x", testWebhookSecret) },
		"secret in custom header": func(r *http.Request) { r.Header.Set("X-Talon-Webhook-Secret", testWebhookSecret) },
		"admin-key header":        func(r *http.Request) { r.Header.Set("X-Talon-Admin-Key", testWebhookSecret) },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/triggers/deploy", bytes.NewReader(body))
			set(req)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			var resp webhookResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "unauthorized", resp.Error)
			assert.Contains(t, resp.Message, "secret_name")
		})
	}
	t.Run("unauthenticated invalid JSON is still 401", func(t *testing.T) {
		w := postWebhook(router, "deploy", "", []byte("not json"))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	assert.Empty(t, runner.calls, "no rejected request may reach the runner")

	t.Run("the right secret runs exactly once", func(t *testing.T) {
		w := postWebhook(router, "deploy", testWebhookSecret, body)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Len(t, runner.calls, 1)
	})
}

// TestHandleWebhook_BodyBounded (#479): the payload is bounded BEFORE it is
// parsed; an oversized body from an authenticated sender is 413 and does not
// run. The bound is after authentication, so an anonymous oversized body is
// still just 401.
func TestHandleWebhook_BodyBounded(t *testing.T) {
	runner := &mockRunner{}
	handler := NewWebhookHandler(runner, testSecrets())
	require.NoError(t, handler.Register(context.Background(), webhookPolicy("deploy-bot",
		policy.WebhookTrigger{Name: "deploy", Source: "github", SecretName: "deploy-webhook", PromptTemplate: "{{.payload.k}}"})))
	router := webhookRouter(handler)

	big := []byte(`{"k":"` + strings.Repeat("a", maxWebhookBody) + `"}`)
	w := postWebhook(router, "deploy", testWebhookSecret, big)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	var resp webhookResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "payload_too_large", resp.Error)
	assert.Empty(t, runner.calls)

	w = postWebhook(router, "deploy", "", big)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Empty(t, runner.calls)
}

func TestHandleWebhook_InvalidJSON(t *testing.T) {
	runner := &mockRunner{}
	handler := NewWebhookHandler(runner, testSecrets())
	require.NoError(t, handler.Register(context.Background(), webhookPolicy("bot",
		policy.WebhookTrigger{Name: "deploy", Source: "generic", SecretName: "deploy-webhook", PromptTemplate: "{{.payload}}"})))
	router := webhookRouter(handler)

	w := postWebhook(router, "deploy", testWebhookSecret, []byte("not json"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, runner.calls)
}

func TestHandleWebhook_ReturnsSuccess(t *testing.T) {
	runner := &mockRunner{}
	handler := NewWebhookHandler(runner, testSecrets())
	require.NoError(t, handler.Register(context.Background(), webhookPolicy("bot",
		policy.WebhookTrigger{Name: "deploy", Source: "generic", SecretName: "deploy-webhook", PromptTemplate: "Alert: {{.payload.msg}}"})))
	router := webhookRouter(handler)

	body, _ := json.Marshal(map[string]string{"msg": "server down"})
	w := postWebhook(router, "deploy", testWebhookSecret, body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp webhookResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ok", resp.Status)
}

// TestWebhookHandler_RegisterFailsClosed (#479): registration refuses every
// definition serve must not expose, before any route exists.
func TestWebhookHandler_RegisterFailsClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("missing secret_name", func(t *testing.T) {
		handler := NewWebhookHandler(&mockRunner{}, testSecrets())
		err := handler.Register(ctx, webhookPolicy("bot", policy.WebhookTrigger{Name: "deploy", Source: "generic", PromptTemplate: "x"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_name")
		assert.Contains(t, err.Error(), `webhook "deploy" on agent "bot"`)
		assert.Empty(t, handler.webhooks, "nothing is routed")
	})

	t.Run("require_approval is refused, not silently accepted", func(t *testing.T) {
		handler := NewWebhookHandler(&mockRunner{}, testSecrets())
		err := handler.Register(ctx, webhookPolicy("jira-bot",
			policy.WebhookTrigger{Name: "jira-update", Source: "jira", SecretName: "deploy-webhook", PromptTemplate: "x", RequireApproval: true}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "require_approval")
		assert.Contains(t, err.Error(), "no queue for held trigger events")
	})

	t.Run("secret absent from the vault", func(t *testing.T) {
		handler := NewWebhookHandler(&mockRunner{}, testSecrets())
		err := handler.Register(ctx, webhookPolicy("bot", policy.WebhookTrigger{Name: "deploy", Source: "generic", SecretName: "unminted", PromptTemplate: "x"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), `secret_name "unminted"`)
		assert.Contains(t, err.Error(), "talon secrets set unminted")
	})

	t.Run("empty or short vault value", func(t *testing.T) {
		for name, v := range map[string]string{"blank": "  \n", "short": "hunter2", "thirty-one": strings.Repeat("a", 31)} {
			handler := NewWebhookHandler(&mockRunner{}, &mapSecrets{values: map[string]string{name: v}})
			err := handler.Register(ctx, webhookPolicy("bot", policy.WebhookTrigger{Name: "deploy", Source: "generic", SecretName: name, PromptTemplate: "x"}))
			require.Error(t, err, name)
			assert.Contains(t, err.Error(), "needs at least 32")
			assert.Contains(t, err.Error(), "openssl rand -hex 24")
		}
		handler := NewWebhookHandler(&mockRunner{}, &mapSecrets{values: map[string]string{"exact": strings.Repeat("a", 32)}})
		require.NoError(t, handler.Register(ctx, webhookPolicy("bot", policy.WebhookTrigger{Name: "deploy", Source: "generic", SecretName: "exact", PromptTemplate: "x"})), "32 bytes is the floor")
	})

	t.Run("no secret store", func(t *testing.T) {
		handler := NewWebhookHandler(&mockRunner{}, nil)
		err := handler.Register(ctx, webhookPolicy("bot", policy.WebhookTrigger{Name: "deploy", Source: "generic", SecretName: "deploy-webhook", PromptTemplate: "x"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no secret store")
	})

	t.Run("the vault is read as the declaring agent in its tenant", func(t *testing.T) {
		store := testSecrets()
		handler := NewWebhookHandler(&mockRunner{}, store)
		pol := webhookPolicy("deploy-bot", policy.WebhookTrigger{Name: "deploy", Source: "generic", SecretName: "deploy-webhook", PromptTemplate: "x"})
		pol.Agent.TenantID = "acme"
		require.NoError(t, handler.Register(ctx, pol))
		assert.Equal(t, []string{"acme/deploy-bot/deploy-webhook"}, store.scopes)

		store2 := testSecrets()
		handler2 := NewWebhookHandler(&mockRunner{}, store2)
		require.NoError(t, handler2.Register(ctx, webhookPolicy("deploy-bot", policy.WebhookTrigger{Name: "deploy", Source: "generic", SecretName: "deploy-webhook", PromptTemplate: "x"})))
		assert.Equal(t, []string{"default/deploy-bot/deploy-webhook"}, store2.scopes, "an undeclared tenant is the default tenant")
	})
}

// TestWebhookHandler_FleetRegistration (#267): webhook names are ONE route
// namespace across the fleet — each route dispatches to the agent whose
// policy declared it, and a name claimed twice fails closed naming both.
func TestWebhookHandler_FleetRegistration(t *testing.T) {
	ctx := context.Background()
	runner := &mockRunner{}
	handler := NewWebhookHandler(runner, testSecrets())
	require.NoError(t, handler.Register(ctx, webhookPolicy("support",
		policy.WebhookTrigger{Name: "ticket", Source: "zendesk", SecretName: "ticket-webhook", PromptTemplate: "Ticket: {{.payload.id}}"})))
	require.NoError(t, handler.Register(ctx, webhookPolicy("coding",
		policy.WebhookTrigger{Name: "push", Source: "github", SecretName: "deploy-webhook", PromptTemplate: "Push: {{.payload.ref}}"})))

	// Each route dispatches to ITS declaring agent, under ITS secret.
	router := webhookRouter(handler)
	body, _ := json.Marshal(map[string]string{"ref": "main"})
	w := postWebhook(router, "push", testWebhookSecret, body)
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, runner.calls, 1)
	assert.Contains(t, runner.calls[0], "coding", "the push webhook dispatches to the agent that declared it")
	w = postWebhook(router, "ticket", testWebhookSecret, body)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "the push secret does not open the ticket webhook")
	assert.Len(t, runner.calls, 1)

	// A duplicate name across agents fails closed, naming both agents.
	err := handler.Register(ctx, webhookPolicy("summarizer",
		policy.WebhookTrigger{Name: "ticket", Source: "jira", SecretName: "ticket-webhook", PromptTemplate: "T: {{.payload.id}}"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "support")
	assert.Contains(t, err.Error(), "summarizer")
}

func TestRenderTemplate_UntrustedPayload_Sanitized(t *testing.T) {
	// Nested payload is sanitized to JSON-like types only; template cannot invoke methods.
	payload := map[string]interface{}{
		"action": "deploy",
		"repo":   "acme/app",
		"nested": map[string]interface{}{"key": "value"},
	}
	safe := sanitizePayload(payload).(map[string]interface{})
	prompt, err := renderTemplate("Event: {{.payload.action}} / {{.payload.repo}}", map[string]interface{}{"payload": safe})
	require.NoError(t, err)
	assert.Equal(t, "Event: deploy / acme/app", prompt)
}

func TestSanitizePayload_OnlyAllowsJSONLikeTypes(t *testing.T) {
	// Primitives and collections pass through; other types become string.
	t.Run("nil", func(t *testing.T) {
		assert.Nil(t, sanitizePayload(nil))
	})
	t.Run("map", func(t *testing.T) {
		in := map[string]interface{}{"a": "b"}
		out := sanitizePayload(in).(map[string]interface{})
		assert.Equal(t, "b", out["a"])
	})
	t.Run("slice", func(t *testing.T) {
		in := []interface{}{"x", "y"}
		out := sanitizePayload(in).([]interface{})
		assert.Len(t, out, 2)
		assert.Equal(t, "x", out[0])
	})
	t.Run("nested", func(t *testing.T) {
		in := map[string]interface{}{"issue": map[string]interface{}{"key": "PROJ-1"}}
		out := sanitizePayload(in).(map[string]interface{})
		nested := out["issue"].(map[string]interface{})
		assert.Equal(t, "PROJ-1", nested["key"])
	})
}

// mockRunner is defined in scheduler_test.go; AgentRunner is satisfied there.
var _ AgentRunner = (*mockRunner)(nil)

// TestHandleWebhook_WholeBodyIsTheMessage (#521 review): the body is ONE
// JSON value and nothing else. A valid value followed by trailing data is
// 400, and — because the whole body is read up to the bound before parsing —
// a small valid prefix followed by an oversized tail is 413 rather than a
// run. Both are authenticated requests; neither reaches the runner.
func TestHandleWebhook_WholeBodyIsTheMessage(t *testing.T) {
	runner := &mockRunner{}
	handler := NewWebhookHandler(runner, testSecrets())
	require.NoError(t, handler.Register(context.Background(), webhookPolicy("deploy-bot",
		policy.WebhookTrigger{Name: "deploy", Source: "github", SecretName: "deploy-webhook", PromptTemplate: "{{.payload.k}}"})))
	router := webhookRouter(handler)

	t.Run("trailing data after the JSON value", func(t *testing.T) {
		w := postWebhook(router, "deploy", testWebhookSecret, []byte(`{"k":"v"} {"k":"second"}`))
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		w = postWebhook(router, "deploy", testWebhookSecret, []byte(`{"k":"v"}garbage`))
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	})
	t.Run("small valid prefix, oversized tail", func(t *testing.T) {
		body := append([]byte(`{"k":"v"}`), bytes.Repeat([]byte(" "), maxWebhookBody)...)
		w := postWebhook(router, "deploy", testWebhookSecret, body)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code, w.Body.String())
	})
	assert.Empty(t, runner.calls, "neither malformed body may start a run")
}
