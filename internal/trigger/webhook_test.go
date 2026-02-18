package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

func webhookRouter(handler *WebhookHandler) *chi.Mux {
	r := chi.NewRouter()
	r.Post("/v1/triggers/{name}", handler.HandleWebhook)
	return r
}

func TestHandleWebhook_RendersTemplate(t *testing.T) {
	runner := &mockRunner{}
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "deploy-bot"},
		Triggers: &policy.TriggersConfig{
			Webhooks: []policy.WebhookTrigger{
				{Name: "deploy", Source: "github", PromptTemplate: "Deploy event: {{.payload.action}}"},
			},
		},
	}
	handler := NewWebhookHandler(runner, pol)
	router := webhookRouter(handler)

	body, _ := json.Marshal(map[string]string{"action": "completed"})
	req := httptest.NewRequest(http.MethodPost, "/v1/triggers/deploy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.Len(t, runner.calls, 1)
	assert.Contains(t, runner.calls[0], "Deploy event: completed")
	assert.Contains(t, runner.calls[0], "webhook:deploy")
}

func TestHandleWebhook_UnknownTrigger(t *testing.T) {
	runner := &mockRunner{}
	pol := &policy.Policy{Agent: policy.AgentConfig{Name: "bot"}}
	handler := NewWebhookHandler(runner, pol)
	router := webhookRouter(handler)

	body, _ := json.Marshal(map[string]string{"action": "test"})
	req := httptest.NewRequest(http.MethodPost, "/v1/triggers/unknown", bytes.NewReader(body))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleWebhook_InvalidJSON(t *testing.T) {
	runner := &mockRunner{}
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "bot"},
		Triggers: &policy.TriggersConfig{
			Webhooks: []policy.WebhookTrigger{
				{Name: "test", Source: "generic", PromptTemplate: "{{.payload}}"},
			},
		},
	}
	handler := NewWebhookHandler(runner, pol)
	router := webhookRouter(handler)

	req := httptest.NewRequest(http.MethodPost, "/v1/triggers/test", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleWebhook_ReturnsSuccess(t *testing.T) {
	runner := &mockRunner{}
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "bot"},
		Triggers: &policy.TriggersConfig{
			Webhooks: []policy.WebhookTrigger{
				{Name: "notify", Source: "generic", PromptTemplate: "Alert: {{.payload.msg}}"},
			},
		},
	}
	handler := NewWebhookHandler(runner, pol)
	router := webhookRouter(handler)

	body, _ := json.Marshal(map[string]string{"msg": "server down"})
	req := httptest.NewRequest(http.MethodPost, "/v1/triggers/notify", bytes.NewReader(body))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp webhookResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ok", resp.Status)
}

// Satisfy interface at compile time
var _ AgentRunner = (*mockRunner)(nil)

func (m *mockRunner) RunFromTriggerCtx(ctx context.Context, agentName, prompt, invocationType string) error {
	return m.RunFromTrigger(ctx, agentName, prompt, invocationType)
}
