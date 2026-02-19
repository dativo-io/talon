package trigger

import (
	"bytes"
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

func TestHandleWebhook_RequireApproval_GatesExecution(t *testing.T) {
	runner := &mockRunner{}
	pol := &policy.Policy{
		Agent: policy.AgentConfig{Name: "jira-bot"},
		Triggers: &policy.TriggersConfig{
			Webhooks: []policy.WebhookTrigger{
				{
					Name:            "jira-update",
					Source:          "jira",
					PromptTemplate:  "Analyze: {{.payload.issue.key}}",
					RequireApproval: true,
				},
			},
		},
	}
	handler := NewWebhookHandler(runner, pol)
	router := webhookRouter(handler)

	body, _ := json.Marshal(map[string]interface{}{"issue": map[string]string{"key": "PROJ-123"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/triggers/jira-update", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
	var resp webhookResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "pending_approval", resp.Status)
	assert.Contains(t, resp.Message, "human approval")
	assert.Empty(t, runner.calls, "agent must not run when require_approval is true")
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
