package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/policy"
)

// WebhookHandler handles incoming webhook triggers.
type WebhookHandler struct {
	runner   AgentRunner
	webhooks map[string]policy.WebhookTrigger
	agent    string
}

// NewWebhookHandler creates a handler from the policy's webhook configuration.
func NewWebhookHandler(runner AgentRunner, pol *policy.Policy) *WebhookHandler {
	wh := &WebhookHandler{
		runner:   runner,
		webhooks: make(map[string]policy.WebhookTrigger),
		agent:    pol.Agent.Name,
	}
	if pol.Triggers != nil {
		for _, w := range pol.Triggers.Webhooks {
			wh.webhooks[w.Name] = w
		}
	}
	return wh
}

// webhookResponse is the JSON response for a webhook execution.
type webhookResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// HandleWebhook processes an incoming webhook trigger.
func (wh *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	trigger, ok := wh.webhooks[name]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(webhookResponse{Status: "error", Error: fmt.Sprintf("trigger %q not found", name)})
		return
	}

	var payload interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(webhookResponse{Status: "error", Error: "invalid JSON body"})
		return
	}

	prompt, err := renderTemplate(trigger.PromptTemplate, map[string]interface{}{"payload": payload})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(webhookResponse{Status: "error", Error: fmt.Sprintf("template error: %v", err)})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()

	invocationType := "webhook:" + name

	log.Info().
		Str("agent_id", wh.agent).
		Str("trigger", name).
		Msg("webhook_trigger_fired")

	if err := wh.runner.RunFromTrigger(ctx, wh.agent, prompt, invocationType); err != nil {
		log.Error().Err(err).
			Str("agent_id", wh.agent).
			Str("trigger", name).
			Msg("webhook_trigger_failed")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(webhookResponse{Status: "error", Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(webhookResponse{Status: "ok", Message: "trigger executed"})
}

// renderTemplate renders a Go text/template with the given data.
func renderTemplate(tmplStr string, data interface{}) (string, error) {
	tmpl, err := template.New("webhook").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parsing template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing template: %w", err)
	}
	return buf.String(), nil
}
