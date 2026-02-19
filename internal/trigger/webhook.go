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

	safePayload := sanitizePayload(payload)
	prompt, err := renderTemplate(trigger.PromptTemplate, map[string]interface{}{"payload": safePayload})
	if err != nil {
		log.Warn().Err(err).Str("trigger", name).Msg("webhook_template_failed")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(webhookResponse{Status: "error", Error: "invalid webhook template"})
		return
	}

	// Human oversight gate (EU AI Act Art. 14): when require_approval is true,
	// do not execute the agent. Return 202 so the caller knows the webhook was
	// received but no run was started until an operator approves.
	if trigger.RequireApproval {
		log.Info().
			Str("agent_id", wh.agent).
			Str("trigger", name).
			Msg("webhook_received_pending_approval")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(webhookResponse{
			Status:  "pending_approval",
			Message: "Webhook received; execution requires human approval (EU AI Act Art. 14). No run was started.",
		})
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
		_ = json.NewEncoder(w).Encode(webhookResponse{Status: "error", Error: "trigger execution failed"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(webhookResponse{Status: "ok", Message: "trigger executed"})
}

// sanitizePayload recursively restricts the payload to JSON-like types only
// (map[string]interface{}, []interface{}, string, float64, bool, nil). This
// prevents the template engine from calling methods on unexpected types
// when rendering with untrusted webhook body data.
func sanitizePayload(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, elem := range val {
			out[k] = sanitizePayload(elem)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, elem := range val {
			out[i] = sanitizePayload(elem)
		}
		return out
	case string, float64, bool:
		return v
	default:
		// Numbers from JSON decode as float64; ints not possible from standard encoding/json.
		// Any other type (e.g. future custom decoder) is reduced to a safe string form.
		return fmt.Sprint(v)
	}
}

// renderTemplate renders a Go text/template with the given data. It uses an
// explicit empty FuncMap so no template functions are available, and callers
// must pass sanitized data (e.g. from sanitizePayload) to avoid method calls
// on untrusted payloads.
func renderTemplate(tmplStr string, data interface{}) (string, error) {
	tmpl, err := template.New("webhook").Funcs(template.FuncMap{}).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parsing template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing template: %w", err)
	}
	return buf.String(), nil
}
