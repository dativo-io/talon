package trigger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

// maxWebhookBody bounds an inbound webhook payload before it is parsed. The
// body is untrusted input from a remote sender; the bound mirrors the Action
// Gateway request bound (internal/server maxActionBody) so one number governs
// every externally fed JSON surface.
const maxWebhookBody = 512 * 1024

// minWebhookSecretBytes is the shortest bearer secret a webhook may bind
// (#479). The route has no per-webhook rate limit, so the secret's length is
// what makes online guessing infeasible: 32 bytes of the documented mint
// (`openssl rand -hex 24` yields 48) is at least 128 bits even when the
// value is hex. Length is the only strength property Talon can verify;
// entropy is the operator's, which is why the docs prescribe the mint.
const minWebhookSecretBytes = 32

// SecretResolver reads one vault secret under the declaring agent's scope.
// *secrets.SecretStore satisfies it; tests inject a map.
type SecretResolver interface {
	Get(ctx context.Context, name, tenantID, agentID string) (*secrets.Secret, error)
}

// webhookRoute binds one webhook trigger to the agent whose policy declared
// it — dispatch always names THAT agent, resolved from the current catalog
// generation at fire time (#267) — and to the sha256 of the bearer secret
// senders must present (#479). The secret is resolved once at registration;
// rotating it is restart-required, like every trigger definition (#297).
type webhookRoute struct {
	trigger    policy.WebhookTrigger
	agent      string
	secretHash [sha256.Size]byte
}

// WebhookHandler handles incoming webhook triggers for the whole fleet:
// webhook names are one shared route namespace, registered per agent policy.
type WebhookHandler struct {
	runner   AgentRunner
	secrets  SecretResolver
	webhooks map[string]webhookRoute
}

// NewWebhookHandler creates an empty handler; register each discovered
// agent's policy with Register. secrets resolves each webhook's
// `secret_name`; a nil resolver makes every registration of a webhook fail.
func NewWebhookHandler(runner AgentRunner, secrets SecretResolver) *WebhookHandler {
	return &WebhookHandler{
		runner:   runner,
		secrets:  secrets,
		webhooks: make(map[string]webhookRoute),
	}
}

// Register adds one agent policy's webhook triggers. It fails closed on
// every definition serve must not expose: a name claimed by two agents (the
// route would silently dispatch to whichever registered last), a webhook
// without `secret_name`, `require_approval: true`, and a secret that the
// vault cannot provide for the declaring agent (#479).
func (wh *WebhookHandler) Register(ctx context.Context, pol *policy.Policy) error {
	if pol.Triggers == nil {
		return nil
	}
	if err := ValidatePolicyTriggers(pol, ServeRules{}); err != nil {
		return err
	}
	tenantID := pol.Agent.TenantID
	if tenantID == "" {
		tenantID = "default"
	}
	for _, w := range pol.Triggers.Webhooks {
		if prev, dup := wh.webhooks[w.Name]; dup {
			return fmt.Errorf("webhook %q declared by both agent %q and agent %q — webhook names are unique per installation", w.Name, prev.agent, pol.Agent.Name)
		}
		if wh.secrets == nil {
			return fmt.Errorf("webhook %q on agent %q: no secret store is available to resolve secret_name %q", w.Name, pol.Agent.Name, w.SecretName)
		}
		secret, err := wh.secrets.Get(ctx, w.SecretName, tenantID, pol.Agent.Name)
		if err != nil {
			return fmt.Errorf("webhook %q on agent %q: resolving secret_name %q from the vault: %w — mint it with `talon secrets set %s <value>` (the sender presents the value as `Authorization: Bearer`)", w.Name, pol.Agent.Name, w.SecretName, err, w.SecretName)
		}
		value := bytes.TrimSpace(secret.Value)
		if len(value) < minWebhookSecretBytes {
			return fmt.Errorf("webhook %q on agent %q: vault secret %q is %d bytes; a webhook secret needs at least %d — mint it with `talon secrets set %s \"$(openssl rand -hex 24)\"`", w.Name, pol.Agent.Name, w.SecretName, len(value), minWebhookSecretBytes, w.SecretName)
		}
		wh.webhooks[w.Name] = webhookRoute{trigger: w, agent: pol.Agent.Name, secretHash: sha256.Sum256(value)}
	}
	return nil
}

// webhookResponse is the JSON response for a webhook execution.
type webhookResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func writeWebhookJSON(w http.ResponseWriter, status int, resp webhookResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// authorized reports whether the request presents the route's secret as a
// bearer token. Both sides are compared as sha256 digests so the comparison
// is constant-time regardless of the presented length.
func (route webhookRoute) authorized(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	presented := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if presented == "" {
		return false
	}
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(got[:], route.secretHash[:]) == 1
}

// HandleWebhook processes an incoming webhook trigger. Order matters: the
// route is resolved, the sender is authenticated, and only then is the
// (bounded) body read and parsed — an unauthenticated sender never costs a
// parse, a template render, or a run.
func (wh *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	route, ok := wh.webhooks[name]
	if !ok {
		writeWebhookJSON(w, http.StatusNotFound, webhookResponse{Status: "error", Error: fmt.Sprintf("trigger %q not found", name)})
		return
	}
	if !route.authorized(r) {
		log.Warn().
			Str("agent_id", route.agent).
			Str("trigger", name).
			Str("remote_addr", r.RemoteAddr).
			Msg("webhook_unauthorized")
		writeWebhookJSON(w, http.StatusUnauthorized, webhookResponse{
			Status:  "error",
			Error:   "unauthorized",
			Message: fmt.Sprintf("webhook %q requires its secret as `Authorization: Bearer <secret>` (agent file: triggers.webhooks[].secret_name)", name),
		})
		return
	}
	trigger := route.trigger

	// The whole body is read up to the bound and must be exactly one JSON
	// value: a streaming Decode would stop at the first value, accept trailing
	// data and never see an oversized tail (#521 review).
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeWebhookJSON(w, http.StatusRequestEntityTooLarge, webhookResponse{Status: "error", Error: "payload_too_large", Message: fmt.Sprintf("webhook payloads are limited to %d bytes", maxWebhookBody)})
			return
		}
		writeWebhookJSON(w, http.StatusBadRequest, webhookResponse{Status: "error", Error: "unreadable body"})
		return
	}
	var payload interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeWebhookJSON(w, http.StatusBadRequest, webhookResponse{Status: "error", Error: "invalid JSON body"})
		return
	}

	safePayload := sanitizePayload(payload)
	prompt, err := renderTemplate(trigger.PromptTemplate, map[string]interface{}{"payload": safePayload})
	if err != nil {
		log.Warn().Err(err).Str("trigger", name).Msg("webhook_template_failed")
		writeWebhookJSON(w, http.StatusInternalServerError, webhookResponse{Status: "error", Error: "invalid webhook template"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()

	invocationType := "webhook:" + name

	log.Info().
		Str("agent_id", route.agent).
		Str("trigger", name).
		Msg("webhook_trigger_fired")

	if err := wh.runner.RunFromTrigger(ctx, route.agent, prompt, invocationType); err != nil {
		log.Error().Err(err).
			Str("agent_id", route.agent).
			Str("trigger", name).
			Msg("webhook_trigger_failed")
		writeWebhookJSON(w, http.StatusInternalServerError, webhookResponse{Status: "error", Error: "trigger execution failed"})
		return
	}

	writeWebhookJSON(w, http.StatusOK, webhookResponse{Status: "ok", Message: "trigger executed"})
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
