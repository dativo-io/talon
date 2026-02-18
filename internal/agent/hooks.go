package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// HookPoint identifies where in the pipeline a hook fires.
type HookPoint string

const (
	HookPrePolicy      HookPoint = "pre_policy"
	HookPostPolicy     HookPoint = "post_policy"
	HookPrePlanReview  HookPoint = "pre_plan_review"
	HookPostPlanReview HookPoint = "post_plan_review"
	HookPreLLM         HookPoint = "pre_llm"
	HookPostLLM        HookPoint = "post_llm"
	HookPreTool        HookPoint = "pre_tool"
	HookPostTool       HookPoint = "post_tool"
	HookPreMemory      HookPoint = "pre_memory_write"
	HookPostEvidence   HookPoint = "post_evidence"
)

// Hook is the interface for all pipeline hooks.
type Hook interface {
	Point() HookPoint
	Execute(ctx context.Context, data *HookData) (*HookResult, error)
}

// HookData provides context to hook implementations.
type HookData struct {
	TenantID      string          `json:"tenant_id"`
	AgentID       string          `json:"agent_id"`
	CorrelationID string          `json:"correlation_id"`
	Stage         HookPoint       `json:"stage"`
	Payload       json.RawMessage `json:"payload"`
}

// HookResult controls pipeline flow after hook execution.
type HookResult struct {
	Continue bool            `json:"continue"`
	Modified json.RawMessage `json:"modified,omitempty"`
}

// HookConfig from .talon.yaml.
type HookConfig struct {
	Type string `yaml:"type"` // "webhook"
	URL  string `yaml:"url"`
	On   string `yaml:"on"` // "fired" | "allowed" | "denied" | "all"
}

// HookRegistry manages registered hooks for each pipeline stage.
type HookRegistry struct {
	hooks map[HookPoint][]Hook
}

// NewHookRegistry creates an empty hook registry.
func NewHookRegistry() *HookRegistry {
	return &HookRegistry{
		hooks: make(map[HookPoint][]Hook),
	}
}

// Register adds a hook at the specified pipeline point.
func (r *HookRegistry) Register(hook Hook) {
	r.hooks[hook.Point()] = append(r.hooks[hook.Point()], hook)
}

// Execute runs all hooks for a given pipeline point.
// Hook failures do not abort the pipeline by default.
func (r *HookRegistry) Execute(ctx context.Context, point HookPoint, data *HookData) (*HookResult, error) {
	ctx, span := tracer.Start(ctx, "hooks.execute",
		trace.WithAttributes(
			attribute.String("hook_point", string(point)),
			attribute.String("tenant_id", data.TenantID),
		))
	defer span.End()

	hooks, ok := r.hooks[point]
	if !ok || len(hooks) == 0 {
		return &HookResult{Continue: true}, nil
	}

	for _, hook := range hooks {
		result, err := hook.Execute(ctx, data)
		if err != nil {
			log.Warn().Err(err).Str("hook_point", string(point)).Msg("hook_execution_failed")
			continue
		}
		if result != nil && !result.Continue {
			span.SetAttributes(attribute.Bool("hook_aborted", true))
			return result, nil
		}
		if result != nil && result.Modified != nil {
			data.Payload = result.Modified
		}
	}

	return &HookResult{Continue: true}, nil
}

// WebhookHook sends HTTP POST to a configured URL.
type WebhookHook struct {
	point  HookPoint
	url    string
	filter string
	client *http.Client
}

// NewWebhookHook creates a webhook hook from config.
func NewWebhookHook(point HookPoint, config HookConfig) *WebhookHook {
	return &WebhookHook{
		point:  point,
		url:    config.URL,
		filter: config.On,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Point returns the pipeline point this hook is registered at.
func (h *WebhookHook) Point() HookPoint { return h.point }

// outcomeFromPayload derives allow/deny from HookData.Payload for filtering.
// Payload may contain "decision": "allow"|"deny" (e.g. post_policy). If absent, the
// hook point is only reached after policy allowed, so we treat as "allowed".
func outcomeFromPayload(payload json.RawMessage) string {
	if len(payload) == 0 {
		return "allowed"
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return "allowed"
	}
	d, _ := m["decision"].(string)
	switch d {
	case "deny":
		return "denied"
	case "allow":
		return "allowed"
	default:
		return "allowed"
	}
}

// shouldDeliver returns true if the webhook should fire given the On filter and payload outcome.
func (h *WebhookHook) shouldDeliver(outcome string) bool {
	switch h.filter {
	case "", "all", "fired":
		return true
	case "allowed":
		return outcome == "allowed"
	case "denied":
		return outcome == "denied"
	default:
		return true
	}
}

// Execute sends the hook data as JSON POST to the configured URL.
// It only delivers when the configured On filter matches the payload outcome (e.g. on: "denied" only for denials).
func (h *WebhookHook) Execute(ctx context.Context, data *HookData) (*HookResult, error) {
	if h.url == "" {
		return &HookResult{Continue: true}, nil
	}

	outcome := outcomeFromPayload(data.Payload)
	if !h.shouldDeliver(outcome) {
		return &HookResult{Continue: true}, nil
	}

	body, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling hook data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Hook", string(h.point))

	// G704: URL is from operator-controlled .talon.yaml hook config, not user input.
	resp, err := h.client.Do(req) // #nosec G704
	if err != nil {
		log.Warn().Err(err).Str("url", h.url).Msg("webhook_delivery_failed")
		return &HookResult{Continue: true}, nil
	}
	defer resp.Body.Close()

	log.Debug().Int("status", resp.StatusCode).Str("url", h.url).Msg("webhook_delivered")
	return &HookResult{Continue: true}, nil
}

// LoadHooksFromConfig creates hooks from .talon.yaml hook configuration.
func LoadHooksFromConfig(hooksConfig map[string][]HookConfig) *HookRegistry {
	registry := NewHookRegistry()

	for pointStr, configs := range hooksConfig {
		point := HookPoint(pointStr)
		for _, config := range configs {
			if config.URL == "" {
				continue
			}
			switch config.Type {
			case "webhook":
				registry.Register(NewWebhookHook(point, config))
			default:
				log.Warn().Str("type", config.Type).Msg("unknown_hook_type")
			}
		}
	}

	return registry
}
