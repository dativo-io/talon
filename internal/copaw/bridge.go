// Package copaw provides integration points for governing CoPaw (AgentScope) personal AI assistant
// when used with Talon as the LLM gateway. The bridge exposes CoPaw skills as MCP tools so that
// skill invocations can be policy-governed and audited.
package copaw

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/agent/tools"
)

var tracer = otel.Tracer("github.com/dativo-io/talon/internal/copaw")

// BridgeConfig configures the connection to a CoPaw instance (REST API, typically port 8088).
type BridgeConfig struct {
	BaseURL    string       // e.g. "http://localhost:8088"
	HTTPClient *http.Client // optional; default 30s timeout
	Timeout    time.Duration
}

// Bridge exposes CoPaw skills as MCP tools. It discovers skills via CoPaw's REST API
// (GET /api/skills) and registers each as a governed tool. Invocations are forwarded
// to CoPaw and evidence is generated. The bridge does NOT add a Python runtime to Talon.
type Bridge struct {
	cfg    BridgeConfig
	client *http.Client
}

// NewBridge creates a bridge that can list and invoke CoPaw skills.
func NewBridge(cfg BridgeConfig) *Bridge {
	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	return &Bridge{cfg: cfg, client: client}
}

// SkillInfo describes a CoPaw skill for MCP tool registration.
type SkillInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
}

func (b *Bridge) listSkillsTimeout() time.Duration {
	if b.cfg.Timeout > 0 {
		return b.cfg.Timeout
	}
	return 30 * time.Second
}

// ListSkills calls CoPaw's GET /api/skills and returns skill names and metadata.
// Enforces a context deadline so the caller cannot block indefinitely.
// Returns nil, nil when CoPaw is unreachable (caller may log and continue without bridge tools).
func (b *Bridge) ListSkills(ctx context.Context) ([]SkillInfo, error) {
	ctx, span := tracer.Start(ctx, "copaw.bridge.list_skills",
		trace.WithAttributes(attribute.String("copaw.base_url", b.cfg.BaseURL)))
	defer span.End()

	timeout := b.listSkillsTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := b.cfg.BaseURL + "/api/skills"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("copaw list skills request: %w", err)
	}

	// G704: URL is from BridgeConfig.BaseURL (operator-configured), not user input; path is fixed "/api/skills".
	resp, err := b.client.Do(req) //nolint:gosec
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("copaw list skills: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, resp.Status)
		return nil, fmt.Errorf("copaw list skills: status %s", resp.Status)
	}

	var raw []struct {
		Name    string `json:"name"`
		Content string `json:"content"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("copaw list skills decode: %w", err)
	}

	skills := make([]SkillInfo, 0, len(raw))
	for _, s := range raw {
		skills = append(skills, SkillInfo{
			Name:        s.Name,
			Description: truncateDescription(s.Content, 200),
			Enabled:     s.Enabled,
		})
	}
	span.SetAttributes(attribute.Int("copaw.skills_count", len(skills)))
	return skills, nil
}

func truncateDescription(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// RegisterAsTools discovers CoPaw skills and registers each as an MCP tool in the given registry.
// Only enabled skills are registered. Each tool execution is forwarded to CoPaw (invoke path TBD).
// On CoPaw unreachable (e.g. network error), logs a warning and returns nil so gateway boot does not fail.
func (b *Bridge) RegisterAsTools(ctx context.Context, reg *tools.ToolRegistry) error {
	skills, err := b.ListSkills(ctx)
	if err != nil {
		log.Warn().Err(err).Str("base_url", b.cfg.BaseURL).Msg("copaw bridge: CoPaw unreachable, no skills registered")
		return nil
	}
	for _, s := range skills {
		if !s.Enabled {
			continue
		}
		tool := &copawSkillTool{bridge: b, info: s}
		reg.Register(tool)
	}
	return nil
}

// copawSkillTool implements tools.Tool for a single CoPaw skill.
type copawSkillTool struct {
	bridge *Bridge
	info   SkillInfo
}

func (t *copawSkillTool) Name() string { return "copaw_skill_" + t.info.Name }

func (t *copawSkillTool) Description() string {
	if t.info.Description != "" {
		return t.info.Description
	}
	return "CoPaw skill: " + t.info.Name
}

func (t *copawSkillTool) InputSchema() json.RawMessage {
	// CoPaw skills accept arbitrary JSON; minimal schema for tool discovery.
	// TODO(v2): When MCP invoke path is implemented, use per-skill schemas from CoPaw API so policy evaluation has accurate input schemas for tool-call decisions.
	return json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"},"params":{"type":"object"}}}`)
}

func (t *copawSkillTool) Execute(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	_, span := tracer.Start(ctx, "copaw.bridge.execute_skill",
		trace.WithAttributes(
			attribute.String("copaw.skill_name", t.info.Name),
		))
	defer span.End()

	// CoPaw does not expose a generic "invoke skill by name" HTTP endpoint in the current API;
	// skills are executed in-process when the agent runs. Return an error so tool policy and
	// evidence store classify this as unsupported, not successful.
	return nil, fmt.Errorf("copaw skill direct invocation not yet supported: route CoPaw through Talon gateway for governed execution (skill: %s)", t.info.Name)
}
