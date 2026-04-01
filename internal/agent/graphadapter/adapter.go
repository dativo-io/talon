package graphadapter

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/policy"
)

var tracer = otel.Tracer("github.com/dativo-io/talon/internal/agent/graphadapter")

// Adapter processes governance events from external agent runtimes and
// returns control decisions. It bridges the framework-agnostic event
// contract to Talon's policy engine and evidence store.
type Adapter struct {
	policyEngine  *policy.Engine
	evidenceGen   *evidence.Generator
	evidenceStore *evidence.Store
}

// NewAdapter creates a graph runtime adapter.
func NewAdapter(pe *policy.Engine, eg *evidence.Generator, es *evidence.Store) *Adapter {
	return &Adapter{
		policyEngine:  pe,
		evidenceGen:   eg,
		evidenceStore: es,
	}
}

// HandleEvent evaluates a governance event against policy and records
// evidence. It returns a Decision the external runtime must respect.
func (a *Adapter) HandleEvent(ctx context.Context, ev *Event) (*Decision, error) {
	ctx, span := tracer.Start(ctx, "graphadapter.handle_event",
		trace.WithAttributes(
			attribute.String("event.type", string(ev.Type)),
			attribute.String("graph_run_id", ev.GraphRunID),
			attribute.String("tenant_id", ev.TenantID),
			attribute.String("agent_id", ev.AgentID),
			attribute.String("node_id", ev.NodeID),
			attribute.Int("step_index", ev.StepIndex),
		))
	defer span.End()

	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}

	switch ev.Type {
	case EventRunStart:
		return a.handleRunStart(ctx, span, ev)
	case EventStepStart:
		return a.handleStepStart(ctx, span, ev)
	case EventStepEnd:
		return a.handleStepEnd(ctx, span, ev)
	case EventToolCall:
		return a.handleToolCall(ctx, span, ev)
	case EventRetry:
		return a.handleRetry(ctx, span, ev)
	case EventRunEnd:
		return a.handleRunEnd(ctx, span, ev)
	default:
		span.SetStatus(codes.Error, "unknown event type")
		return &Decision{Action: ActionDeny, Allowed: false, Reasons: []string{"unknown event type: " + string(ev.Type)}}, nil
	}
}

func (a *Adapter) handleRunStart(ctx context.Context, span trace.Span, ev *Event) (*Decision, error) {
	input := map[string]interface{}{
		"event_type":   string(ev.Type),
		"tenant_id":    ev.TenantID,
		"agent_id":     ev.AgentID,
		"graph_run_id": ev.GraphRunID,
	}
	if ev.RunMeta != nil {
		input["framework"] = ev.RunMeta.Framework
		input["node_count"] = ev.RunMeta.NodeCount
		input["model"] = ev.RunMeta.Model
	}

	dec, err := a.evaluatePolicy(ctx, span, input)
	if err != nil {
		return nil, err
	}

	a.recordStepEvidence(ctx, ev, "run_start", dec)

	log.Info().
		Str("graph_run_id", ev.GraphRunID).
		Str("tenant_id", ev.TenantID).
		Str("agent_id", ev.AgentID).
		Bool("allowed", dec.Allowed).
		Msg("graph_run_start")

	return dec, nil
}

func (a *Adapter) handleStepStart(ctx context.Context, span trace.Span, ev *Event) (*Decision, error) {
	input := map[string]interface{}{
		"event_type":   string(ev.Type),
		"tenant_id":    ev.TenantID,
		"agent_id":     ev.AgentID,
		"graph_run_id": ev.GraphRunID,
		"node_id":      ev.NodeID,
		"step_index":   ev.StepIndex,
		"cost_so_far":  ev.Cost,
	}
	if ev.NodeMeta != nil {
		input["node_name"] = ev.NodeMeta.Name
		input["node_type"] = ev.NodeMeta.Type
		input["model"] = ev.NodeMeta.Model
	}

	dec, err := a.evaluatePolicy(ctx, span, input)
	if err != nil {
		return nil, err
	}

	a.recordStepEvidence(ctx, ev, "step_start", dec)
	return dec, nil
}

func (a *Adapter) handleStepEnd(ctx context.Context, span trace.Span, ev *Event) (*Decision, error) {
	stepType := "llm_call"
	if ev.NodeMeta != nil && ev.NodeMeta.Type == "tool" {
		stepType = "tool_call"
	}
	toolName := ""
	if ev.ToolMeta != nil {
		toolName = ev.ToolMeta.Name
	}

	cost := ev.Cost
	if ev.Result != nil {
		cost = ev.Result.Cost
	}
	durationMS := int64(0)
	if ev.Result != nil {
		durationMS = ev.Result.DurationMS
	}

	if a.evidenceGen != nil {
		_, _ = a.evidenceGen.GenerateStep(ctx, evidence.StepParams{
			CorrelationID: ev.GraphRunID,
			SessionID:     ev.SessionID,
			TenantID:      ev.TenantID,
			AgentID:       ev.AgentID,
			StepIndex:     ev.StepIndex,
			Type:          stepType,
			ToolName:      toolName,
			DurationMS:    durationMS,
			Cost:          cost,
			Status:        a.stepStatus(ev),
			Error:         a.stepError(ev),
		})
	}

	return &Decision{Action: ActionAllow, Allowed: true}, nil
}

func (a *Adapter) handleToolCall(ctx context.Context, span trace.Span, ev *Event) (*Decision, error) {
	if ev.ToolMeta == nil {
		return &Decision{Action: ActionDeny, Allowed: false, Reasons: []string{"tool_call event requires tool_meta"}}, nil
	}

	if a.policyEngine != nil {
		toolDec, err := a.policyEngine.EvaluateToolAccess(ctx, ev.ToolMeta.Name, ev.ToolMeta.Arguments, nil)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("evaluating tool access for %s: %w", ev.ToolMeta.Name, err)
		}
		if !toolDec.Allowed {
			span.SetAttributes(attribute.Bool("tool.denied", true))
			a.recordStepEvidence(ctx, ev, "tool_denied", &Decision{Action: ActionDeny, Allowed: false, Reasons: toolDec.Reasons})
			return &Decision{
				Action:  ActionDeny,
				Allowed: false,
				Reasons: toolDec.Reasons,
			}, nil
		}
	}

	a.recordStepEvidence(ctx, ev, "tool_allowed", &Decision{Action: ActionAllow, Allowed: true})
	return &Decision{Action: ActionAllow, Allowed: true}, nil
}

func (a *Adapter) handleRetry(ctx context.Context, span trace.Span, ev *Event) (*Decision, error) {
	retryCount := 0
	if ev.Error != nil {
		retryCount = ev.Error.RetryCount
	}

	input := map[string]interface{}{
		"event_type":   string(ev.Type),
		"tenant_id":    ev.TenantID,
		"agent_id":     ev.AgentID,
		"graph_run_id": ev.GraphRunID,
		"node_id":      ev.NodeID,
		"retry_count":  retryCount,
		"cost_so_far":  ev.Cost,
		"step_index":   ev.StepIndex,
	}

	dec, err := a.evaluatePolicy(ctx, span, input)
	if err != nil {
		return nil, err
	}

	a.recordStepEvidence(ctx, ev, "retry", dec)

	log.Info().
		Str("graph_run_id", ev.GraphRunID).
		Str("node_id", ev.NodeID).
		Int("retry_count", retryCount).
		Bool("allowed", dec.Allowed).
		Msg("graph_retry_decision")

	return dec, nil
}

func (a *Adapter) handleRunEnd(ctx context.Context, span trace.Span, ev *Event) (*Decision, error) {
	status := "completed"
	if ev.Result != nil {
		status = ev.Result.Status
	}

	if a.evidenceGen != nil {
		_, _ = a.evidenceGen.Generate(ctx, evidence.GenerateParams{
			CorrelationID:  ev.GraphRunID,
			SessionID:      ev.SessionID,
			TenantID:       ev.TenantID,
			AgentID:        ev.AgentID,
			InvocationType: "graph_run",
			PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
			Cost:           ev.Cost,
			DurationMS:     a.runDuration(ev),
			Status:         status,
		})
	}

	log.Info().
		Str("graph_run_id", ev.GraphRunID).
		Str("tenant_id", ev.TenantID).
		Str("status", status).
		Float64("total_cost", ev.Cost).
		Msg("graph_run_end")

	return &Decision{Action: ActionAllow, Allowed: true}, nil
}

func (a *Adapter) evaluatePolicy(ctx context.Context, span trace.Span, input map[string]interface{}) (*Decision, error) {
	if a.policyEngine == nil {
		return &Decision{Action: ActionAllow, Allowed: true}, nil
	}

	dec, err := a.policyEngine.EvaluateGraphGovernance(ctx, input)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("graph governance evaluation: %w", err)
	}

	if !dec.Allowed {
		span.SetAttributes(attribute.Bool("policy.denied", true))
		return &Decision{
			Action:  ActionDeny,
			Allowed: false,
			Reasons: dec.Reasons,
		}, nil
	}

	return &Decision{Action: ActionAllow, Allowed: true}, nil
}

func (a *Adapter) recordStepEvidence(ctx context.Context, ev *Event, eventLabel string, dec *Decision) {
	if a.evidenceGen == nil {
		return
	}

	stepType := "graph_event"
	if ev.ToolMeta != nil {
		stepType = "tool_call"
	}

	status := "completed"
	if dec != nil && !dec.Allowed {
		status = "denied"
	}

	_, _ = a.evidenceGen.GenerateStep(ctx, evidence.StepParams{
		CorrelationID: ev.GraphRunID,
		SessionID:     ev.SessionID,
		TenantID:      ev.TenantID,
		AgentID:       ev.AgentID,
		StepIndex:     ev.StepIndex,
		Type:          stepType,
		ToolName:      eventLabel,
		Status:        status,
	})
}

func (a *Adapter) stepStatus(ev *Event) string {
	if ev.Error != nil {
		return "failed"
	}
	if ev.Result != nil {
		return ev.Result.Status
	}
	return "completed"
}

func (a *Adapter) stepError(ev *Event) string {
	if ev.Error != nil {
		return ev.Error.Message
	}
	return ""
}

func (a *Adapter) runDuration(ev *Event) int64 {
	if ev.Result != nil {
		return ev.Result.DurationMS
	}
	return 0
}
