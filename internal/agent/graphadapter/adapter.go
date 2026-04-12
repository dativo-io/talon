package graphadapter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/policy"
)

var tracer = otel.Tracer("github.com/dativo-io/talon/internal/agent/graphadapter")

const (
	defaultRunStateTTL        = 30 * time.Minute
	defaultMaxInFlightRuns    = 10000
	maxDenialReasonsPerRun    = 32
	maxStateEvictionsPerSweep = 256
)

var ErrGraphRunStateLimitExceeded = errors.New("graph run state limit exceeded")

// runState tracks mid-run denial state for a single graph execution,
// allowing handleRunEnd to reflect prior denials on the evidence record.
type runState struct {
	mu        sync.Mutex
	denied    bool
	reasons   []string
	toolCalls int
	maxStep   int
	lastSeen  time.Time
}

// Adapter processes governance events from external agent runtimes and
// returns control decisions. It bridges the framework-agnostic event
// contract to Talon's policy engine and evidence store.
type Adapter struct {
	policyEngine    *policy.Engine
	evidenceGen     *evidence.Generator
	runs            sync.Map // graph_run_id -> *runState
	runStateTTL     time.Duration
	maxInFlightRuns int
	inFlightRuns    atomic.Int64
}

// NewAdapter creates a graph runtime adapter.
func NewAdapter(pe *policy.Engine, eg *evidence.Generator, _ *evidence.Store) *Adapter {
	return &Adapter{
		policyEngine:    pe,
		evidenceGen:     eg,
		runStateTTL:     defaultRunStateTTL,
		maxInFlightRuns: defaultMaxInFlightRuns,
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
	a.evictExpiredRunStates(ev.Timestamp)

	switch ev.Type {
	case EventRunStart:
		if _, err := a.getOrCreateRunState(ev.GraphRunID, ev.Timestamp); err != nil {
			return a.capacityDecision(ctx, ev, err), nil
		}
		return a.handleRunStart(ctx, span, ev)
	case EventStepStart:
		rs, err := a.getOrCreateRunState(ev.GraphRunID, ev.Timestamp)
		if err != nil {
			return a.capacityDecision(ctx, ev, err), nil
		}
		a.markStep(rs, ev.StepIndex, ev.Timestamp)
		return a.handleStepStart(ctx, span, ev)
	case EventStepEnd:
		rs, err := a.getOrCreateRunState(ev.GraphRunID, ev.Timestamp)
		if err != nil {
			return a.capacityDecision(ctx, ev, err), nil
		}
		a.markStep(rs, ev.StepIndex, ev.Timestamp)
		return a.handleStepEnd(ctx, span, ev)
	case EventToolCall:
		return a.handleToolCall(ctx, span, ev)
	case EventRetry:
		rs, err := a.getOrCreateRunState(ev.GraphRunID, ev.Timestamp)
		if err != nil {
			return a.capacityDecision(ctx, ev, err), nil
		}
		a.touchRunState(rs, ev.Timestamp)
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

	dec.EvidenceID = a.recordStepEvidence(ctx, ev, "run_start", dec)

	log.Info().
		Str("graph_run_id", ev.GraphRunID).
		Str("tenant_id", ev.TenantID).
		Str("agent_id", ev.AgentID).
		Bool("allowed", dec.Allowed).
		Msg("graph_run_start")

	return dec, nil
}

func (a *Adapter) handleStepStart(ctx context.Context, span trace.Span, ev *Event) (*Decision, error) {
	toolCalls := a.toolCallsForRun(ev.GraphRunID)
	input := map[string]interface{}{
		"event_type":        string(ev.Type),
		"tenant_id":         ev.TenantID,
		"agent_id":          ev.AgentID,
		"graph_run_id":      ev.GraphRunID,
		"node_id":           ev.NodeID,
		"step_index":        ev.StepIndex,
		"cost_so_far":       ev.Cost,
		"tool_calls_so_far": toolCalls,
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

	if !dec.Allowed {
		a.trackDenial(ev.GraphRunID, dec.Reasons, ev.Timestamp)
	}
	dec.EvidenceID = a.recordStepEvidence(ctx, ev, "step_start", dec)
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

	dec := &Decision{Action: ActionAllow, Allowed: true}
	if a.evidenceGen != nil {
		step, _ := a.evidenceGen.GenerateStep(ctx, evidence.StepParams{
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
			GraphRunID:    ev.GraphRunID,
			PlanID:        a.planID(ev),
		})
		if step != nil {
			dec.EvidenceID = step.ID
		}
	}

	return dec, nil
}

func (a *Adapter) handleToolCall(ctx context.Context, span trace.Span, ev *Event) (*Decision, error) {
	if ev.ToolMeta == nil {
		return &Decision{Action: ActionDeny, Allowed: false, Reasons: []string{"tool_call event requires tool_meta"}}, nil
	}

	rs, err := a.getOrCreateRunState(ev.GraphRunID, ev.Timestamp)
	if err != nil {
		return a.capacityDecision(ctx, ev, err), nil
	}
	toolCalls := a.incrementToolCalls(rs, ev.Timestamp)

	policyInput := map[string]interface{}{
		"event_type":        string(ev.Type),
		"tenant_id":         ev.TenantID,
		"agent_id":          ev.AgentID,
		"graph_run_id":      ev.GraphRunID,
		"node_id":           ev.NodeID,
		"step_index":        ev.StepIndex,
		"cost_so_far":       ev.Cost,
		"tool_calls_so_far": toolCalls,
	}
	policyDec, err := a.evaluatePolicy(ctx, span, policyInput)
	if err != nil {
		return nil, err
	}
	if !policyDec.Allowed {
		a.trackDenial(ev.GraphRunID, policyDec.Reasons, ev.Timestamp)
		policyDec.EvidenceID = a.recordStepEvidence(ctx, ev, "tool_denied", policyDec)
		return policyDec, nil
	}

	if a.policyEngine != nil {
		toolDec, err := a.policyEngine.EvaluateToolAccess(ctx, ev.ToolMeta.Name, ev.ToolMeta.Arguments, nil)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("evaluating tool access for %s: %w", ev.ToolMeta.Name, err)
		}
		if !toolDec.Allowed {
			span.SetAttributes(attribute.Bool("tool.denied", true))
			denyDec := &Decision{Action: ActionDeny, Allowed: false, Reasons: toolDec.Reasons}
			a.trackDenial(ev.GraphRunID, denyDec.Reasons, ev.Timestamp)
			denyDec.EvidenceID = a.recordStepEvidence(ctx, ev, "tool_denied", denyDec)
			return denyDec, nil
		}
	}

	allowDec := &Decision{Action: ActionAllow, Allowed: true}
	allowDec.EvidenceID = a.recordStepEvidence(ctx, ev, "tool_allowed", allowDec)
	return allowDec, nil
}

func (a *Adapter) handleRetry(ctx context.Context, span trace.Span, ev *Event) (*Decision, error) {
	retryCount := 0
	if ev.Error != nil {
		retryCount = ev.Error.RetryCount
	}
	toolCalls := a.toolCallsForRun(ev.GraphRunID)

	input := map[string]interface{}{
		"event_type":        string(ev.Type),
		"tenant_id":         ev.TenantID,
		"agent_id":          ev.AgentID,
		"graph_run_id":      ev.GraphRunID,
		"node_id":           ev.NodeID,
		"retry_count":       retryCount,
		"cost_so_far":       ev.Cost,
		"step_index":        ev.StepIndex,
		"tool_calls_so_far": toolCalls,
	}

	dec, err := a.evaluatePolicy(ctx, span, input)
	if err != nil {
		return nil, err
	}

	if !dec.Allowed {
		a.trackDenial(ev.GraphRunID, dec.Reasons, ev.Timestamp)
	}
	dec.EvidenceID = a.recordStepEvidence(ctx, ev, "retry", dec)

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

	rs := a.consumeRunState(ev.GraphRunID)
	finalReasons, err := a.evaluateRunEndPolicy(ctx, span, ev, rs)
	if err != nil {
		return nil, err
	}
	policyDec := evidence.PolicyDecision{Allowed: true, Action: "allow"}
	var facts []explanation.Fact

	if len(finalReasons) > 0 {
		policyDec = evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: finalReasons}
		status = "denied"
		for _, reason := range finalReasons {
			facts = append(facts, explanation.Fact{
				Code:     explanation.CodePolicyDenied,
				Decision: explanation.DecisionDeny,
				Stage:    "graph_governance",
				Trigger:  reason,
			})
		}
	} else {
		facts = []explanation.Fact{{
			Code:     explanation.CodeGraphRunAllowed,
			Decision: explanation.DecisionAllow,
			Stage:    "graph_governance",
		}}
	}

	dec := &Decision{Action: ActionAllow, Allowed: policyDec.Allowed}
	if !policyDec.Allowed {
		dec.Action = ActionDeny
		dec.Reasons = finalReasons
	}

	if a.evidenceGen != nil {
		evRec, _ := a.evidenceGen.Generate(ctx, evidence.GenerateParams{
			CorrelationID:    ev.GraphRunID,
			SessionID:        ev.SessionID,
			TenantID:         ev.TenantID,
			AgentID:          ev.AgentID,
			InvocationType:   "graph_run",
			PolicyDecision:   policyDec,
			Cost:             ev.Cost,
			DurationMS:       a.runDuration(ev),
			Status:           status,
			FailureReason:    a.failureReason(finalReasons),
			GraphRunID:       ev.GraphRunID,
			PlanID:           a.planID(ev),
			ExplanationFacts: facts,
		})
		if evRec != nil {
			dec.EvidenceID = evRec.ID
		}
	}

	log.Info().
		Str("graph_run_id", ev.GraphRunID).
		Str("tenant_id", ev.TenantID).
		Str("status", status).
		Float64("total_cost", ev.Cost).
		Msg("graph_run_end")

	return dec, nil
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

func (a *Adapter) recordStepEvidence(ctx context.Context, ev *Event, eventLabel string, dec *Decision) string {
	if a.evidenceGen == nil {
		return ""
	}

	stepType := "graph_event"
	if ev.ToolMeta != nil {
		stepType = "tool_call"
	}

	status := "completed"
	if dec != nil && !dec.Allowed {
		status = "denied"
	}

	step, _ := a.evidenceGen.GenerateStep(ctx, evidence.StepParams{
		CorrelationID: ev.GraphRunID,
		SessionID:     ev.SessionID,
		TenantID:      ev.TenantID,
		AgentID:       ev.AgentID,
		StepIndex:     ev.StepIndex,
		Type:          stepType,
		ToolName:      eventLabel,
		Status:        status,
		GraphRunID:    ev.GraphRunID,
		PlanID:        a.planID(ev),
	})
	if step != nil {
		return step.ID
	}
	return ""
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

func (a *Adapter) failureReason(reasons []string) string {
	if len(reasons) > 0 {
		return "graph_governance_deny"
	}
	return ""
}

func (a *Adapter) planID(ev *Event) string {
	if ev.RunMeta != nil {
		return ev.RunMeta.PlanID
	}
	return ""
}

func (a *Adapter) trackDenial(graphRunID string, reasons []string, now time.Time) {
	rs, err := a.getOrCreateRunState(graphRunID, now)
	if err != nil {
		return
	}
	rs.mu.Lock()
	rs.lastSeen = now
	rs.denied = true
	for _, reason := range reasons {
		if len(rs.reasons) >= maxDenialReasonsPerRun {
			break
		}
		rs.reasons = append(rs.reasons, reason)
	}
	rs.mu.Unlock()
}

func (a *Adapter) consumeRunState(graphRunID string) *runState {
	val, ok := a.runs.LoadAndDelete(graphRunID)
	if !ok {
		return nil
	}
	rs := val.(*runState)
	a.inFlightRuns.Add(-1)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	snapshot := &runState{
		denied:    rs.denied,
		reasons:   make([]string, len(rs.reasons)),
		toolCalls: rs.toolCalls,
		maxStep:   rs.maxStep,
		lastSeen:  rs.lastSeen,
	}
	copy(snapshot.reasons, rs.reasons)
	return snapshot
}

func (a *Adapter) evaluateRunEndPolicy(ctx context.Context, span trace.Span, ev *Event, rs *runState) ([]string, error) {
	if a.policyEngine == nil {
		if rs == nil {
			return nil, nil
		}
		return rs.reasons, nil
	}

	maxStep := ev.StepIndex
	toolCalls := 0
	if rs != nil {
		if rs.maxStep > maxStep {
			maxStep = rs.maxStep
		}
		toolCalls = rs.toolCalls
	}
	input := map[string]interface{}{
		"event_type":        string(ev.Type),
		"tenant_id":         ev.TenantID,
		"agent_id":          ev.AgentID,
		"graph_run_id":      ev.GraphRunID,
		"step_index":        maxStep,
		"cost_so_far":       ev.Cost,
		"tool_calls_so_far": toolCalls,
	}
	dec, err := a.evaluatePolicy(ctx, span, input)
	if err != nil {
		return nil, err
	}

	combined := make([]string, 0, maxDenialReasonsPerRun)
	if rs != nil {
		combined = append(combined, rs.reasons...)
	}
	if !dec.Allowed {
		combined = append(combined, dec.Reasons...)
	}
	return trimUniqueReasons(combined), nil
}

func (a *Adapter) getOrCreateRunState(graphRunID string, now time.Time) (*runState, error) {
	if graphRunID == "" {
		return nil, nil
	}
	if val, ok := a.runs.Load(graphRunID); ok {
		rs := val.(*runState)
		a.touchRunState(rs, now)
		return rs, nil
	}
	if a.maxInFlightRuns > 0 && a.inFlightRuns.Load() >= int64(a.maxInFlightRuns) {
		return nil, ErrGraphRunStateLimitExceeded
	}
	rs := &runState{lastSeen: now}
	val, loaded := a.runs.LoadOrStore(graphRunID, rs)
	if loaded {
		existing := val.(*runState)
		a.touchRunState(existing, now)
		return existing, nil
	}
	a.inFlightRuns.Add(1)
	return rs, nil
}

func (a *Adapter) touchRunState(rs *runState, now time.Time) {
	rs.mu.Lock()
	rs.lastSeen = now
	rs.mu.Unlock()
}

func (a *Adapter) markStep(rs *runState, stepIndex int, now time.Time) {
	rs.mu.Lock()
	rs.lastSeen = now
	if stepIndex > rs.maxStep {
		rs.maxStep = stepIndex
	}
	rs.mu.Unlock()
}

func (a *Adapter) incrementToolCalls(rs *runState, now time.Time) int {
	rs.mu.Lock()
	rs.lastSeen = now
	rs.toolCalls++
	toolCalls := rs.toolCalls
	rs.mu.Unlock()
	return toolCalls
}

func (a *Adapter) toolCallsForRun(graphRunID string) int {
	val, ok := a.runs.Load(graphRunID)
	if !ok {
		return 0
	}
	rs := val.(*runState)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.toolCalls
}

func (a *Adapter) evictExpiredRunStates(now time.Time) {
	if a.runStateTTL <= 0 {
		return
	}
	evicted := 0
	a.runs.Range(func(key, value interface{}) bool {
		if evicted >= maxStateEvictionsPerSweep {
			return false
		}
		graphRunID := key.(string)
		rs := value.(*runState)
		rs.mu.Lock()
		expired := now.Sub(rs.lastSeen) > a.runStateTTL
		rs.mu.Unlock()
		if expired {
			if _, ok := a.runs.LoadAndDelete(graphRunID); ok {
				a.inFlightRuns.Add(-1)
				evicted++
			}
		}
		return true
	})
}

func (a *Adapter) capacityDecision(ctx context.Context, ev *Event, err error) *Decision {
	dec := &Decision{
		Action:  ActionDeny,
		Allowed: false,
		Reasons: []string{err.Error()},
	}
	dec.EvidenceID = a.recordStepEvidence(ctx, ev, "state_limit_denied", dec)
	return dec
}

func trimUniqueReasons(reasons []string) []string {
	if len(reasons) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(reasons))
	out := make([]string, 0, maxDenialReasonsPerRun)
	for _, reason := range reasons {
		if reason == "" {
			continue
		}
		if _, exists := seen[reason]; exists {
			continue
		}
		seen[reason] = struct{}{}
		out = append(out, reason)
		if len(out) >= maxDenialReasonsPerRun {
			break
		}
	}
	return out
}
