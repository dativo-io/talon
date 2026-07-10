package metrics

import (
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/events"
	"github.com/dativo-io/talon/internal/evidence"
)

// MapToGatewayEvent converts supported event payloads into a GatewayEvent.
func MapToGatewayEvent(input interface{}) (GatewayEvent, bool) {
	return mapToGatewayEvent(input)
}

// GatewayEventFromMap converts the legacy gateway event map into a typed event.
func GatewayEventFromMap(m map[string]interface{}) GatewayEvent {
	e, ok := mapToGatewayEvent(m)
	if !ok {
		return GatewayEvent{}
	}
	return e
}

// GatewayEventFromEvidence creates the unified event projection from evidence.
func GatewayEventFromEvidence(e *evidence.Evidence) GatewayEvent {
	ev, ok := mapToGatewayEvent(e)
	if !ok {
		return GatewayEvent{}
	}
	return ev
}

func mapToGatewayEvent(input interface{}) (GatewayEvent, bool) {
	switch v := input.(type) {
	case GatewayEvent:
		return v, true
	case *GatewayEvent:
		if v == nil {
			return GatewayEvent{}, false
		}
		return *v, true
	case map[string]interface{}:
		ev := GatewayEvent{}
		mapTimestampField(v, &ev)
		mapStringFields(v, &ev)
		mapSliceFields(v, &ev)
		mapNumericFields(v, &ev)
		mapBoolFields(v, &ev)
		return ev, true
	case evidence.Evidence:
		return gatewayEventFromEvidence(&v), true
	case *evidence.Evidence:
		if v == nil {
			return GatewayEvent{}, false
		}
		return gatewayEventFromEvidence(v), true
	case events.OperationalEvent:
		return GatewayEventFromOperationalEvent(v), true
	case *events.OperationalEvent:
		if v == nil {
			return GatewayEvent{}, false
		}
		return GatewayEventFromOperationalEvent(*v), true
	default:
		return GatewayEvent{}, false
	}
}

// GatewayEventFromOperationalEvent converts the canonical operational projection into
// dashboard metrics event shape.
func GatewayEventFromOperationalEvent(ev events.OperationalEvent) GatewayEvent {
	return GatewayEvent{
		EvidenceID:    ev.EvidenceID,
		Timestamp:     ev.Timestamp,
		AgentName:      firstNonEmpty(ev.Agent, ev.AgentID),
		Model:         ev.Model,
		Blocked:       ev.Decision == "blocked",
		CostEUR:       ev.CostEUR,
		LatencyMS:     ev.DurationMS,
		HasError:      ev.HasError || ev.Decision == "error",
		TimedOut:      isTimedOutError(ev.ReasonText),
		PIIDetected:   append([]string(nil), ev.PIIDetected...),
		ToolsFiltered: append([]string(nil), ev.ToolsFiltered...),
		CacheHit:      ev.CacheHit,
		CostSaved:     ev.CostSaved,
		AgentID:       ev.AgentID,
	}
}

func gatewayEventFromEvidence(e *evidence.Evidence) GatewayEvent {
	ev := GatewayEventFromOperationalEvent(events.FromEvidence(e))
	ev.AgentName = firstNonEmpty(e.RequestSourceID, ev.AgentName)
	ev.TokensInput = e.Execution.Tokens.Input
	ev.TokensOutput = e.Execution.Tokens.Output
	ev.TTFTMS = e.Execution.TTFTMS
	ev.TPOTMS = e.Execution.TPOTMS
	ev.EvidenceID = e.ID
	ev.WouldHaveBlocked = e.ObservationModeOverride
	ev.TimedOut = isTimedOutError(e.Execution.Error)

	if len(e.Classification.PIIDetected) > 0 {
		ev.PIIDetected = append([]string(nil), e.Classification.PIIDetected...)
	}
	if e.Classification.PIIRedacted {
		ev.PIIAction = "redact"
	}
	if e.ToolGovernance != nil {
		ev.ToolsRequested = append([]string(nil), e.ToolGovernance.ToolsRequested...)
		ev.ToolsFiltered = append([]string(nil), e.ToolGovernance.ToolsFiltered...)
	}
	for _, sv := range e.ShadowViolations {
		ev.ShadowViolations = append(ev.ShadowViolations, sv.Type)
	}
	// Session/orchestration projection (#199): previously dropped, which made
	// session stats impossible to rebuild from evidence. Attribution only.
	ev.SessionID = e.SessionID
	if e.Orchestration != nil {
		ev.SessionSource = e.Orchestration.SessionSource
		ev.OrchAgentID = e.Orchestration.AgentID
		ev.OrchClient = e.Orchestration.Client
	}
	if ev.Blocked {
		ev.DenyReasonCode = denyReasonCode(e.PolicyDecision.Reasons)
	}
	return ev
}

// denyReasonCode classifies a deny by the machine-code prefix convention
// ("session_budget_exceeded: ...", "budget_exceeded: ...", bare egress codes)
// so session denials don't lump under a generic policy_deny bucket (#199).
// Unrecognized shapes fall back to "policy_deny".
func denyReasonCode(reasons []string) string {
	if len(reasons) == 0 {
		return "policy_deny"
	}
	code := reasons[0]
	if i := strings.IndexByte(code, ':'); i >= 0 {
		code = code[:i]
	}
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 64 {
		return "policy_deny"
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return "policy_deny"
		}
	}
	return code
}

// SnapshotFromEvidenceRecords aggregates a standalone snapshot from evidence rows.
func SnapshotFromEvidenceRecords(records []evidence.Evidence, now time.Time) Snapshot {
	c := &Collector{
		startTime:        now,
		enforcementMode:  "standalone",
		buckets:          make(map[string]*bucket),
		agentStats:      make(map[string]*agentAccum),
		piiCounts:        make(map[string]int),
		toolFiltered:     make(map[string]int),
		shadowViolations: make(map[string]*shadowViolationAccum),
		byRiskLevel:      make(map[string]*riskLevelAccum),
		anomalousAgents:  make(map[string]bool),
	}
	for i := range records {
		c.processEvent(GatewayEventFromEvidence(&records[i]))
		if c.currency == "" {
			// Standalone snapshots have no pricing table in scope: take the
			// cost unit from the records themselves (#216).
			c.currency = records[i].Execution.Currency
		}
	}
	snap := c.buildInMemorySnapshot()
	snap.GeneratedAt = now.UTC()
	snap.Uptime = "standalone"
	return snap
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "unknown"
}

func isTimedOutError(execErr string) bool {
	errLower := strings.ToLower(execErr)
	return strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline exceeded")
}

func mapTimestampField(m map[string]interface{}, e *GatewayEvent) {
	if v, ok := m["timestamp"].(time.Time); ok {
		e.Timestamp = v
		return
	}
	e.Timestamp = time.Now().UTC()
}

func mapStringFields(m map[string]interface{}, e *GatewayEvent) {
	if v, ok := m["agent_name"].(string); ok {
		e.AgentName = v
	}
	if v, ok := m["model"].(string); ok {
		e.Model = v
	}
	if v, ok := m["pii_action"].(string); ok {
		e.PIIAction = v
	}
	if v, ok := m["enforcement_mode"].(string); ok {
		e.EnforcementMode = v
	}
	if v, ok := m["evidence_id"].(string); ok {
		e.EvidenceID = v
	}
}

func mapSliceFields(m map[string]interface{}, e *GatewayEvent) {
	if v, ok := m["pii_detected"].([]string); ok {
		e.PIIDetected = v
	}
	if v, ok := m["tools_requested"].([]string); ok {
		e.ToolsRequested = v
	}
	if v, ok := m["tools_filtered"].([]string); ok {
		e.ToolsFiltered = v
	}
	if v, ok := m["shadow_violations"].([]string); ok {
		e.ShadowViolations = v
	}
}

func mapNumericFields(m map[string]interface{}, e *GatewayEvent) {
	if v, ok := m["cost_eur"].(float64); ok {
		e.CostEUR = v
	}
	if v, ok := m["tokens_input"].(int); ok {
		e.TokensInput = v
	}
	if v, ok := m["tokens_output"].(int); ok {
		e.TokensOutput = v
	}
	if v, ok := m["latency_ms"].(int64); ok {
		e.LatencyMS = v
	}
	if v, ok := m["cost_saved"].(float64); ok {
		e.CostSaved = v
	}
	if v, ok := m["ttft_ms"].(int64); ok {
		e.TTFTMS = v
	}
	if v, ok := m["tpot_ms"].(float64); ok {
		e.TPOTMS = v
	}
}

func mapBoolFields(m map[string]interface{}, e *GatewayEvent) {
	if v, ok := m["blocked"].(bool); ok {
		e.Blocked = v
	}
	if v, ok := m["would_have_blocked"].(bool); ok {
		e.WouldHaveBlocked = v
	}
	if v, ok := m["has_error"].(bool); ok {
		e.HasError = v
	}
	if v, ok := m["timed_out"].(bool); ok {
		e.TimedOut = v
	}
	if v, ok := m["cache_hit"].(bool); ok {
		e.CacheHit = v
	}
}
