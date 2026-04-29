package metrics

import (
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

// GatewayEventFromMap converts the legacy gateway event map into a typed event.
func GatewayEventFromMap(m map[string]interface{}) GatewayEvent {
	e := GatewayEvent{}
	mapTimestampField(m, &e)
	mapStringFields(m, &e)
	mapSliceFields(m, &e)
	mapNumericFields(m, &e)
	mapBoolFields(m, &e)
	return e
}

// GatewayEventFromEvidence creates the unified event projection from evidence.
func GatewayEventFromEvidence(e *evidence.Evidence) GatewayEvent {
	ev := GatewayEvent{
		Timestamp:        e.Timestamp,
		CallerID:         firstNonEmpty(e.RequestSourceID, e.AgentID),
		Model:            e.Execution.ModelUsed,
		Blocked:          !e.PolicyDecision.Allowed,
		CostEUR:          e.Execution.Cost,
		TokensInput:      e.Execution.Tokens.Input,
		TokensOutput:     e.Execution.Tokens.Output,
		LatencyMS:        e.Execution.DurationMS,
		TTFTMS:           e.Execution.TTFTMS,
		TPOTMS:           e.Execution.TPOTMS,
		HasError:         e.Execution.Error != "",
		TimedOut:         isTimedOutError(e.Execution.Error),
		WouldHaveBlocked: e.ObservationModeOverride,
		CacheHit:         e.CacheHit,
		CostSaved:        e.CostSaved,
		AgentID:          e.AgentID,
	}

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
	return ev
}

// SnapshotFromEvidenceRecords aggregates a standalone snapshot from evidence rows.
func SnapshotFromEvidenceRecords(records []evidence.Evidence, now time.Time) Snapshot {
	c := &Collector{
		startTime:        now,
		enforcementMode:  "standalone",
		buckets:          make(map[string]*bucket),
		callerStats:      make(map[string]*callerAccum),
		piiCounts:        make(map[string]int),
		toolFiltered:     make(map[string]int),
		shadowViolations: make(map[string]*shadowViolationAccum),
		byRiskLevel:      make(map[string]*riskLevelAccum),
		anomalousAgents:  make(map[string]bool),
	}
	for i := range records {
		c.processEvent(GatewayEventFromEvidence(&records[i]))
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
	if v, ok := m["caller_id"].(string); ok {
		e.CallerID = v
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
