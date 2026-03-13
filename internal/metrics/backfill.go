package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

// EvidenceLister is satisfied by *evidence.Store (List method).
type EvidenceLister interface {
	List(ctx context.Context, tenantID, agentID string, from, to time.Time, limit int) ([]evidence.Evidence, error)
}

// BackfillFromStore replays the last 24 hours of evidence into the collector
// so that the dashboard has data immediately after a restart.
func (c *Collector) BackfillFromStore(ctx context.Context, store EvidenceLister) error {
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)

	records, err := store.List(ctx, "", "", since, now, 10000)
	if err != nil {
		return fmt.Errorf("backfill list: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range records {
		ev := evidenceToEvent(&records[i])
		c.processEvent(ev)
	}

	return nil
}

func evidenceToEvent(e *evidence.Evidence) GatewayEvent {
	ev := GatewayEvent{
		Timestamp:        e.Timestamp,
		CallerID:         e.RequestSourceID,
		Model:            e.Execution.ModelUsed,
		Blocked:          !e.PolicyDecision.Allowed,
		CostEUR:          e.Execution.Cost,
		TokensInput:      e.Execution.Tokens.Input,
		TokensOutput:     e.Execution.Tokens.Output,
		LatencyMS:        e.Execution.DurationMS,
		TTFTMS:           e.Execution.TTFTMS,
		TPOTMS:           e.Execution.TPOTMS,
		HasError:         e.Execution.Error != "",
		WouldHaveBlocked: e.ObservationModeOverride,
		CacheHit:         e.CacheHit,
		CostSaved:        e.CostSaved,
	}

	if len(e.Classification.PIIDetected) > 0 {
		ev.PIIDetected = e.Classification.PIIDetected
	}
	if e.Classification.PIIRedacted {
		ev.PIIAction = "redact"
	}

	if e.ToolGovernance != nil {
		ev.ToolsRequested = e.ToolGovernance.ToolsRequested
		ev.ToolsFiltered = e.ToolGovernance.ToolsFiltered
	}

	for _, sv := range e.ShadowViolations {
		ev.ShadowViolations = append(ev.ShadowViolations, sv.Type)
	}

	if ev.CallerID == "" && e.AgentID != "" {
		ev.CallerID = e.AgentID
	}

	return ev
}
