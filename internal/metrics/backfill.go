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
		ev, ok := MapToGatewayEvent(&records[i])
		if !ok {
			continue
		}
		c.processEvent(ev)
	}

	return nil
}
