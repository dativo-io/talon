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

const (
	defaultReconcileWindow = 24 * time.Hour
	defaultReconcileLimit  = 10000
)

// BackfillFromStore replays the last 24 hours of evidence into the collector
// so that the dashboard has data immediately after a restart.
func (c *Collector) BackfillFromStore(ctx context.Context, store EvidenceLister) error {
	_, err := c.ReconcileFromStore(ctx, store, defaultReconcileWindow, defaultReconcileLimit)
	if err != nil {
		return fmt.Errorf("backfill list: %w", err)
	}
	return nil
}

// ReconcileFromStore rebuilds the collector from bounded evidence history.
// It is idempotent and returns the number of recovered events compared to
// the collector request total before reconciliation.
func (c *Collector) ReconcileFromStore(ctx context.Context, store EvidenceLister, window time.Duration, limit int) (int, error) {
	if store == nil {
		err := fmt.Errorf("evidence store is nil")
		c.mu.Lock()
		c.markReconcileFailure(err)
		c.mu.Unlock()
		return 0, err
	}
	if window <= 0 {
		window = defaultReconcileWindow
	}
	if limit <= 0 {
		limit = defaultReconcileLimit
	}

	now := time.Now().UTC()
	since := now.Add(-window)
	records, err := store.List(ctx, "", "", since, now, limit)
	if err != nil {
		c.mu.Lock()
		c.markReconcileFailure(err)
		c.mu.Unlock()
		return 0, fmt.Errorf("reconcile list: %w", err)
	}

	var lag time.Duration
	if len(records) > 0 {
		latest := records[0].Timestamp
		for i := 1; i < len(records); i++ {
			if records[i].Timestamp.After(latest) {
				latest = records[i].Timestamp
			}
		}
		if latest.Before(now) {
			lag = now.Sub(latest)
		}
	}

	c.mu.Lock()
	before := c.totalRequests
	c.rebuildFromEvidence(records)
	after := c.totalRequests
	recovered := after - before
	if recovered < 0 {
		recovered = 0
	}
	c.markReconcileSuccess(recovered, lag)
	c.mu.Unlock()
	return recovered, nil
}
