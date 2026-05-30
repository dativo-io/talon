package metrics

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

// ReconcileLoopConfig configures periodic evidence->collector reconciliation.
type ReconcileLoopConfig struct {
	Interval time.Duration
	Window   time.Duration
	Limit    int
}

// DefaultReconcileLoopConfig returns conservative default settings.
func DefaultReconcileLoopConfig() ReconcileLoopConfig {
	return ReconcileLoopConfig{
		Interval: 30 * time.Second,
		Window:   defaultReconcileWindow,
		Limit:    defaultReconcileLimit,
	}
}

// StartReconcileLoop runs periodic idempotent reconciliation until stop is called
// or ctx is cancelled.
func (c *Collector) StartReconcileLoop(ctx context.Context, store EvidenceLister, cfg ReconcileLoopConfig) (stop func()) {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = defaultReconcileWindow
	}
	if cfg.Limit <= 0 {
		cfg.Limit = defaultReconcileLimit
	}

	loopCtx, cancel := context.WithCancel(ctx)
	ticker := time.NewTicker(cfg.Interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				recovered, err := c.ReconcileFromStore(loopCtx, store, cfg.Window, cfg.Limit)
				if err != nil {
					log.Warn().Err(err).Msg("metrics_reconcile_failed")
					continue
				}
				if recovered > 0 {
					log.Info().Int("recovered_events", recovered).Msg("metrics_reconcile_recovered")
				}
			}
		}
	}()
	return cancel
}
