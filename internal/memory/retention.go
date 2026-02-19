package memory

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/policy"
)

// RunRetention purges expired entries and enforces max_entries for all agents
// in the store, using the provided policy for retention_days and max_entries.
// This is designed to be called periodically (e.g., daily) from talon serve.
func RunRetention(ctx context.Context, store *Store, pol *policy.Policy) {
	if store == nil || pol == nil || pol.Memory == nil || !pol.Memory.Enabled {
		return
	}

	ctx, span := tracer.Start(ctx, "memory.retention",
		trace.WithAttributes(
			attribute.Int("retention_days", pol.Memory.RetentionDays),
			attribute.Int("max_entries", pol.Memory.MaxEntries),
		),
	)
	defer span.End()

	agents, err := store.DistinctAgents(ctx)
	if err != nil {
		log.Error().Err(err).Msg("retention: failed to list agents")
		return
	}

	var totalPurged, totalEvicted int64
	for _, pair := range agents {
		tenantID, agentID := pair[0], pair[1]

		if pol.Memory.RetentionDays > 0 {
			purged, err := store.PurgeExpired(ctx, tenantID, agentID, pol.Memory.RetentionDays)
			if err != nil {
				log.Error().Err(err).Str("tenant_id", tenantID).Str("agent_id", agentID).Msg("retention: purge failed")
			}
			totalPurged += purged
		}

		if pol.Memory.MaxEntries > 0 {
			evicted, err := store.EnforceMaxEntries(ctx, tenantID, agentID, pol.Memory.MaxEntries)
			if err != nil {
				log.Error().Err(err).Str("tenant_id", tenantID).Str("agent_id", agentID).Msg("retention: max_entries enforcement failed")
			}
			totalEvicted += evicted
		}
	}

	if totalPurged > 0 || totalEvicted > 0 {
		log.Info().
			Int64("purged", totalPurged).
			Int64("evicted", totalEvicted).
			Int("agents", len(agents)).
			Msg("memory_retention_completed")
	}
}

// StartRetentionLoop runs retention every interval in a goroutine.
// Returns a cancel function to stop the loop.
func StartRetentionLoop(ctx context.Context, store *Store, pol *policy.Policy, interval time.Duration) func() {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Run immediately on start, then on each tick
		RunRetention(ctx, store, pol)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				RunRetention(ctx, store, pol)
			}
		}
	}()
	return cancel
}
