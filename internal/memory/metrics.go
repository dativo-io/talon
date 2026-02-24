package memory

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var meter = otel.Meter("github.com/dativo-io/talon/internal/memory")

var (
	writesTotal                metric.Int64Counter
	writesDenied               metric.Int64Counter
	conflictsFound             metric.Int64Counter
	readsTotal                 metric.Int64Counter
	entriesGauge               metric.Int64Gauge
	dedupSkips                 metric.Int64Counter
	consolidationNoops         metric.Int64Counter
	consolidationInvalidations metric.Int64Counter
	consolidationUpdates       metric.Int64Counter
)

func init() {
	var err error
	writesTotal, err = meter.Int64Counter("memory.writes.total",
		metric.WithDescription("Total memory write operations"))
	if err != nil {
		writesTotal, _ = meter.Int64Counter("memory.writes.total.fallback")
	}

	writesDenied, err = meter.Int64Counter("memory.writes.denied",
		metric.WithDescription("Memory writes denied by governance"))
	if err != nil {
		writesDenied, _ = meter.Int64Counter("memory.writes.denied.fallback")
	}

	conflictsFound, err = meter.Int64Counter("memory.conflicts.detected",
		metric.WithDescription("Memory conflicts detected"))
	if err != nil {
		conflictsFound, _ = meter.Int64Counter("memory.conflicts.detected.fallback")
	}

	readsTotal, err = meter.Int64Counter("memory.reads.total",
		metric.WithDescription("Total memory read operations"))
	if err != nil {
		readsTotal, _ = meter.Int64Counter("memory.reads.total.fallback")
	}

	entriesGauge, err = meter.Int64Gauge("memory.entries.count",
		metric.WithDescription("Current number of memory entries"))
	if err != nil {
		entriesGauge, _ = meter.Int64Gauge("memory.entries.count.fallback")
	}

	dedupSkips, err = meter.Int64Counter("memory.dedup.skips",
		metric.WithDescription("Memory writes skipped due to input-hash deduplication"))
	if err != nil {
		dedupSkips, _ = meter.Int64Counter("memory.dedup.skips.fallback")
	}

	consolidationNoops, err = meter.Int64Counter("memory.consolidation.noops",
		metric.WithDescription("Consolidation: NOOP (near-duplicate skipped)"))
	if err != nil {
		consolidationNoops, _ = meter.Int64Counter("memory.consolidation.noops.fallback")
	}
	consolidationInvalidations, err = meter.Int64Counter("memory.consolidation.invalidations",
		metric.WithDescription("Consolidation: old entry invalidated (superseded)"))
	if err != nil {
		consolidationInvalidations, _ = meter.Int64Counter("memory.consolidation.invalidations.fallback")
	}
	consolidationUpdates, err = meter.Int64Counter("memory.consolidation.updates",
		metric.WithDescription("Consolidation: existing entry updated with new content"))
	if err != nil {
		consolidationUpdates, _ = meter.Int64Counter("memory.consolidation.updates.fallback")
	}
}

// DedupSkipsAdd records memory writes skipped due to input-hash deduplication.
func DedupSkipsAdd(ctx context.Context, n int64) {
	dedupSkips.Add(ctx, n)
}
