package memory

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var meter = otel.Meter("github.com/dativo-io/talon/internal/memory")

var (
	writesTotal    metric.Int64Counter
	writesDenied   metric.Int64Counter
	conflictsFound metric.Int64Counter
	readsTotal     metric.Int64Counter
	entriesGauge   metric.Int64Gauge
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
}
