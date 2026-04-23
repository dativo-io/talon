package health

import "sync/atomic"

var (
	activeEventStreams int64
	eventStreamGaps    int64
	eventReplayMisses  int64
)

// IncActiveEventStreams increments active SSE stream count.
func IncActiveEventStreams() int64 {
	return atomic.AddInt64(&activeEventStreams, 1)
}

// DecActiveEventStreams decrements active SSE stream count.
func DecActiveEventStreams() int64 {
	return atomic.AddInt64(&activeEventStreams, -1)
}

// ActiveEventStreams returns current active SSE stream count.
func ActiveEventStreams() int64 {
	return atomic.LoadInt64(&activeEventStreams)
}

// IncEventStreamGap increments count of emitted gap notifications.
func IncEventStreamGap() {
	atomic.AddInt64(&eventStreamGaps, 1)
}

// EventStreamGaps returns total number of stream gap notifications.
func EventStreamGaps() int64 {
	return atomic.LoadInt64(&eventStreamGaps)
}

// IncEventReplayMiss increments replay miss count.
func IncEventReplayMiss() {
	atomic.AddInt64(&eventReplayMisses, 1)
}

// EventReplayMisses returns total replay misses.
func EventReplayMisses() int64 {
	return atomic.LoadInt64(&eventReplayMisses)
}

// ResetEventStreamStatsForTest resets stream counters used in tests.
func ResetEventStreamStatsForTest() {
	atomic.StoreInt64(&activeEventStreams, 0)
	atomic.StoreInt64(&eventStreamGaps, 0)
	atomic.StoreInt64(&eventReplayMisses, 0)
}
