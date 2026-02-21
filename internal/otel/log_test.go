package otel

import (
	"context"
	"io"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestTraceContextFrom_NoSpan(t *testing.T) {
	traceID, spanID := TraceContextFrom(context.Background())
	assert.Empty(t, traceID)
	assert.Empty(t, spanID)
}

func TestLogTraceFields_NoPanic(t *testing.T) {
	logger := zerolog.New(io.Discard)
	ev := logger.Info()
	LogTraceFields(context.Background())(ev)
}
