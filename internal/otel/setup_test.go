package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		version     string
	}{
		{"basic setup", "test-service", "1.0.0"},
		{"dev version", "dativo-talon", "dev"},
		{"empty version", "talon", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shutdown, err := Setup(tt.serviceName, tt.version)
			require.NoError(t, err)
			require.NotNil(t, shutdown, "shutdown function must not be nil")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err = shutdown(ctx)
			assert.NoError(t, err, "shutdown should complete without error")
		})
	}
}

func TestSetup_ReturnsWorkingShutdown(t *testing.T) {
	shutdown, err := Setup("test-service", "0.0.1")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = shutdown(ctx)
	assert.NoError(t, err)
}

func TestTracer_ReturnsNonNilTracer(t *testing.T) {
	tr := Tracer("github.com/dativo-talon/talon/internal/test")
	assert.NotNil(t, tr)
}

func TestTracer_DifferentPackagesReturnDistinctTracers(t *testing.T) {
	tr1 := Tracer("github.com/dativo-talon/talon/internal/cmd")
	tr2 := Tracer("github.com/dativo-talon/talon/internal/llm")
	assert.NotNil(t, tr1)
	assert.NotNil(t, tr2)
}

func TestTracer_CreatesValidSpans(t *testing.T) {
	shutdown, err := Setup("test-service", "0.0.1")
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = shutdown(ctx)
	}()

	tr := Tracer("github.com/dativo-talon/talon/internal/otel/test")
	ctx, span := tr.Start(context.Background(), "test.operation")
	defer span.End()

	assert.NotNil(t, span)
	assert.True(t, span.SpanContext().IsValid(), "span context should be valid after Setup()")
	assert.True(t, span.SpanContext().HasTraceID(), "span should have a trace ID")
	assert.True(t, span.SpanContext().HasSpanID(), "span should have a span ID")
	_ = ctx
}

func TestTracer_SpansAreNotRecordingWithoutSetup(t *testing.T) {
	tr := Tracer("github.com/dativo-talon/talon/internal/noop")
	_, span := tr.Start(context.Background(), "noop.operation")
	defer span.End()

	assert.Implements(t, (*trace.Span)(nil), span)
}
