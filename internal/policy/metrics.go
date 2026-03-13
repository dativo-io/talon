package policy

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var policyMeter = otel.Meter("github.com/dativo-io/talon/internal/policy")

var (
	evaluationsCounter metric.Int64Counter
	evaluationDuration metric.Float64Histogram
)

func init() {
	var err error
	evaluationsCounter, err = policyMeter.Int64Counter("talon.policy.evaluations.total",
		metric.WithDescription("Total policy evaluations by decision"),
		metric.WithUnit("{evaluation}"))
	if err != nil {
		evaluationsCounter, _ = policyMeter.Int64Counter("talon.policy.evaluations.total.fallback")
	}

	evaluationDuration, err = policyMeter.Float64Histogram("talon.policy.evaluation.duration",
		metric.WithDescription("Policy evaluation latency"),
		metric.WithUnit("ms"))
	if err != nil {
		evaluationDuration, _ = policyMeter.Float64Histogram("talon.policy.evaluation.duration.fallback")
	}
}

// RecordPolicyEvaluation records the result and duration of a policy evaluation.
func RecordPolicyEvaluation(ctx context.Context, decision string, tenantID, agentID string, elapsed time.Duration) {
	evaluationsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("decision", decision),
		attribute.String("tenant_id", tenantID),
		attribute.String("agent_id", agentID),
	))
	evaluationDuration.Record(ctx, float64(elapsed.Milliseconds()), metric.WithAttributes(
		attribute.String("tenant_id", tenantID),
	))
}
