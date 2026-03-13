package secrets

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var secretsMeter = otel.Meter("github.com/dativo-io/talon/internal/secrets")

var accessCounter metric.Int64Counter

func init() {
	var err error
	accessCounter, err = secretsMeter.Int64Counter("talon.secrets.access.total",
		metric.WithDescription("Secret access attempts by outcome"),
		metric.WithUnit("{access}"))
	if err != nil {
		accessCounter, _ = secretsMeter.Int64Counter("talon.secrets.access.total.fallback")
	}
}

// RecordSecretAccess increments the secret access counter.
func RecordSecretAccess(ctx context.Context, secretName, agentID, outcome string) {
	accessCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("secret_name", secretName),
		attribute.String("agent_id", agentID),
		attribute.String("outcome", outcome),
	))
}
