package gateway

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var gatewayMeter = otel.Meter("github.com/dativo-io/talon/internal/gateway")

var (
	gatewayRequestsCounter  metric.Int64Counter
	gatewayErrorsCounter    metric.Int64Counter
	dataTierCounter         metric.Int64Counter
	toolGovernanceCounter   metric.Int64Counter
	cacheHitsCounter        metric.Int64Counter
	cacheMissesCounter      metric.Int64Counter
	shadowViolationsCounter metric.Int64Counter
	budgetUtilizationGauge  metric.Float64Gauge
	budgetAlertsCounter     metric.Int64Counter

	gwMetricsOnce       sync.Once
	gwMetricsRegistered bool
)

func initGatewayMetrics() {
	var err error

	gatewayRequestsCounter, err = gatewayMeter.Int64Counter("talon.gateway.requests.total",
		metric.WithDescription("Total gateway requests"),
		metric.WithUnit("{request}"))
	if err != nil {
		return
	}

	gatewayErrorsCounter, err = gatewayMeter.Int64Counter("talon.gateway.errors.total",
		metric.WithDescription("Gateway errors by type"),
		metric.WithUnit("{error}"))
	if err != nil {
		return
	}

	dataTierCounter, err = gatewayMeter.Int64Counter("talon.data_tier.requests",
		metric.WithDescription("Requests by data classification tier"),
		metric.WithUnit("{request}"))
	if err != nil {
		return
	}

	toolGovernanceCounter, err = gatewayMeter.Int64Counter("talon.tools.governance.total",
		metric.WithDescription("Tool governance decisions"),
		metric.WithUnit("{decision}"))
	if err != nil {
		return
	}

	cacheHitsCounter, err = gatewayMeter.Int64Counter("talon.cache.hits",
		metric.WithDescription("Semantic cache hits"),
		metric.WithUnit("{hit}"))
	if err != nil {
		return
	}

	cacheMissesCounter, err = gatewayMeter.Int64Counter("talon.cache.misses",
		metric.WithDescription("Semantic cache misses"),
		metric.WithUnit("{miss}"))
	if err != nil {
		return
	}

	shadowViolationsCounter, err = gatewayMeter.Int64Counter("talon.shadow.violations.total",
		metric.WithDescription("Shadow mode violations (would-have-blocked)"),
		metric.WithUnit("{violation}"))
	if err != nil {
		return
	}

	budgetUtilizationGauge, err = gatewayMeter.Float64Gauge("talon.budget.utilization",
		metric.WithDescription("Budget utilization percentage"),
		metric.WithUnit("%"))
	if err != nil {
		return
	}

	budgetAlertsCounter, err = gatewayMeter.Int64Counter("talon.budget.alerts.total",
		metric.WithDescription("Budget threshold breach alerts"),
		metric.WithUnit("{alert}"))
	if err != nil {
		return
	}

	gwMetricsRegistered = true
}

func ensureGatewayMetrics() {
	gwMetricsOnce.Do(initGatewayMetrics)
}

// RecordGatewayRequest increments the gateway request counter.
func RecordGatewayRequest(ctx context.Context, caller, model, provider, status string) {
	ensureGatewayMetrics()
	if !gwMetricsRegistered {
		return
	}
	gatewayRequestsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("caller", caller),
		attribute.String("model", model),
		attribute.String("gen_ai.system", provider),
		attribute.String("status", status),
	))
}

// RecordGatewayError increments the gateway error counter by error type.
func RecordGatewayError(ctx context.Context, errorType string) {
	ensureGatewayMetrics()
	if !gwMetricsRegistered {
		return
	}
	gatewayErrorsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("error_type", errorType),
	))
}

// RecordDataTier increments the data tier request counter.
func RecordDataTier(ctx context.Context, tier int, caller string) {
	ensureGatewayMetrics()
	if !gwMetricsRegistered {
		return
	}
	dataTierCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.Int("tier", tier),
		attribute.String("caller", caller),
	))
}

// RecordToolGovernance increments the tool governance counter per tool and action.
func RecordToolGovernance(ctx context.Context, tool, action string) {
	ensureGatewayMetrics()
	if !gwMetricsRegistered {
		return
	}
	toolGovernanceCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tool", tool),
		attribute.String("action", action),
	))
}

// RecordCacheResult increments cache hit or miss counter.
func RecordCacheResult(ctx context.Context, tenantID string, hit bool) {
	ensureGatewayMetrics()
	if !gwMetricsRegistered {
		return
	}
	if hit {
		cacheHitsCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("tenant_id", tenantID),
		))
	} else {
		cacheMissesCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("tenant_id", tenantID),
		))
	}
}

// RecordShadowViolation increments the shadow violation counter.
func RecordShadowViolation(ctx context.Context, violationType string) {
	ensureGatewayMetrics()
	if !gwMetricsRegistered {
		return
	}
	shadowViolationsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("violation_type", violationType),
	))
}

// RecordBudgetUtilization sets the budget utilization gauge.
func RecordBudgetUtilization(ctx context.Context, tenantID, period string, percent float64) {
	ensureGatewayMetrics()
	if !gwMetricsRegistered {
		return
	}
	budgetUtilizationGauge.Record(ctx, percent, metric.WithAttributes(
		attribute.String("tenant_id", tenantID),
		attribute.String("period", period),
	))
}

// RecordBudgetAlert increments the budget alert counter when a threshold is crossed.
func RecordBudgetAlert(ctx context.Context, tenantID string, threshold float64) {
	ensureGatewayMetrics()
	if !gwMetricsRegistered {
		return
	}
	budgetAlertsCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tenant_id", tenantID),
		attribute.Float64("threshold", threshold),
	))
}
