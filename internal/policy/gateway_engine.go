package policy

import (
	"context"

	"github.com/open-policy-agent/opa/rego"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var gatewayAccessPolicy = []regoPolicy{
	{file: "rego/gateway_access.rego", query: "data.talon.policy.gateway_access.deny"},
}

// GatewayEngine evaluates gateway-specific access policy (model allowlist, cost, data tier).
type GatewayEngine struct {
	prepared map[string]rego.PreparedEvalQuery
}

// NewGatewayEngine creates a policy engine for gateway requests.
// No OPA data is required; input is fully built by the gateway.
func NewGatewayEngine(ctx context.Context) (*GatewayEngine, error) {
	ctx, span := tracer.Start(ctx, "policy.gateway_engine.new")
	defer span.End()

	prepared, err := prepareRegoQueries(ctx, gatewayAccessPolicy, map[string]interface{}{})
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	span.SetAttributes(attribute.Int("policy.gateway.prepared_count", len(prepared)))
	return &GatewayEngine{prepared: prepared}, nil
}

// EvaluateGateway runs the gateway access policy and returns whether the request is allowed and any deny reasons.
func (e *GatewayEngine) EvaluateGateway(ctx context.Context, input map[string]interface{}) (allowed bool, reasons []string, err error) {
	ctx, span := tracer.Start(ctx, "policy.gateway.evaluate",
		trace.WithAttributes(
			attribute.String("input.model", stringOr(input["model"])),
			attribute.String("input.caller_name", stringOr(input["caller_name"])),
		))
	defer span.End()

	reasons, err = evaluateDenyReasons(ctx, e.prepared, "rego/gateway_access.rego", input)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, nil, err
	}
	allowed = len(reasons) == 0
	span.SetAttributes(
		attribute.Bool("policy.allowed", allowed),
		attribute.Int("policy.deny_reasons", len(reasons)),
	)
	if allowed {
		span.SetStatus(codes.Ok, "gateway policy passed")
	}
	return allowed, reasons, nil
}

func stringOr(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
