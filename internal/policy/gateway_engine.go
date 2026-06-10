package policy

import (
	"context"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var gatewayAccessPolicy = []regoPolicy{
	{file: "rego/gateway_access.rego", query: "data.talon.policy.gateway_access.deny"},
	{file: "rego/gateway_egress.rego", query: "data.talon.policy.gateway_egress.deny"},
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
	start := time.Now()
	ctx, span := tracer.Start(ctx, "policy.gateway.evaluate",
		trace.WithAttributes(
			attribute.String("input.model", stringOr(input["model"])),
			attribute.String("input.caller_name", stringOr(input["caller_name"])),
			attribute.String("input.provider", stringOr(input["provider"])),
			attribute.String("input.destination_region", stringOr(input["destination_region"])),
		))
	defer span.End()

	for _, rp := range gatewayAccessPolicy {
		fileReasons, evalErr := evaluateDenyReasons(ctx, e.prepared, rp.file, input)
		if evalErr != nil {
			span.RecordError(evalErr)
			span.SetStatus(codes.Error, evalErr.Error())
			RecordPolicyEvaluation(ctx, "error", stringOr(input["tenant_id"]), stringOr(input["caller_name"]), time.Since(start))
			return false, nil, evalErr
		}
		reasons = append(reasons, fileReasons...)
	}
	allowed = len(reasons) == 0
	decision := "allow"
	if !allowed {
		decision = "deny"
	}
	RecordPolicyEvaluation(ctx, decision, stringOr(input["tenant_id"]), stringOr(input["caller_name"]), time.Since(start))
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
