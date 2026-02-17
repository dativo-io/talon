package llm

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/trace"

	talonotel "github.com/dativo-io/talon/internal/otel"
)

// BedrockProvider implements Provider for AWS Bedrock (EU region locked).
// This is a stub for MVP — full Bedrock integration will use aws-sdk-go-v2
// and be restricted to EU regions (eu-west-1, eu-central-1) for data sovereignty.
type BedrockProvider struct {
	region string
}

// NewBedrockProvider creates a Bedrock provider for the specified EU region.
func NewBedrockProvider(region string) *BedrockProvider {
	if region == "" {
		region = "eu-central-1"
	}
	return &BedrockProvider{
		region: region,
	}
}

// Name returns the provider identifier.
func (p *BedrockProvider) Name() string {
	return "bedrock"
}

// Generate is a stub that returns an error until Bedrock is fully integrated.
func (p *BedrockProvider) Generate(ctx context.Context, req *Request) (*Response, error) {
	_, span := tracer.Start(ctx, "gen_ai.generate",
		trace.WithAttributes(
			talonotel.GenAISystem.String("bedrock"),
			talonotel.GenAIRequestModel.String(req.Model),
		))
	defer span.End()

	span.RecordError(ErrNotImplemented)
	return nil, fmt.Errorf("bedrock provider (region %s): %w", p.region, ErrNotImplemented)
}

// EstimateCost estimates the cost in EUR for Bedrock models.
func (p *BedrockProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	type pricing struct {
		input  float64
		output float64
	}

	// Bedrock pricing in EUR per 1K tokens (approximate)
	prices := map[string]pricing{
		"anthropic.claude-3-sonnet-20240229-v1:0": {input: 0.003, output: 0.015},
		"anthropic.claude-3-haiku-20240307-v1:0":  {input: 0.00025, output: 0.00125},
		"amazon.titan-text-premier-v1:0":          {input: 0.0005, output: 0.0015},
	}

	pr, ok := prices[model]
	if !ok {
		// Default to Sonnet pricing
		pr = pricing{input: 0.003, output: 0.015}
	}

	inputCost := (float64(inputTokens) / 1000.0) * pr.input
	outputCost := (float64(outputTokens) / 1000.0) * pr.output

	return inputCost + outputCost
}
