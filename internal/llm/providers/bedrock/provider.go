package bedrock

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/llm/providers/bedrock")

// BedrockProvider implements llm.Provider for AWS Bedrock (Converse API).
//
//nolint:revive // type name matches package for clarity at call sites
type BedrockProvider struct {
	client *bedrockruntime.Client
	region string
}

type bedrockConfig struct {
	Region string `yaml:"region"`
}

func init() {
	llm.Register("bedrock", func(configYAML []byte) (llm.Provider, error) {
		region := "eu-central-1"
		if len(configYAML) > 0 {
			var cfg bedrockConfig
			if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
				return nil, fmt.Errorf("bedrock config: %w", err)
			}
			if strings.TrimSpace(cfg.Region) != "" {
				region = cfg.Region
			}
		}
		ctx := context.Background()
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("bedrock aws config: %w", err)
		}
		client := bedrockruntime.NewFromConfig(cfg)
		return &BedrockProvider{client: client, region: region}, nil
	})
}

// NewBedrockProvider creates a Bedrock provider for the specified region.
func NewBedrockProvider(region string) *BedrockProvider {
	if region == "" {
		region = "eu-central-1"
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return &BedrockProvider{region: region}
	}
	return &BedrockProvider{client: bedrockruntime.NewFromConfig(cfg), region: region}
}

// Name returns the provider identifier.
func (p *BedrockProvider) Name() string {
	return "bedrock"
}

// Metadata returns static compliance and identity information.
func (p *BedrockProvider) Metadata() llm.ProviderMetadata {
	return bedrockMetadata()
}

// Generate sends a completion request to Bedrock using the Converse API.
//
//nolint:gocyclo // model/role mapping and error handling branches
func (p *BedrockProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	if p.client == nil {
		return nil, fmt.Errorf("bedrock: client not initialized (check AWS credentials)")
	}
	ctx, span := tracer.Start(ctx, "gen_ai.generate",
		trace.WithAttributes(
			talonotel.GenAISystem.String("bedrock"),
			talonotel.GenAIRequestModel.String(req.Model),
		))
	defer span.End()

	ctx, cancel := context.WithTimeout(ctx, llm.TimeoutLLMCall)
	defer cancel()

	messages := make([]types.Message, 0, len(req.Messages))
	for _, msg := range req.Messages {
		role := types.ConversationRoleUser
		if msg.Role == "assistant" {
			role = types.ConversationRoleAssistant
		}
		if msg.Role == "system" {
			continue
		}
		messages = append(messages, types.Message{
			Role: role,
			Content: []types.ContentBlock{
				&types.ContentBlockMemberText{Value: msg.Content},
			},
		})
	}
	if len(messages) == 0 {
		messages = append(messages, types.Message{
			Role:    types.ConversationRoleUser,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: ""}},
		})
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 || maxTokens > math.MaxInt32 {
		maxTokens = 4096
	}
	maxTokens32 := int32(maxTokens) // #nosec G115 -- clamped to math.MaxInt32 above
	inferenceConfig := &types.InferenceConfiguration{
		MaxTokens:     aws.Int32(maxTokens32),
		Temperature:   aws.Float32(float32(req.Temperature)),
		TopP:          nil,
		StopSequences: nil,
	}

	input := &bedrockruntime.ConverseInput{
		ModelId:         aws.String(req.Model),
		Messages:        messages,
		InferenceConfig: inferenceConfig,
	}

	out, err := p.client.Converse(ctx, input)
	if err != nil {
		span.RecordError(err)
		errStr := err.Error()
		if strings.Contains(errStr, "ThrottlingException") || strings.Contains(errStr, "429") {
			return nil, &llm.ProviderError{Code: "rate_limit", Message: errStr, Provider: "bedrock"}
		}
		if strings.Contains(errStr, "UnsupportedAuthentication") || strings.Contains(errStr, "403") || strings.Contains(errStr, "401") {
			return nil, &llm.ProviderError{Code: "auth_failed", Message: errStr, Provider: "bedrock"}
		}
		return nil, fmt.Errorf("bedrock converse: %w", err)
	}

	var content string
	var inputTokens, outputTokens int
	if out.Output != nil {
		if msg, ok := out.Output.(*types.ConverseOutputMemberMessage); ok {
			for _, block := range msg.Value.Content {
				if t, ok := block.(*types.ContentBlockMemberText); ok {
					content += t.Value
				}
			}
		}
	}
	if out.Usage != nil {
		if out.Usage.InputTokens != nil {
			inputTokens = int(*out.Usage.InputTokens)
		}
		if out.Usage.OutputTokens != nil {
			outputTokens = int(*out.Usage.OutputTokens)
		}
	}

	span.SetAttributes(
		talonotel.GenAIUsageInputTokens.Int(inputTokens),
		talonotel.GenAIUsageOutputTokens.Int(outputTokens),
		talonotel.GenAIResponseFinishReason.String(string(out.StopReason)),
	)

	finishReason := "stop"
	if out.StopReason != "" {
		finishReason = string(out.StopReason)
	}

	return &llm.Response{
		Content:      content,
		FinishReason: finishReason,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		Model:        req.Model,
	}, nil
}

// Stream is not implemented for Bedrock in this version.
func (p *BedrockProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	close(ch)
	return llm.ErrNotImplemented
}

// EstimateCost estimates the cost in EUR for Bedrock models.
func (p *BedrockProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	type pricing struct {
		input  float64
		output float64
	}
	prices := map[string]pricing{
		"anthropic.claude-3-sonnet-20240229-v1:0": {input: 0.003, output: 0.015},
		"anthropic.claude-3-haiku-20240307-v1:0":  {input: 0.00025, output: 0.00125},
		"amazon.titan-text-premier-v1:0":          {input: 0.0005, output: 0.0015},
	}
	pr, ok := prices[model]
	if !ok {
		pr = pricing{input: 0.003, output: 0.015}
	}
	return (float64(inputTokens)/1000.0)*pr.input + (float64(outputTokens)/1000.0)*pr.output
}

// ValidateConfig checks that region is set.
func (p *BedrockProvider) ValidateConfig() error {
	if strings.TrimSpace(p.region) == "" {
		return fmt.Errorf("bedrock: region is required")
	}
	if p.client == nil {
		return fmt.Errorf("bedrock: AWS credentials not available")
	}
	return nil
}

// HealthCheck performs a lightweight liveness check without calling the Converse API.
// The Bedrock Runtime API has no free liveness endpoint; ListFoundationModels lives on
// the control-plane client (service/bedrock), which we do not use. Do NOT use Converse
// (e.g. a minimal prompt to anthropic.claude-3-haiku) for health checks—it is billable
// and would incur ongoing inference costs when called periodically (e.g. every 30s).
// We only verify the client is initialized; callers get nil (healthy) or ErrProviderUnhealthy.
func (p *BedrockProvider) HealthCheck(ctx context.Context) error {
	if p.client == nil {
		return llm.ErrProviderUnhealthy
	}
	return nil
}

// WithHTTPClient returns a copy of the provider with a custom HTTP client (for tests).
func (p *BedrockProvider) WithHTTPClient(client *http.Client) llm.Provider {
	if p.client == nil {
		return &BedrockProvider{region: p.region}
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(p.region), config.WithHTTPClient(client))
	if err != nil {
		return &BedrockProvider{region: p.region}
	}
	return &BedrockProvider{client: bedrockruntime.NewFromConfig(cfg), region: p.region}
}
