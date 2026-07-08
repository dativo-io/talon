package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/llm"
	talonotel "github.com/dativo-io/talon/internal/otel"
	"github.com/dativo-io/talon/internal/pricing"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/llm/providers/ollama")

// OllamaProvider implements llm.Provider for local Ollama models.
//
//nolint:revive // type name matches package for clarity at call sites
type OllamaProvider struct {
	baseURL       string
	httpClient    *http.Client
	pricing       *pricing.PricingTable
	maxNumPredict int // optional operator ceiling on num_predict; 0 = honor caller's MaxTokens verbatim (default)
}

type ollamaConfig struct {
	BaseURL string `yaml:"base_url"`
	// MaxNumPredict, when set to a positive value, caps num_predict (output
	// tokens) per request — an OPT-IN operator setting for slow local hosts
	// where an unbounded generation would blow past the call timeout. Unset (or
	// 0) means honor the caller's MaxTokens verbatim (the default): Talon does
	// not silently shrink a caller's requested output length.
	MaxNumPredict *int `yaml:"max_num_predict"`
}

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  *ollamaOptions  `json:"options,omitempty"`
}

// ollamaOptions carries generation controls. num_predict caps the number of
// output tokens; without it a slow local model can generate unbounded and blow
// past the caller's call timeout (the runner sets MaxTokens but it was
// previously dropped on the floor for Ollama).
type ollamaOptions struct {
	NumPredict int `json:"num_predict,omitempty"`
}

// optionsFromRequest builds Ollama generation options from the llm.Request.
// The caller's MaxTokens maps to num_predict verbatim (the real fix: MaxTokens
// used to be dropped on the floor for Ollama). If — and only if — an operator
// has configured a positive maxNumPredict ceiling, num_predict is capped to it
// (opt-in, for slow local hosts). Returns nil when nothing needs to be set.
func (p *OllamaProvider) optionsFromRequest(req *llm.Request) *ollamaOptions {
	if req == nil {
		return nil
	}
	n := req.MaxTokens
	if p.maxNumPredict > 0 && (n <= 0 || n > p.maxNumPredict) {
		n = p.maxNumPredict
	}
	if n > 0 {
		return &ollamaOptions{NumPredict: n}
	}
	return nil
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

func init() {
	llm.Register("ollama", func(configYAML []byte) (llm.Provider, error) {
		baseURL := "http://localhost:11434"
		maxNumPredict := 0 // default: honor the caller's MaxTokens verbatim
		if len(configYAML) > 0 {
			var cfg ollamaConfig
			if err := yaml.Unmarshal(configYAML, &cfg); err != nil {
				return nil, fmt.Errorf("ollama config: %w", err)
			}
			if strings.TrimSpace(cfg.BaseURL) != "" {
				baseURL = strings.TrimRight(cfg.BaseURL, "/")
			}
			if cfg.MaxNumPredict != nil {
				maxNumPredict = *cfg.MaxNumPredict
			}
		}
		return &OllamaProvider{baseURL: baseURL, httpClient: &http.Client{}, maxNumPredict: maxNumPredict}, nil
	})
}

// NewOllamaProvider creates an Ollama provider pointing at the given base URL.
// No num_predict clamp by default — the caller's MaxTokens is honored verbatim.
func NewOllamaProvider(baseURL string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &OllamaProvider{baseURL: strings.TrimRight(baseURL, "/"), httpClient: &http.Client{}}
}

// Name returns the provider identifier.
func (p *OllamaProvider) Name() string {
	return "ollama"
}

// Metadata returns static compliance and identity information.
func (p *OllamaProvider) Metadata() llm.ProviderMetadata {
	meta := ollamaMetadata()
	if p.pricing != nil {
		meta.PricingAvailable = p.pricing.ModelCount(p.Name()) > 0
	}
	return meta
}

// Generate sends a chat request to the local Ollama instance.
func (p *OllamaProvider) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	ctx, span := tracer.Start(ctx, "gen_ai.generate",
		trace.WithAttributes(
			talonotel.GenAISystem.String("ollama"),
			talonotel.GenAIRequestModel.String(req.Model),
		))
	defer span.End()

	ctx, cancel := context.WithTimeout(ctx, llm.TimeoutLLMCall)
	defer cancel()

	messages := make([]ollamaMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = ollamaMessage{Role: msg.Role, Content: msg.Content}
	}

	apiReq := ollamaRequest{Model: req.Model, Messages: messages, Stream: false, Options: p.optionsFromRequest(req)}
	body, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("marshalling ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating ollama request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq) // #nosec G704 -- URL from operator config (Ollama baseURL), not user input
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("ollama api call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama api error %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding ollama response: %w", err)
	}

	inputTokens := 0
	for _, msg := range req.Messages {
		inputTokens += len(msg.Content) / 4
	}
	outputTokens := len(apiResp.Message.Content) / 4

	span.SetAttributes(
		talonotel.GenAIUsageInputTokens.Int(inputTokens),
		talonotel.GenAIUsageOutputTokens.Int(outputTokens),
	)

	return &llm.Response{
		Content:      apiResp.Message.Content,
		FinishReason: "stop",
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		Model:        req.Model,
	}, nil
}

// Stream sends a streaming chat request to Ollama.
// Must close ch when done (success or error) per Provider interface.
func (p *OllamaProvider) Stream(ctx context.Context, req *llm.Request, ch chan<- llm.StreamChunk) error {
	ctx, cancel := context.WithTimeout(ctx, llm.TimeoutLLMCall)
	defer cancel()

	messages := make([]ollamaMessage, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = ollamaMessage{Role: msg.Role, Content: msg.Content}
	}
	apiReq := ollamaRequest{Model: req.Model, Messages: messages, Stream: true, Options: p.optionsFromRequest(req)}
	body, err := json.Marshal(apiReq)
	if err != nil {
		close(ch)
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		close(ch)
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq) // #nosec G704 -- URL from operator config (Ollama baseURL), not user input
	if err != nil {
		close(ch)
		return fmt.Errorf("ollama stream: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		close(ch)
		return fmt.Errorf("ollama stream error %d: %s", resp.StatusCode, string(b))
	}

	dec := json.NewDecoder(resp.Body)
	for {
		var chunk struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Done bool `json:"done"`
		}
		if err := dec.Decode(&chunk); err != nil {
			if err == io.EOF {
				break
			}
			ch <- llm.StreamChunk{Error: err}
			close(ch)
			return err
		}
		if chunk.Message.Content != "" {
			ch <- llm.StreamChunk{Content: chunk.Message.Content}
		}
		if chunk.Done {
			ch <- llm.StreamChunk{FinishReason: "stop"}
			break
		}
	}
	close(ch)
	return nil
}

// SetPricing injects the config-driven pricing table for cost estimation.
func (p *OllamaProvider) SetPricing(pt *pricing.PricingTable) { p.pricing = pt }

// EstimateCost returns cost from pricing table (typically 0 for ollama's empty models map).
func (p *OllamaProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	if p.pricing == nil {
		return 0
	}
	cost, _ := p.pricing.Estimate(p.Metadata().ID, model, inputTokens, outputTokens)
	return cost
}

// ValidateConfig always succeeds for Ollama (base_url is optional).
func (p *OllamaProvider) ValidateConfig() error {
	return nil
}

// HealthCheck performs GET /api/tags. On connection refused returns an actionable error.
func (p *OllamaProvider) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*llm.TimeoutLLMCall/60)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", p.baseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := p.httpClient.Do(req) // #nosec G704 -- URL from operator config (Ollama baseURL), not user input
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "connect: connection refused") {
			return fmt.Errorf("ollama not reachable at %s — is `ollama serve` running?", p.baseURL)
		}
		return fmt.Errorf("ollama health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama health check: status %d", resp.StatusCode)
	}
	return nil
}

// WithHTTPClient returns a copy of the provider using the given HTTP client.
func (p *OllamaProvider) WithHTTPClient(client *http.Client) llm.Provider {
	return &OllamaProvider{baseURL: p.baseURL, httpClient: client, pricing: p.pricing}
}
