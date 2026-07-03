package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	otelsdk "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/adapter"
	"github.com/dativo-io/talon/internal/classifier/presidio"
	talonotel "github.com/dativo-io/talon/internal/otel"

	"github.com/rs/zerolog/log"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/classifier/adapter/llm")

var hallucinationsCounter, _ = otelsdk.Meter("github.com/dativo-io/talon/internal/classifier/adapter/llm").
	Int64Counter("talon.scanner.llm.hallucinations.total",
		metric.WithDescription("LLM-reported entity values not found verbatim in the scanned text (dropped)"),
		metric.WithUnit("{entity}"))

// maxResponseBytes bounds how much of a model response is read (untrusted input).
const maxResponseBytes = 4 << 20

// Config describes an OpenAI-compatible NER scanner engine.
type Config struct {
	Endpoint    string  // OpenAI-compatible base URL, e.g. http://localhost:11434/v1
	Model       string  // required, e.g. "llama3.1:8b"
	Confidence  float64 // score assigned to relocated entities; default 0.8
	Timeout     time.Duration
	EntityTypes []string          // Presidio-style labels the prompt hunts for (policy-derived)
	Name        string            // detector identity override; default "llm:<model>"
	Transport   http.RoundTripper // optional base transport (e.g. air-gap egress guard)
}

// Adapter is a classifier.Facade backed by an OpenAI-compatible chat endpoint
// prompted for NER with the built-in versioned prompt.
type Adapter struct {
	cfg      Config
	client   *http.Client
	baseURL  string
	detector string
	prompt   string
}

var _ classifier.Facade = (*Adapter)(nil)

// New builds the llm scanner adapter. It validates configuration but performs
// no I/O; use HealthCheck for the eager startup probe.
func New(cfg Config) (*Adapter, error) {
	if cfg.Model == "" {
		return nil, fmt.Errorf("llm scanner: model is required")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("llm scanner: endpoint is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Confidence <= 0 || cfg.Confidence > 1 {
		cfg.Confidence = 0.8
	}
	if len(cfg.EntityTypes) == 0 {
		var err error
		cfg.EntityTypes, err = classifier.SupportedEntityTypes()
		if err != nil {
			return nil, fmt.Errorf("llm scanner: deriving entity types: %w", err)
		}
	}
	detector := cfg.Name
	if detector == "" {
		detector = "llm:" + cfg.Model
	}
	client := &http.Client{}
	if cfg.Transport != nil {
		client.Transport = cfg.Transport
	}
	return &Adapter{
		cfg:      cfg,
		client:   client,
		baseURL:  strings.TrimRight(cfg.Endpoint, "/"),
		detector: detector,
		prompt:   BuildSystemPrompt(cfg.EntityTypes),
	}, nil
}

// Detector returns the engine identity recorded in evidence.
func (a *Adapter) Detector() string { return a.detector }

// EngineType returns "llm" for evidence.
func (a *Adapter) EngineType() string { return "llm" }

// EngineVersion returns the built-in prompt version — the component whose
// semantics define what this engine detects.
func (a *Adapter) EngineVersion() string { return PromptVersion }

// maxCompletionTokens bounds NER generation. A correct entities object for
// maxDetections entities fits comfortably; without a ceiling, small models in
// JSON mode can fall into repetition spirals on unusual inputs (e.g. text that
// is only redaction placeholders) and generate until the context window fills
// — minutes on CPU hosts, surfacing as deterministic scan timeouts.
const maxCompletionTokens = 2048

// chatRequest is the OpenAI-compatible /chat/completions request body.
type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	Temperature    float64       `json:"temperature"`
	MaxTokens      int           `json:"max_tokens"`
	Stream         bool          `json:"stream"`
	ResponseFormat *respFormat   `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type respFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// Analyze prompts the model for NER over text and relocates the reported
// verbatim values to deterministic byte offsets. Any failure — transport,
// timeout, non-JSON reply — is a classified *adapter.Error; callers on
// enforcement paths must block egress.
func (a *Adapter) Analyze(ctx context.Context, text string) (*classifier.Classification, error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	ctx, span := tracer.Start(ctx, "scanner.adapter.llm.analyze")
	defer span.End()
	span.SetAttributes(
		attribute.String("scanner.engine", a.detector),
		attribute.String("scanner.type", "llm"),
		attribute.String("scanner.prompt_version", PromptVersion),
	)

	cls, err := a.analyze(ctx, text)
	outcome := "ok"
	if err != nil {
		outcome = adapter.FailureKind(err)
		span.RecordError(err)
		span.SetAttributes(attribute.String("scanner.failure", outcome))
	} else {
		span.SetAttributes(
			attribute.Bool("pii.detected", cls.HasPII),
			attribute.Int("pii.entity_count", len(cls.Entities)),
			attribute.Int("pii.tier", cls.Tier),
		)
	}
	adapter.RecordScan(ctx, a.detector, outcome, time.Since(started))
	return cls, err
}

func (a *Adapter) analyze(ctx context.Context, text string) (*classifier.Classification, error) {
	content, err := a.complete(ctx, []chatMessage{
		{Role: "system", Content: a.prompt},
		{Role: "user", Content: text},
	})
	if err != nil {
		return nil, err
	}

	detections, err := ParseDetections(content)
	if err != nil {
		// Never echo the untrusted model output into the error or evidence.
		// A truncated head at debug level is the operator escape hatch for
		// diagnosing model-side reply shapes (run serve with --log-level debug).
		log.Debug().
			Str("engine", a.detector).
			Int("reply_len", len(content)).
			Str("reply_head", truncateForLog(content, 300)).
			Msg("llm_ner_reply_unparseable")
		return nil, a.fail(adapter.KindDecode, err)
	}

	relocated := Relocate(text, detections, a.cfg.Confidence)
	if relocated.Hallucinated > 0 {
		hallucinationsCounter.Add(ctx, int64(relocated.Hallucinated),
			metric.WithAttributes(attribute.String("model", a.cfg.Model)))
	}

	entities := []classifier.PIIEntity{}
	if len(relocated.Results) > 0 {
		// Relocation produced the offsets, so normalization's substring
		// re-check is a final self-consistency gate, not a trust boundary.
		canonical, err := presidio.NormalizeResults(text, relocated.Results)
		if err != nil {
			return nil, a.fail(adapter.KindValidation, fmt.Errorf("normalizing relocated results: %w", err))
		}
		for _, c := range canonical {
			c.Source = a.detector
		}
		entities = classifier.CanonicalToPIIEntities(canonical)
		direction := classifier.PIIDirectionFromContext(ctx)
		for _, e := range entities {
			classifier.RecordPIIDetection(ctx, e.Type, direction, "detected")
		}
	}

	return &classifier.Classification{
		HasPII:   len(entities) > 0,
		Entities: entities,
		Tier:     classifier.DetermineTier(entities),
	}, nil
}

// complete performs one OpenAI-compatible chat completion and returns the
// first choice's content.
func (a *Adapter) complete(ctx context.Context, messages []chatMessage) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:          a.cfg.Model,
		Messages:       messages,
		Temperature:    0,
		MaxTokens:      maxCompletionTokens,
		Stream:         false,
		ResponseFormat: &respFormat{Type: "json_object"},
	})
	if err != nil {
		return "", a.fail(adapter.KindTransport, fmt.Errorf("encoding request: %w", err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", a.fail(adapter.KindTransport, fmt.Errorf("building request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", a.fail(classifyTransportError(err), errors.New("request failed"))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", a.fail(adapter.KindStatus, fmt.Errorf("model endpoint returned HTTP %d", resp.StatusCode))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", a.fail(classifyTransportError(err), errors.New("reading response"))
	}
	if len(raw) > maxResponseBytes {
		return "", a.fail(adapter.KindValidation, fmt.Errorf("response exceeds %d bytes", maxResponseBytes))
	}

	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", a.fail(adapter.KindDecode, errors.New("response is not a chat completion object"))
	}
	if len(cr.Choices) == 0 {
		return "", a.fail(adapter.KindDecode, errors.New("chat completion has no choices"))
	}
	return cr.Choices[0].Message.Content, nil
}

// RedactText scans through the model and applies Talon's own byte-exact
// placeholder redaction. An error means the text was not scanned; callers
// must not egress the original text.
func (a *Adapter) RedactText(ctx context.Context, text string) (string, error) {
	cls, err := a.Analyze(ctx, text)
	if err != nil {
		return "", err
	}
	if !cls.HasPII {
		return text, nil
	}
	merged := classifier.MergeEntitySpans(text, cls.Entities)
	return classifier.RedactEntities(ctx, text, merged), nil
}

// VerifyEgress re-scans redacted text and fails closed on residual PII or on
// engine failure. The prompt instructs the model to ignore [TYPE]
// placeholders, and Relocate drops placeholder-shaped values as a backstop,
// so already-redacted text does not false-positive here.
func (a *Adapter) VerifyEgress(ctx context.Context, text string) error {
	return classifier.NewRedactGuard(a).Verify(ctx, text)
}

// modelsResponse is the OpenAI-compatible GET /models body.
type modelsResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// HealthCheck probes the endpoint and verifies the configured model is
// available. Endpoints without /models fall back to a minimal completion.
func (a *Adapter) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	ctx, span := tracer.Start(ctx, "scanner.adapter.health")
	defer span.End()
	span.SetAttributes(attribute.String("scanner.engine", a.detector))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/models", nil)
	if err != nil {
		return a.fail(adapter.KindTransport, fmt.Errorf("building health request: %w", err))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return a.fail(classifyTransportError(err), errors.New("health request failed"))
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var mr modelsResponse
		if err := json.Unmarshal(raw, &mr); err != nil {
			return a.fail(adapter.KindDecode, errors.New("models response is not valid JSON"))
		}
		found := false
		for _, m := range mr.Data {
			if m.ID == a.cfg.Model {
				found = true
				break
			}
		}
		if !found {
			return a.fail(adapter.KindValidation,
				fmt.Errorf("model %q is not available at the endpoint (pull it first, e.g. `ollama pull %s`)", a.cfg.Model, a.cfg.Model))
		}
		// Listed is not runnable: a host without enough memory still lists a
		// pulled model but fails to load it on first use, which would pass a
		// presence-only probe and then fail-closed-block every scan. Warm the
		// model up with a minimal completion (within the scan timeout) so
		// startup fails with an actionable error instead — and the first real
		// scan doesn't pay the cold-load latency.
		return a.warmUp(ctx)
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		// No /models endpoint: the completion probe is the whole check.
		return a.warmUp(ctx)
	default:
		return a.fail(adapter.KindStatus, fmt.Errorf("models endpoint returned HTTP %d", resp.StatusCode))
	}
}

// warmUp issues a minimal completion to prove the model actually runs on
// this host (and to absorb the cold-start load before real scans).
func (a *Adapter) warmUp(ctx context.Context) error {
	if _, err := a.complete(ctx, []chatMessage{{Role: "user", Content: "ping"}}); err != nil {
		return fmt.Errorf("model %q is listed but did not answer a warm-up completion within the scan timeout — the host may lack memory for it or the model is too slow for scanner.timeout: %w", a.cfg.Model, err)
	}
	return nil
}

func (a *Adapter) fail(kind adapter.Kind, err error) *adapter.Error {
	return &adapter.Error{Kind: kind, Detector: a.detector, Err: err}
}

// classifyTransportError separates deadline expiry from other transport failures.
func classifyTransportError(err error) adapter.Kind {
	if errors.Is(err, context.DeadlineExceeded) {
		return adapter.KindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return adapter.KindTimeout
	}
	return adapter.KindTransport
}

// truncateForLog bounds untrusted text for debug logging.
func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}
