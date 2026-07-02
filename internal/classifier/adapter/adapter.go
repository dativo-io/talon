package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/entity"
	"github.com/dativo-io/talon/internal/classifier/presidio"
	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/classifier/adapter")

// maxResponseBytes bounds how much of an adapter response Talon will read.
// Larger responses are rejected wholesale (untrusted input).
const maxResponseBytes = 10 << 20

// Engine type identifiers (mirror config.ScannerType* without importing config).
const (
	TypePresidio = "presidio"
	TypeHTTP     = "http"
)

// Default detector identities recorded in evidence when scanner.name is unset.
const (
	DetectorPresidioHTTP = "presidio-http"
	DetectorScannerHTTP  = "scanner-http"
)

// Config describes one external scanner engine. Values are expected to be
// effective (defaults already applied by the caller); New still hardens the
// zero values so a hand-built Config behaves sanely.
type Config struct {
	Type          string // presidio | http
	Endpoint      string // http(s)://host:port or unix:///path.sock
	Name          string // detector identity for evidence; default per type
	EngineVersion string // operator-declared, recorded in evidence
	Language      string // forwarded in /analyze requests
	Timeout       time.Duration
	MinScore      float64
	// DefaultOffsetEncoding is applied to results that do not declare their
	// own offset_encoding. Stock Presidio reports codepoint (rune) offsets
	// and no encoding field, so type presidio defaults to rune; type http
	// defaults to byte.
	DefaultOffsetEncoding string
	Entities              []string          // optional entity filter forwarded to the engine
	Transport             http.RoundTripper // optional base transport (e.g. air-gap egress guard)
}

// HTTPAdapter is a classifier.Facade backed by an external engine speaking
// the Presidio analyzer REST wire format over HTTP or a Unix domain socket.
type HTTPAdapter struct {
	cfg      Config
	client   *http.Client
	baseURL  string
	detector string
}

var _ classifier.Facade = (*HTTPAdapter)(nil)

// New builds an adapter for the configured engine. It validates the endpoint
// but performs no I/O; use HealthCheck for the eager startup probe.
func New(cfg Config) (*HTTPAdapter, error) {
	baseURL, socketPath, err := ParseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Language == "" {
		cfg.Language = "en"
	}
	if cfg.MinScore <= 0 {
		cfg.MinScore = classifier.DefaultMinScore
	}
	if cfg.DefaultOffsetEncoding == "" {
		if cfg.Type == TypePresidio {
			cfg.DefaultOffsetEncoding = presidio.OffsetEncodingRune
		} else {
			cfg.DefaultOffsetEncoding = presidio.OffsetEncodingByte
		}
	}
	detector := cfg.Name
	if detector == "" {
		if cfg.Type == TypePresidio {
			detector = DetectorPresidioHTTP
		} else {
			detector = DetectorScannerHTTP
		}
	}
	return &HTTPAdapter{
		cfg:      cfg,
		client:   newHTTPClient(socketPath, cfg.Transport),
		baseURL:  baseURL,
		detector: detector,
	}, nil
}

// Detector returns the engine identity recorded in evidence.
func (a *HTTPAdapter) Detector() string { return a.detector }

// EngineType returns the configured engine type (presidio or http).
func (a *HTTPAdapter) EngineType() string { return a.cfg.Type }

// EngineVersion returns the operator-declared engine version for evidence.
func (a *HTTPAdapter) EngineVersion() string { return a.cfg.EngineVersion }

// analyzeRequest is the Presidio analyzer /analyze request body.
type analyzeRequest struct {
	Text           string   `json:"text"`
	Language       string   `json:"language"`
	ScoreThreshold float64  `json:"score_threshold,omitempty"`
	Entities       []string `json:"entities,omitempty"`
}

// Analyze scans text through the external engine and normalizes the response
// into Talon's canonical model. Any failure — timeout, transport, status,
// decode, or a single invalid entity — rejects the whole scan with an
// *Error; callers on enforcement paths must block egress.
func (a *HTTPAdapter) Analyze(ctx context.Context, text string) (*classifier.Classification, error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	ctx, span := tracer.Start(ctx, "scanner.adapter.analyze")
	defer span.End()
	span.SetAttributes(
		attribute.String("scanner.engine", a.detector),
		attribute.String("scanner.type", a.cfg.Type),
	)

	cls, err := a.analyze(ctx, text)
	outcome := "ok"
	if err != nil {
		outcome = FailureKind(err)
		span.RecordError(err)
		span.SetAttributes(attribute.String("scanner.failure", outcome))
	} else {
		span.SetAttributes(
			attribute.Bool("pii.detected", cls.HasPII),
			attribute.Int("pii.entity_count", len(cls.Entities)),
			attribute.Int("pii.tier", cls.Tier),
		)
	}
	RecordScan(ctx, a.detector, outcome, time.Since(started))
	return cls, err
}

func (a *HTTPAdapter) analyze(ctx context.Context, text string) (*classifier.Classification, error) {
	body, err := json.Marshal(analyzeRequest{
		Text:           text,
		Language:       a.cfg.Language,
		ScoreThreshold: a.cfg.MinScore,
		Entities:       a.cfg.Entities,
	})
	if err != nil {
		return nil, a.fail(KindTransport, fmt.Errorf("encoding request: %w", err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, a.fail(KindTransport, fmt.Errorf("building request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, a.fail(classifyTransportError(err), errors.New("request failed"))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, a.fail(KindStatus, fmt.Errorf("engine returned HTTP %d", resp.StatusCode))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, a.fail(classifyTransportError(err), errors.New("reading response"))
	}
	if len(raw) > maxResponseBytes {
		return nil, a.fail(KindValidation, fmt.Errorf("response exceeds %d bytes", maxResponseBytes))
	}

	var results []presidio.RecognizerResult
	if err := json.Unmarshal(raw, &results); err != nil {
		// Never echo the untrusted body into the error.
		return nil, a.fail(KindDecode, errors.New("response is not a recognizer result array"))
	}

	return a.normalize(ctx, text, results)
}

// normalize filters, offset-normalizes, and canonicalizes untrusted engine
// results into a Classification.
func (a *HTTPAdapter) normalize(ctx context.Context, text string, results []presidio.RecognizerResult) (*classifier.Classification, error) {
	kept := results[:0]
	for i := range results {
		r := results[i]
		if r.Score < a.cfg.MinScore {
			continue
		}
		if r.OffsetEncoding == "" {
			r.OffsetEncoding = a.cfg.DefaultOffsetEncoding
		}
		kept = append(kept, r)
	}

	entities := []classifier.PIIEntity{}
	if len(kept) > 0 {
		canonical, err := presidio.NormalizeResults(text, kept)
		if err != nil {
			// One invalid entity rejects the entire response (fail-closed).
			return nil, a.fail(KindValidation, fmt.Errorf("normalizing results: %w", err))
		}
		for _, c := range canonical {
			if c.Source == entity.SourcePresidio {
				c.Source = a.detector
			}
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

// RedactText scans through the external engine and applies Talon's own
// byte-exact placeholder redaction. An error means the text was not scanned;
// callers must not egress the original text.
func (a *HTTPAdapter) RedactText(ctx context.Context, text string) (string, error) {
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
// engine failure.
func (a *HTTPAdapter) VerifyEgress(ctx context.Context, text string) error {
	return classifier.NewRedactGuard(a).Verify(ctx, text)
}

// HealthCheck probes the engine. It prefers GET /health (stock Presidio) and
// falls back to a minimal /analyze call for compatible engines that do not
// implement a health endpoint.
func (a *HTTPAdapter) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	ctx, span := tracer.Start(ctx, "scanner.adapter.health")
	defer span.End()
	span.SetAttributes(attribute.String("scanner.engine", a.detector))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/health", nil)
	if err != nil {
		return a.fail(KindTransport, fmt.Errorf("building health request: %w", err))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return a.fail(classifyTransportError(err), errors.New("health request failed"))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		// Engine speaks the wire format but has no /health: probe /analyze.
		if _, err := a.analyze(ctx, "talon scanner health probe"); err != nil {
			return err
		}
		return nil
	default:
		return a.fail(KindStatus, fmt.Errorf("health endpoint returned HTTP %d", resp.StatusCode))
	}
}

func (a *HTTPAdapter) fail(kind Kind, err error) *Error {
	return &Error{Kind: kind, Detector: a.detector, Err: err}
}

// classifyTransportError separates deadline expiry from other transport
// failures so evidence and metrics can distinguish a slow engine from a dead one.
func classifyTransportError(err error) Kind {
	if errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return KindTimeout
	}
	return KindTransport
}
