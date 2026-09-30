package action

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"time"
)

// Dispatcher performs the downstream effect of an ALREADY AUTHORIZED,
// CLAIMED and ARMED attempt. It never decides anything and never retries.
type Dispatcher interface {
	Dispatch(ctx context.Context, req DispatchRequest) Outcome
}

// DispatchRequest carries exactly what the trusted dispatcher needs.
type DispatchRequest struct {
	Definition     *Definition
	Payload        []byte // canonical arguments
	OperationRef   string
	AttemptID      string
	IdempotencyKey string
}

// Outcome is what Talon can truthfully say after one dispatch (#458 B3/B4).
//
// Observation facts (what Talon saw) and the outcome verdict (what Talon
// may conclude) are separate:
//
//	RequestWritten=false                      the request never left Talon
//	                                          → failed / not_dispatched; an
//	                                          unchanged explicit retry is safe
//	RequestWritten=true, ResponseObserved=true,
//	  status ∈ definition's success contract   → succeeded / observed
//	RequestWritten=true, anything else          → UNKNOWN / unknown. This
//	                                          includes any undeclared status
//	                                          (500 after the effect, 409, a
//	                                          redirect), a lost response, a
//	                                          timeout after send and a
//	                                          truncated body. No retry.
//
// An HTTP status is never a business outcome by itself; only the trusted
// success contract turns an observed response into "succeeded".
type Outcome struct {
	Status           string // succeeded | failed | unknown
	Provenance       string // observed | unknown | not_dispatched
	RequestWritten   bool
	ResponseObserved bool
	HTTPStatus       int
	Code             string
	Ref              string // sha256 of the response body when observed
}

// HTTPDispatcher forwards the canonical payload to the definition's
// destination with a stable idempotency identity.
type HTTPDispatcher struct {
	Client *http.Client
	// Timeout bounds one dispatch (default 30s).
	Timeout time.Duration
	// MaxResponseBytes bounds the response read (default 1 MiB).
	MaxResponseBytes int64
}

// NewHTTPDispatcher returns a dispatcher whose client can neither replay a
// request nor follow a redirect:
//   - keep-alives are disabled so net/http never transparently resends a
//     request on a stale connection (a hidden second effect);
//   - redirects are refused (ErrUseLastResponse): the approved destination
//     is the ONLY destination an attempt may contact; a 3xx answer is an
//     observed non-success from that destination (#458 B2).
func NewHTTPDispatcher(client *http.Client) *HTTPDispatcher {
	c := http.Client{}
	if client != nil {
		c = *client
	}
	if c.Transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DisableKeepAlives = true
		t.MaxIdleConnsPerHost = -1
		c.Transport = t
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPDispatcher{Client: &c, Timeout: 30 * time.Second, MaxResponseBytes: 1 << 20}
}

// Dispatch implements Dispatcher.
func (d *HTTPDispatcher) Dispatch(ctx context.Context, req DispatchRequest) Outcome {
	def := req.Definition
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	wrote := false
	trace := &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { wrote = true }}
	ctx = httptrace.WithClientTrace(ctx, trace)

	hreq, err := http.NewRequestWithContext(ctx, def.Destination.Method, def.Destination.URL, bytes.NewReader(req.Payload))
	if err != nil {
		return Outcome{Status: AttemptFailed, Provenance: ResultProvenanceNotDispatched, Code: "dispatch_request_invalid"}
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Idempotency-Key", req.IdempotencyKey)
	hreq.Header.Set("X-Talon-Operation-Ref", req.OperationRef)
	hreq.Header.Set("X-Talon-Attempt-Id", req.AttemptID)
	hreq.ContentLength = int64(len(req.Payload))
	// Non-replayable for net/http: with GetBody set (or an Idempotency-Key
	// header) the transport would resend a POST after a connection-level
	// failure on its own.
	hreq.GetBody = nil

	client := d.Client
	if client == nil {
		client = NewHTTPDispatcher(nil).Client
	}
	resp, err := client.Do(hreq)
	if err != nil {
		if !wrote {
			return Outcome{Status: AttemptFailed, Provenance: ResultProvenanceNotDispatched, Code: "dispatch_transport_error"}
		}
		code := "dispatch_response_lost"
		if errors.Is(err, context.DeadlineExceeded) {
			code = "dispatch_timeout_after_send"
		}
		return Outcome{Status: AttemptUnknown, Provenance: ResultProvenanceUnknown, RequestWritten: true, Code: code}
	}
	defer resp.Body.Close()
	maxBytes := d.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if readErr != nil {
		return Outcome{Status: AttemptUnknown, Provenance: ResultProvenanceUnknown, RequestWritten: true, Code: "dispatch_response_truncated", HTTPStatus: resp.StatusCode}
	}
	sum := sha256.Sum256(body)
	ref := hex.EncodeToString(sum[:])
	base := Outcome{RequestWritten: true, ResponseObserved: true, HTTPStatus: resp.StatusCode, Ref: ref, Code: "http_" + strconv.Itoa(resp.StatusCode)}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		base.Code = "dispatch_redirect_refused"
	}
	if def.IsAuthoritativeSuccess(resp.StatusCode) {
		base.Status, base.Provenance = AttemptSucceeded, ResultProvenanceObserved
		return base
	}
	// The request reached the destination and the answer is not a declared
	// authoritative success: the business effect may or may not have
	// happened. Conservative UNKNOWN; never a retryable "failed".
	base.Status, base.Provenance = AttemptUnknown, ResultProvenanceUnknown
	return base
}
