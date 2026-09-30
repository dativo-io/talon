package action

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"time"
)

// Dispatcher performs the downstream effect of an ALREADY AUTHORIZED and
// CLAIMED attempt. It never decides anything.
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

// Outcome classifies what Talon knows after one dispatch.
//
//	Dispatched=false           the request never left Talon → known failure,
//	                           safe to retry (ResultProvenanceNotDispatched)
//	Dispatched=true, observed  Talon read a response → succeeded/failed,
//	                           ResultProvenanceObserved
//	Dispatched=true, no answer the request was written but no reliable
//	                           response arrived → AttemptUnknown,
//	                           ResultProvenanceUnknown; NEVER retried
//	                           automatically
type Outcome struct {
	Status     string // succeeded | failed | unknown
	Dispatched bool
	Provenance string
	Code       string
	Ref        string // safe reference: sha256 of the response body
	HTTPStatus int
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

// NewHTTPDispatcher returns a dispatcher with sane defaults.
func NewHTTPDispatcher(client *http.Client) *HTTPDispatcher {
	if client == nil {
		client = &http.Client{}
	}
	// Never reuse a connection for a dispatch: net/http transparently
	// replays a request on a stale keep-alive connection when it believes
	// the request is replayable, which would be a hidden second effect.
	// A fresh connection per attempt also keeps the wrote-request boundary
	// exact.
	if client.Transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DisableKeepAlives = true
		t.MaxIdleConnsPerHost = -1
		c := *client
		c.Transport = t
		client = &c
	}
	return &HTTPDispatcher{Client: client, Timeout: 30 * time.Second, MaxResponseBytes: 1 << 20}
}

// Dispatch implements Dispatcher. The wrote-request trace hook is the
// dispatch boundary: an error before it is a known non-dispatch, an error
// after it is UNKNOWN.
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
	// Make the request non-replayable for net/http: with GetBody set (or an
	// Idempotency-Key header) the transport would retry a POST on its own
	// after a connection-level failure — an automatic second dispatch that
	// this contract forbids. With GetBody nil the transport surfaces the
	// error instead, and the outcome classification decides.
	hreq.GetBody = nil

	resp, err := d.Client.Do(hreq)
	if err != nil {
		if !wrote {
			return Outcome{Status: AttemptFailed, Provenance: ResultProvenanceNotDispatched, Code: "dispatch_transport_error"}
		}
		code := "dispatch_response_lost"
		if errors.Is(err, context.DeadlineExceeded) {
			code = "dispatch_timeout_after_send"
		}
		return Outcome{Status: AttemptUnknown, Dispatched: true, Provenance: ResultProvenanceUnknown, Code: code}
	}
	defer resp.Body.Close()
	max := d.MaxResponseBytes
	if max <= 0 {
		max = 1 << 20
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, max))
	if readErr != nil {
		// Headers arrived but the body did not: the effect may have
		// happened; the status line is not a reliable outcome on its own.
		return Outcome{Status: AttemptUnknown, Dispatched: true, Provenance: ResultProvenanceUnknown, Code: "dispatch_response_truncated", HTTPStatus: resp.StatusCode}
	}
	sum := sha256.Sum256(body)
	ref := hex.EncodeToString(sum[:])
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return Outcome{Status: AttemptSucceeded, Dispatched: true, Provenance: ResultProvenanceObserved, Code: "http_" + strconv.Itoa(resp.StatusCode), Ref: ref, HTTPStatus: resp.StatusCode}
	}
	return Outcome{Status: AttemptFailed, Dispatched: true, Provenance: ResultProvenanceObserved, Code: fmt.Sprintf("http_%d", resp.StatusCode), Ref: ref, HTTPStatus: resp.StatusCode}
}
