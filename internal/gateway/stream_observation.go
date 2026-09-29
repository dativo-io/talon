package gateway

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
)

// streamObservationCaptureLimit bounds the raw SSE bytes a streamed `warn`
// response keeps for post-delivery observation (#476). The client stream is
// never affected by the bound: past it the capture stops growing and the
// observation is recorded as incomplete (capture_limit_exceeded). Raw SSE
// framing is roughly 100–250 bytes per content delta, so 4 MiB covers
// interactive responses of well over ten thousand output tokens while
// keeping a malicious never-ending stream from growing gateway memory.
//
// A variable rather than a constant only so tests can exercise the overflow
// path with a small bound; production never changes it.
var streamObservationCaptureLimit = 4 << 20

// observingStreamWriter tees a streamed response into a bounded in-memory
// capture while delivering it to the real client writer first. It is the
// `warn` streaming path's only addition to the hot path: every Write and
// Flush goes straight through, so time-to-first-token is the upstream's,
// and the scanner runs only after the stream has terminated.
type observingStreamWriter struct {
	http.ResponseWriter
	limit      int
	statusCode int
	capture    bytes.Buffer
	overflowed bool
}

func newObservingStreamWriter(w http.ResponseWriter) *observingStreamWriter {
	return &observingStreamWriter{ResponseWriter: w, limit: streamObservationCaptureLimit}
}

func (o *observingStreamWriter) WriteHeader(code int) {
	if o.statusCode == 0 {
		o.statusCode = code
	}
	o.ResponseWriter.WriteHeader(code)
}

// Write delivers to the client first; the capture only records what the
// client actually received and never turns a capture limit into a client
// error.
func (o *observingStreamWriter) Write(b []byte) (int, error) {
	if o.statusCode == 0 {
		o.statusCode = http.StatusOK // net/http's implicit status on first Write
	}
	n, err := o.ResponseWriter.Write(b)
	if n > 0 {
		o.observe(b[:n])
	}
	return n, err
}

func (o *observingStreamWriter) observe(b []byte) {
	if o.overflowed {
		return
	}
	room := o.limit - o.capture.Len()
	if len(b) > room {
		o.capture.Write(b[:room])
		o.overflowed = true
		return
	}
	o.capture.Write(b)
}

// Flush delegates immediately: streamCopy flushes after every SSE event and
// that cadence must reach the client unchanged.
func (o *observingStreamWriter) Flush() {
	if f, ok := o.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (o *observingStreamWriter) status() int {
	if o.statusCode == 0 {
		return http.StatusOK
	}
	return o.statusCode
}

// upstreamStreamed reports whether the response actually delivered to the
// client was an SSE stream — the same test Forward applies (success status
// and text/event-stream content type) — rather than whether the client
// asked for one. A provider that answers a stream:true request with a JSON
// error was not streamed, and evidence must say so.
func upstreamStreamed(h http.Header, status int) bool {
	if status == 0 {
		status = http.StatusOK
	}
	return status < http.StatusBadRequest && strings.Contains(h.Get("Content-Type"), "text/event-stream")
}

// observeStreamedResponse is the post-delivery half of the streaming `warn`
// path: the stream has terminated (normally, by upstream failure, idle
// abort or client cancellation) and every byte the client will ever get has
// been written. It extracts model text from the bounded capture with the
// same SSE parsing the preventive path uses, scans it, and records what was
// observed. It never writes to the client, never changes the request
// outcome, and reports any gap as an incomplete observation instead of a
// clean scan. forwardErr is the streaming outcome; clientCtx is the request
// context (a cancellation there means the client went away).
func observeStreamedResponse(ctx context.Context, obs *observingStreamWriter, action string, scanner classifier.Facade, forwardErr error, clientCtx context.Context) *ResponsePIIScanResult {
	result := &ResponsePIIScanResult{
		Action:        action,
		Enforcement:   evidence.ResponseScanEnforcementPostDelivery,
		Streamed:      upstreamStreamed(obs.Header(), obs.status()),
		Status:        evidence.ResponseScanStatusComplete,
		BytesObserved: int64(obs.capture.Len()),
		CaptureLimit:  int64(obs.limit),
	}
	// Stream integrity first: a truncated or errored stream can only ever be
	// partially observed, whatever the scanner finds in the captured part.
	markStreamIncomplete(result, forwardErr, clientCtx)
	if result.Status == evidence.ResponseScanStatusComplete && obs.status() >= http.StatusBadRequest {
		result.markIncomplete(evidence.ResponseScanIncompleteUpstreamError)
	}
	if result.Status == evidence.ResponseScanStatusComplete && obs.overflowed {
		result.markIncomplete(evidence.ResponseScanIncompleteCaptureLimitExceeded)
	}

	raw := obs.capture.Bytes()
	contentText := ""
	if completed := extractCompletedResponseFromSSE(raw); completed != nil {
		contentText = extractResponseContentText(completed)
	}
	if contentText == "" {
		contentText = accumulateSSEContent(raw)
	}
	if contentText == "" {
		if result.Status == evidence.ResponseScanStatusComplete {
			result.markIncomplete(evidence.ResponseScanIncompleteNoTextContent)
		}
		return result
	}
	if scanner == nil {
		result.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		return result
	}

	// The client may already be gone (cancel) — the observation still has to
	// finish for the evidence record, so the scan does not inherit the
	// request cancellation. It stays bounded by the scanner's own timeout.
	cls, scanErr := scanner.Analyze(context.WithoutCancel(ctx), contentText)
	if scanErr != nil {
		result.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		result.ScannerFailure = scannerFailureKind(scanErr)
		log.Warn().Err(scanErr).Msg("response_pii_scanner_unavailable_warn_stream")
		return result
	}
	if cls == nil || !cls.HasPII {
		return result
	}
	result.PIIDetected = true
	result.PIITypes = uniqueSortedEntityTypes(cls.Entities)
	result.Entities = applyDefaultFieldPath(classifier.MergeEntitySpans(contentText, cls.Entities), "response.content")
	result.Tier = cls.Tier
	log.Warn().
		Strs("pii_types", result.PIITypes).
		Str("response_scan", result.Enforcement).
		Msg("response_pii_detected_warn_stream")
	return result
}

// markStreamIncomplete records a stream that did not terminate normally on a
// response-scan result (nil-safe). Client cancellation and upstream failure
// are distinguished because they mean different things to an operator: the
// first is the caller's choice, the second is a provider/transport fact.
func markStreamIncomplete(result *ResponsePIIScanResult, forwardErr error, clientCtx context.Context) {
	if result == nil || forwardErr == nil {
		return
	}
	if clientCtx != nil && clientCtx.Err() != nil && errors.Is(forwardErr, context.Canceled) {
		result.markIncomplete(evidence.ResponseScanIncompleteClientCancelled)
		return
	}
	result.markIncomplete(evidence.ResponseScanIncompleteUpstreamError)
}

func (r *ResponsePIIScanResult) markIncomplete(reason string) {
	if r.Status == evidence.ResponseScanStatusIncomplete && r.IncompleteReason != "" {
		return // first cause wins; later gaps are consequences of it
	}
	r.Status = evidence.ResponseScanStatusIncomplete
	r.IncompleteReason = reason
}

// responseScanEvidence projects the in-memory scan result onto the signed
// response_scan field. Nil when no response scan ran (allow, or no result).
func responseScanEvidence(r *ResponsePIIScanResult) *evidence.ResponseScan {
	if r == nil || r.Action == "" {
		return nil
	}
	return &evidence.ResponseScan{
		Action:           r.Action,
		Enforcement:      r.Enforcement,
		Streamed:         r.Streamed,
		Status:           r.Status,
		IncompleteReason: r.IncompleteReason,
		BytesObserved:    r.BytesObserved,
		CaptureLimit:     r.CaptureLimit,
	}
}

// uniqueSortedEntityTypes returns the distinct entity types in deterministic
// order — evidence must not depend on map iteration.
func uniqueSortedEntityTypes(entities []classifier.PIIEntity) []string {
	set := make(map[string]struct{}, len(entities))
	for _, e := range entities {
		set[e.Type] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
