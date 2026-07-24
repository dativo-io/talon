package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// TokenUsage holds token counts from the upstream response. Input excludes
// cache tokens (normalized per provider family); CacheRead/CacheWrite are the
// prompt-cache read/write token counts when the provider reports them.
type TokenUsage struct {
	Input      int
	Output     int
	CacheRead  int
	CacheWrite int
}

// StreamingMetrics holds timing and counts for streaming responses (filled by streamCopy).
type StreamingMetrics struct {
	TTFT       time.Duration // time from request sent to first content-bearing chunk
	ChunkCount int           // number of SSE events that contained content (for TPOT)
}

// Stream flavors select the terminal SSE event emitted when an in-flight
// stream dies mid-way (#195). Chat Completions has no standard mid-stream
// error event, so its flavor emits nothing (documented truncation).
const (
	streamFlavorAnthropic = "anthropic" // Anthropic Messages: event: error
	streamFlavorResponses = "responses" // OpenAI Responses: event: response.failed
	streamFlavorChat      = "chat"      // OpenAI Chat Completions: no standard event
)

// ForwardParams groups parameters for forwarding a request to the upstream provider.
type ForwardParams struct {
	Context          context.Context
	Client           *http.Client
	UpstreamURL      string
	Method           string
	Body             []byte
	Headers          map[string]string // auth and other headers to send upstream
	Timeouts         ParsedTimeouts
	TokenUsage       *TokenUsage       // filled in from response (streaming or non-streaming)
	StreamingMetrics *StreamingMetrics // filled in for streaming responses (TTFT, chunk count)
	// StreamFlavor selects the family-correct terminal event on mid-stream
	// failure (#195): streamFlavorAnthropic | streamFlavorResponses |
	// streamFlavorChat. Empty behaves like chat (emit nothing).
	StreamFlavor string
}

// Forward sends the request to the upstream provider and writes the response to w.
// For streaming responses it passes through bytes and flushes incrementally; token usage is captured when present.
//
// Timeout semantics (#217): request_timeout bounds the whole exchange for
// non-streaming responses, enforced via a cancelable child context rather than
// http.Client.Timeout (which cannot distinguish streams). Once the response is
// identified as a live SSE stream, the total bound is released and
// stream_idle_timeout takes over: a healthy stream may run past
// request_timeout as long as the provider keeps sending; silence longer than
// the idle timeout aborts with a family-correct terminal event.
func Forward(w http.ResponseWriter, p ForwardParams) error {
	if p.Client == nil {
		p.Client = &http.Client{} // timeouts are enforced via reqCtx below
	}

	reqCtx, cancel := context.WithCancel(p.Context)
	defer cancel()
	wd := newGatewayWatchdog(cancel, p.Timeouts.RequestTimeout, p.Timeouts.StreamIdleTimeout)
	defer wd.stop()

	bodyReader := io.NopCloser(bytes.NewReader(p.Body))
	req, err := http.NewRequestWithContext(reqCtx, p.Method, p.UpstreamURL, bodyReader)
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(p.Body))
	for k, v := range p.Headers {
		if strings.EqualFold(k, "Accept-Encoding") {
			continue // let Go's transport manage compression transparently
		}
		req.Header.Set(k, v)
	}
	// Content-Type from body if not set
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// #nosec G704 -- upstream URL is from gateway config (provider base URL), not user-controlled
	streamStart := time.Now()
	resp, err := p.Client.Do(req)
	if err != nil {
		return wd.mapErr(err)
	}
	defer resp.Body.Close()

	// Copy response headers to client (including rate-limit headers)
	copyResponseHeaders(w, resp.Header, p.Headers)
	w.WriteHeader(resp.StatusCode)

	// Only treat as streaming when response is actually SSE. Many upstreams use
	// Transfer-Encoding: chunked for normal JSON responses; using that would
	// misroute to streamCopy and break token usage parsing (and cost/evidence).
	// Never stream 4xx/5xx: read the full body so the client gets a decompressed,
	// readable error (avoids 404 + raw gzip/binary being shown as garbage).
	contentType := resp.Header.Get("Content-Type")
	isStream := resp.StatusCode < 400 && strings.Contains(contentType, "text/event-stream")

	if isStream {
		return wd.mapErr(streamCopy(reqCtx, w, wd.streamBody(resp.Body), streamStart, p.TokenUsage, p.StreamingMetrics, resp.Header.Get("X-Request-Id"), p.StreamFlavor, wd))
	}

	// Non-streaming: read full body, parse usage if present, then write
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return wd.mapErr(err)
	}
	if p.TokenUsage != nil {
		parseUsageFromJSON(all, resp.Header.Get("X-Request-Id"), p.TokenUsage)
	}
	_, err = w.Write(all)
	return err
}

func copyResponseHeaders(w http.ResponseWriter, from http.Header, upstreamHeaders map[string]string) {
	// Forward rate-limit and other provider headers. Retry-After and the
	// Anthropic request-id/token-remaining/reset headers matter for client
	// backoff during 429s; dropping them breaks coding-agent retry behavior.
	for _, h := range []string{
		"Content-Type", "X-Request-Id", "Request-Id", "Anthropic-Request-Id", "Retry-After",
		"x-ratelimit-limit-requests", "x-ratelimit-remaining-requests", "x-ratelimit-reset-requests",
		"anthropic-ratelimit-requests-limit", "anthropic-ratelimit-requests-remaining", "anthropic-ratelimit-requests-reset",
		"anthropic-ratelimit-tokens-limit", "anthropic-ratelimit-tokens-remaining", "anthropic-ratelimit-tokens-reset",
	} {
		if v := from.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
}

// gatewayTimeoutError marks a timeout the gateway itself enforced: the total
// request_timeout or the stream_idle_timeout (#217). It unwraps to
// context.DeadlineExceeded and reports Timeout() true so failover
// classification (ClassTimeout, transient) matches the pre-#217
// http.Client.Timeout behavior — never context.Canceled, which classifies as
// a non-transient client disconnect.
type gatewayTimeoutError struct{ msg string }

func (e *gatewayTimeoutError) Error() string { return e.msg }
func (e *gatewayTimeoutError) Unwrap() error { return context.DeadlineExceeded }
func (e *gatewayTimeoutError) Timeout() bool { return true }

// gatewayWatchdog enforces request_timeout and stream_idle_timeout for one
// Forward call by canceling the upstream request's child context (#217).
// Canceling the child unblocks a read parked inside bufio.Scanner and aborts
// the in-flight request without touching the caller's context, so evidence,
// session accounting, and metrics still run after an abort.
type gatewayWatchdog struct {
	cancel     context.CancelFunc
	total      time.Duration
	idle       time.Duration
	totalTimer *time.Timer
	idleTimer  *time.Timer
	totalFired atomic.Bool
	idleFired  atomic.Bool
}

func newGatewayWatchdog(cancel context.CancelFunc, total, idle time.Duration) *gatewayWatchdog {
	wd := &gatewayWatchdog{cancel: cancel, total: total, idle: idle}
	if total > 0 {
		wd.totalTimer = time.AfterFunc(total, func() {
			wd.totalFired.Store(true)
			cancel()
		})
	}
	return wd
}

func (wd *gatewayWatchdog) stop() {
	if wd.totalTimer != nil {
		wd.totalTimer.Stop()
	}
	if wd.idleTimer != nil {
		wd.idleTimer.Stop()
	}
}

// streamBody switches enforcement from total duration to idle silence: the
// response is a live SSE stream, so request_timeout no longer applies. The
// returned reader arms the idle timer only while a Read is blocked on the
// upstream — a slow client (write backpressure) never trips it — and re-arms
// on every read, not per SSE event, since one large event spans many reads.
// stream_idle_timeout <= 0 disables idle enforcement (the outer server
// write timeout remains the only ceiling).
func (wd *gatewayWatchdog) streamBody(r io.Reader) io.Reader {
	if wd.totalTimer != nil {
		wd.totalTimer.Stop()
	}
	if wd.idle <= 0 {
		return r
	}
	wd.idleTimer = time.AfterFunc(wd.idle, func() {
		wd.idleFired.Store(true)
		wd.cancel()
	})
	wd.idleTimer.Stop()
	return &idleResetReader{r: r, wd: wd}
}

// mapErr rewrites errors caused by a watchdog cancellation into a
// gatewayTimeoutError so evidence and logs say what actually happened
// ("stream idle timeout", not "context canceled") and failover still
// classifies the attempt as a transient timeout.
func (wd *gatewayWatchdog) mapErr(err error) error {
	if err == nil {
		return nil
	}
	if wd.idleFired.Load() {
		return &gatewayTimeoutError{msg: fmt.Sprintf("stream idle timeout: no data from provider for %s", wd.idle)}
	}
	if wd.totalFired.Load() {
		return &gatewayTimeoutError{msg: fmt.Sprintf("gateway request timeout after %s", wd.total)}
	}
	return err
}

// terminalMessage picks the terminal-event message for a dying stream.
// Nil-safe: a nil watchdog always returns the fallback.
func (wd *gatewayWatchdog) terminalMessage(fallback string) string {
	if wd == nil {
		return fallback
	}
	if wd.idleFired.Load() {
		return "stream idle timeout: no data from provider"
	}
	if wd.totalFired.Load() {
		return "gateway request timeout"
	}
	return fallback
}

// idleResetReader arms the watchdog's idle timer for the duration of each
// blocking Read and disarms it as soon as data arrives.
type idleResetReader struct {
	r  io.Reader
	wd *gatewayWatchdog
}

func (ir *idleResetReader) Read(p []byte) (int, error) {
	ir.wd.idleTimer.Reset(ir.wd.idle)
	n, err := ir.r.Read(p)
	ir.wd.idleTimer.Stop()
	return n, err
}

// streamCopy copies the SSE stream to w, flushing after each event, and extracts token usage when seen.
// streamStart is when the HTTP request was sent (for TTFT). If streamingMetrics is non-nil, TTFT is set
// on the first content-bearing SSE event. On mid-stream failure a family-correct
// terminal event is emitted per flavor (#195) so clients see an explicit error
// instead of a silently truncated stream. wd (nil-safe) refines the terminal
// message when the gateway's own idle/total watchdog caused the abort (#217).
func streamCopy(ctx context.Context, w http.ResponseWriter, r io.Reader, streamStart time.Time, usage *TokenUsage, streamingMetrics *StreamingMetrics, requestID string, flavor string, wd *gatewayWatchdog) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback: copy without flush
		_, err := io.Copy(w, r)
		if err != nil {
			writeStreamTerminalError(w, nil, flavor, wd.terminalMessage("upstream stream interrupted"))
		}
		return err
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, 512*1024) // allow large tokens in one line
	var buf []byte
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			writeStreamTerminalError(w, flusher, flavor, wd.terminalMessage("stream interrupted by gateway"))
			return ctx.Err()
		default:
		}
		line := scanner.Bytes()
		buf = append(buf, line...)
		buf = append(buf, '\n')
		// Flush on empty line (end of SSE event)
		if len(line) == 0 {
			// Record time to first content-bearing chunk (TTFT) on first event that has data
			if streamingMetrics != nil && streamingMetrics.TTFT == 0 && hasContentData(buf) {
				streamingMetrics.TTFT = time.Since(streamStart)
			}
			if streamingMetrics != nil && hasContentData(buf) {
				streamingMetrics.ChunkCount++
			}
			// #nosec G705 -- proxy forwards upstream LLM response; Content-Type controlled by upstream
			if _, err := w.Write(buf); err != nil {
				return err
			}
			flusher.Flush()
			// Try to extract usage from data line (OpenAI final chunk or Anthropic message_delta)
			if usage != nil {
				extractUsageFromSSELine(buf, usage)
			}
			buf = buf[:0]
		}
	}
	if len(buf) > 0 {
		// #nosec G705 -- proxy forwards upstream LLM response; Content-Type controlled by upstream
		_, _ = w.Write(buf)
		flusher.Flush()
	}
	if err := scanner.Err(); err != nil {
		// Upstream died mid-stream. Without a terminal event the client sees a
		// truncated-but-"successful" stream: Codex retry-loops waiting for
		// response.completed; Anthropic SDKs hang until their own timeout.
		writeStreamTerminalError(w, flusher, flavor, wd.terminalMessage("upstream connection lost mid-stream"))
		return err
	}
	return nil
}

// writeStreamTerminalError emits the family-correct terminal SSE event after a
// mid-stream failure (#195). Anthropic streams get the documented `event:
// error`; Responses streams get `response.failed` (the terminal event Codex
// waits for). Chat Completions has no standard mid-stream error event, so
// nothing is emitted for that flavor — the truncation is documented in
// LIMITATIONS.md. Messages are gateway-authored constants plus a fixed reason;
// no upstream error text (which could contain anything) is ever forwarded.
func writeStreamTerminalError(w http.ResponseWriter, flusher http.Flusher, flavor, message string) {
	var event string
	switch flavor {
	case streamFlavorAnthropic:
		payload, _ := json.Marshal(map[string]interface{}{
			"type":  "error",
			"error": map[string]string{"type": "api_error", "message": message},
		})
		event = "event: error\ndata: " + string(payload) + "\n\n"
	case streamFlavorResponses:
		payload, _ := json.Marshal(map[string]interface{}{
			"type": "response.failed",
			"response": map[string]interface{}{
				"status": "failed",
				"error":  map[string]string{"code": "upstream_error", "message": message},
			},
		})
		event = "event: response.failed\ndata: " + string(payload) + "\n\n"
	default:
		return
	}
	// The stream may have died mid-event, leaving an unterminated partial
	// event on the wire; without a separator, SSE parsers would fold the
	// terminal event's lines into that partial and never dispatch the error.
	// A leading blank line closes any pending event (and dispatches nothing
	// when none is pending), so the terminal event always parses as its own
	// event (#393).
	event = "\n\n" + event
	// A terminal event written through an uncommitted failover writer would
	// count as the first body byte of a 200, committing the response and
	// permanently disabling failover for a stream that delivered nothing.
	// Defer it instead: flushTo emits it when no fallback takes over (#217).
	if d, ok := w.(interface{ deferTerminalEvent([]byte) bool }); ok && d.deferTerminalEvent([]byte(event)) {
		return
	}
	//nolint:gosec // G705: gateway-authored constant SSE error event, not upstream content
	_, _ = w.Write([]byte(event))
	if flusher != nil {
		flusher.Flush()
	}
}

// hasContentData returns true if the SSE buffer contains a data: line with JSON that has content
// (e.g. choices[].delta.content for OpenAI or content_block.delta.text for Anthropic).
func hasContentData(buf []byte) bool {
	lines := bytes.Split(buf, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data: ")) {
			continue
		}
		payload := bytes.TrimPrefix(line, []byte("data: "))
		payload = bytes.TrimSpace(payload)
		if bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(payload, &m); err != nil {
			continue
		}
		// OpenAI: choices[0].delta.content
		if choices, _ := m["choices"].([]interface{}); len(choices) > 0 {
			if choice, _ := choices[0].(map[string]interface{}); choice != nil {
				if delta, _ := choice["delta"].(map[string]interface{}); delta != nil {
					if _, has := delta["content"]; has {
						return true
					}
				}
			}
		}
		// Anthropic: type content_block_delta and delta.text
		if typ, _ := m["type"].(string); typ == "content_block_delta" {
			if delta, _ := m["delta"].(map[string]interface{}); delta != nil {
				if _, has := delta["text"]; has {
					return true
				}
			}
		}
	}
	return false
}

func extractUsageFromSSELine(block []byte, usage *TokenUsage) {
	// Block may contain multiple lines (event: ...\ndata: {...}). Find data: lines.
	lines := bytes.Split(block, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data: ")) {
			continue
		}
		payload := bytes.TrimPrefix(line, []byte("data: "))
		payload = bytes.TrimSpace(payload)
		if bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		extractUsageFromJSONPayload(payload, usage)
	}
}

func extractUsageFromJSONPayload(payload []byte, usage *TokenUsage) {
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return
	}
	// Anthropic events are typed and must be handled before the generic
	// top-level "usage" branch: a real message_delta event carries usage as a
	// top-level sibling of "delta", so the OpenAI branch would match it, find
	// no prompt/completion tokens, and return — losing output tokens entirely.
	switch typ, _ := m["type"].(string); typ {
	case "message_start":
		// message_start carries message.usage with input and cache tokens.
		if msg, ok := m["message"].(map[string]interface{}); ok {
			if u, ok := msg["usage"].(map[string]interface{}); ok {
				applyAnthropicUsage(u, usage)
			}
		}
		return
	case "message_delta":
		// message_delta has top-level usage.output_tokens (cumulative)
		if u, ok := m["usage"].(map[string]interface{}); ok {
			if n, _ := u["output_tokens"].(float64); n > 0 {
				usage.Output = int(n)
			}
		}
		return
	case "response.completed", "response.incomplete":
		// OpenAI Responses API streaming: usage arrives nested under "response"
		// only in the terminal event (Codex always streams; without this its
		// cost is estimate-only).
		if resp, ok := m["response"].(map[string]interface{}); ok {
			if u, ok := resp["usage"].(map[string]interface{}); ok {
				applyOpenAIUsage(u, usage)
			}
		}
		return
	}
	// OpenAI chat-completions usage at top level (final chunk with include_usage).
	if u, ok := m["usage"].(map[string]interface{}); ok {
		applyOpenAIUsage(u, usage)
	}
}

// applyAnthropicUsage reads an Anthropic usage object. input_tokens EXCLUDES
// cache tokens; cache_creation_input_tokens / cache_read_input_tokens are the
// write/read counts. Values map to TokenUsage directly (no subtraction).
func applyAnthropicUsage(u map[string]interface{}, usage *TokenUsage) {
	if n, _ := u["input_tokens"].(float64); n > 0 {
		usage.Input = int(n)
	}
	if n, _ := u["output_tokens"].(float64); n > 0 {
		usage.Output = int(n)
	}
	if n, _ := u["cache_creation_input_tokens"].(float64); n > 0 {
		usage.CacheWrite = int(n)
	}
	if n, _ := u["cache_read_input_tokens"].(float64); n > 0 {
		usage.CacheRead = int(n)
	}
}

// applyOpenAIUsage reads an OpenAI usage object (Chat Completions or Responses
// API). cached_tokens is a SUBSET of prompt/input tokens, so Input is
// normalized to prompt_tokens − cached_tokens and the cached count becomes
// CacheRead. OpenAI has no cache-write token (caching is automatic, free-write).
func applyOpenAIUsage(u map[string]interface{}, usage *TokenUsage) {
	prompt, _ := u["prompt_tokens"].(float64)
	if prompt == 0 {
		prompt, _ = u["input_tokens"].(float64) // Responses API naming
	}
	var cached float64
	if d, ok := u["prompt_tokens_details"].(map[string]interface{}); ok {
		cached, _ = d["cached_tokens"].(float64)
	} else if d, ok := u["input_tokens_details"].(map[string]interface{}); ok {
		cached, _ = d["cached_tokens"].(float64)
	}
	if prompt > 0 {
		in := prompt - cached
		if in < 0 {
			in = 0
		}
		usage.Input = int(in)
	}
	if cached > 0 {
		usage.CacheRead = int(cached)
	}
	if n, _ := u["completion_tokens"].(float64); n > 0 {
		usage.Output = int(n)
	} else if n, _ := u["output_tokens"].(float64); n > 0 {
		usage.Output = int(n)
	}
}

func parseUsageFromJSON(body []byte, _ string, usage *TokenUsage) {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return
	}
	if u, ok := m["usage"].(map[string]interface{}); ok {
		// Anthropic reports cache tokens as separate (non-subset) counts, so it
		// must not go through the OpenAI subset normalization. Route by the
		// presence of Anthropic cache-token keys; both families' non-cache
		// shape ({input,output}_tokens) is handled correctly by applyOpenAIUsage.
		_, hasCacheWrite := u["cache_creation_input_tokens"]
		_, hasCacheRead := u["cache_read_input_tokens"]
		if hasCacheWrite || hasCacheRead {
			applyAnthropicUsage(u, usage)
		} else {
			applyOpenAIUsage(u, usage)
		}
		return
	}
	// Anthropic /v1/messages/count_tokens responds {"input_tokens": N} with no
	// usage wrapper; record the count so evidence carries a meaningful token
	// figure (the request itself is free — cost is zeroed by the agent).
	if n, _ := m["input_tokens"].(float64); n > 0 {
		usage.Input = int(n)
	}
}

// HTTPClientForGateway returns an http.Client with gateway timeouts.
// When transport is non-nil it wraps the timeout-aware base transport
// (e.g. air-gap egress guard layered on top of the ResponseHeaderTimeout transport).
func HTTPClientForGateway(timeouts ParsedTimeouts, transport http.RoundTripper) *http.Client {
	base := &http.Transport{
		// connect_timeout bounds connection establishment: TCP dial plus TLS
		// handshake. It must not bound the header wait — non-streaming LLM
		// calls routinely take >10s to first byte (#230).
		DialContext: (&net.Dialer{
			Timeout:   timeouts.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   timeouts.ConnectTimeout,
		ResponseHeaderTimeout: timeouts.ResponseHeaderTimeout,
		// A custom DialContext disables the automatic HTTP/2 upgrade; keep h2
		// for upstreams that negotiate it (OpenAI, Anthropic).
		ForceAttemptHTTP2: true,
	}
	var rt http.RoundTripper = base
	if transport != nil {
		if guard, ok := transport.(interface{ SetBase(http.RoundTripper) }); ok {
			guard.SetBase(base)
		}
		rt = transport
	}
	return &http.Client{
		// No http.Client.Timeout: request_timeout and stream_idle_timeout are
		// enforced per-request in Forward via context cancellation, so a
		// healthy SSE stream is bounded by idle silence instead of being
		// hard-cut at request_timeout (#217).
		Transport: rt,
	}
}
