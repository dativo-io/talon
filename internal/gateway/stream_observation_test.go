package gateway

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
)

// pacedUpstream is a deterministic multi-chunk SSE provider: it emits its
// head events, blocks until the test releases it, then emits the tail. The
// release point is the coordination primitive that proves streaming: a
// client that sees the head while the upstream is still blocked was not
// served from a buffer of the completed stream.
type pacedUpstream struct {
	head    string
	tail    string
	release chan struct{}
	done    chan struct{}
	relOnce sync.Once
	mu      sync.Mutex
	headAt  time.Time
	tailAt  time.Time
}

// unblock releases the tail (idempotent). Preventive actions hold even the
// response headers until the verdict, so the client cannot observe anything
// before the upstream finishes; the harness therefore releases on a timer as
// well as on first-event arrival.
func (p *pacedUpstream) unblock() { p.relOnce.Do(func() { close(p.release) }) }

func (p *pacedUpstream) headWrittenAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.headAt
}

func (p *pacedUpstream) tailWrittenAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tailAt
}

func newPacedUpstream(head, tail string) *pacedUpstream {
	return &pacedUpstream{head: head, tail: tail, release: make(chan struct{}), done: make(chan struct{})}
}

func (p *pacedUpstream) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer close(p.done)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, p.head)
		flusher.Flush()
		p.mu.Lock()
		p.headAt = time.Now()
		p.mu.Unlock()
		select {
		case <-p.release:
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		_, _ = io.WriteString(w, p.tail)
		flusher.Flush()
		p.mu.Lock()
		p.tailAt = time.Now()
		p.mu.Unlock()
	}
}

// completed reports whether the upstream handler has returned.
func (p *pacedUpstream) completed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// serveGateway exposes the gateway over a real listener so the client observes
// chunk arrival as it happens (httptest.ResponseRecorder only shows the final
// body).
func serveGateway(t *testing.T, gw *Gateway) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) { r.Handle("/*", gw) })
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func streamRequest(t *testing.T, srv *httptest.Server, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// sseCapture drains a streamed response on ONE goroutine: it reports the
// first SSE event (through its blank-line terminator) as soon as it arrives
// and the complete body once the stream ends, with receive timestamps. A
// single reader avoids racing bufio between a first-event wait and the body
// drain.
type sseCapture struct {
	first      chan string
	done       chan string
	firstAt    time.Time
	lastAt     time.Time
	eventsSeen int
}

func captureSSE(r io.Reader) *sseCapture {
	c := &sseCapture{first: make(chan string, 1), done: make(chan string, 1)}
	go func() {
		br := bufio.NewReader(r)
		var all, ev strings.Builder
		for {
			line, err := br.ReadString('\n')
			all.WriteString(line)
			ev.WriteString(line)
			if line == "\n" || (err != nil && ev.Len() > 0) {
				now := time.Now()
				if c.eventsSeen == 0 {
					c.firstAt = now
					c.first <- ev.String()
				}
				c.eventsSeen++
				c.lastAt = now
				ev.Reset()
			}
			if err != nil {
				if c.eventsSeen == 0 {
					c.first <- ""
				}
				c.done <- all.String()
				return
			}
		}
	}()
	return c
}

// waitFirst returns the first event and whether it arrived within the bound.
// The deadline is a failure bound, not a pacing sleep: on the passing path
// it returns as soon as the gateway flushes the event.
func (c *sseCapture) waitFirst(within time.Duration) (string, bool) {
	select {
	case ev := <-c.first:
		return ev, ev != ""
	case <-time.After(within):
		return "", false
	}
}

// body blocks until the stream has ended and returns the complete body.
func (c *sseCapture) body(t *testing.T) string {
	t.Helper()
	select {
	case b := <-c.done:
		return b
	case <-time.After(30 * time.Second):
		t.Fatal("stream did not end")
		return ""
	}
}

func chatDelta(content string) string {
	return `data: {"id":"chatcmpl-test","choices":[{"index":0,"delta":{"content":"` + content + `"},"finish_reason":null}]}` + "\n\n"
}

const chatTerminal = `data: {"id":"chatcmpl-test","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}` + "\n\n" + "data: [DONE]\n\n"

// TestGateway_StreamingWarn_FirstChunkBeforeUpstreamCompletion is the #476
// contract: under response_pii_action warn the first SSE event reaches the
// client while the provider is still generating, the delivered bytes are the
// upstream bytes (PII split across deltas included), and the signed record
// says the PII was observed after delivery — not prevented.
func TestGateway_StreamingWarn_FirstChunkBeforeUpstreamCompletion(t *testing.T) {
	head := chatDelta("Contact ")
	tail := chatDelta("jan.kowalski") + chatDelta("@gmail.com for details") + chatTerminal
	up := newPacedUpstream(head, tail)

	gw, _, evStore := setupOpenClawGateway(t, "warn", up.handler())
	gw.config.OrganizationPolicy.Defaults.ResponsePIIAction = "warn"
	srv := serveGateway(t, gw)

	timer := time.AfterFunc(5*time.Second, up.unblock)
	defer timer.Stop()
	resp := streamRequest(t, srv, "/v1/proxy/openai/v1/chat/completions", //nolint:bodyclose // closed by t.Cleanup in streamRequest
		`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"who is the contact?"}],"stream":true}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	cap := captureSSE(resp.Body)
	first, ok := cap.waitFirst(5 * time.Second)
	upstreamDoneAtFirstChunk := up.completed()
	up.unblock()
	require.True(t, ok, "first SSE event must arrive while the upstream is still streaming (warn must not buffer the whole stream)")
	assert.Equal(t, head, first, "first event must be the upstream's first event, unchanged")
	assert.False(t, upstreamDoneAtFirstChunk, "first chunk must be delivered before the upstream stream completes")
	got := cap.body(t)
	assert.Equal(t, head+tail, got, "warn must deliver the upstream stream byte-identically")
	// Timing record (issue #476 performance invariant): the downstream first
	// chunk precedes the upstream terminal chunk on a paced multi-chunk stream.
	assert.True(t, cap.firstAt.Before(up.tailWrittenAt()), "downstream first chunk %s must precede upstream terminal %s", cap.firstAt, up.tailWrittenAt())
	t.Logf("timing: upstream_first=%s downstream_first=%s upstream_terminal=%s downstream_terminal=%s",
		up.headWrittenAt().Format(time.RFC3339Nano), cap.firstAt.Format(time.RFC3339Nano), up.tailWrittenAt().Format(time.RFC3339Nano), cap.lastAt.Format(time.RFC3339Nano))

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.PolicyDecision.Allowed, "warn never denies")
	assert.True(t, ev.Classification.OutputPIIDetected, "PII split across deltas must be detected after delivery")
	assert.Contains(t, ev.Classification.OutputPIITypes, "email")
	require.NotNil(t, ev.Classification.ResponseScan, "streaming warn must record the response_scan observation")
	assert.Equal(t, evidence.ResponseScanEnforcementPostDelivery, ev.Classification.ResponseScan.Enforcement)
	assert.Equal(t, evidence.ResponseScanStatusComplete, ev.Classification.ResponseScan.Status)
	assert.Equal(t, "warn", ev.Classification.ResponseScan.Action)
	assert.Positive(t, ev.Classification.ResponseScan.BytesObserved)
	assert.True(t, evStore.VerifyRecord(ev))
	for _, item := range ev.DataFlow.Items {
		if item.Source == evidence.FlowSourceResponse {
			assert.Equal(t, evidence.FlowDispositionSurfaced, item.Disposition, "delivered PII must not be recorded as redacted or blocked")
		}
	}
	for _, ex := range ev.Explanations {
		assert.NotEqual(t, "deny", ex.Decision, "an observed warn must not carry a deny explanation: %+v", ex)
	}
}

// ---------------------------------------------------------------------------
// Shared fixtures for the streaming response-scan matrix
// ---------------------------------------------------------------------------

// setupStreamGateway is setupGatewayWithClassifier with both wire families
// (openai + anthropic) pointed at the same upstream and the response action
// set explicitly, so one harness covers Chat Completions, Responses and
// Messages streams.
func setupStreamGateway(t *testing.T, responseAction string, upstreamHandler http.HandlerFunc, cls classifier.Facade) (*Gateway, *evidence.Store) {
	t.Helper()
	gw, upstream, evStore := setupGatewayWithClassifier(t, "warn", upstreamHandler, cls)
	gw.config.Providers["anthropic"] = ProviderConfig{Enabled: true, BaseURL: upstream.URL, SecretName: "openai-api-key"}
	gw.config.OrganizationPolicy.Defaults.ResponsePIIAction = responseAction
	return gw, evStore
}

const (
	chatPath      = "/v1/proxy/openai/v1/chat/completions"
	responsesPath = "/v1/proxy/openai/v1/responses"
	messagesPath  = "/v1/proxy/anthropic/v1/messages"

	chatStreamBody      = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"who is the contact?"}],"stream":true}`
	responsesStreamBody = `{"model":"gpt-4o-mini","input":"who is the contact?","stream":true}`
	messagesStreamBody  = `{"model":"gpt-4o-mini","max_tokens":64,"messages":[{"role":"user","content":"who is the contact?"}],"stream":true}`
)

func responsesDelta(text string) string {
	return `event: response.output_text.delta` + "\n" + `data: {"type":"response.output_text.delta","delta":"` + text + `"}` + "\n\n"
}

func responsesCompleted(text string) string {
	return `event: response.completed` + "\n" + `data: {"type":"response.completed","response":{"id":"resp_1","output":[{"type":"message","content":[{"type":"output_text","text":"` + text + `"}]}],"usage":{"input_tokens":5,"output_tokens":7}}}` + "\n\n"
}

func anthropicDelta(text string) string {
	return "event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + text + `"}}` + "\n\n"
}

const anthropicHead = "event: message_start\n" + `data: {"type":"message_start","message":{"id":"msg_1","role":"assistant","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n" +
	"event: content_block_start\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n"

const anthropicTail = "event: content_block_stop\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n" +
	"event: message_delta\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}` + "\n\n" +
	"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"

// countingWriter records downstream Write/Flush calls for the writer unit test.
type countingWriter struct {
	header  http.Header
	status  int
	body    bytes.Buffer
	writes  int
	flushes int
	failAt  int // 0 = never; n = the n-th write returns an error after a short write
}

func (c *countingWriter) Header() http.Header {
	if c.header == nil {
		c.header = http.Header{}
	}
	return c.header
}
func (c *countingWriter) WriteHeader(code int) { c.status = code }
func (c *countingWriter) Write(b []byte) (int, error) {
	c.writes++
	if c.failAt != 0 && c.writes == c.failAt {
		n := len(b) / 2
		c.body.Write(b[:n])
		return n, io.ErrShortWrite
	}
	return c.body.Write(b)
}
func (c *countingWriter) Flush() { c.flushes++ }

func TestObservingStreamWriter_DeliversFirstAndCapturesBounded(t *testing.T) {
	down := &countingWriter{}
	w := newObservingStreamWriter(down)
	w.limit = 10

	n, err := w.Write([]byte("abcd"))
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, 1, down.writes, "every write reaches the client immediately")
	assert.Equal(t, "abcd", down.body.String())
	assert.Equal(t, "abcd", w.capture.String(), "capture mirrors delivered bytes under the limit")
	assert.Equal(t, http.StatusOK, w.status(), "an implicit status is 200, as net/http would send")

	w.Flush()
	assert.Equal(t, 1, down.flushes, "flush delegates immediately")

	n, err = w.Write([]byte("efghijkl")) // crosses the 10-byte bound
	require.NoError(t, err)
	assert.Equal(t, 8, n, "the bound never shortens a client write")
	assert.Equal(t, "abcdefghijkl", down.body.String(), "byte order and completeness preserved downstream")
	assert.Equal(t, "abcdefghij", w.capture.String(), "capture stops exactly at the bound")
	assert.True(t, w.overflowed, "overflow is an explicit state")

	n, err = w.Write([]byte("mnop"))
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, 10, w.capture.Len(), "capture never grows past the bound")
	assert.Equal(t, "abcdefghijklmnop", down.body.String())
	assert.False(t, w.overflowed && down.writes != 3, "overflow never fails or drops downstream writes")
}

func TestObservingStreamWriter_StatusAndPartialWrite(t *testing.T) {
	down := &countingWriter{failAt: 1}
	w := newObservingStreamWriter(down)
	w.WriteHeader(http.StatusAccepted)
	assert.Equal(t, http.StatusAccepted, down.status, "status passes through")
	assert.Equal(t, http.StatusAccepted, w.status())

	n, err := w.Write([]byte("0123456789"))
	require.ErrorIs(t, err, io.ErrShortWrite)
	assert.Equal(t, 5, n)
	assert.Equal(t, "01234", w.capture.String(), "the capture records only what the client actually received")
}

// firstEventBeforeCompletion drives one streamed request against the paced
// upstream and reports whether the first SSE event was delivered while the
// upstream was still blocked, plus the full client body and status.
func firstEventBeforeCompletion(t *testing.T, srv *httptest.Server, up *pacedUpstream, path, body string, wait time.Duration) (early bool, status int, full string) {
	t.Helper()
	timer := time.AfterFunc(wait, up.unblock)
	defer timer.Stop()
	resp := streamRequest(t, srv, path, body) //nolint:bodyclose // closed by t.Cleanup in streamRequest
	cap := captureSSE(resp.Body)
	_, ok := cap.waitFirst(wait)
	early = ok && !up.completed()
	up.unblock()
	return early, resp.StatusCode, cap.body(t)
}

func TestGateway_StreamingAllow_DirectStreamNoResponseScan(t *testing.T) {
	head := chatDelta("Contact ")
	tail := chatDelta("jan.kowalski@gmail.com") + chatTerminal
	up := newPacedUpstream(head, tail)
	gw, evStore := setupStreamGateway(t, "allow", up.handler(), nil)
	srv := serveGateway(t, gw)

	early, status, got := firstEventBeforeCompletion(t, srv, up, chatPath, chatStreamBody, 5*time.Second)
	assert.Equal(t, http.StatusOK, status)
	assert.True(t, early, "allow streams directly")
	assert.Equal(t, head+tail, got)

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.PolicyDecision.Allowed)
	assert.False(t, ev.Classification.OutputPIIDetected, "allow performs no response scan")
	assert.Nil(t, ev.Classification.ResponseScan, "no response scan ran, so no response_scan fact")
}

// Preventive redact: the client never sees the raw PII, which requires the
// stream to be held until the verdict — the documented time-to-first-token
// trade-off. The evidence says preventive, redacted before release.
func TestGateway_StreamingRedact_RemainsPreventiveAndBuffered(t *testing.T) {
	head := chatDelta("Contact ")
	tail := chatDelta("jan.kowalski@gmail.com") + chatDelta(" for details") + chatTerminal
	up := newPacedUpstream(head, tail)
	gw, evStore := setupStreamGateway(t, "redact", up.handler(), nil)
	srv := serveGateway(t, gw)

	early, status, got := firstEventBeforeCompletion(t, srv, up, chatPath, chatStreamBody, 300*time.Millisecond)
	assert.Equal(t, http.StatusOK, status)
	assert.False(t, early, "redact is preventive: nothing is released before the scan verdict (buffered by design)")
	assert.NotContains(t, got, "jan.kowalski@gmail.com", "raw PII must never reach the client under redact")
	assert.Contains(t, got, "Contact", "non-PII content is delivered")
	assert.Contains(t, got, "[DONE]")

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.PolicyDecision.Allowed)
	assert.True(t, ev.Classification.OutputPIIDetected)
	require.NotNil(t, ev.Classification.ResponseScan)
	assert.Equal(t, "redact", ev.Classification.ResponseScan.Action)
	assert.Equal(t, evidence.ResponseScanEnforcementPreventive, ev.Classification.ResponseScan.Enforcement)
	assert.Equal(t, evidence.ResponseScanStatusComplete, ev.Classification.ResponseScan.Status)
	assert.True(t, ev.Classification.ResponseScan.Streamed)
	assert.True(t, ev.Classification.ResponsePIIRedacted(ev.DataFlow))
	for _, item := range ev.DataFlow.Items {
		if item.Source == evidence.FlowSourceResponse {
			assert.Equal(t, evidence.FlowDispositionRedacted, item.Disposition)
		}
	}
	primary := ev.Explanations[0]
	assert.Equal(t, "POLICY_REDACTED_PII_OUTPUT", primary.Code)
	assert.Equal(t, "modify", primary.Decision)
	assert.True(t, evStore.VerifyRecord(ev))
}

func TestGateway_StreamingBlock_RemainsPreventive(t *testing.T) {
	head := chatDelta("Your IBAN is ")
	tail := chatDelta("DE89370400440532013000") + chatTerminal
	up := newPacedUpstream(head, tail)
	gw, evStore := setupStreamGateway(t, "block", up.handler(), nil)
	srv := serveGateway(t, gw)

	early, status, got := firstEventBeforeCompletion(t, srv, up, chatPath, chatStreamBody, 300*time.Millisecond)
	assert.False(t, early, "block is preventive: the stream is withheld until the verdict")
	assert.Equal(t, http.StatusUnavailableForLegalReasons, status)
	assert.NotContains(t, got, "DE89370400440532013000")
	assert.Contains(t, got, "pii_policy_violation")

	ev := latestEvidence(t, evStore)
	assert.False(t, ev.PolicyDecision.Allowed, "a withheld response is a denial")
	assert.Contains(t, ev.PolicyDecision.Reasons, "output_pii_blocked")
	require.NotNil(t, ev.Classification.ResponseScan)
	assert.Equal(t, "block", ev.Classification.ResponseScan.Action)
	assert.Equal(t, evidence.ResponseScanEnforcementPreventive, ev.Classification.ResponseScan.Enforcement)
	assert.Equal(t, "POLICY_DENIED_PII_OUTPUT", ev.Explanations[0].Code)
	assert.Equal(t, "deny", ev.Explanations[0].Decision)
}

// PII split across deltas on every supported streaming wire: delivered
// unchanged, detected after delivery, recorded as post-delivery observation.
func TestGateway_StreamingWarn_AllWireFamilies(t *testing.T) {
	cases := []struct {
		name, path, body, head, tail string
	}{
		{
			"chat_completions", chatPath, chatStreamBody,
			chatDelta("Reach me at "), chatDelta("jan.kow") + chatDelta("alski@gmail.com") + chatTerminal,
		},
		{
			"responses", responsesPath, responsesStreamBody,
			responsesDelta("Reach me at "), responsesDelta("jan.kow") + responsesDelta("alski@gmail.com") + responsesCompleted("Reach me at jan.kowalski@gmail.com") + "data: [DONE]\n\n",
		},
		{
			"anthropic_messages", messagesPath, messagesStreamBody,
			anthropicHead + anthropicDelta("Reach me at "), anthropicDelta("jan.kow") + anthropicDelta("alski@gmail.com") + anthropicTail,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newPacedUpstream(tc.head, tc.tail)
			gw, evStore := setupStreamGateway(t, "warn", up.handler(), nil)
			srv := serveGateway(t, gw)

			early, status, got := firstEventBeforeCompletion(t, srv, up, tc.path, tc.body, 5*time.Second)
			assert.Equal(t, http.StatusOK, status)
			assert.True(t, early, "first event before upstream completion")
			assert.Equal(t, tc.head+tc.tail, got, "byte-identical delivery")

			ev := latestEvidence(t, evStore)
			assert.True(t, ev.PolicyDecision.Allowed)
			assert.True(t, ev.Classification.OutputPIIDetected, "PII split across deltas must be detected after delivery")
			assert.Equal(t, []string{"email"}, ev.Classification.OutputPIITypes, "deterministic type ordering")
			require.NotNil(t, ev.Classification.ResponseScan)
			assert.Equal(t, evidence.ResponseScanEnforcementPostDelivery, ev.Classification.ResponseScan.Enforcement)
			assert.Equal(t, evidence.ResponseScanStatusComplete, ev.Classification.ResponseScan.Status)
			assert.Equal(t, int64(len(tc.head+tc.tail)), ev.Classification.ResponseScan.BytesObserved)
			assert.Equal(t, "POLICY_OBSERVED_PII_OUTPUT", ev.Explanations[0].Code)
			assert.Equal(t, "allow", ev.Explanations[0].Decision)
			assert.True(t, ev.Classification.ResponsePIIObserved(ev.DataFlow))
			assert.False(t, ev.Classification.ResponsePIIRedacted(ev.DataFlow))
			assert.Positive(t, ev.Execution.Tokens.Output, "usage accounting still comes from the stream")
			assert.True(t, evStore.VerifyRecord(ev))
		})
	}
}

// A scanner failure after delivery cannot change what the client already
// received: the stream stays successful, the observation is recorded as
// incomplete with the typed failure kind, and no "no PII" claim is made.
func TestGateway_StreamingWarn_ScannerFailureAfterDelivery(t *testing.T) {
	const marker = "RESPONSE-ONLY-MARKER"
	head := chatDelta("prefix ")
	tail := chatDelta(marker) + chatTerminal
	up := newPacedUpstream(head, tail)
	gw, evStore := setupStreamGateway(t, "warn", up.handler(), failOnMarkerScanner(t, marker))
	srv := serveGateway(t, gw)

	early, status, got := firstEventBeforeCompletion(t, srv, up, chatPath, chatStreamBody, 5*time.Second)
	assert.Equal(t, http.StatusOK, status, "no retroactive error after a delivered stream")
	assert.True(t, early)
	assert.Equal(t, head+tail, got, "the delivered stream is untouched by the scanner failure")

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.PolicyDecision.Allowed, "warn scanner failure never turns into a denial")
	assert.Empty(t, ev.Execution.Error)
	assert.False(t, ev.Classification.OutputPIIDetected)
	require.NotNil(t, ev.Classification.ResponseScan)
	assert.Equal(t, evidence.ResponseScanStatusIncomplete, ev.Classification.ResponseScan.Status)
	assert.Equal(t, evidence.ResponseScanIncompleteScannerUnavailable, ev.Classification.ResponseScan.IncompleteReason)
	require.NotNil(t, ev.Classification.Scanner)
	assert.Equal(t, "status", ev.Classification.Scanner.Failure, "typed adapter failure kind is recorded")
	assert.True(t, evStore.VerifyRecord(ev))
}

// The same scanner failure under a preventive action stays fail-closed.
func TestGateway_StreamingRedact_ScannerFailureStaysFailClosed(t *testing.T) {
	const marker = "RESPONSE-ONLY-MARKER"
	up := newPacedUpstream(chatDelta("prefix "), chatDelta(marker)+chatTerminal)
	gw, evStore := setupStreamGateway(t, "redact", up.handler(), failOnMarkerScanner(t, marker))
	srv := serveGateway(t, gw)

	_, status, got := firstEventBeforeCompletion(t, srv, up, chatPath, chatStreamBody, 200*time.Millisecond)
	assert.Equal(t, http.StatusBadGateway, status)
	assert.NotContains(t, got, marker, "nothing of the buffered stream is released when the preventive scan fails")
	assert.Contains(t, got, "scanner_unavailable")

	ev := latestEvidence(t, evStore)
	assert.False(t, ev.PolicyDecision.Allowed)
	assert.Contains(t, ev.PolicyDecision.Reasons, "output_scanner_unavailable")
	require.NotNil(t, ev.Classification.ResponseScan)
	assert.Equal(t, evidence.ResponseScanEnforcementPreventive, ev.Classification.ResponseScan.Enforcement)
	assert.Equal(t, evidence.ResponseScanIncompleteScannerUnavailable, ev.Classification.ResponseScan.IncompleteReason)
}

// Upstream dies mid-stream under warn: already delivered bytes are not held
// back, the family-correct terminal behaviour is unchanged (#392/#393), the
// captured partial content is still observed, and the record says the
// observation was incomplete because of the upstream failure.
func TestGateway_StreamingWarn_UpstreamDiesMidStream(t *testing.T) {
	t.Run("chat_completions_no_terminal_event", func(t *testing.T) {
		partial := chatDelta("Your IBAN is DE89370400440532013000")
		gw, evStore := setupStreamGateway(t, "warn", dieMidStreamHandler(partial), nil)
		w := makeGatewayRequest(gw, chatStreamBody)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, partial, w.Body.String(), "delivered bytes stay delivered; Chat Completions has no terminal error event")

		ev := latestEvidence(t, evStore)
		assert.True(t, ev.PolicyDecision.Allowed)
		assert.NotEmpty(t, ev.Execution.Error, "the upstream failure is recorded as the execution error")
		assert.True(t, ev.Classification.OutputPIIDetected, "PII in the delivered partial is still observed")
		require.NotNil(t, ev.Classification.ResponseScan)
		assert.Equal(t, evidence.ResponseScanStatusIncomplete, ev.Classification.ResponseScan.Status)
		assert.Equal(t, evidence.ResponseScanIncompleteUpstreamError, ev.Classification.ResponseScan.IncompleteReason)
	})
	t.Run("responses_keeps_terminal_event", func(t *testing.T) {
		partial := responsesDelta("Hello there")
		gw, evStore := setupStreamGateway(t, "warn", dieMidStreamHandler(partial), nil)
		w := makeGatewayRequestToPath(gw, responsesPath, responsesStreamBody)
		body := w.Body.String()
		assert.True(t, strings.HasPrefix(body, partial), "delivered bytes come first, unchanged")
		assert.Contains(t, body, "event: response.failed", "gateway terminal event is preserved (#392)")
		assert.Contains(t, body, "upstream connection lost mid-stream")

		ev := latestEvidence(t, evStore)
		assert.False(t, ev.Classification.OutputPIIDetected)
		require.NotNil(t, ev.Classification.ResponseScan)
		assert.Equal(t, evidence.ResponseScanStatusIncomplete, ev.Classification.ResponseScan.Status, "a clean partial is not a clean scan")
		assert.Equal(t, evidence.ResponseScanIncompleteUpstreamError, ev.Classification.ResponseScan.IncompleteReason)
	})
}

// Idle timeout under warn: the chunks before the stall were streamed, the
// family-correct terminal event is emitted (#217), and the observation is
// truthfully incomplete.
func TestGateway_StreamingWarn_IdleTimeoutIsIncomplete(t *testing.T) {
	stall := make(chan struct{})
	defer close(stall)
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, anthropicHead+anthropicDelta("Contact jan.kowalski@gmail.com"))
		flusher.Flush()
		select {
		case <-stall:
		case <-r.Context().Done():
		}
	}
	gw, evStore := setupStreamGateway(t, "warn", handler, nil)
	gw.timeouts.StreamIdleTimeout = 150 * time.Millisecond
	srv := serveGateway(t, gw)

	resp := streamRequest(t, srv, messagesPath, messagesStreamBody) //nolint:bodyclose // closed by t.Cleanup in streamRequest
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "jan.kowalski@gmail.com", "bytes before the stall were streamed, warn never recalls them")
	assert.Contains(t, string(body), "event: error")
	assert.Contains(t, string(body), "stream idle timeout")

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.PolicyDecision.Allowed)
	assert.True(t, ev.Classification.OutputPIIDetected)
	require.NotNil(t, ev.Classification.ResponseScan)
	assert.Equal(t, evidence.ResponseScanStatusIncomplete, ev.Classification.ResponseScan.Status)
	assert.Equal(t, evidence.ResponseScanIncompleteUpstreamError, ev.Classification.ResponseScan.IncompleteReason)
}

// Client cancels mid-stream: the upstream request is torn down, the request
// lifecycle still commits evidence, and the observation says client_cancelled
// instead of fabricating a clean scan over what was captured.
func TestGateway_StreamingWarn_ClientCancelIsIncomplete(t *testing.T) {
	upstreamGone := make(chan struct{})
	handler := func(w http.ResponseWriter, r *http.Request) {
		defer close(upstreamGone)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, chatDelta("Contact jan.kowalski@gmail.com"))
		flusher.Flush()
		select {
		case <-r.Context().Done(): // the gateway cancelled the upstream request
		case <-time.After(10 * time.Second):
			t.Error("upstream request was not cancelled after the client went away")
		}
	}
	gw, evStore := setupStreamGateway(t, "warn", handler, nil)
	srv := serveGateway(t, gw)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+chatPath, strings.NewReader(chatStreamBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	first, ok := captureSSE(resp.Body).waitFirst(5 * time.Second)
	require.True(t, ok)
	assert.Contains(t, first, "jan.kowalski@gmail.com")
	cancel()
	_ = resp.Body.Close()

	select {
	case <-upstreamGone:
	case <-time.After(10 * time.Second):
		t.Fatal("upstream handler did not return: cancellation leaked")
	}
	require.Eventually(t, func() bool {
		list, err := evStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 1)
		return err == nil && len(list) == 1
	}, 5*time.Second, 20*time.Millisecond, "evidence must still be committed after a client cancel")

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.PolicyDecision.Allowed)
	require.NotNil(t, ev.Classification.ResponseScan)
	assert.Equal(t, evidence.ResponseScanStatusIncomplete, ev.Classification.ResponseScan.Status)
	assert.Equal(t, evidence.ResponseScanIncompleteClientCancelled, ev.Classification.ResponseScan.IncompleteReason)
	assert.True(t, ev.Classification.OutputPIIDetected, "the delivered partial was still observed")
}

// Past the capture bound the client keeps streaming untouched; the capture
// stops growing, what was captured is still scanned, and the record can
// never read as a complete clean scan.
func TestGateway_StreamingWarn_CaptureLimitExceeded(t *testing.T) {
	prev := streamObservationCaptureLimit
	streamObservationCaptureLimit = 256
	t.Cleanup(func() { streamObservationCaptureLimit = prev })

	head := chatDelta("Contact jan.kowalski@gmail.com now")
	var tail strings.Builder
	for i := 0; i < 50; i++ {
		tail.WriteString(chatDelta("more filler text "))
	}
	tail.WriteString(chatTerminal)
	up := newPacedUpstream(head, tail.String())
	gw, evStore := setupStreamGateway(t, "warn", up.handler(), nil)
	srv := serveGateway(t, gw)

	early, status, got := firstEventBeforeCompletion(t, srv, up, chatPath, chatStreamBody, 5*time.Second)
	assert.Equal(t, http.StatusOK, status)
	assert.True(t, early)
	assert.Equal(t, head+tail.String(), got, "the bound never affects the client stream")

	ev := latestEvidence(t, evStore)
	require.NotNil(t, ev.Classification.ResponseScan)
	assert.Equal(t, evidence.ResponseScanStatusIncomplete, ev.Classification.ResponseScan.Status)
	assert.Equal(t, evidence.ResponseScanIncompleteCaptureLimitExceeded, ev.Classification.ResponseScan.IncompleteReason)
	assert.Equal(t, int64(256), ev.Classification.ResponseScan.BytesObserved)
	assert.Equal(t, int64(256), ev.Classification.ResponseScan.CaptureLimit)
	assert.True(t, ev.Classification.OutputPIIDetected, "PII inside the observed prefix is still reported")
}

// An upstream error status on a streaming request (never an SSE stream) is
// not model output: no PII claim, observation incomplete (upstream_error).
func TestGateway_StreamingWarn_UpstreamErrorStatusIsNotAScan(t *testing.T) {
	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"bad request","type":"invalid_request_error"}}`)
	}
	gw, evStore := setupStreamGateway(t, "warn", handler, nil)
	w := makeGatewayRequest(gw, chatStreamBody)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request_error", "upstream error body passes through")

	ev := latestEvidence(t, evStore)
	assert.False(t, ev.Classification.OutputPIIDetected)
	require.NotNil(t, ev.Classification.ResponseScan)
	assert.Equal(t, evidence.ResponseScanStatusIncomplete, ev.Classification.ResponseScan.Status)
	assert.Equal(t, evidence.ResponseScanIncompleteUpstreamError, ev.Classification.ResponseScan.IncompleteReason)
}

// Many concurrent warn streams: every client gets its own bytes, every record
// carries exactly its own observation, nothing crosses requests. Run under
// -race by the package's race target.
func TestGateway_StreamingWarn_ConcurrentStreamsIsolated(t *testing.T) {
	const n = 12
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		tag := r.Header.Get("X-Test-Tag")
		_, _ = io.WriteString(w, chatDelta("tag "+tag+" "))
		flusher.Flush()
		_, _ = io.WriteString(w, chatDelta("mail user"+tag+"@example.com")+chatTerminal)
		flusher.Flush()
	}
	gw, evStore := setupStreamGateway(t, "warn", handler, nil)
	gw.config.RateLimits = RateLimitsConfig{GlobalRequestsPerMin: 100000, PerAgentRequestsPerMin: 100000}
	gw.rateLimiter = NewRateLimiter(100000, 100000)
	srv := serveGateway(t, gw)

	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			tag := fmt.Sprintf("%02d", i)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+chatPath, strings.NewReader(chatStreamBody))
			if err != nil {
				errs <- err
				return
			}
			req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Test-Tag", tag)
			resp, err := srv.Client().Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errs <- err
				return
			}
			if !strings.Contains(string(body), "user"+tag+"@example.com") || strings.Count(string(body), "mail user") != 1 {
				errs <- fmt.Errorf("stream %s got wrong body: %q", tag, body)
				return
			}
			errs <- nil
		}(i)
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-errs)
	}
	list, err := evStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, n+5)
	require.NoError(t, err)
	require.Len(t, list, n)
	for _, ev := range list {
		require.NotNil(t, ev.Classification.ResponseScan)
		assert.Equal(t, evidence.ResponseScanStatusComplete, ev.Classification.ResponseScan.Status)
		assert.True(t, ev.Classification.OutputPIIDetected)
		assert.Equal(t, int64(len(chatDelta("tag 00 ")+chatDelta("mail user00@example.com")+chatTerminal)), ev.Classification.ResponseScan.BytesObserved)
	}
}

// Non-streaming responses carry the same response_scan vocabulary so every
// projection reads one shape: warn is observation (never alters), redact and
// block are preventive.
func TestGateway_NonStreaming_ResponseScanFacts(t *testing.T) {
	upstream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"Contact jan.kowalski@gmail.com"}}],"usage":{"prompt_tokens":5,"completion_tokens":6}}`)
	}
	cases := []struct {
		action, enforcement, code, decision string
		allowed, redactedFlag               bool
	}{
		{"warn", evidence.ResponseScanEnforcementObservation, "POLICY_OBSERVED_PII_OUTPUT", "allow", true, false},
		{"redact", evidence.ResponseScanEnforcementPreventive, "POLICY_REDACTED_PII_OUTPUT", "modify", true, true},
		{"block", evidence.ResponseScanEnforcementPreventive, "POLICY_DENIED_PII_OUTPUT", "deny", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			gw, evStore := setupStreamGateway(t, tc.action, upstream, nil)
			w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"contact?"}]}`)
			if tc.allowed {
				assert.Equal(t, http.StatusOK, w.Code)
			}
			ev := latestEvidence(t, evStore)
			assert.Equal(t, tc.allowed, ev.PolicyDecision.Allowed)
			assert.True(t, ev.Classification.OutputPIIDetected)
			require.NotNil(t, ev.Classification.ResponseScan)
			assert.Equal(t, tc.action, ev.Classification.ResponseScan.Action)
			assert.Equal(t, tc.enforcement, ev.Classification.ResponseScan.Enforcement)
			assert.False(t, ev.Classification.ResponseScan.Streamed)
			assert.Equal(t, evidence.ResponseScanStatusComplete, ev.Classification.ResponseScan.Status)
			assert.Equal(t, tc.code, ev.Explanations[0].Code)
			assert.Equal(t, tc.decision, ev.Explanations[0].Decision)
			assert.Equal(t, tc.redactedFlag, ev.Classification.ResponsePIIRedacted(ev.DataFlow))
			assert.True(t, evStore.VerifyRecord(ev))
		})
	}
}

// A retried/failed provider attempt is its own record without a response
// scan; only the attempt that produced the delivered response carries one.
func TestGateway_FailoverAttempt_NoDuplicateResponseScanFacts(t *testing.T) {
	primary := newFailoverUpstream(t, http.StatusServiceUnavailable)
	backup := newFailoverUpstream(t, http.StatusOK)
	gw, store := setupFailoverGateway(t, "", "EU", "EU", primary, backup, "")
	gw.config.OrganizationPolicy.Defaults.ResponsePIIAction = "warn"

	w := makeFailoverRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`)
	require.Equal(t, http.StatusOK, w.Code)

	list, err := store.List(context.Background(), "", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	var final, attempts int
	for _, ev := range list {
		switch ev.InvocationType {
		case "gateway":
			final++
			require.NotNil(t, ev.Classification.ResponseScan, "the delivered response carries the scan facts")
			assert.Equal(t, evidence.ResponseScanEnforcementObservation, ev.Classification.ResponseScan.Enforcement)
		case "gateway_failover_attempt":
			attempts++
			assert.Nil(t, ev.Classification.ResponseScan, "a failed attempt delivered no response and scans nothing")
		}
	}
	assert.Equal(t, 1, final)
	assert.GreaterOrEqual(t, attempts, 1)
}
