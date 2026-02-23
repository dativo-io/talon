package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// TokenUsage holds input/output token counts from the upstream response.
type TokenUsage struct {
	Input  int
	Output int
}

// ForwardParams groups parameters for forwarding a request to the upstream provider.
type ForwardParams struct {
	Context     context.Context
	Client      *http.Client
	UpstreamURL string
	Method      string
	Body        []byte
	Headers     map[string]string // auth and other headers to send upstream
	Timeouts    ParsedTimeouts
	TokenUsage  *TokenUsage // filled in from response (streaming or non-streaming)
}

// Forward sends the request to the upstream provider and writes the response to w.
// For streaming responses it passes through bytes and flushes incrementally; token usage is captured when present.
func Forward(w http.ResponseWriter, p ForwardParams) error {
	ctx := p.Context
	if p.Client == nil {
		p.Client = &http.Client{Timeout: p.Timeouts.RequestTimeout}
	}

	bodyReader := io.NopCloser(bytes.NewReader(p.Body))
	req, err := http.NewRequestWithContext(ctx, p.Method, p.UpstreamURL, bodyReader)
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(p.Body))
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	// Content-Type from body if not set
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Copy response headers to client (including rate-limit headers)
	copyResponseHeaders(w, resp.Header, p.Headers)
	w.WriteHeader(resp.StatusCode)

	contentType := resp.Header.Get("Content-Type")
	isStream := strings.Contains(contentType, "text/event-stream") || resp.Header.Get("Transfer-Encoding") == "chunked"

	if isStream {
		return streamCopy(ctx, w, resp.Body, p.TokenUsage, resp.Header.Get("X-Request-Id"))
	}

	// Non-streaming: read full body, parse usage if present, then write
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if p.TokenUsage != nil {
		parseUsageFromJSON(all, resp.Header.Get("X-Request-Id"), p.TokenUsage)
	}
	_, err = w.Write(all)
	return err
}

func copyResponseHeaders(w http.ResponseWriter, from http.Header, upstreamHeaders map[string]string) {
	// Forward rate-limit and other provider headers
	for _, h := range []string{
		"Content-Type", "X-Request-Id",
		"x-ratelimit-limit-requests", "x-ratelimit-remaining-requests", "x-ratelimit-reset-requests",
		"anthropic-ratelimit-requests-limit", "anthropic-ratelimit-requests-remaining", "anthropic-ratelimit-tokens-limit",
	} {
		if v := from.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
}

// streamCopy copies the SSE stream to w, flushing after each event, and extracts token usage when seen.
func streamCopy(ctx context.Context, w http.ResponseWriter, r io.Reader, usage *TokenUsage, requestID string) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback: copy without flush
		_, err := io.Copy(w, r)
		return err
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, 512*1024) // allow large tokens in one line
	var buf []byte
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Bytes()
		buf = append(buf, line...)
		buf = append(buf, '\n')
		// Flush on empty line (end of SSE event)
		if len(line) == 0 {
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
		_, _ = w.Write(buf)
		flusher.Flush()
	}
	return scanner.Err()
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
	// OpenAI usage at top level
	if u, ok := m["usage"].(map[string]interface{}); ok {
		if n, _ := u["prompt_tokens"].(float64); n > 0 {
			usage.Input = int(n)
		}
		if n, _ := u["completion_tokens"].(float64); n > 0 {
			usage.Output = int(n)
		}
		return
	}
	// Anthropic message_start has message.usage.input_tokens
	if typ, _ := m["type"].(string); typ == "message_start" {
		if msg, ok := m["message"].(map[string]interface{}); ok {
			if u, ok := msg["usage"].(map[string]interface{}); ok {
				if n, _ := u["input_tokens"].(float64); n > 0 {
					usage.Input = int(n)
				}
			}
		}
		return
	}
	// Anthropic message_delta has usage.output_tokens
	if typ, _ := m["type"].(string); typ == "message_delta" {
		if u, ok := m["usage"].(map[string]interface{}); ok {
			if n, _ := u["output_tokens"].(float64); n > 0 {
				usage.Output = int(n)
			}
		}
	}
}

func parseUsageFromJSON(body []byte, _ string, usage *TokenUsage) {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return
	}
	if u, ok := m["usage"].(map[string]interface{}); ok {
		if n, _ := u["prompt_tokens"].(float64); n > 0 {
			usage.Input = int(n)
		}
		if n, _ := u["completion_tokens"].(float64); n > 0 {
			usage.Output = int(n)
		}
		if usage.Input == 0 && usage.Output == 0 {
			if n, _ := u["input_tokens"].(float64); n > 0 {
				usage.Input = int(n)
			}
			if n, _ := u["output_tokens"].(float64); n > 0 {
				usage.Output = int(n)
			}
		}
	}
}

// HTTPClientForGateway returns an http.Client with gateway timeouts.
func HTTPClientForGateway(timeouts ParsedTimeouts) *http.Client {
	return &http.Client{
		Timeout: timeouts.RequestTimeout,
		Transport: &http.Transport{
			ResponseHeaderTimeout: timeouts.ConnectTimeout,
		},
	}
}
