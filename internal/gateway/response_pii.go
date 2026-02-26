package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/classifier"
)

// ResponsePIIScanResult captures what the response PII scanner found.
type ResponsePIIScanResult struct {
	PIIDetected bool
	PIITypes    []string
	Redacted    bool
}

// responseCapture wraps an http.ResponseWriter to capture the response body
// for non-streaming responses, allowing post-write PII scanning.
type responseCapture struct {
	http.ResponseWriter
	body       bytes.Buffer
	statusCode int
	written    bool
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	rc.written = true
	return rc.body.Write(b)
}

func (rc *responseCapture) Flush() {}

// flushTo writes the (possibly modified) body to the real writer.
func (rc *responseCapture) flushTo(w http.ResponseWriter) {
	if rc.statusCode != 0 {
		w.WriteHeader(rc.statusCode)
	}
	//nolint:gosec // G705: API response body (JSON), not HTML; gateway passthrough
	_, _ = w.Write(rc.body.Bytes())
}

// resolveResponsePIIAction determines the response PII action for a caller.
func resolveResponsePIIAction(defaultPolicy *DefaultPolicyConfig, callerOverrides *CallerPolicyOverrides) string {
	action := ""
	if defaultPolicy != nil {
		action = defaultPolicy.ResponsePIIAction
		if action == "" {
			action = defaultPolicy.DefaultPIIAction
		}
	}
	if callerOverrides != nil && callerOverrides.ResponsePIIAction != "" {
		action = callerOverrides.ResponsePIIAction
	}
	if action == "" {
		action = "allow"
	}
	return action
}

// scanResponseForPII scans only the LLM-generated content fields in a non-streaming
// response body for PII and applies the action. API envelope fields (id, created,
// usage, model, etc.) are never scanned, preventing false positives on timestamps
// and token counts.
func scanResponseForPII(ctx context.Context, body []byte, action string, scanner *classifier.Scanner) ([]byte, *ResponsePIIScanResult) {
	result := &ResponsePIIScanResult{}
	if scanner == nil || action == "allow" || action == "" {
		return body, result
	}

	contentText := extractResponseContentText(body)
	if contentText == "" {
		return body, result
	}

	cls := scanner.Scan(ctx, contentText)
	if cls == nil || !cls.HasPII {
		return body, result
	}

	result.PIIDetected = true
	types := make(map[string]bool)
	for _, e := range cls.Entities {
		types[e.Type] = true
	}
	for t := range types {
		result.PIITypes = append(result.PIITypes, t)
	}

	switch action {
	case "redact":
		modified := redactResponseContentFields(ctx, body, scanner)
		result.Redacted = true
		log.Info().
			Strs("pii_types", result.PIITypes).
			Msg("response_pii_redacted")
		return modified, result

	case "block":
		safeErr := map[string]interface{}{
			"error": map[string]interface{}{
				"message": "Response blocked: contains PII that violates policy",
				"type":    "pii_policy_violation",
			},
		}
		blocked, _ := json.Marshal(safeErr)
		result.Redacted = true
		log.Warn().
			Strs("pii_types", result.PIITypes).
			Msg("response_pii_blocked")
		return blocked, result

	case "warn":
		log.Warn().
			Strs("pii_types", result.PIITypes).
			Msg("response_pii_detected_warn")
		return body, result
	}

	return body, result
}

// extractResponseContentText extracts only the LLM-generated text from a
// non-streaming response, covering OpenAI and Anthropic response shapes.
func extractResponseContentText(body []byte) string {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}

	var sb strings.Builder

	// OpenAI Chat Completions: choices[].message.content
	if choices, ok := m["choices"].([]interface{}); ok {
		for _, c := range choices {
			choice, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			if msg, ok := choice["message"].(map[string]interface{}); ok {
				sb.WriteString(contentFieldToText(msg["content"]))
			}
		}
	}

	// Anthropic: content[].text
	extractAnthropicContentText(m, &sb)

	// OpenAI Responses API: output[].content[].text (type "output_text")
	extractResponsesOutputText(m, &sb)

	return sb.String()
}

// extractAnthropicContentText appends Anthropic content[].text blocks.
func extractAnthropicContentText(m map[string]interface{}, sb *strings.Builder) {
	content, ok := m["content"].([]interface{})
	if !ok {
		return
	}
	for _, block := range content {
		if b, ok := block.(map[string]interface{}); ok {
			if text, ok := b["text"].(string); ok {
				sb.WriteString(text)
			}
		}
	}
}

// extractResponsesOutputText appends text from OpenAI Responses API
// output[].content[] blocks of type "output_text".
func extractResponsesOutputText(m map[string]interface{}, sb *strings.Builder) {
	output, ok := m["output"].([]interface{})
	if !ok {
		return
	}
	for _, item := range output {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := obj["content"].([]interface{})
		if !ok {
			continue
		}
		for _, block := range content {
			b, ok := block.(map[string]interface{})
			if !ok {
				continue
			}
			if typ, _ := b["type"].(string); typ == "output_text" {
				if text, ok := b["text"].(string); ok {
					sb.WriteString(text)
				}
			}
		}
	}
}

// contentFieldToText converts an OpenAI message content field (string or
// array of content blocks) to plain text for scanning.
func contentFieldToText(c interface{}) string {
	if c == nil {
		return ""
	}
	switch v := c.(type) {
	case string:
		return v
	case []interface{}:
		var sb strings.Builder
		for _, part := range v {
			if m, ok := part.(map[string]interface{}); ok {
				if typ, _ := m["type"].(string); typ == "text" {
					if text, _ := m["text"].(string); text != "" {
						sb.WriteString(text)
					}
				}
			}
		}
		return sb.String()
	}
	return ""
}

// redactResponseContentFields redacts PII only within the LLM content fields
// of the JSON response, leaving the API envelope (id, created, usage, etc.)
// untouched. Falls back to returning the original body on parse errors.
func redactResponseContentFields(ctx context.Context, body []byte, scanner *classifier.Scanner) []byte {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}

	// OpenAI Chat Completions: choices[].message.content
	if choices, ok := m["choices"].([]interface{}); ok {
		for _, c := range choices {
			choice, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			if msg, ok := choice["message"].(map[string]interface{}); ok {
				msg["content"] = redactContentField(ctx, msg["content"], scanner)
			}
		}
	}

	// Anthropic: content[].text
	redactAnthropicResponseContent(ctx, m, scanner)

	// OpenAI Responses API: output[].content[].text (type "output_text")
	redactResponsesOutputContent(ctx, m, scanner)

	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// redactAnthropicResponseContent redacts PII in Anthropic response content[].text blocks.
func redactAnthropicResponseContent(ctx context.Context, m map[string]interface{}, scanner *classifier.Scanner) {
	content, ok := m["content"].([]interface{})
	if !ok {
		return
	}
	for _, block := range content {
		if b, ok := block.(map[string]interface{}); ok {
			if text, ok := b["text"].(string); ok {
				b["text"] = scanner.Redact(ctx, text)
			}
		}
	}
}

// redactResponsesOutputContent redacts PII in OpenAI Responses API
// output[].content[] blocks of type "output_text".
func redactResponsesOutputContent(ctx context.Context, m map[string]interface{}, scanner *classifier.Scanner) {
	output, ok := m["output"].([]interface{})
	if !ok {
		return
	}
	for _, item := range output {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := obj["content"].([]interface{})
		if !ok {
			continue
		}
		for _, block := range content {
			b, ok := block.(map[string]interface{})
			if !ok {
				continue
			}
			if typ, _ := b["type"].(string); typ == "output_text" {
				if text, ok := b["text"].(string); ok {
					b["text"] = scanner.Redact(ctx, text)
				}
			}
		}
	}
}

// redactContentField redacts PII in an OpenAI content field (string or array).
func redactContentField(ctx context.Context, c interface{}, scanner *classifier.Scanner) interface{} {
	if c == nil {
		return nil
	}
	switch v := c.(type) {
	case string:
		return scanner.Redact(ctx, v)
	case []interface{}:
		for _, part := range v {
			if m, ok := part.(map[string]interface{}); ok {
				if typ, _ := m["type"].(string); typ == "text" {
					if text, ok := m["text"].(string); ok {
						m["text"] = scanner.Redact(ctx, text)
					}
				}
			}
		}
		return v
	}
	return c
}

func extractContentFromSSE(m map[string]interface{}) string {
	// OpenAI: choices[0].delta.content
	if choices, ok := m["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if delta, ok := choice["delta"].(map[string]interface{}); ok {
				if c, ok := delta["content"].(string); ok {
					return c
				}
			}
		}
	}
	// Anthropic: content_block.text or delta.text
	if delta, ok := m["delta"].(map[string]interface{}); ok {
		if text, ok := delta["text"].(string); ok {
			return text
		}
	}
	return ""
}

// isStreamingRequest checks if the request body asks for streaming.
func isStreamingRequest(body []byte) bool {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	v, ok := m["stream"].(bool)
	return ok && v
}

// handleStreamingPIIScan implements scan-first PII handling for buffered SSE
// streams. The entire response is already buffered in capture, so we extract
// content, scan for PII, then decide what to forward:
//
//   - allow / no scanner: forward original buffered events as-is.
//   - No PII found: forward original (zero latency penalty for clean responses).
//   - warn + PII: forward original, log findings for evidence.
//   - redact + PII + completedJSON: redact content, re-wrap in SSE, forward redacted.
//   - redact + PII + delta-only: build synthetic response from accumulated deltas, redact, forward.
//   - block + PII: return JSON error, discard original stream.
func handleStreamingPIIScan(
	ctx context.Context,
	w http.ResponseWriter,
	capture *responseCapture,
	action string,
	scanner *classifier.Scanner,
) *ResponsePIIScanResult {
	raw := capture.body.Bytes()

	if scanner == nil || action == "allow" || action == "" {
		forwardBufferedSSE(w, capture)
		return nil
	}

	completedJSON := extractCompletedResponseFromSSE(raw)
	contentText := ""
	if completedJSON != nil {
		contentText = extractResponseContentText(completedJSON)
	}
	if contentText == "" {
		contentText = accumulateSSEContent(raw)
	}
	if contentText == "" {
		forwardBufferedSSE(w, capture)
		return nil
	}

	cls := scanner.Scan(ctx, contentText)
	if cls == nil || !cls.HasPII {
		forwardBufferedSSE(w, capture)
		return &ResponsePIIScanResult{PIIDetected: false}
	}

	types := make(map[string]bool)
	for _, e := range cls.Entities {
		types[e.Type] = true
	}
	var piiTypes []string
	for t := range types {
		piiTypes = append(piiTypes, t)
	}
	result := &ResponsePIIScanResult{PIIDetected: true, PIITypes: piiTypes}

	switch action {
	case "warn":
		forwardBufferedSSE(w, capture)
		log.Warn().
			Strs("pii_types", piiTypes).
			Msg("response_pii_detected_warn_stream")

	case "redact":
		if completedJSON != nil {
			redacted := redactResponseContentFields(ctx, completedJSON, scanner)
			forwardRedactedAsSSE(w, capture, completedJSON, redacted)
		} else {
			synthetic := buildSyntheticChatResponse(scanner.Redact(ctx, contentText))
			forwardRedactedAsSSE(w, capture, synthetic, synthetic)
		}
		result.Redacted = true
		log.Info().
			Strs("pii_types", piiTypes).
			Msg("response_pii_redacted_stream")

	case "block":
		forwardBlockedResponse(w)
		result.Redacted = true
		log.Warn().
			Strs("pii_types", piiTypes).
			Msg("response_pii_blocked_stream")

	default:
		forwardBufferedSSE(w, capture)
	}

	return result
}

// forwardBufferedSSE writes the original buffered SSE events to the client.
func forwardBufferedSSE(w http.ResponseWriter, capture *responseCapture) {
	if capture.statusCode != 0 {
		w.WriteHeader(capture.statusCode)
	}
	//nolint:gosec // G705: forwarding buffered upstream SSE response
	_, _ = w.Write(capture.body.Bytes())
}

// buildSyntheticChatResponse creates a minimal Chat Completions JSON response
// from accumulated (and redacted) delta content. Used when the original stream
// had no completed response event — we reconstruct one so the client receives
// valid, redacted JSON instead of raw delta chunks containing PII.
func buildSyntheticChatResponse(content string) []byte {
	resp := map[string]interface{}{
		"choices": []interface{}{
			map[string]interface{}{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": "stop",
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// forwardRedactedAsSSE wraps redacted response JSON in SSE format and writes
// it to the client. For Responses API payloads (detected by the presence of an
// "output" key), wraps in an event: response.completed envelope. For other
// formats, sends as a plain data: event.
func forwardRedactedAsSSE(w http.ResponseWriter, capture *responseCapture, originalJSON, redactedJSON []byte) {
	w.Header().Set("Content-Type", "text/event-stream")
	if capture.statusCode != 0 {
		w.WriteHeader(capture.statusCode)
	}

	var buf bytes.Buffer
	var m map[string]interface{}
	isResponsesAPI := false
	if json.Unmarshal(originalJSON, &m) == nil {
		_, isResponsesAPI = m["output"]
	}

	if isResponsesAPI {
		wrapper, _ := json.Marshal(map[string]interface{}{
			"type":     "response.completed",
			"response": json.RawMessage(redactedJSON),
		})
		buf.WriteString("event: response.completed\ndata: ")
		buf.Write(wrapper)
		buf.WriteString("\n\n")
	} else {
		buf.WriteString("data: ")
		buf.Write(redactedJSON)
		buf.WriteString("\n\n")
	}
	buf.WriteString("data: [DONE]\n\n")
	//nolint:gosec // G705: forwarding redacted SSE response
	_, _ = w.Write(buf.Bytes())
}

// forwardBlockedResponse writes a JSON error for blocked streaming requests.
// Since the SSE stream was buffered (never written to w), we can override
// Content-Type and set an appropriate status code.
func forwardBlockedResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnavailableForLegalReasons)
	safeErr, _ := json.Marshal(map[string]interface{}{
		"error": map[string]interface{}{
			"message": "Response blocked: contains PII that violates policy",
			"type":    "pii_policy_violation",
		},
	})
	//nolint:gosec // G705: error response body (JSON), not HTML
	_, _ = w.Write(safeErr)
}

// extractCompletedResponseFromSSE finds the response.completed event or the
// last data payload in an SSE stream and returns it as JSON bytes.
func extractCompletedResponseFromSSE(raw []byte) []byte {
	lines := bytes.Split(raw, []byte("\n"))
	var lastDataPayload []byte
	nextIsCompleted := false

	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)

		// Responses API: "event: response.completed" followed by "data: {...}"
		if bytes.Equal(trimmed, []byte("event: response.completed")) {
			nextIsCompleted = true
			continue
		}

		if !bytes.HasPrefix(trimmed, []byte("data: ")) {
			if len(trimmed) == 0 {
				nextIsCompleted = false
			}
			continue
		}

		payload := bytes.TrimPrefix(trimmed, []byte("data: "))
		payload = bytes.TrimSpace(payload)
		if bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}

		if nextIsCompleted {
			// Responses API: the response.completed event data contains the
			// full response. But it's wrapped as {"type":"response.completed","response":{...}}.
			// Extract the inner "response" object.
			var wrapper map[string]json.RawMessage
			if err := json.Unmarshal(payload, &wrapper); err == nil {
				if resp, ok := wrapper["response"]; ok {
					return resp
				}
			}
			return payload
		}

		lastDataPayload = payload
	}

	if lastDataPayload != nil && isCompleteResponsePayload(lastDataPayload) {
		return lastDataPayload
	}
	return nil
}

// isCompleteResponsePayload checks whether a JSON payload is a complete
// (non-streaming) response rather than a streaming delta chunk. Chat Completions
// deltas have choices[].delta; only complete responses have choices[].message.
func isCompleteResponsePayload(payload []byte) bool {
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return false
	}
	if choices, ok := m["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			_, hasMsg := choice["message"]
			return hasMsg
		}
	}
	_, hasOutput := m["output"]
	return hasOutput
}

// accumulateSSEContent extracts all content text from accumulated SSE events
// (delta-based streaming). Used as fallback when no completed response is available.
func accumulateSSEContent(events []byte) string {
	var sb strings.Builder
	lines := bytes.Split(events, []byte("\n"))
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if !bytes.HasPrefix(trimmed, []byte("data: ")) {
			continue
		}
		payload := bytes.TrimPrefix(trimmed, []byte("data: "))
		payload = bytes.TrimSpace(payload)
		if bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(payload, &m); err != nil {
			continue
		}
		c := extractContentFromSSE(m)
		sb.WriteString(c)
	}
	return sb.String()
}
