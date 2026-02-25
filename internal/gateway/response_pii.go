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

// scanResponseForPII scans a non-streaming response body for PII and applies the action.
// Returns the (possibly modified) body and scan results for evidence.
func scanResponseForPII(ctx context.Context, body []byte, action string, scanner *classifier.Scanner) ([]byte, *ResponsePIIScanResult) {
	result := &ResponsePIIScanResult{}
	if scanner == nil || action == "allow" || action == "" {
		return body, result
	}

	cls := scanner.Scan(ctx, string(body))
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
		redacted := scanner.Redact(ctx, string(body))
		result.Redacted = true
		log.Info().
			Strs("pii_types", result.PIITypes).
			Msg("response_pii_redacted")
		return []byte(redacted), result

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

// scanSSEChunkForPII scans a single SSE chunk's content field for PII.
// Returns the (possibly modified) chunk and whether PII was found.
// Scaffolding for streaming PII scanning (Gap F Phase 2).
//
//nolint:unused // scaffolding for streaming PII scanning
func scanSSEChunkForPII(ctx context.Context, chunk []byte, action string, scanner *classifier.Scanner) ([]byte, bool) {
	if scanner == nil || action == "allow" || action == "" {
		return chunk, false
	}

	lines := bytes.Split(chunk, []byte("\n"))
	modified := false
	piiFound := false
	for i, line := range lines {
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

		content := extractContentFromSSE(m)
		if content == "" {
			continue
		}

		cls := scanner.Scan(ctx, content)
		if cls == nil || !cls.HasPII {
			continue
		}
		piiFound = true

		if action == "redact" {
			redacted := scanner.Redact(ctx, content)
			if redacted != content {
				setContentInSSE(m, redacted)
				newPayload, err := json.Marshal(m)
				if err == nil {
					lines[i] = []byte("data: " + string(newPayload))
					modified = true
				}
			}
		}
	}

	if modified {
		return bytes.Join(lines, []byte("\n")), piiFound
	}
	return chunk, piiFound
}

//nolint:unused // scaffolding for streaming PII scanning
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

//nolint:unused // scaffolding for streaming PII scanning
func setContentInSSE(m map[string]interface{}, content string) {
	if choices, ok := m["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if delta, ok := choice["delta"].(map[string]interface{}); ok {
				delta["content"] = content
			}
		}
	}
	if delta, ok := m["delta"].(map[string]interface{}); ok {
		if _, ok := delta["text"]; ok {
			delta["text"] = content
		}
	}
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

// accumulateSSEContent extracts all content text from accumulated SSE events for post-completion scanning.
//
//nolint:unused // scaffolding for streaming PII scanning
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
