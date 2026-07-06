package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
)

// OpenAI error response shape: https://platform.openai.com/docs/guides/error-codes
type openAIErrorBody struct {
	Error openAIError `json:"error"`
}

type openAIError struct {
	Message string `json:"message"`
	Type    string `json:"type,omitempty"`
	Code    string `json:"code,omitempty"`
}

// Anthropic error response shape: https://docs.anthropic.com/en/api/errors
type anthropicErrorBody struct {
	Type  string         `json:"type"`
	Error anthropicError `json:"error"`
}

type anthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// WriteOpenAIError writes an OpenAI-format error response.
func WriteOpenAIError(w http.ResponseWriter, status int, message, errType string) {
	if errType == "" {
		errType = "invalid_request_error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openAIErrorBody{
		Error: openAIError{Message: message, Type: errType, Code: errType},
	})
}

// anthropicTypeForStatus maps an HTTP status to a member of Anthropic's error
// type enum (https://docs.anthropic.com/en/api/errors) — the fallback when a
// denial carries no machine code. Talon machine codes (session_budget_exceeded,
// egress_*, ...) still travel in error.type by the documented prefix
// convention; the enum contract table is owned by #142.
func anthropicTypeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case 529: // Anthropic's overloaded status
		return "overloaded_error"
	}
	if status >= 500 {
		return "api_error"
	}
	return "invalid_request_error"
}

// WriteAnthropicError writes an Anthropic-format error response. An empty
// errType falls back to the status-mapped member of Anthropic's error enum —
// never the invalid literal "error" (#195).
func WriteAnthropicError(w http.ResponseWriter, status int, message, errType string) {
	if errType == "" {
		errType = anthropicTypeForStatus(status)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(anthropicErrorBody{
		Type:  "error",
		Error: anthropicError{Type: errType, Message: message},
	})
}

// providerErrorBody renders the provider-native error envelope as bytes, for
// paths that return bodies instead of writing responses directly (e.g. the
// response-PII block bodies, #195). Same shapes as the Write* functions —
// never a second envelope implementation.
func providerErrorBody(apiFamily string, status int, message, errType string) []byte {
	if apiFamily == "anthropic" {
		if errType == "" {
			errType = anthropicTypeForStatus(status)
		}
		b, _ := json.Marshal(anthropicErrorBody{
			Type:  "error",
			Error: anthropicError{Type: errType, Message: message},
		})
		return b
	}
	if errType == "" {
		errType = "invalid_request_error"
	}
	b, _ := json.Marshal(openAIErrorBody{
		Error: openAIError{Message: message, Type: errType, Code: errType},
	})
	return b
}

// WriteProviderError writes a provider-native error response based on provider name.
func WriteProviderError(w http.ResponseWriter, provider string, status int, message string) {
	cleanMessage, errType := normalizeGatewayError(message)
	switch provider {
	case "openai", "ollama":
		WriteOpenAIError(w, status, cleanMessage, errType)
	case "anthropic":
		WriteAnthropicError(w, status, cleanMessage, errType)
	default:
		WriteOpenAIError(w, status, cleanMessage, errType)
	}
}

func normalizeGatewayError(message string) (cleanMessage string, errType string) {
	raw := strings.TrimSpace(message)
	if raw == "" {
		return "", ""
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return raw, ""
	}
	errType = strings.TrimSpace(parts[0])
	msg := strings.TrimSpace(parts[1])
	if errType == "" || msg == "" {
		return raw, ""
	}
	// Restrict machine codes to safe token characters.
	for _, r := range errType {
		isLower := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		isSeparator := r == '_' || r == '-'
		if !isLower && !isDigit && !isSeparator {
			return raw, ""
		}
	}
	return msg, errType
}
