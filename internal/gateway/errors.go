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

// WriteAnthropicError writes an Anthropic-format error response.
func WriteAnthropicError(w http.ResponseWriter, status int, message, errType string) {
	if errType == "" {
		errType = "error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(anthropicErrorBody{
		Type:  "error",
		Error: anthropicError{Type: errType, Message: message},
	})
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
