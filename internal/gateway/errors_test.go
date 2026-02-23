package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteOpenAIError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteOpenAIError(w, http.StatusForbidden, "Model not allowed", "policy_denied")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	body := w.Body.String()
	if body == "" {
		t.Error("body empty")
	}
	if !strings.Contains(body, "error") || !strings.Contains(body, "Model not allowed") {
		t.Errorf("body missing expected fields: %s", body)
	}
}

func TestWriteAnthropicError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteAnthropicError(w, http.StatusUnauthorized, "Invalid API key", "authentication_error")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "type") || !strings.Contains(body, "error") || !strings.Contains(body, "Invalid API key") {
		t.Errorf("body missing expected fields: %s", body)
	}
}

func TestWriteProviderError(t *testing.T) {
	t.Run("openai", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteProviderError(w, "openai", http.StatusBadRequest, "Bad request")
		if w.Code != 400 {
			t.Errorf("status = %d", w.Code)
		}
		if w.Header().Get("Content-Type") != "application/json" {
			t.Error("content-type not json")
		}
	})
	t.Run("anthropic", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteProviderError(w, "anthropic", http.StatusForbidden, "Forbidden")
		if w.Code != 403 {
			t.Errorf("status = %d", w.Code)
		}
	})
	t.Run("ollama", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteProviderError(w, "ollama", http.StatusInternalServerError, "Error")
		if w.Code != 500 {
			t.Errorf("status = %d", w.Code)
		}
	})
}
