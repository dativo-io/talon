package gateway

import (
	"encoding/json"
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
	t.Run("openai budget_exceeded code", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteProviderError(w, "openai", http.StatusForbidden, "budget_exceeded: request would exceed caller daily cost limit (10.00)")
		if w.Code != 403 {
			t.Errorf("status = %d", w.Code)
		}
		var body openAIErrorBody
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.Error.Code != "budget_exceeded" {
			t.Fatalf("code = %q", body.Error.Code)
		}
		if strings.Contains(strings.ToLower(body.Error.Message), "budget_exceeded:") {
			t.Fatalf("message still contains machine prefix: %q", body.Error.Message)
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

// #195: an empty errType must fall back to a member of Anthropic's error
// enum mapped from the HTTP status — never the invalid literal "error".
func TestWriteAnthropicError_StatusMappedTypes(t *testing.T) {
	cases := map[int]string{
		400: "invalid_request_error",
		401: "authentication_error",
		403: "permission_error",
		404: "not_found_error",
		413: "request_too_large",
		429: "rate_limit_error",
		500: "api_error",
		502: "api_error",
		529: "overloaded_error",
		418: "invalid_request_error", // unmapped 4xx → safest member
	}
	for status, wantType := range cases {
		w := httptest.NewRecorder()
		WriteAnthropicError(w, status, "denied", "")
		var body struct {
			Type  string `json:"type"`
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		if body.Error.Type != wantType {
			t.Errorf("status %d: error.type = %q, want %q", status, body.Error.Type, wantType)
		}
		if body.Type != "error" {
			t.Errorf("status %d: envelope type = %q, want error", status, body.Type)
		}
		if body.Error.Type == "error" {
			t.Errorf("status %d: the invalid literal \"error\" must never appear as error.type", status)
		}
	}

	// Machine codes from the prefix convention are preserved, not remapped.
	w := httptest.NewRecorder()
	WriteAnthropicError(w, 403, "session spend 6.00 exceeds limit", "session_budget_exceeded")
	if !strings.Contains(w.Body.String(), `"type":"session_budget_exceeded"`) {
		t.Errorf("machine code must stay in error.type: %s", w.Body.String())
	}
}

// #195: providerErrorBody renders the same envelopes as the Write* functions.
func TestProviderErrorBody_PerFamily(t *testing.T) {
	anth := providerErrorBody("anthropic", 451, "blocked", "pii_policy_violation")
	var ab struct {
		Type  string `json:"type"`
		Error struct{ Type, Message string }
	}
	if err := json.Unmarshal(anth, &ab); err != nil {
		t.Fatal(err)
	}
	if ab.Type != "error" || ab.Error.Type != "pii_policy_violation" {
		t.Errorf("anthropic envelope wrong: %s", anth)
	}

	oai := providerErrorBody("openai", 451, "blocked", "pii_policy_violation")
	var ob struct {
		Error struct{ Message, Type, Code string }
	}
	if err := json.Unmarshal(oai, &ob); err != nil {
		t.Fatal(err)
	}
	if ob.Error.Type != "pii_policy_violation" || ob.Error.Code != "pii_policy_violation" {
		t.Errorf("openai envelope wrong: %s", oai)
	}

	// Empty errType: anthropic maps by status; openai uses its default.
	anthEmpty := providerErrorBody("anthropic", 502, "scanner down", "")
	if !strings.Contains(string(anthEmpty), `"type":"api_error"`) {
		t.Errorf("anthropic empty type must map 502→api_error: %s", anthEmpty)
	}
}

// #195: a semantic-cache hit on an anthropic route must be an Anthropic
// Messages object, not an OpenAI chat completion.
func TestWriteCachedCompletion_AnthropicShape(t *testing.T) {
	w := httptest.NewRecorder()
	writeCachedCompletion(w, "anthropic", "claude-opus-4-8", "cached answer")
	var msg struct {
		Type       string `json:"type"`
		Role       string `json:"role"`
		Content    []struct{ Type, Text string }
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Type != "message" || msg.Role != "assistant" || msg.StopReason != "end_turn" {
		t.Errorf("not a Messages object: %s", w.Body.String())
	}
	if len(msg.Content) != 1 || msg.Content[0].Text != "cached answer" {
		t.Errorf("content block wrong: %s", w.Body.String())
	}

	// OpenAI routes keep the chat-completion shape.
	w2 := httptest.NewRecorder()
	writeCachedCompletion(w2, "openai", "gpt-5.3-codex", "cached answer")
	if !strings.Contains(w2.Body.String(), `"object":"chat.completion"`) {
		t.Errorf("openai cache hit must stay chat.completion: %s", w2.Body.String())
	}
}
