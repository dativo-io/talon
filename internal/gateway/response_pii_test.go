package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Unit tests — scanResponseForPII (no Gateway, no HTTP)
// ---------------------------------------------------------------------------

func TestScanResponseForPII_Unit(t *testing.T) {
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name           string
		body           string
		action         string
		wantPII        bool
		wantRedacted   bool
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:        "no_pii_in_content_timestamp_in_envelope",
			body:        `{"id":"chatcmpl-1","created":1772057232,"choices":[{"message":{"content":"Hi there"}}],"usage":{"prompt_tokens":9}}`,
			action:      "redact",
			wantPII:     false,
			mustContain: []string{"1772057232", "chatcmpl-1", "Hi there"},
		},
		{
			name:    "email_in_content_redacted",
			body:    `{"choices":[{"message":{"content":"Email: user@example.com"}}],"usage":{"prompt_tokens":5}}`,
			action:  "redact",
			wantPII: true, wantRedacted: true,
			mustNotContain: []string{"user@example.com"},
			mustContain:    []string{"[EMAIL]"},
		},
		{
			name:        "warn_mode_preserves_body",
			body:        `{"choices":[{"message":{"content":"Email: user@example.com"}}]}`,
			action:      "warn",
			wantPII:     true,
			mustContain: []string{"user@example.com"},
		},
		{
			name:        "allow_skips_scan",
			body:        `{"choices":[{"message":{"content":"Email: user@example.com"}}]}`,
			action:      "allow",
			wantPII:     false,
			mustContain: []string{"user@example.com"},
		},
		{
			name:    "block_mode_replaces_body",
			body:    `{"choices":[{"message":{"content":"IBAN: DE89370400440532013000"}}]}`,
			action:  "block",
			wantPII: true, wantRedacted: true,
			mustNotContain: []string{"DE89370400440532013000"},
			mustContain:    []string{"pii_policy_violation"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, result := scanResponseForPII(ctx, []byte(tt.body), tt.action, scanner)
			assert.Equal(t, tt.wantPII, result.PIIDetected)
			if tt.wantRedacted {
				assert.True(t, result.Redacted)
			}
			outStr := string(out)
			for _, s := range tt.mustContain {
				assert.Contains(t, outStr, s)
			}
			for _, s := range tt.mustNotContain {
				assert.NotContains(t, outStr, s)
			}
		})
	}
}

// TestScanResponseForPII_FalsePositivePrevention checks every API envelope
// field that could trigger a PII false positive (timestamps, token counts,
// model names, fingerprints, etc.).
func TestScanResponseForPII_FalsePositivePrevention(t *testing.T) {
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "realistic_openai_full_response",
			body: `{
				"id": "chatcmpl-DDAecAkvDjlDU1enFHTuUgZR0fFkD",
				"object": "chat.completion",
				"created": 1772057232,
				"model": "gpt-4o-mini-2024-07-18",
				"choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello! How can I help you today?"}, "logprobs": null, "finish_reason": "stop"}],
				"usage": {"prompt_tokens": 9, "completion_tokens": 8, "total_tokens": 17, "prompt_tokens_details": {"cached_tokens": 0, "audio_tokens": 0}, "completion_tokens_details": {"reasoning_tokens": 0, "audio_tokens": 0, "accepted_prediction_tokens": 0, "rejected_prediction_tokens": 0}},
				"service_tier": "default",
				"system_fingerprint": "fp_373a14eb6f"
			}`,
		},
		{
			name: "timestamp_matches_AT_SVN_pattern",
			body: `{"id":"c-1","created":1740112032,"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`,
		},
		{
			name: "timestamp_matches_SE_personnummer_10digit",
			body: `{"id":"c-2","created":5507131234,"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":5}}`,
		},
		{
			name: "large_prompt_tokens_9digits",
			body: `{"id":"c-3","created":1772057232,"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":123456789,"completion_tokens":987654321,"total_tokens":1111111110}}`,
		},
		{
			name: "model_with_digits_gpt4o_20240718",
			body: `{"id":"c-4","created":1772057232,"model":"gpt-4o-mini-2024-07-18","choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":5}}`,
		},
		{
			name: "anthropic_response_format",
			body: `{"id":"msg_01XFDUDYJgAACzvnptvVoYEL","type":"message","role":"assistant","content":[{"type":"text","text":"Hello! How can I help?"}],"model":"claude-sonnet-4-20250514","stop_reason":"end_turn","usage":{"input_tokens":25,"output_tokens":150}}`,
		},
		{
			name: "multiple_choices",
			body: `{"id":"c-5","created":1772057232,"choices":[{"index":0,"message":{"content":"Answer A"}},{"index":1,"message":{"content":"Answer B"}}],"usage":{"prompt_tokens":10,"completion_tokens":20}}`,
		},
		{
			name: "system_fingerprint_hex",
			body: `{"id":"c-6","created":1772057232,"system_fingerprint":"fp_44709d6fcb","choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":5}}`,
		},
		{
			name: "response_with_annotations_and_refusal",
			body: `{"id":"c-7","created":1772057232,"choices":[{"index":0,"message":{"role":"assistant","content":"I can help with that.","refusal":null,"annotations":[]},"logprobs":null,"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":5,"total_tokens":14}}`,
		},
		{
			name: "content_array_multimodal",
			body: `{"id":"c-8","created":1772057232,"choices":[{"message":{"content":[{"type":"text","text":"The image shows a sunset."}]}}],"usage":{"prompt_tokens":100}}`,
		},
		{
			name: "empty_content",
			body: `{"id":"c-9","created":1772057232,"choices":[{"message":{"content":""}}],"usage":{"prompt_tokens":5}}`,
		},
		{
			name: "null_content",
			body: `{"id":"c-10","created":1772057232,"choices":[{"message":{"content":null,"refusal":"I cannot help with that."}}],"usage":{"prompt_tokens":5}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, result := scanResponseForPII(ctx, []byte(tt.body), "redact", scanner)
			assert.False(t, result.PIIDetected,
				"no PII in content → no detection (envelope must not trigger false positive)")
			assert.False(t, result.Redacted, "nothing to redact when no PII in content")
			assert.JSONEq(t, tt.body, string(out),
				"output body must be identical to input when no PII is in content")
		})
	}
}

// TestScanResponseForPII_ContentPII_EnvelopePreserved ensures that when the
// content has real PII, only the content is modified — envelope stays intact.
func TestScanResponseForPII_ContentPII_EnvelopePreserved(t *testing.T) {
	scanner, err := classifier.NewScanner()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name              string
		body              string
		wantPIITypes      []string
		mustNotContain    []string
		envelopePreserved []string
	}{
		{
			name:              "email_in_openai_content",
			body:              `{"id":"chatcmpl-abc","created":1772057232,"choices":[{"message":{"content":"Please email jan@example.de for details"}}],"usage":{"prompt_tokens":10,"completion_tokens":15}}`,
			wantPIITypes:      []string{"email"},
			mustNotContain:    []string{"jan@example.de"},
			envelopePreserved: []string{"chatcmpl-abc", "1772057232", `"prompt_tokens":10`, `"completion_tokens":15`},
		},
		{
			name:              "iban_in_openai_content",
			body:              `{"id":"chatcmpl-def","created":1772057232,"choices":[{"message":{"content":"Your IBAN is DE89370400440532013000"}}],"usage":{"prompt_tokens":8,"completion_tokens":12}}`,
			wantPIITypes:      []string{"iban"},
			mustNotContain:    []string{"DE89370400440532013000"},
			envelopePreserved: []string{"chatcmpl-def", "1772057232", `"prompt_tokens":8`},
		},
		{
			name:              "email_in_anthropic_content",
			body:              `{"id":"msg_123","type":"message","content":[{"type":"text","text":"Contact user@company.eu for info"}],"usage":{"input_tokens":20,"output_tokens":30}}`,
			wantPIITypes:      []string{"email"},
			mustNotContain:    []string{"user@company.eu"},
			envelopePreserved: []string{"msg_123", `"input_tokens":20`, `"output_tokens":30`},
		},
		{
			name:              "multimodal_content_array_with_pii",
			body:              `{"id":"chatcmpl-mm","created":1772057232,"choices":[{"message":{"content":[{"type":"text","text":"Call +48505977880 for help"}]}}],"usage":{"prompt_tokens":5}}`,
			wantPIITypes:      []string{"phone"},
			mustNotContain:    []string{"+48505977880"},
			envelopePreserved: []string{"chatcmpl-mm", "1772057232"},
		},
		{
			name:              "email_in_responses_api_output",
			body:              `{"id":"resp_abc","output":[{"type":"message","content":[{"type":"output_text","text":"The support email is support@company.eu"}]}],"usage":{"input_tokens":10,"output_tokens":15}}`,
			wantPIITypes:      []string{"email"},
			mustNotContain:    []string{"support@company.eu"},
			envelopePreserved: []string{"resp_abc", `"input_tokens":10`, `"output_tokens":15`},
		},
		{
			name:              "iban_in_responses_api_output",
			body:              `{"id":"resp_def","output":[{"type":"message","content":[{"type":"output_text","text":"Your IBAN is DE89370400440532013000"}]}],"usage":{"input_tokens":8,"output_tokens":12}}`,
			wantPIITypes:      []string{"iban"},
			mustNotContain:    []string{"DE89370400440532013000"},
			envelopePreserved: []string{"resp_def", `"input_tokens":8`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, result := scanResponseForPII(ctx, []byte(tt.body), "redact", scanner)
			assert.True(t, result.PIIDetected, "PII in content should be detected")
			assert.True(t, result.Redacted, "PII in content should be redacted")
			outStr := string(out)
			for _, s := range tt.mustNotContain {
				assert.NotContains(t, outStr, s, "PII must be redacted from content")
			}
			for _, s := range tt.envelopePreserved {
				assert.Contains(t, outStr, s, "envelope field must be preserved")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — extractResponseContentText
// ---------------------------------------------------------------------------

func TestExtractResponseContentText_Unit(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantText string
	}{
		{
			name:     "openai_string_content",
			body:     `{"choices":[{"message":{"content":"Hello world"}}]}`,
			wantText: "Hello world",
		},
		{
			name:     "openai_array_content",
			body:     `{"choices":[{"message":{"content":[{"type":"text","text":"Part 1"},{"type":"image_url","image_url":{}},{"type":"text","text":" Part 2"}]}}]}`,
			wantText: "Part 1 Part 2",
		},
		{
			name:     "anthropic_content",
			body:     `{"content":[{"type":"text","text":"Anthropic says hello"}]}`,
			wantText: "Anthropic says hello",
		},
		{
			name:     "empty_content",
			body:     `{"choices":[{"message":{"content":""}}]}`,
			wantText: "",
		},
		{
			name:     "null_content",
			body:     `{"choices":[{"message":{"content":null}}]}`,
			wantText: "",
		},
		{
			name:     "no_choices_no_content",
			body:     `{"id":"test","created":123456}`,
			wantText: "",
		},
		{
			name:     "multiple_choices",
			body:     `{"choices":[{"message":{"content":"First"}},{"message":{"content":" Second"}}]}`,
			wantText: "First Second",
		},
		{
			name:     "invalid_json",
			body:     `not json`,
			wantText: "",
		},
		{
			name:     "envelope_numbers_not_extracted",
			body:     `{"id":"c-1","created":1772057232,"choices":[{"message":{"content":"OK"}}],"usage":{"prompt_tokens":123456789}}`,
			wantText: "OK",
		},
		{
			name:     "responses_api_output_text",
			body:     `{"id":"resp_1","output":[{"type":"message","content":[{"type":"output_text","text":"Hello from Responses API"}]}]}`,
			wantText: "Hello from Responses API",
		},
		{
			name:     "responses_api_multiple_outputs",
			body:     `{"id":"resp_2","output":[{"type":"message","content":[{"type":"output_text","text":"First part"}]},{"type":"message","content":[{"type":"output_text","text":" Second part"}]}]}`,
			wantText: "First part Second part",
		},
		{
			name:     "responses_api_non_text_output_ignored",
			body:     `{"id":"resp_3","output":[{"type":"function_call","name":"get_weather","arguments":"{}"},{"type":"message","content":[{"type":"output_text","text":"Here is the weather"}]}]}`,
			wantText: "Here is the weather",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractResponseContentText([]byte(tt.body))
			assert.Equal(t, tt.wantText, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Component tests — response-path PII through the Gateway handler
// ---------------------------------------------------------------------------

func TestGateway_ResponsePIIRedaction(t *testing.T) {
	upstreamResponse := `{"choices":[{"message":{"content":"The customer email is jan.kowalski@gmail.com"}}],"usage":{"prompt_tokens":10,"completion_tokens":20}}`
	gw, _, evidenceStore := setupOpenClawGateway(t, "redact", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	respBody := rec.Body.String()
	assert.NotContains(t, respBody, "jan.kowalski@gmail.com", "email should be redacted from response")

	evList, err := evidenceStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.NotEmpty(t, evList)
	found := false
	for _, ev := range evList {
		if ev.Classification.OutputPIIDetected {
			found = true
			assert.NotEmpty(t, ev.Classification.OutputPIITypes)
			break
		}
	}
	assert.True(t, found, "evidence should record OutputPIIDetected")
}

func TestGateway_ResponsePIIBlockMode(t *testing.T) {
	upstreamResponse := `{"choices":[{"message":{"content":"IBAN: DE89370400440532013000"}}],"usage":{"prompt_tokens":10,"completion_tokens":20}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "block"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"what is my IBAN?"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	respBody := rec.Body.String()
	assert.NotContains(t, respBody, "DE89370400440532013000", "IBAN should not appear in blocked response")
	assert.Contains(t, respBody, "pii_policy_violation", "should contain policy violation error")
}

func TestGateway_ResponsePIIWarnModeRecordsEvidence(t *testing.T) {
	upstreamResponse := `{"choices":[{"message":{"content":"Email: user@company.eu"}}],"usage":{"prompt_tokens":5,"completion_tokens":10}}`
	gw, _, evidenceStore := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "warn"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"what is the email?"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "user@company.eu", "warn mode should not redact")

	evList, err := evidenceStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.NotEmpty(t, evList)
	found := false
	for _, ev := range evList {
		if ev.Classification.OutputPIIDetected {
			found = true
			assert.NotEmpty(t, ev.Classification.OutputPIITypes)
		}
	}
	assert.True(t, found, "evidence should record OutputPIIDetected even in warn mode")
}

func TestGateway_ResponsePII_TimestampNotFalsePositive(t *testing.T) {
	upstreamResponse := `{"id":"chatcmpl-1","object":"chat.completion","created":1772057232,"model":"gpt-4o-mini-2024-07-18","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there! How can I help?"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":5,"total_tokens":14}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	respBody := rec.Body.String()
	assert.Contains(t, respBody, "1772057232", "created timestamp must NOT be redacted")
	assert.Contains(t, respBody, "chatcmpl-1", "response id must NOT be redacted")
	assert.Contains(t, respBody, `"prompt_tokens"`, "usage fields must NOT be redacted")
	assert.NotContains(t, respBody, "[NATIONAL_ID]", "no false positive national_id in envelope")
}

func TestGateway_ResponsePII_ContentStillRedacted(t *testing.T) {
	upstreamResponse := `{"id":"chatcmpl-2","created":1772057232,"choices":[{"message":{"content":"Contact jan.kowalski@gmail.com for IBAN DE89370400440532013000"}}],"usage":{"prompt_tokens":10,"completion_tokens":20}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	respBody := rec.Body.String()
	assert.NotContains(t, respBody, "jan.kowalski@gmail.com", "email in content must be redacted")
	assert.NotContains(t, respBody, "DE89370400440532013000", "IBAN in content must be redacted")
	assert.Contains(t, respBody, "1772057232", "created timestamp must be preserved")
	assert.Contains(t, respBody, "chatcmpl-2", "response id must be preserved")
}

func TestGateway_ResponsePII_NoPIIInContent_NoFalsePositive(t *testing.T) {
	upstreamResponse := `{"id":"chatcmpl-3","created":1772057232,"choices":[{"message":{"content":"Hello! I am a helpful assistant."}}],"usage":{"prompt_tokens":9,"completion_tokens":8,"total_tokens":17}}`
	gw, _, evidenceStore := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})
	gw.config.DefaultPolicy.ResponsePIIAction = "warn"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer talon-gw-openclaw-001")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Hello! I am a helpful assistant.")

	evList, err := evidenceStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Now().Add(time.Second), 10)
	require.NoError(t, err)
	for _, ev := range evList {
		assert.False(t, ev.Classification.OutputPIIDetected,
			"no PII in content means no output PII should be detected (envelope must not trigger)")
	}
}

// ---------------------------------------------------------------------------
// Chat Completions streaming (delta-based SSE) — PII scanning
// ---------------------------------------------------------------------------

// chatCompletionSSE builds a realistic Chat Completions SSE stream from a
// series of content delta strings, ending with a finish_reason chunk.
func chatCompletionSSE(deltas ...string) string {
	var sb strings.Builder
	for _, d := range deltas {
		sb.WriteString(`data: {"id":"chatcmpl-test","choices":[{"index":0,"delta":{"content":"` + d + `"},"finish_reason":null}]}` + "\n\n")
	}
	sb.WriteString(`data: {"id":"chatcmpl-test","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}` + "\n\n")
	sb.WriteString("data: [DONE]\n\n")
	return sb.String()
}

func TestGateway_ChatCompletions_StreamingPIIRedacted(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(chatCompletionSSE("Contact ", "jan.kowalski@gmail.com", " for info")))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"give me the email"}],"stream":true}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	respBody := w.Body.String()
	assert.NotContains(t, respBody, "jan.kowalski@gmail.com",
		"email must not appear in delta-based streaming response (redact mode)")
	assert.Contains(t, respBody, "Contact",
		"non-PII content should still be present")
	assert.Contains(t, respBody, "[DONE]",
		"SSE stream must end with [DONE]")
}

func TestGateway_ChatCompletions_StreamingPIIBlocked(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(chatCompletionSSE("Your IBAN is ", "DE89370400440532013000")))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "block"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"what is my IBAN?"}],"stream":true}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusUnavailableForLegalReasons, w.Code,
		"block mode must return HTTP 451 for streaming Chat Completions with PII")

	respBody := w.Body.String()
	assert.NotContains(t, respBody, "DE89370400440532013000",
		"IBAN must not appear in blocked response")
	assert.Contains(t, respBody, "pii_policy_violation",
		"blocked response must include violation type")
}

func TestGateway_ChatCompletions_StreamingPIIWarn(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(chatCompletionSSE("Contact ", "jan.kowalski@gmail.com", " for details")))
	})

	gw, _, _ := setupOpenClawGateway(t, "warn", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "warn"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"give me the contact"}],"stream":true}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	respBody := w.Body.String()
	assert.Contains(t, respBody, "jan.kowalski@gmail.com",
		"warn mode must forward PII unchanged in delta-based streaming response")
	assert.Contains(t, respBody, "[DONE]",
		"SSE stream must end with [DONE]")
}

func TestGateway_ChatCompletions_StreamingNoPII(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(chatCompletionSSE("Hello", " world")))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"say hello"}],"stream":true}`
	w := makeGatewayRequest(gw, body)
	require.Equal(t, http.StatusOK, w.Code)

	respBody := w.Body.String()
	assert.Contains(t, respBody, "Hello",
		"clean streaming response must pass through")
	assert.Contains(t, respBody, "world",
		"all delta content must be forwarded")
}
