package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsResponsesAPIPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/v1/responses", true},
		{"/v1/responses/rs_abc123", true},
		{"/v1/chat/completions", false},
		{"/v1/models", false},
		{"/v1/responses-extra", true},
		{"/v2/responses", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, isResponsesAPIPath(tt.path))
		})
	}
}

func TestEnsureResponsesStore(t *testing.T) {
	t.Run("adds store true when missing", func(t *testing.T) {
		input := `{"model":"gpt-4o","input":"Hello"}`
		result := ensureResponsesStore([]byte(input))

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &m))
		assert.Equal(t, true, m["store"])
		assert.Equal(t, "gpt-4o", m["model"])
		assert.Equal(t, "Hello", m["input"])
	})

	t.Run("overwrites store false so multi-turn works through proxy", func(t *testing.T) {
		input := `{"model":"gpt-4o","input":"Hello","store":false}`
		result := ensureResponsesStore([]byte(input))

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &m))
		assert.Equal(t, true, m["store"], "gateway forces store:true so referenced response IDs persist")
	})

	t.Run("preserves store true when already set", func(t *testing.T) {
		input := `{"model":"gpt-4o","input":"Hello","store":true}`
		result := ensureResponsesStore([]byte(input))

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &m))
		assert.Equal(t, true, m["store"])
	})

	t.Run("preserves all other fields", func(t *testing.T) {
		input := `{"model":"gpt-4o","input":[{"type":"message","role":"user","content":"Hi"}],"previous_response_id":"rs_abc123","temperature":0.7}`
		result := ensureResponsesStore([]byte(input))

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(result, &m))
		assert.Equal(t, true, m["store"])
		assert.Equal(t, "gpt-4o", m["model"])
		assert.Equal(t, "rs_abc123", m["previous_response_id"])
		assert.InDelta(t, 0.7, m["temperature"], 0.001)
	})

	t.Run("invalid json returns original body", func(t *testing.T) {
		input := `not json`
		result := ensureResponsesStore([]byte(input))
		assert.Equal(t, input, string(result))
	})
}

// ---------------------------------------------------------------------------
// Integration tests — full Responses API pipeline through Gateway
// ---------------------------------------------------------------------------

func TestGateway_ResponsesAPI_RequestPII_StringInput(t *testing.T) {
	var capturedBody []byte
	var capturedPath string
	gw, _, _ := setupOpenClawGateway(t, "redact", responsesAPIUpstream(&capturedBody, &capturedPath))

	body := `{"model":"gpt-4o","input":"Send report to hans.mueller@example.de about the project"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)
	assert.NotContains(t, forwarded, "hans.mueller@example.de",
		"email in Responses API string input must be redacted before forwarding")
	assert.Contains(t, forwarded, "report",
		"non-PII text must be preserved")
	assert.Contains(t, forwarded, `"store":true`,
		"store:true must be injected for Responses API")
	assert.Equal(t, "/v1/responses", capturedPath,
		"request must be routed to /v1/responses")
}

func TestGateway_ResponsesAPI_RequestPII_ArrayContentString(t *testing.T) {
	var capturedBody []byte
	var capturedPath string
	gw, _, _ := setupOpenClawGateway(t, "redact", responsesAPIUpstream(&capturedBody, &capturedPath))

	body := `{"model":"gpt-4o","input":[{"role":"user","content":"Contact alice@company.eu please"}]}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)
	assert.NotContains(t, forwarded, "alice@company.eu",
		"email in Responses API array input content must be redacted")
	assert.Contains(t, forwarded, "Contact",
		"non-PII content must be preserved")
}

func TestGateway_ResponsesAPI_RequestPII_InputTextBlock(t *testing.T) {
	var capturedBody []byte
	var capturedPath string
	gw, _, _ := setupOpenClawGateway(t, "redact", responsesAPIUpstream(&capturedBody, &capturedPath))

	body := `{"model":"gpt-4o","input":[{"role":"user","content":[{"type":"input_text","text":"Email bob@test.eu now"}]}]}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)
	assert.NotContains(t, forwarded, "bob@test.eu",
		"email in input_text block must be redacted")
	assert.Contains(t, forwarded, "input_text",
		"block type must be preserved")
}

func TestGateway_ResponsesAPI_ItemReferenceNotCorrupted(t *testing.T) {
	var capturedBody []byte
	var capturedPath string
	gw, _, _ := setupOpenClawGateway(t, "redact", responsesAPIUpstream(&capturedBody, &capturedPath))

	body := `{"model":"gpt-4o","input":[{"type":"item_reference","id":"rs_abc123"},{"role":"user","content":"Email alice@test.com"}],"previous_response_id":"rs_prev"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)
	assert.NotContains(t, forwarded, "alice@test.com",
		"email must be redacted")
	assert.Contains(t, forwarded, "item_reference",
		"item_reference type must be preserved")
	assert.Contains(t, forwarded, "rs_abc123",
		"reference ID must be preserved")
	assert.Contains(t, forwarded, "rs_prev",
		"previous_response_id must be preserved")
	assert.NotContains(t, forwarded, `"content":null`,
		"content:null must NOT be added to items that had no content field")
}

func TestGateway_ResponsesAPI_ResponsePIIRedacted(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_pii","output":[{"type":"message","content":[{"type":"output_text","text":"The support email is support@company.eu"}]}],"usage":{"input_tokens":10,"output_tokens":15}}`))
	})

	gw, _, evStore := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o","input":"What is the support email?"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	respBody := w.Body.String()
	assert.NotContains(t, respBody, "support@company.eu",
		"email in Responses API output must be redacted")
	assert.Contains(t, respBody, "resp_pii",
		"response ID must be preserved in envelope")
	assert.Contains(t, respBody, "output_text",
		"output_text type must be preserved")

	time.Sleep(50 * time.Millisecond)
	list, err := evStore.List(context.Background(), "test-tenant", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	found := false
	for _, ev := range list {
		if ev.Classification.OutputPIIDetected {
			found = true
			assert.NotEmpty(t, ev.Classification.OutputPIITypes)
		}
	}
	assert.True(t, found, "evidence should record OutputPIIDetected for Responses API")
}

func TestGateway_ResponsesAPI_ResponsePIIBlock(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_block","output":[{"type":"message","content":[{"type":"output_text","text":"Your IBAN is DE89370400440532013000"}]}],"usage":{"input_tokens":10,"output_tokens":15}}`))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "block"

	body := `{"model":"gpt-4o","input":"What is the IBAN?"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)

	assert.NotContains(t, w.Body.String(), "DE89370400440532013000",
		"IBAN must not appear in blocked response")
	assert.Contains(t, w.Body.String(), "PII",
		"block response should mention PII")
}

func TestGateway_ResponsesAPI_NoPIIPassesThrough(t *testing.T) {
	expectedOutput := `{"id":"resp_clean","output":[{"type":"message","content":[{"type":"output_text","text":"Greenland has a Premier, not a president."}]}],"usage":{"input_tokens":10,"output_tokens":12}}`

	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedOutput))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o","input":"Who is the president of Greenland?"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	forwarded := string(capturedBody)
	assert.Contains(t, forwarded, "Who is the president of Greenland",
		"non-PII input must be preserved")
	assert.Contains(t, forwarded, `"store":true`,
		"store:true must be injected")

	assert.Contains(t, w.Body.String(), "Greenland has a Premier",
		"non-PII response must pass through")
	assert.Contains(t, w.Body.String(), "resp_clean",
		"envelope must be preserved")
}

func TestGateway_ResponsesAPI_BlockRequestPII(t *testing.T) {
	upstreamCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	})

	gw, _, _ := setupOpenClawGateway(t, "block", handler)

	body := `{"model":"gpt-4o","input":"Contact hans.mueller@example.de about the report"}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"block mode should return 400 when PII detected in Responses API input")
	assert.False(t, upstreamCalled,
		"upstream must NOT be called when PII is blocked")
	assert.Contains(t, w.Body.String(), "PII",
		"error response should mention PII")
}

// ---------------------------------------------------------------------------
// Streaming tests — SSE responses through the Gateway
// ---------------------------------------------------------------------------

func TestGateway_ResponsesAPI_StreamingPIIAuditOnly(t *testing.T) {
	respJSON := `{"id":"resp_stream","output":[{"type":"message","content":[{"type":"output_text","text":"aurora@stellarsystems.eu"}]}],"usage":{"input_tokens":10,"output_tokens":5}}`
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sseResponse(respJSON)))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o","input":"Invent a fictional European email","stream":true}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	respBody := w.Body.String()
	assert.Contains(t, respBody, "aurora@stellarsystems.eu",
		"streaming response is forwarded as-is (PII audit only)")
	assert.Contains(t, respBody, "response.completed",
		"original SSE format must be preserved")
	assert.Contains(t, respBody, "[DONE]",
		"SSE stream must end with [DONE]")
}

func TestGateway_ResponsesAPI_StreamingNoPII(t *testing.T) {
	respJSON := `{"id":"resp_clean","output":[{"type":"message","content":[{"type":"output_text","text":"Hello world"}]}],"usage":{"input_tokens":5,"output_tokens":2}}`
	sseBody := sseResponse(respJSON)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sseBody))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "redact"

	body := `{"model":"gpt-4o","input":"Say hello","stream":true}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	respBody := w.Body.String()
	assert.Contains(t, respBody, "Hello world",
		"clean response must pass through")
	assert.Contains(t, respBody, "response.completed",
		"original SSE format must be preserved when no PII")
}

func TestGateway_StreamingAllowed_WhenPIIActionAllow(t *testing.T) {
	var capturedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"id\":\"ok\"}\n\ndata: [DONE]\n\n"))
	})

	gw, _, _ := setupOpenClawGateway(t, "allow", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "allow"

	body := `{"model":"gpt-4o","input":"Hello","stream":true}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	assert.Contains(t, string(capturedBody), `"stream":true`,
		"stream:true must be preserved when response PII action is allow")
}

func TestGateway_ResponsesAPI_StreamingPIIBlockAuditOnly(t *testing.T) {
	respJSON := `{"id":"resp_block","output":[{"type":"message","content":[{"type":"output_text","text":"Your IBAN is DE89370400440532013000"}]}],"usage":{"input_tokens":10,"output_tokens":8}}`
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sseResponse(respJSON)))
	})

	gw, _, _ := setupOpenClawGateway(t, "redact", handler)
	gw.config.DefaultPolicy.ResponsePIIAction = "block"

	body := `{"model":"gpt-4o","input":"What is the IBAN?","stream":true}`
	w := makeGatewayRequestToPath(gw, "/v1/proxy/openai/v1/responses", body)
	require.Equal(t, http.StatusOK, w.Code)

	respBody := w.Body.String()
	assert.Contains(t, respBody, "DE89370400440532013000",
		"streaming response forwarded as-is (block mode audits only for SSE)")
	assert.Contains(t, respBody, "response.completed",
		"SSE format preserved")
}
