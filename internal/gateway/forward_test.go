package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForward_NonStreaming(t *testing.T) {
	// Mock upstream returns JSON with usage
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"Hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`))
	}))
	defer upstream.Close()

	var usage TokenUsage
	w := httptest.NewRecorder()
	timeouts := ParsedTimeouts{
		ConnectTimeout:    5 * time.Second,
		RequestTimeout:    30 * time.Second,
		StreamIdleTimeout: 60 * time.Second,
	}
	err := Forward(w, ForwardParams{
		Context:     context.Background(),
		UpstreamURL: upstream.URL,
		Method:      http.MethodPost,
		Body:        []byte(`{"model":"gpt-4o","messages":[]}`),
		Headers:     map[string]string{"Content-Type": "application/json"},
		Timeouts:    timeouts,
		TokenUsage:  &usage,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 10, usage.Input)
	require.Equal(t, 2, usage.Output)
	body := w.Body.String()
	require.Contains(t, body, "chatcmpl-1")
	require.Contains(t, body, "Hi")
}

// TestForward_ChunkedJSONNotTreatedAsStream ensures that a response with
// Transfer-Encoding: chunked but Content-Type: application/json is handled as
// non-streaming. Many upstreams send normal JSON with chunked encoding; treating
// it as SSE would break token usage parsing and cost/evidence.
func TestForward_ChunkedJSONNotTreatedAsStream(t *testing.T) {
	body := []byte(`{"id":"chunked-1","choices":[{"message":{"role":"assistant","content":"OK"}}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	var usage TokenUsage
	w := httptest.NewRecorder()
	timeouts := ParsedTimeouts{
		ConnectTimeout:    5 * time.Second,
		RequestTimeout:    30 * time.Second,
		StreamIdleTimeout: 60 * time.Second,
	}
	err := Forward(w, ForwardParams{
		Context:     context.Background(),
		UpstreamURL: upstream.URL,
		Method:      http.MethodPost,
		Body:        []byte(`{"model":"gpt-4o","messages":[]}`),
		Headers:     map[string]string{"Content-Type": "application/json"},
		Timeouts:    timeouts,
		TokenUsage:  &usage,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 7, usage.Input, "usage must be parsed from JSON body (chunked must not trigger SSE path)")
	require.Equal(t, 3, usage.Output, "usage must be parsed from JSON body (chunked must not trigger SSE path)")
	require.Equal(t, string(body), w.Body.String())
}

func TestForward_Streaming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: {\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":1}}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	var usage TokenUsage
	w := httptest.NewRecorder()
	timeouts := ParsedTimeouts{
		ConnectTimeout:    5 * time.Second,
		RequestTimeout:    30 * time.Second,
		StreamIdleTimeout: 60 * time.Second,
	}
	err := Forward(w, ForwardParams{
		Context:     context.Background(),
		UpstreamURL: upstream.URL,
		Method:      http.MethodPost,
		Body:        []byte(`{"model":"gpt-4o","messages":[],"stream":true}`),
		Headers:     map[string]string{"Content-Type": "application/json"},
		Timeouts:    timeouts,
		TokenUsage:  &usage,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Hi")
	// Usage may be filled from stream
	if usage.Input != 0 || usage.Output != 0 {
		require.Equal(t, 5, usage.Input)
		require.Equal(t, 1, usage.Output)
	}
}

// TestForward_ErrorResponseNotStreamed verifies that a 4xx/5xx response is
// always read as a single body — even when the upstream returns text/event-stream.
// This prevents the client from receiving raw gzip/binary garbage on errors.
func TestForward_ErrorResponseNotStreamed(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		body        string
	}{
		{
			name:        "404_with_sse_content_type",
			statusCode:  http.StatusNotFound,
			contentType: "text/event-stream",
			body:        `{"error":{"message":"Not found","type":"invalid_request_error"}}`,
		},
		{
			name:        "500_with_sse_content_type",
			statusCode:  http.StatusInternalServerError,
			contentType: "text/event-stream",
			body:        `{"error":{"message":"Internal error","type":"server_error"}}`,
		},
		{
			name:        "429_rate_limited",
			statusCode:  http.StatusTooManyRequests,
			contentType: "application/json",
			body:        `{"error":{"message":"Rate limit exceeded","type":"rate_limit_error"}}`,
		},
		{
			name:        "400_bad_request",
			statusCode:  http.StatusBadRequest,
			contentType: "application/json",
			body:        `{"error":{"message":"Invalid model","type":"invalid_request_error"}}`,
		},
		{
			name:        "401_unauthorized",
			statusCode:  http.StatusUnauthorized,
			contentType: "application/json",
			body:        `{"error":{"message":"Incorrect API key","type":"authentication_error"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer upstream.Close()

			var usage TokenUsage
			w := httptest.NewRecorder()
			err := Forward(w, ForwardParams{
				Context:     context.Background(),
				UpstreamURL: upstream.URL,
				Method:      http.MethodPost,
				Body:        []byte(`{"model":"gpt-4o","messages":[]}`),
				Headers:     map[string]string{"Content-Type": "application/json"},
				Timeouts:    ParsedTimeouts{ConnectTimeout: 5 * time.Second, RequestTimeout: 30 * time.Second, StreamIdleTimeout: 60 * time.Second},
				TokenUsage:  &usage,
			})
			require.NoError(t, err)
			require.Equal(t, tt.statusCode, w.Code, "status code must be preserved")
			require.Equal(t, tt.body, w.Body.String(), "error body must be passed through as readable text")
		})
	}
}

// TestForward_SuccessStreamStillWorks ensures that 200 + text/event-stream is
// still treated as a stream after the error-path change.
func TestForward_SuccessStreamStillWorks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	var usage TokenUsage
	w := httptest.NewRecorder()
	err := Forward(w, ForwardParams{
		Context:     context.Background(),
		UpstreamURL: upstream.URL,
		Method:      http.MethodPost,
		Body:        []byte(`{"model":"gpt-4o","messages":[],"stream":true}`),
		Headers:     map[string]string{"Content-Type": "application/json"},
		Timeouts:    ParsedTimeouts{ConnectTimeout: 5 * time.Second, RequestTimeout: 30 * time.Second, StreamIdleTimeout: 60 * time.Second},
		TokenUsage:  &usage,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "OK", "streaming data must be forwarded")
	require.Contains(t, w.Body.String(), "[DONE]", "stream must complete")
}

// TestForward_GzipErrorDecompressed verifies that when the upstream returns a
// gzip-compressed error body, the client receives readable JSON — not raw binary.
// This reproduces the OpenClaw "404 + binary garbage" bug caused by forwarding
// the client's Accept-Encoding header to the upstream.
func TestForward_GzipErrorDecompressed(t *testing.T) {
	errorJSON := `{"error":{"message":"The model 'gpt-99' does not exist","type":"invalid_request_error","code":"model_not_found"}}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate OpenAI responding with gzip when Accept-Encoding allows it
		if r.Header.Get("Accept-Encoding") != "" {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			_, _ = gz.Write([]byte(errorJSON))
			_ = gz.Close()

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(buf.Bytes())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(errorJSON))
	}))
	defer upstream.Close()

	var usage TokenUsage
	w := httptest.NewRecorder()
	err := Forward(w, ForwardParams{
		Context:     context.Background(),
		UpstreamURL: upstream.URL,
		Method:      http.MethodPost,
		Body:        []byte(`{"model":"gpt-99","messages":[]}`),
		Headers: map[string]string{
			"Content-Type":    "application/json",
			"Accept-Encoding": "gzip, deflate, br",
		},
		Timeouts:   ParsedTimeouts{ConnectTimeout: 5 * time.Second, RequestTimeout: 30 * time.Second, StreamIdleTimeout: 60 * time.Second},
		TokenUsage: &usage,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.JSONEq(t, errorJSON, w.Body.String(),
		"gzip-compressed 404 body must arrive decompressed as readable JSON")
}

// TestForward_GzipSuccessDecompressed verifies that gzip-compressed 200 bodies
// are transparently decompressed so PII scanning and usage parsing work correctly.
func TestForward_GzipSuccessDecompressed(t *testing.T) {
	successJSON := `{"id":"chatcmpl-gz","choices":[{"message":{"role":"assistant","content":"Hello!"}}],"usage":{"prompt_tokens":8,"completion_tokens":1,"total_tokens":9}}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "" {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			_, _ = gz.Write([]byte(successJSON))
			_ = gz.Close()

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(buf.Bytes())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(successJSON))
	}))
	defer upstream.Close()

	var usage TokenUsage
	w := httptest.NewRecorder()
	err := Forward(w, ForwardParams{
		Context:     context.Background(),
		UpstreamURL: upstream.URL,
		Method:      http.MethodPost,
		Body:        []byte(`{"model":"gpt-4o","messages":[]}`),
		Headers: map[string]string{
			"Content-Type":    "application/json",
			"Accept-Encoding": "gzip, deflate, br",
		},
		Timeouts:   ParsedTimeouts{ConnectTimeout: 5 * time.Second, RequestTimeout: 30 * time.Second, StreamIdleTimeout: 60 * time.Second},
		TokenUsage: &usage,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 8, usage.Input, "token usage must be parsed from decompressed body")
	require.Equal(t, 1, usage.Output)
	require.Contains(t, w.Body.String(), "Hello!",
		"gzip-compressed 200 body must arrive decompressed")
}

func TestHTTPClientForGateway(t *testing.T) {
	timeouts := ParsedTimeouts{
		ConnectTimeout:    2 * time.Second,
		RequestTimeout:    10 * time.Second,
		StreamIdleTimeout: 30 * time.Second,
	}
	client := HTTPClientForGateway(timeouts)
	require.NotNil(t, client)
	require.Equal(t, 10*time.Second, client.Timeout)
}

// ---------------------------------------------------------------------------
// Component tests — upstream error forwarding through the Gateway handler
// ---------------------------------------------------------------------------

func TestGateway_Upstream404_ReadableResponse(t *testing.T) {
	errorBody := `{"error":{"message":"The model 'gpt-nonexistent' does not exist","type":"invalid_request_error","code":"model_not_found"}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(errorBody))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusNotFound, w.Code, "404 status must be forwarded to client")
	assert.Contains(t, w.Body.String(), "model_not_found",
		"error body must be readable JSON, not binary")
	assert.Contains(t, w.Body.String(), "gpt-nonexistent",
		"original error message must be preserved")
}

func TestGateway_Upstream500_ReadableResponse(t *testing.T) {
	errorBody := `{"error":{"message":"Internal server error","type":"server_error"}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(errorBody))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Internal server error",
		"500 error body must be readable")
}

func TestGateway_Upstream404WithSSEContentType(t *testing.T) {
	errorBody := `{"error":{"message":"Not found","type":"not_found"}}`
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(errorBody))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Not found",
		"404 with SSE content-type must still return readable error")
}

func TestGateway_UpstreamError_EvidenceStillRecorded(t *testing.T) {
	gw, _, evStore := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"Not found"}}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusNotFound, w.Code)

	records, err := evStore.List(context.Background(), "test-tenant", "",
		time.Time{}, time.Now().Add(time.Second), 10)
	require.NoError(t, err)
	require.NotEmpty(t, records, "evidence must be recorded even when upstream returns an error")
	assert.Equal(t, "openclaw-main", records[0].AgentID)
	assert.Equal(t, "gpt-4o-mini", records[0].Execution.ModelUsed)
}

func TestGateway_PIIRedact_ThenUpstream404(t *testing.T) {
	var capturedBody []byte
	gw, _, _ := setupOpenClawGateway(t, "redact", func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"Model not found","type":"invalid_request_error","code":"model_not_found"}}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Contact mike@johnson.com about the project"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusNotFound, w.Code, "404 status must be forwarded")
	assert.Contains(t, w.Body.String(), "Model not found",
		"error body must be readable even when PII was redacted")
	assert.NotContains(t, string(capturedBody), "mike@johnson.com",
		"PII must be redacted before forwarding to upstream")
}

func TestGateway_Upstream429_RateLimitError(t *testing.T) {
	gw, _, _ := setupOpenClawGateway(t, "allow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-ratelimit-remaining-requests", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"Rate limit reached","type":"rate_limit_error"}}`))
	})

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}`
	w := makeGatewayRequest(gw, body)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "Rate limit reached")
	assert.Equal(t, "0", w.Header().Get("x-ratelimit-remaining-requests"),
		"rate-limit headers from upstream must be forwarded")
}
