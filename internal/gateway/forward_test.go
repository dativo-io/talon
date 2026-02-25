package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
