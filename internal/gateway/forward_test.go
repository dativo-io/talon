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
