package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/presidio"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/testutil"
)

func TestBuild_DefaultIsBuiltinRegex(t *testing.T) {
	for _, cfg := range []*config.Config{
		nil,
		{},
		{Scanner: &config.ScannerConfig{Type: config.ScannerTypeRegex}},
	} {
		facade, err := Build(context.Background(), cfg, nil, nil)
		require.NoError(t, err)
		_, isBuiltin := facade.(*classifier.Scanner)
		assert.True(t, isBuiltin, "absent/regex scanner block must yield the built-in scanner")
	}
}

func TestBuild_ExternalEngineHealthy(t *testing.T) {
	srv := testutil.NewPresidioMockServer(t, func(string) []presidio.RecognizerResult { return nil })

	facade, err := Build(context.Background(), &config.Config{
		Scanner: &config.ScannerConfig{Type: config.ScannerTypePresidio, Endpoint: srv.URL},
	}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "presidio-http", facade.Detector())
}

func TestBuild_StartupFailsOnDeadEndpoint(t *testing.T) {
	_, err := Build(context.Background(), &config.Config{
		Scanner: &config.ScannerConfig{
			Type:     config.ScannerTypePresidio,
			Endpoint: "http://127.0.0.1:1", // nothing listens on port 1
			Timeout:  "200ms",
		},
	}, nil, nil)
	require.Error(t, err, "eager health check must refuse startup against a dead engine")
	assert.Contains(t, err.Error(), "refuses to start")
}

func TestBuild_HealthCheckCanBeDisabled(t *testing.T) {
	off := false
	facade, err := Build(context.Background(), &config.Config{
		Scanner: &config.ScannerConfig{
			Type:        config.ScannerTypePresidio,
			Endpoint:    "http://127.0.0.1:1",
			HealthCheck: &off,
		},
	}, nil, nil)
	require.NoError(t, err)

	// First scan then fails closed instead.
	_, scanErr := facade.Analyze(context.Background(), "text")
	assert.Error(t, scanErr)
}

func TestBuild_AirGapRejectsPublicEndpoint(t *testing.T) {
	_, err := Build(context.Background(), &config.Config{
		Sovereignty: &config.SovereigntyConfig{DeploymentMode: config.SovereigntyModeAirGap},
		Scanner: &config.ScannerConfig{
			Type:     config.ScannerTypePresidio,
			Endpoint: "https://scanner.example.com",
		},
	}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not provably local")
}

func TestBuild_AirGapAcceptsLoopback(t *testing.T) {
	srv := testutil.NewPresidioMockServer(t, func(string) []presidio.RecognizerResult { return nil })

	_, err := Build(context.Background(), &config.Config{
		Sovereignty: &config.SovereigntyConfig{DeploymentMode: config.SovereigntyModeAirGap},
		Scanner:     &config.ScannerConfig{Type: config.ScannerTypePresidio, Endpoint: srv.URL},
	}, nil, nil)
	require.NoError(t, err, "loopback endpoints are local; air-gap must accept them")
}

func TestBuild_LLMEngine(t *testing.T) {
	srv := testutil.NewNERMockServer(t, func(string) string { return `{"entities":[]}` }, "llama3.1:8b")

	facade, err := Build(context.Background(), &config.Config{
		Scanner: &config.ScannerConfig{
			Type:     config.ScannerTypeLLM,
			Endpoint: srv.URL + "/v1",
			LLM:      &config.ScannerLLMConfig{Model: "llama3.1:8b"},
		},
	}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "llm:llama3.1:8b", facade.Detector())
}

func TestBuild_LLMStartupFailsWhenModelMissing(t *testing.T) {
	srv := testutil.NewNERMockServer(t, func(string) string { return `{"entities":[]}` }, "some-other-model")

	_, err := Build(context.Background(), &config.Config{
		Scanner: &config.ScannerConfig{
			Type:     config.ScannerTypeLLM,
			Endpoint: srv.URL + "/v1",
			LLM:      &config.ScannerLLMConfig{Model: "llama3.1:8b"},
		},
	}, nil, nil)
	require.Error(t, err, "health probe must verify the configured model is pulled")
	assert.Contains(t, err.Error(), "refuses to start")
}

func TestValidateEndpointLocality(t *testing.T) {
	tests := []struct {
		endpoint string
		airGap   bool
		wantErr  bool
	}{
		{"unix:///var/run/scanner.sock", true, false},
		{"http://localhost:5002", true, false},
		{"http://127.0.0.1:5002", true, false},
		{"http://[::1]:5002", true, false},
		{"http://10.1.2.3:5002", true, false},
		{"http://172.16.0.9:5002", true, false},
		{"http://192.168.1.50:5002", true, false},
		{"http://[fd12:3456::1]:5002", true, false},
		{"http://169.254.1.1:5002", true, false},
		{"https://scanner.example.com", true, true},
		{"http://8.8.8.8:5002", true, true},
		{"http://scanner.internal:5002", true, true}, // DNS name: not provably local
		{"https://scanner.example.com", false, false},
		{"http://scanner.internal:5002", false, false},
	}
	for _, tt := range tests {
		err := ValidateEndpointLocality(tt.endpoint, tt.airGap)
		if tt.wantErr {
			assert.Error(t, err, "%s airGap=%v", tt.endpoint, tt.airGap)
		} else {
			assert.NoError(t, err, "%s airGap=%v", tt.endpoint, tt.airGap)
		}
	}
}

func TestBuild_LLMEntitiesOverrideNarrowsPrompt(t *testing.T) {
	// scanner.entities is the operator lever for prompt size (prompt eval
	// dominates CPU scan latency); it must reach the llm engine's prompt,
	// replacing the full policy-derived entity list.
	var mu sync.Mutex
	var systemPrompts []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"llama3.2:1b"}]}`))
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		for _, m := range req.Messages {
			if m.Role == "system" {
				mu.Lock()
				systemPrompts = append(systemPrompts, m.Content)
				mu.Unlock()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"entities\":[]}"}}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	facade, err := Build(context.Background(), &config.Config{
		Scanner: &config.ScannerConfig{
			Type:     config.ScannerTypeLLM,
			Endpoint: srv.URL + "/v1",
			Entities: []string{"EMAIL_ADDRESS", "IBAN_CODE"},
			LLM:      &config.ScannerLLMConfig{Model: "llama3.2:1b"},
		},
	}, nil, nil)
	require.NoError(t, err)

	_, err = facade.Analyze(context.Background(), "some text")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, systemPrompts, "warm-up and scan must carry the system prompt")
	prompt := systemPrompts[len(systemPrompts)-1]
	assert.Contains(t, prompt, "EMAIL_ADDRESS")
	assert.Contains(t, prompt, "IBAN_CODE")
	assert.NotContains(t, prompt, "PL_PESEL",
		"the policy-derived full entity list must be replaced, not appended to")
}
