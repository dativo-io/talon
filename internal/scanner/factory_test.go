package scanner

import (
	"context"
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

func TestBuild_LLMNotImplementedYet(t *testing.T) {
	_, err := Build(context.Background(), &config.Config{
		Scanner: &config.ScannerConfig{
			Type:     config.ScannerTypeLLM,
			Endpoint: "http://localhost:11434/v1",
			LLM:      &config.ScannerLLMConfig{Model: "llama3.1:8b"},
		},
	}, nil, nil)
	require.Error(t, err)
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
