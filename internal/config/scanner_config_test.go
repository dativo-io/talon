package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScannerConfig_AbsentDefaultsToRegex(t *testing.T) {
	resetViper(t)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Nil(t, cfg.Scanner)
	assert.Equal(t, ScannerTypeRegex, cfg.Scanner.EngineType())
	assert.False(t, cfg.Scanner.IsExternal())
	assert.Equal(t, DefaultScannerTimeout, cfg.Scanner.ParsedTimeout())
	assert.True(t, cfg.Scanner.HealthCheckEnabled())
	assert.Equal(t, DefaultScannerMinScore, cfg.Scanner.EffectiveMinScore())
	assert.Equal(t, DefaultScannerLanguage, cfg.Scanner.EffectiveLanguage())
}

func TestScannerConfig_PresidioBlock(t *testing.T) {
	resetViper(t)
	viper.Set("scanner", map[string]interface{}{
		"type":           "presidio",
		"endpoint":       "http://localhost:5002",
		"timeout":        "2s",
		"min_score":      0.7,
		"name":           "presidio-prod",
		"engine_version": "2.2.354",
	})

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Scanner)

	assert.Equal(t, ScannerTypePresidio, cfg.Scanner.EngineType())
	assert.True(t, cfg.Scanner.IsExternal())
	assert.Equal(t, 2*time.Second, cfg.Scanner.ParsedTimeout())
	assert.Equal(t, 0.7, cfg.Scanner.EffectiveMinScore())
	assert.Equal(t, "presidio-prod", cfg.Scanner.Name)
	assert.Equal(t, "2.2.354", cfg.Scanner.EngineVersion)
}

func TestScannerConfig_UnixSocketEndpoint(t *testing.T) {
	resetViper(t)
	viper.Set("scanner", map[string]interface{}{
		"type":     "http",
		"endpoint": "unix:///var/run/scanner/analyzer.sock",
	})

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, ScannerTypeHTTP, cfg.Scanner.EngineType())
}

func TestScannerConfig_LLMEndpointDefaultsFromOllama(t *testing.T) {
	resetViper(t)
	viper.Set("scanner", map[string]interface{}{
		"type": "llm",
		"llm":  map[string]interface{}{"model": "llama3.1:8b"},
	})

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Scanner)

	assert.Equal(t, DefaultOllamaURL+"/v1", cfg.Scanner.Endpoint)
	assert.Equal(t, "llama3.1:8b", cfg.Scanner.LLM.Model)
	assert.Equal(t, DefaultScannerLLMConfidence, cfg.Scanner.LLM.EffectiveConfidence())
}

func TestScannerConfig_HealthCheckDisabled(t *testing.T) {
	resetViper(t)
	viper.Set("scanner", map[string]interface{}{
		"type":         "presidio",
		"endpoint":     "http://localhost:5002",
		"health_check": false,
	})

	cfg, err := Load()
	require.NoError(t, err)
	assert.False(t, cfg.Scanner.HealthCheckEnabled())
}

func TestScannerConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		block   map[string]interface{}
		wantErr string
	}{
		{
			name:    "unknown type",
			block:   map[string]interface{}{"type": "grpc", "endpoint": "http://localhost:1"},
			wantErr: "scanner.type",
		},
		{
			name:    "external without endpoint",
			block:   map[string]interface{}{"type": "presidio"},
			wantErr: "scanner.endpoint is required",
		},
		{
			name:    "bad timeout",
			block:   map[string]interface{}{"type": "presidio", "endpoint": "http://localhost:1", "timeout": "banana"},
			wantErr: "scanner.timeout",
		},
		{
			name:    "negative timeout",
			block:   map[string]interface{}{"type": "presidio", "endpoint": "http://localhost:1", "timeout": "-5s"},
			wantErr: "scanner.timeout must be positive",
		},
		{
			name:    "min_score out of range",
			block:   map[string]interface{}{"type": "presidio", "endpoint": "http://localhost:1", "min_score": 1.5},
			wantErr: "scanner.min_score",
		},
		{
			name:    "bad offset encoding",
			block:   map[string]interface{}{"type": "presidio", "endpoint": "http://localhost:1", "offset_encoding": "utf16"},
			wantErr: "scanner.offset_encoding",
		},
		{
			name:    "unsupported scheme",
			block:   map[string]interface{}{"type": "presidio", "endpoint": "grpc://localhost:5002"},
			wantErr: "unsupported",
		},
		{
			name:    "http endpoint without host",
			block:   map[string]interface{}{"type": "presidio", "endpoint": "http://"},
			wantErr: "no host",
		},
		{
			name:    "unix endpoint without path",
			block:   map[string]interface{}{"type": "http", "endpoint": "unix://"},
			wantErr: "no socket path",
		},
		{
			name:    "llm without model",
			block:   map[string]interface{}{"type": "llm", "endpoint": "http://localhost:11434/v1"},
			wantErr: "scanner.llm.model is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetViper(t)
			viper.Set("scanner", tt.block)

			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestScannerConfig_RegexTypeNeedsNoEndpoint(t *testing.T) {
	resetViper(t)
	viper.Set("scanner", map[string]interface{}{"type": "regex"})

	cfg, err := Load()
	require.NoError(t, err)
	assert.False(t, cfg.Scanner.IsExternal())
}
