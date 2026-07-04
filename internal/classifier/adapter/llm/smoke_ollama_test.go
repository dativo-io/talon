//go:build ollama_smoke

package llm_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier/adapter/llm"
)

// TestOllamaSmoke exercises the llm scanner adapter against a real Ollama
// instance. It is excluded from normal builds (ollama_smoke tag) and runs in
// the scheduled scanner-ollama-smoke workflow.
//
//	TALON_SCANNER_SMOKE_URL   OpenAI-compatible base (default http://localhost:11434/v1)
//	TALON_SCANNER_SMOKE_MODEL model id (default llama3.2:1b — small, CI-friendly)
func TestOllamaSmoke(t *testing.T) {
	base := os.Getenv("TALON_SCANNER_SMOKE_URL")
	if base == "" {
		base = "http://localhost:11434/v1"
	}
	model := os.Getenv("TALON_SCANNER_SMOKE_MODEL")
	if model == "" {
		model = "llama3.2:1b"
	}

	a, err := llm.New(llm.Config{
		Endpoint: base,
		Model:    model,
		Timeout:  120 * time.Second, // cold CPU inference in CI
	})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, a.HealthCheck(ctx), "ollama must be up with %s pulled", model)

	text := "Please contact kai.nova@example.com about invoice 42."
	cls, err := a.Analyze(ctx, text)
	require.NoError(t, err)
	require.True(t, cls.HasPII, "a real model should find the email address")

	foundEmail := false
	for _, e := range cls.Entities {
		assert.Equal(t, e.Value, text[e.Position:e.Position+len(e.Value)],
			"relocated offsets must be byte-exact regardless of model behavior")
		if e.Type == "email" && strings.Contains(e.Value, "kai.nova@example.com") {
			foundEmail = true
		}
	}
	assert.True(t, foundEmail, "expected an email entity, got %+v", cls.Entities)

	redacted, err := a.RedactText(ctx, text)
	require.NoError(t, err)
	assert.NotContains(t, redacted, "kai.nova@example.com")

	assert.NoError(t, a.VerifyEgress(ctx, redacted),
		"redacted text must pass the verify re-scan (placeholder guard)")
}
