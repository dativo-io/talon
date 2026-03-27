package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

const piiPrompt = "Please contact Hans Mueller at hans.mueller@example.de about IBAN DE89370400440532013000"

func setupRunner(t *testing.T, dir string, provider llm.Provider) *Runner {
	t.Helper()
	secretsStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretsStore.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evidenceStore.Close() })

	providers := map[string]llm.Provider{"openai": provider}
	router := llm.NewRouter(&policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4"},
		Tier1: &policy.TierConfig{Primary: "gpt-4"},
		Tier2: &policy.TierConfig{Primary: "gpt-4"},
	}, providers, nil)

	return NewRunner(RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     router,
		Secrets:    secretsStore,
		Evidence:   evidenceStore,
	})
}

func TestRun_InputRedaction(t *testing.T) {
	tests := []struct {
		name          string
		redactInput   bool
		redactOutput  bool
		llmResponse   string
		wantInputPII  bool // expect LLM to see raw PII in prompt
		wantOutputPII bool // expect raw PII in returned response
	}{
		{
			name:          "both_redact",
			redactInput:   true,
			redactOutput:  true,
			llmResponse:   "Contact hans.mueller@example.de for info",
			wantInputPII:  false,
			wantOutputPII: false,
		},
		{
			name:          "input_only",
			redactInput:   true,
			redactOutput:  false,
			llmResponse:   "Contact hans.mueller@example.de for info",
			wantInputPII:  false,
			wantOutputPII: true,
		},
		{
			name:          "output_only",
			redactInput:   false,
			redactOutput:  true,
			llmResponse:   "Contact hans.mueller@example.de for info",
			wantInputPII:  true,
			wantOutputPII: false,
		},
		{
			name:          "neither_redact",
			redactInput:   false,
			redactOutput:  false,
			llmResponse:   "Contact hans.mueller@example.de for info",
			wantInputPII:  true,
			wantOutputPII: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			testutil.WriteInputOutputRedactPolicyFile(t, dir, "test-agent", tt.redactInput, tt.redactOutput)

			capProvider := &testutil.CapturingMockProvider{
				MockProvider: testutil.MockProvider{ProviderName: "openai", Content: tt.llmResponse},
			}
			runner := setupRunner(t, dir, capProvider)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			resp, err := runner.Run(ctx, &RunRequest{
				TenantID:       "default",
				AgentName:      "test-agent",
				Prompt:         piiPrompt,
				InvocationType: "manual",
			})
			require.NoError(t, err)
			require.True(t, resp.PolicyAllow, "expected policy to allow the request")

			llmSawPrompt := capProvider.GetLastPrompt()

			if tt.wantInputPII {
				assert.Contains(t, llmSawPrompt, "hans.mueller@example.de",
					"LLM should see raw PII when input redaction is off")
			} else {
				assert.NotContains(t, llmSawPrompt, "hans.mueller@example.de",
					"LLM should NOT see raw PII when input redaction is on")
				assert.True(t,
					strings.Contains(llmSawPrompt, "[EMAIL") || strings.Contains(llmSawPrompt, "<PII"),
					"LLM prompt should contain PII placeholder")
			}

			if tt.wantOutputPII {
				assert.Contains(t, resp.Response, "hans.mueller@example.de",
					"response should contain raw PII when output redaction is off")
			} else {
				assert.NotContains(t, resp.Response, "hans.mueller@example.de",
					"response should NOT contain raw PII when output redaction is on")
			}
		})
	}
}

func TestRun_InputRedaction_LegacyRedactPII(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteOutputScanPolicyFile(t, dir, "test-agent", true, false)

	capProvider := &testutil.CapturingMockProvider{
		MockProvider: testutil.MockProvider{ProviderName: "openai", Content: "Contact hans.mueller@example.de"},
	}
	runner := setupRunner(t, dir, capProvider)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := runner.Run(ctx, &RunRequest{
		TenantID:       "default",
		AgentName:      "test-agent",
		Prompt:         piiPrompt,
		InvocationType: "manual",
	})
	require.NoError(t, err)
	require.True(t, resp.PolicyAllow)

	llmSawPrompt := capProvider.GetLastPrompt()
	assert.NotContains(t, llmSawPrompt, "hans.mueller@example.de",
		"redact_pii: true should enable input redaction by default")
	assert.NotContains(t, resp.Response, "hans.mueller@example.de",
		"redact_pii: true should enable output redaction by default")
}
