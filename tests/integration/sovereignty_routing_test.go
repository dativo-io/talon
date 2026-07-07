//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agent"
	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/llm"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/server"
	"github.com/dativo-io/talon/internal/testutil"
)

// jurisdictionCountingProvider is a mock LLM provider with a configurable
// jurisdiction (US/LOCAL) that counts how many times it is dispatched — enough
// to prove a US candidate is rejected pre-emptively and never called.
type jurisdictionCountingProvider struct {
	name         string
	jurisdiction string
	calls        int
}

func (p *jurisdictionCountingProvider) Name() string { return p.name }
func (p *jurisdictionCountingProvider) Metadata() llm.ProviderMetadata {
	return llm.ProviderMetadata{ID: p.name, DisplayName: p.name, Jurisdiction: p.jurisdiction}
}
func (p *jurisdictionCountingProvider) Generate(_ context.Context, req *llm.Request) (*llm.Response, error) {
	p.calls++
	return &llm.Response{Content: "answer from " + p.name, FinishReason: "stop", InputTokens: 5, OutputTokens: 5, Model: req.Model}, nil
}
func (p *jurisdictionCountingProvider) Stream(_ context.Context, _ *llm.Request, _ chan<- llm.StreamChunk) error {
	return llm.ErrNotImplemented
}
func (p *jurisdictionCountingProvider) EstimateCost(string, int, int) float64 { return 0.0001 }
func (p *jurisdictionCountingProvider) ValidateConfig() error                 { return nil }
func (p *jurisdictionCountingProvider) HealthCheck(context.Context) error     { return nil }
func (p *jurisdictionCountingProvider) WithHTTPClient(*http.Client) llm.Provider {
	return p
}

// TestSovereigntyRouting_ServerHTTP_ConfidentialToLocal is the #261 regression:
// it drives the REAL server HTTP handler (POST /v1/chat/completions), with the
// server configured in eu_preferred mode, through the real classifier and the
// real embedded routing rego (no custom evaluator) — proving a confidential
// (tier-2, IBAN) request routes away from the healthy US provider to the LOCAL
// one, with both candidates in signed evidence and the client-asserted session
// id preserved. Without the #261 fix the server drops SovereigntyMode and no
// RoutingDecision would be recorded, so this test protects the actual bug.
func TestSovereigntyRouting_ServerHTTP_ConfidentialToLocal(t *testing.T) {
	dir := t.TempDir()

	// Agent policy mirrors examples/governed-session/agent.talon.yaml: tier-2's
	// primary is a US model, its fallback a local llama; PII is NOT blocked (so
	// confidential input reaches routing) and no human-oversight gate. Named
	// after the tenant key's agent so the server resolves it.
	policyPath := filepath.Join(dir, "gov.talon.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(`
agent:
  name: "gov"
  version: "1.0.0"
policies:
  cost_limits:
    per_request: 100.0
    daily: 1000.0
    monthly: 10000.0
  data_classification:
    input_scan: true
    redact_pii: false
  model_routing:
    tier_0: { primary: "gpt-4o", fallback_chain: ["llama3.2"] }
    tier_1: { primary: "gpt-4o", fallback_chain: ["llama3.2"] }
    tier_2: { primary: "gpt-4o", fallback_chain: ["llama3.2"] }
compliance:
  human_oversight: "none"
`), 0o600))

	routingCfg := &policy.ModelRoutingConfig{
		Tier0: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"llama3.2"}},
		Tier1: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"llama3.2"}},
		Tier2: &policy.TierConfig{Primary: "gpt-4o", FallbackChain: []string{"llama3.2"}},
	}
	openaiUS := &jurisdictionCountingProvider{name: "openai", jurisdiction: "US"}
	ollamaLocal := &jurisdictionCountingProvider{name: "ollama", jurisdiction: "LOCAL"}

	evStore, err := evidence.NewStore(filepath.Join(dir, "evidence.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "secrets.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { secStore.Close() })

	runner := agent.NewRunner(agent.RunnerConfig{
		PolicyDir:  dir,
		Classifier: classifier.MustNewScanner(),
		AttScanner: attachment.MustNewScanner(),
		Extractor:  attachment.NewExtractor(10),
		Router:     llm.NewRouter(routingCfg, map[string]llm.Provider{"openai": openaiUS, "ollama": ollamaLocal}, nil),
		Secrets:    secStore,
		Evidence:   evStore,
	})

	// Real server, eu_preferred mode — the #261 fix threads this into the
	// RunRequest built by the /v1/chat/completions handler.
	tenantKeys := map[string]string{"tenant-key-gov": "gov"}
	srv := server.NewServer(runner, evStore, nil, nil, nil, policyPath, secStore, "",
		tenantKeys, server.WithSovereigntyMode("eu_preferred"))
	api := httptest.NewServer(srv.Routes())
	t.Cleanup(api.Close)

	const sessionID = "sess-governed-abc123"
	body, _ := json.Marshal(map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": "Summarize the AI Act evidence duty for IBAN DE89370400440532013000."},
		},
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		api.URL+"/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tenant-key-gov")
	req.Header.Set("X-Talon-Session-ID", sessionID)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// US provider rejected pre-emptively (0 dispatches); LOCAL served it.
	assert.Equal(t, 0, openaiUS.calls, "confidential tier: the US provider must never be called")
	assert.Equal(t, 1, ollamaLocal.calls, "the LOCAL provider must serve the request")

	// Signed evidence records BOTH candidates and preserves the asserted session.
	// (The tenant key maps to tenant_id "gov"; the default agent name is "default".)
	records, err := evStore.ListBySessionID(context.Background(), sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	ev := records[0]
	require.NotNil(t, ev.RoutingDecision, "a RoutingDecision must be recorded — the #261 fix must have threaded SovereigntyMode through the handler")
	assert.Equal(t, "ollama", ev.RoutingDecision.SelectedProvider)
	require.NotEmpty(t, ev.RoutingDecision.RejectedCandidates, "the rejected US candidate must be recorded")
	var openaiRejected *evidence.RejectedCandidate
	for i := range ev.RoutingDecision.RejectedCandidates {
		if ev.RoutingDecision.RejectedCandidates[i].ProviderID == "openai" {
			openaiRejected = &ev.RoutingDecision.RejectedCandidates[i]
		}
	}
	require.NotNil(t, openaiRejected, "openai/US must appear as a rejected candidate")
	assert.Contains(t, openaiRejected.Reason, "confidential", "rejection must cite the confidential-tier routing policy")
	assert.Equal(t, sessionID, ev.SessionID, "the client-asserted session id must be preserved in evidence")
	assert.True(t, evStore.VerifyRecord(ev), "the routed record's HMAC signature must verify")
}
