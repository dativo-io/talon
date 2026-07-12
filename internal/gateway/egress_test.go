package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

const (
	egressTestAgentKey = "talon-gw-egress-001"
	// German IBAN classifies as tier 2 (see internal/classifier/pii_test.go).
	egressTier2Body = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Customer IBAN is DE89370400440532013000"}]}`
	egressCleanBody = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize our public roadmap"}]}`
)

// euOnlyEgressPolicy allows tier 0 anywhere, tier 1 to approved providers,
// and tier 2 only to EU/LOCAL regions.
func euOnlyEgressPolicy() *EgressPolicyConfig {
	t0, t1, t2 := TierPublic, TierInternal, TierConfidential
	return &EgressPolicyConfig{
		DefaultAction: EgressActionAllow,
		Rules: []EgressRule{
			{Tier: &t0, AllowedProviders: []string{"*"}},
			{Tier: &t1, AllowedProviders: []string{"openai", "anthropic"}},
			{Tier: &t2, AllowedRegions: []string{"EU", "LOCAL"}},
		},
	}
}

// setupEgressGateway wires a gateway with a real policy engine, a mock
// upstream that counts invocations, and the given egress policy / provider
// region. override customizes the agent's policy override (nil = the standard
// warn/caps override). Returns the gateway, the upstream call counter, and the
// evidence store.
func setupEgressGateway(t *testing.T, mode Mode, egress *EgressPolicyConfig, providerRegion string, override *PolicyOverride) (*Gateway, *atomic.Int64, *evidence.Store) {
	t.Helper()

	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"Done"}}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         mode,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstream.URL, SecretName: "openai-api-key", Region: providerRegion},
		},
		OrganizationPolicy: OrganizationPolicy{
			DefaultPIIAction: "warn",
			MaxDailyCost:     100,
			MaxMonthlyCost:   2000,
			Egress:           egress,
		},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	if override == nil {
		override = &PolicyOverride{
			PIIAction:      "warn",
			MaxDailyCost:   100,
			MaxMonthlyCost: 2000,
		}
	}
	registry := testRegistry(testIdentity("egress-bot", "test-tenant", egressTestAgentKey, override))

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	require.NoError(t, secStore.Set(context.Background(), "openai-api-key",
		[]byte("sk-test-egress-key-1234567890"),
		secrets.ACL{Tenants: []string{"test-tenant"}, Agents: []string{"*"}}))

	policyEngine, err := policy.NewGatewayEngine(context.Background())
	require.NoError(t, err)

	gw, err := NewGateway(cfg, registry, classifier.MustNewScanner(), evStore, secStore, policyEngine, nil)
	require.NoError(t, err)
	return gw, &upstreamCalls, evStore
}

func makeEgressRequest(gw *Gateway, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Route("/v1/proxy", func(r chi.Router) {
		r.Handle("/*", gw)
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://test/v1/proxy/openai/v1/chat/completions", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+egressTestAgentKey)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func latestEgressEvidence(t *testing.T, evStore *evidence.Store) *evidence.Evidence {
	t.Helper()
	records, err := evStore.List(context.Background(), "test-tenant", "egress-bot", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	require.NotEmpty(t, records, "an evidence record must exist")
	return &records[0]
}

func TestGateway_Egress_Tier2DeniedAndEvidenced(t *testing.T) {
	gw, upstreamCalls, evStore := setupEgressGateway(t, ModeEnforce, euOnlyEgressPolicy(), "US", nil)

	w := makeEgressRequest(gw, egressTier2Body)

	// HTTP denial with the egress machine code in the provider-native error.
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), EgressReasonTierDestination)

	// No request bytes left Talon.
	assert.Equal(t, int64(0), upstreamCalls.Load(), "upstream must not be called for a denied request")

	// Signed evidence carries the egress denial facts.
	ev := latestEgressEvidence(t, evStore)
	assert.False(t, ev.PolicyDecision.Allowed)
	assert.Equal(t, "deny", ev.PolicyDecision.Action)
	require.NotEmpty(t, ev.PolicyDecision.Reasons)
	assert.Contains(t, ev.PolicyDecision.Reasons[0], EgressReasonTierDestination)
	assert.Equal(t, 2, ev.Classification.InputTier)

	require.NotNil(t, ev.EgressDecision, "egress_decision section must be present")
	assert.Equal(t, 2, ev.EgressDecision.Tier)
	assert.Equal(t, "openai", ev.EgressDecision.Provider)
	assert.Equal(t, "US", ev.EgressDecision.Region)
	assert.Equal(t, EgressActionDeny, ev.EgressDecision.Decision)
	assert.Equal(t, "tier_2", ev.EgressDecision.MatchedRule)
	assert.Equal(t, EgressReasonTierDestination, ev.EgressDecision.Reason)

	assert.True(t, evStore.VerifyRecord(ev), "denied egress evidence must be signature-verifiable")

	// Explanation maps to POLICY_DENIED_EGRESS.
	var hasEgressExplanation bool
	for _, item := range ev.Explanations {
		if item.Code == explanation.CodePolicyDeniedEgress {
			hasEgressExplanation = true
		}
	}
	assert.True(t, hasEgressExplanation, "explanations must include POLICY_DENIED_EGRESS, got %+v", ev.Explanations)
}

func TestGateway_Egress_Tier2AllowedToEURegion(t *testing.T) {
	gw, upstreamCalls, evStore := setupEgressGateway(t, ModeEnforce, euOnlyEgressPolicy(), "EU", nil)

	w := makeEgressRequest(gw, egressTier2Body)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, int64(1), upstreamCalls.Load(), "upstream must be called for an allowed request")

	ev := latestEgressEvidence(t, evStore)
	assert.True(t, ev.PolicyDecision.Allowed)
	require.NotNil(t, ev.EgressDecision)
	assert.Equal(t, EgressActionAllow, ev.EgressDecision.Decision)
	assert.Equal(t, "tier_2:allowed_regions", ev.EgressDecision.MatchedRule)
	assert.Empty(t, ev.EgressDecision.Reason)
	assert.True(t, evStore.VerifyRecord(ev))
}

func TestGateway_Egress_Tier0AllowedToGlobalProvider(t *testing.T) {
	gw, upstreamCalls, evStore := setupEgressGateway(t, ModeEnforce, euOnlyEgressPolicy(), "US", nil)

	w := makeEgressRequest(gw, egressCleanBody)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, int64(1), upstreamCalls.Load())

	ev := latestEgressEvidence(t, evStore)
	require.NotNil(t, ev.EgressDecision)
	assert.Equal(t, 0, ev.EgressDecision.Tier)
	assert.Equal(t, EgressActionAllow, ev.EgressDecision.Decision)
	assert.Equal(t, "tier_0:allowed_providers", ev.EgressDecision.MatchedRule)
}

func TestGateway_Egress_UnconfiguredKeepsCurrentBehavior(t *testing.T) {
	gw, upstreamCalls, evStore := setupEgressGateway(t, ModeEnforce, nil, "US", nil)

	w := makeEgressRequest(gw, egressTier2Body)

	require.Equal(t, http.StatusOK, w.Code, "tier_2 to US must pass when egress is unconfigured; body: %s", w.Body.String())
	assert.Equal(t, int64(1), upstreamCalls.Load())

	ev := latestEgressEvidence(t, evStore)
	assert.Nil(t, ev.EgressDecision, "no egress_decision section when egress is unconfigured")
}

func TestGateway_Egress_ShadowModeForwardsAndRecordsViolation(t *testing.T) {
	gw, upstreamCalls, evStore := setupEgressGateway(t, ModeShadow, euOnlyEgressPolicy(), "US", nil)

	w := makeEgressRequest(gw, egressTier2Body)

	require.Equal(t, http.StatusOK, w.Code, "shadow mode must forward; body: %s", w.Body.String())
	assert.Equal(t, int64(1), upstreamCalls.Load(), "shadow mode must reach upstream")

	ev := latestEgressEvidence(t, evStore)
	assert.True(t, ev.ObservationModeOverride, "shadow violations must flag observation mode override")
	var hasEgressViolation bool
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "policy_deny" && firstEgressReason([]string{sv.Detail}) != "" {
			hasEgressViolation = true
		}
	}
	assert.True(t, hasEgressViolation, "shadow violations must carry the egress reason, got %+v", ev.ShadowViolations)

	// The egress_decision section records what the control decided even
	// though shadow mode did not enforce it.
	require.NotNil(t, ev.EgressDecision)
	assert.Equal(t, EgressActionDeny, ev.EgressDecision.Decision)
	assert.True(t, evStore.VerifyRecord(ev))
}

func TestGateway_Egress_AgentOverrideDefaultDeny(t *testing.T) {
	t2 := TierConfidential
	// Org sets no egress, so only the agent layer binds (#266 review round 5:
	// egress is a logical intersection of the org and agent boundaries):
	// tier_2 only to ollama, everything else denied by default.
	gw, upstreamCalls, evStore := setupEgressGateway(t, ModeEnforce, nil, "US", &PolicyOverride{
		PIIAction:      "warn",
		MaxDailyCost:   100,
		MaxMonthlyCost: 2000,
		Egress: &EgressPolicyConfig{
			DefaultAction: EgressActionDeny,
			Rules:         []EgressRule{{Tier: &t2, AllowedProviders: []string{"ollama"}}},
		},
	})

	// Tier 0 payload: no rule for tier 0 in the override, default_action deny.
	w := makeEgressRequest(gw, egressCleanBody)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), EgressReasonDestination)
	assert.Equal(t, int64(0), upstreamCalls.Load())

	ev := latestEgressEvidence(t, evStore)
	require.NotNil(t, ev.EgressDecision)
	assert.Equal(t, EgressActionDeny, ev.EgressDecision.Decision)
	assert.Equal(t, "default_action", ev.EgressDecision.MatchedRule)
	assert.Equal(t, EgressReasonDestination, ev.EgressDecision.Reason)
}

// Egress is a logical INTERSECTION (#266 review round 5): even when the ORG
// egress allows the destination, an agent egress that does not permit it must
// deny — end-to-end through the rego, with the agent layer named decisive in
// the signed egress decision.
func TestGateway_Egress_IntersectionAgentDeniesWithinOrgAllow(t *testing.T) {
	t1 := TierInternal
	// Org (euOnlyEgressPolicy): tier 1 → openai/anthropic allowed. Provider
	// region EU. Agent narrows tier 1 to anthropic only, so openai must be
	// denied by the AGENT layer despite the org allowing it.
	gw, upstreamCalls, evStore := setupEgressGateway(t, ModeEnforce, euOnlyEgressPolicy(), "EU", &PolicyOverride{
		PIIAction:      "warn",
		MaxDailyCost:   100,
		MaxMonthlyCost: 2000,
		Egress: &EgressPolicyConfig{
			Rules: []EgressRule{{Tier: &t1, AllowedProviders: []string{"anthropic"}}},
		},
	})

	// Tier-1 payload (low-sensitivity PII: an email address) routed to openai:
	// the org layer passes (tier 1 → openai allowed), the agent layer denies.
	w := makeEgressRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Follow up with jane.doe@example.com about the roadmap"}]}`)
	require.Equal(t, http.StatusForbidden, w.Code, "agent egress must deny within an org allow (intersection)")
	assert.Contains(t, w.Body.String(), EgressReasonTierDestination)
	assert.Equal(t, int64(0), upstreamCalls.Load(), "denied request must never reach the provider")

	ev := latestEgressEvidence(t, evStore)
	require.False(t, ev.PolicyDecision.Allowed)
	require.NotNil(t, ev.EgressDecision)
	assert.Equal(t, EgressActionDeny, ev.EgressDecision.Decision)
}

func TestGateway_Egress_CombinedDenyReasonsPreferEgressCode(t *testing.T) {
	// gateway_access runs before gateway_egress; both deny for tier-2 IBAN → US + model not in allowlist.
	gw, upstreamCalls, evStore := setupEgressGateway(t, ModeEnforce, euOnlyEgressPolicy(), "US", &PolicyOverride{
		PIIAction:      "warn",
		MaxDailyCost:   100,
		MaxMonthlyCost: 2000,
		AllowedModels:  []string{"gpt-4o"},
	})

	w := makeEgressRequest(gw, egressTier2Body)

	require.Equal(t, http.StatusForbidden, w.Code)
	var body openAIErrorBody
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, EgressReasonTierDestination, body.Error.Code,
		"HTTP error body must prefer the egress machine code when egress is among deny reasons")
	assert.NotContains(t, strings.ToLower(body.Error.Message), "allowlist")

	assert.Equal(t, int64(0), upstreamCalls.Load(), "upstream must not be called")

	ev := latestEgressEvidence(t, evStore)
	require.False(t, ev.PolicyDecision.Allowed)
	require.GreaterOrEqual(t, len(ev.PolicyDecision.Reasons), 2)
	joined := strings.Join(ev.PolicyDecision.Reasons, " ")
	assert.Contains(t, joined, "allowlist")
	assert.Contains(t, joined, EgressReasonTierDestination)
	require.NotNil(t, ev.EgressDecision)
	assert.Equal(t, EgressReasonTierDestination, ev.EgressDecision.Reason)
}
