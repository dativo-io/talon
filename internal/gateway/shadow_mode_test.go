package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

func setupShadowGateway(t *testing.T, opts ...func(*GatewayConfig, *PolicyOverride)) (*Gateway, *evidence.Store) {
	t.Helper()

	upstream := testutil.NewOpenAICompatibleServer("shadow test response", 10, 20)
	t.Cleanup(upstream.Close)
	dir := t.TempDir()

	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
		Mode:         ModeShadow,
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: upstream.URL, SecretName: "openai-api-key"},
		},
		OrganizationPolicy: OrganizationPolicy{
			Defaults: OrgDefaults{
				PIIAction:        "block",
				DailyCost:        100,
				MonthlyCost:      2000,
				ToolPolicyAction: "block",
			},
			Constraints: OrgConstraints{
				ForbiddenTools: []string{"delete_*"},
			},
		},
		RateLimits: RateLimitsConfig{
			GlobalRequestsPerMin:   1,
			PerAgentRequestsPerMin: 1,
		},
		Timeouts: TimeoutsConfig{
			ConnectTimeout:    "5s",
			RequestTimeout:    "30s",
			StreamIdleTimeout: "60s",
		},
	}
	override := &PolicyOverride{
		PIIAction:      "block",
		MaxDailyCost:   100,
		MaxMonthlyCost: 2000,
		AllowedModels:  []string{"gpt-4o-mini", "gpt-4o"},
	}
	for _, opt := range opts {
		opt(cfg, override)
	}
	registry := testRegistry(testIdentity("openclaw-main", "test-tenant", "talon-gw-openclaw-001", override))

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })

	require.NoError(t, secStore.Set(context.Background(), "openai-api-key",
		[]byte("sk-test-shadow-key"),
		secrets.ACL{Tenants: []string{"test-tenant"}, Agents: []string{"*"}}))

	cls := classifier.MustNewScanner()
	gw, err := NewGateway(cfg, NewRegistryHolder(registry), cls, evStore, secStore, nil, nil)
	require.NoError(t, err)

	return gw, evStore
}

func latestEvidence(t *testing.T, store *evidence.Store) *evidence.Evidence {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := store.List(ctx, "", "", time.Time{}, time.Time{}, 1)
	require.NoError(t, err)
	require.NotEmpty(t, list, "expected at least one evidence record")
	return &list[0]
}

func requestWithPII() string {
	return `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Email me at hans.mueller@example.de about IBAN DE89370400440532013000"}]}`
}

func requestWithForbiddenTool() string {
	return `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"function","function":{"name":"delete_all","description":"delete everything","parameters":{"type":"object","properties":{}}}}]}`
}

func requestClean() string {
	return `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What is 2+2?"}]}`
}

func TestGateway_ShadowMode_PIIBlockBypassedAndLogged(t *testing.T) {
	gw, evStore := setupShadowGateway(t)

	rr := makeGatewayRequest(gw, requestWithPII())

	assert.Equal(t, http.StatusOK, rr.Code, "shadow mode should forward PII requests")

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.ObservationModeOverride, "should flag observation mode override")

	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "pii_block" {
			found = true
			assert.Equal(t, "block", sv.Action)
			assert.Contains(t, sv.Detail, "PII detected")
		}
	}
	assert.True(t, found, "should record pii_block shadow violation")
}

func TestGateway_ShadowMode_RateLimitBypassedAndLogged(t *testing.T) {
	gw, evStore := setupShadowGateway(t)

	// First request consumes the rate limit token
	rr1 := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusOK, rr1.Code)

	// Second request should exceed rate limit but still succeed in shadow mode
	rr2 := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusOK, rr2.Code, "shadow mode should not block rate-limited requests")

	ev := latestEvidence(t, evStore)
	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "rate_limit" {
			found = true
			assert.Equal(t, "block", sv.Action)
		}
	}
	assert.True(t, found, "should record rate_limit shadow violation")
}

func TestGateway_ShadowMode_ToolBlockBypassedAndLogged(t *testing.T) {
	gw, evStore := setupShadowGateway(t)

	rr := makeGatewayRequest(gw, requestWithForbiddenTool())
	assert.Equal(t, http.StatusOK, rr.Code, "shadow mode should not block forbidden tools")

	ev := latestEvidence(t, evStore)
	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "tool_block" {
			found = true
			assert.Contains(t, sv.Detail, "delete_all")
		}
	}
	assert.True(t, found, "should record tool_block shadow violation")
}

func TestGateway_ShadowMode_PolicyDenyBypassedAndLogged(t *testing.T) {
	gw, evStore := setupShadowGateway(t, func(cfg *GatewayConfig, override *PolicyOverride) {
		cfg.OrganizationPolicy.Constraints.ForbiddenTools = nil
		cfg.OrganizationPolicy.Defaults.PIIAction = "warn"
		override.PIIAction = "warn"
		cfg.RateLimits.GlobalRequestsPerMin = 300
		cfg.RateLimits.PerAgentRequestsPerMin = 60
	})

	// Attach a policy evaluator that always denies
	gw.policy = &denyAllPolicy{}

	rr := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusOK, rr.Code, "shadow mode should not block policy denials")

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.ObservationModeOverride)
	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "policy_deny" {
			found = true
			assert.Equal(t, "block", sv.Action)
		}
	}
	assert.True(t, found, "should record policy_deny shadow violation")
}

func TestGateway_ShadowMode_PolicyErrorBypassedAndLogged(t *testing.T) {
	gw, evStore := setupShadowGateway(t, func(cfg *GatewayConfig, override *PolicyOverride) {
		cfg.OrganizationPolicy.Constraints.ForbiddenTools = nil
		cfg.OrganizationPolicy.Defaults.PIIAction = "warn"
		override.PIIAction = "warn"
		cfg.RateLimits.GlobalRequestsPerMin = 300
		cfg.RateLimits.PerAgentRequestsPerMin = 60
	})

	gw.policy = &errorPolicy{}

	rr := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusOK, rr.Code, "shadow mode should not block on policy evaluation errors")

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.ObservationModeOverride)
	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "policy_deny" {
			found = true
			assert.Contains(t, sv.Detail, "policy evaluation error")
			assert.Equal(t, "block", sv.Action)
		}
	}
	assert.True(t, found, "should record policy error as shadow violation")
}

func TestGateway_EnforceMode_PolicyErrorStillReturns500(t *testing.T) {
	gw, _ := setupShadowGateway(t, func(cfg *GatewayConfig, override *PolicyOverride) {
		cfg.Mode = ModeEnforce
		cfg.OrganizationPolicy.Constraints.ForbiddenTools = nil
		cfg.OrganizationPolicy.Defaults.PIIAction = "warn"
		override.PIIAction = "warn"
		cfg.RateLimits.GlobalRequestsPerMin = 300
		cfg.RateLimits.PerAgentRequestsPerMin = 60
	})

	gw.policy = &errorPolicy{}

	rr := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusInternalServerError, rr.Code, "enforce mode should return 500 on policy errors")
	assert.Contains(t, rr.Body.String(), "Policy evaluation failed")
}

func TestGateway_ShadowMode_EvidenceRecordsShadowViolations(t *testing.T) {
	gw, evStore := setupShadowGateway(t)

	rr := makeGatewayRequest(gw, requestWithPII())
	assert.Equal(t, http.StatusOK, rr.Code)

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.ObservationModeOverride)
	assert.NotEmpty(t, ev.ShadowViolations, "shadow violations should be populated")

	// Verify it round-trips through JSON
	data, err := json.Marshal(ev.ShadowViolations)
	require.NoError(t, err)
	var decoded []evidence.ShadowViolation
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, len(ev.ShadowViolations), len(decoded))
}

func TestGateway_EnforceMode_StillBlocks(t *testing.T) {
	gw, _ := setupShadowGateway(t, func(cfg *GatewayConfig, _ *PolicyOverride) {
		cfg.Mode = ModeEnforce
	})

	rr := makeGatewayRequest(gw, requestWithPII())
	assert.Equal(t, http.StatusBadRequest, rr.Code, "enforce mode should block PII requests")
	assert.Contains(t, rr.Body.String(), "PII")
}

func TestGateway_EnforceMode_ToolBlockStillBlocks(t *testing.T) {
	gw, _ := setupShadowGateway(t, func(cfg *GatewayConfig, _ *PolicyOverride) {
		cfg.Mode = ModeEnforce
	})

	rr := makeGatewayRequest(gw, requestWithForbiddenTool())
	assert.Equal(t, http.StatusForbidden, rr.Code, "enforce mode should block forbidden tools")
	assert.Contains(t, rr.Body.String(), "forbidden")
}

func TestGateway_ShadowMode_NoViolationsNoFlag(t *testing.T) {
	gw, evStore := setupShadowGateway(t, func(cfg *GatewayConfig, override *PolicyOverride) {
		cfg.OrganizationPolicy.Defaults.PIIAction = "warn"
		cfg.OrganizationPolicy.Constraints.ForbiddenTools = nil
		override.PIIAction = "warn"
		cfg.RateLimits.GlobalRequestsPerMin = 300
		cfg.RateLimits.PerAgentRequestsPerMin = 60
	})

	rr := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusOK, rr.Code)

	ev := latestEvidence(t, evStore)
	assert.False(t, ev.ObservationModeOverride, "no violations = no observation mode flag")
	assert.Empty(t, ev.ShadowViolations)
}

// denyAllPolicy is a test policy evaluator that always denies.
type denyAllPolicy struct{}

func (d *denyAllPolicy) EvaluateGateway(_ context.Context, _ map[string]interface{}) (allowed bool, reasons []string, err error) {
	return false, []string{"test: always denied"}, nil
}

// errorPolicy is a test policy evaluator that always returns an error.
type errorPolicy struct{}

func (e *errorPolicy) EvaluateGateway(_ context.Context, _ map[string]interface{}) (allowed bool, reasons []string, err error) {
	return false, nil, fmt.Errorf("OPA evaluation failed: test error")
}

// Verify shadow violations round-trip through the evidence store (store + retrieve).
func TestShadowViolation_EvidenceStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.NewStore(filepath.Join(dir, "test.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()
	ev := &evidence.Evidence{
		ID:                      "sv_test_001",
		CorrelationID:           "corr_001",
		Timestamp:               time.Now(),
		TenantID:                "t1",
		AgentID:                 "a1",
		InvocationType:          "gateway",
		PolicyDecision:          evidence.PolicyDecision{Allowed: true, Action: "allow"},
		Execution:               evidence.Execution{ModelUsed: "gpt-4o"},
		ObservationModeOverride: true,
		ShadowViolations: []evidence.ShadowViolation{
			{Type: "pii_block", Detail: "PII detected: EMAIL", Action: "block"},
			{Type: "rate_limit", Detail: "Rate limit exceeded", Action: "block"},
		},
	}
	require.NoError(t, store.Store(ctx, ev))

	got, err := store.Get(ctx, "sv_test_001")
	require.NoError(t, err)
	assert.True(t, got.ObservationModeOverride)
	require.Len(t, got.ShadowViolations, 2)
	assert.Equal(t, "pii_block", got.ShadowViolations[0].Type)
	assert.Equal(t, "rate_limit", got.ShadowViolations[1].Type)
}

// Verify that the shadow violation types cover the documented set.
func TestShadowViolation_TypeCoverage(t *testing.T) {
	expectedTypes := []string{"pii_block", "rate_limit", "attachment_block", "tool_block", "policy_deny"}
	for _, typ := range expectedTypes {
		sv := evidence.ShadowViolation{Type: typ, Detail: "test", Action: "block"}
		data, err := json.Marshal(sv)
		require.NoError(t, err, "type %s should marshal", typ)
		assert.True(t, strings.Contains(string(data), fmt.Sprintf(`"type":"%s"`, typ)))
	}
}

// TestEnforcementModeMatrix_ObservableVsHard (#266 review round 4): an
// OBSERVABLE governance control (PII block) blocks only in enforce; shadow
// and log_only forward the request (record-only). This pins the two-class
// model so shadow/log_only can never silently block-or-not inconsistently.
// log_only must treat rate limiting as an OBSERVABLE governance control: the
// would-be 429 is recorded but the request forwards. Enforce still returns 429
// (#266 review round 5 — the log_only matrix gap).
func TestLogOnlyMode_RateLimitObservedNotBlocked(t *testing.T) {
	gw, evStore := setupShadowGateway(t, func(c *GatewayConfig, _ *PolicyOverride) {
		c.Mode = ModeLogOnly
	})

	rr1 := makeGatewayRequest(gw, requestClean())
	require.Equal(t, http.StatusOK, rr1.Code)
	// Second request exceeds the burst-1 limit; log_only forwards it.
	rr2 := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusOK, rr2.Code, "log_only must not block rate-limited requests")

	ev := latestEvidence(t, evStore)
	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "rate_limit" {
			found = true
			assert.Equal(t, "block", sv.Action)
		}
	}
	assert.True(t, found, "log_only must record the rate_limit observation")
}

// The same control under enforce still returns 429 — proving the two-class
// split, not a blanket bypass.
func TestEnforceMode_RateLimitStillBlocks(t *testing.T) {
	gw, _ := setupShadowGateway(t, func(c *GatewayConfig, _ *PolicyOverride) {
		c.Mode = ModeEnforce
	})
	rr1 := makeGatewayRequest(gw, requestClean())
	require.Equal(t, http.StatusOK, rr1.Code)
	rr2 := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code, "enforce must return 429 when rate limited")
}

// log_only must treat a PII-scanner failure as observable too: it records the
// would-be block and forwards UNCLASSIFIED rather than returning 502. Enforce
// fails closed (covered by TestExternalScannerFailClosed_EnforceBlocksRequest).
func TestLogOnlyMode_ScannerUnavailableObservedNotBlocked(t *testing.T) {
	upstreamHit := false
	gw, _, evStore := setupGatewayWithClassifier(t, "block", ModeLogOnly,
		func(w http.ResponseWriter, _ *http.Request) {
			upstreamHit = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`))
		},
		failingExternalScanner(t, testutil.ScannerFailStatus))

	w := makeGatewayRequest(gw, `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`)
	assert.Equal(t, http.StatusOK, w.Code, "log_only must not fail closed on scanner unavailability")
	assert.True(t, upstreamHit, "log_only forwards the unclassified request to the provider")

	ev := latestGatewayEvidence(t, evStore)
	found := false
	for _, sv := range ev.ShadowViolations {
		if sv.Type == "scanner_unavailable" {
			found = true
		}
	}
	assert.True(t, found, "log_only must record the scanner_unavailable observation")
}

// Authentication is a HARD platform boundary: an unknown key is rejected in
// EVERY mode, including log_only — the two-class model never opens auth.
func TestLogOnlyMode_UnknownKeyStillRejected(t *testing.T) {
	gw, _ := setupShadowGateway(t, func(c *GatewayConfig, _ *PolicyOverride) {
		c.Mode = ModeLogOnly
	})
	rr := postGateway(gw, "/v1/proxy/openai/v1/chat/completions", "talon-gw-not-a-real-key", requestClean())
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "unknown key must be rejected even in log_only")
}

func TestEnforcementModeMatrix_ObservableVsHard(t *testing.T) {
	cases := []struct {
		mode       Mode
		wantStatus int
	}{
		{ModeEnforce, http.StatusBadRequest},
		{ModeShadow, http.StatusOK},
		{ModeLogOnly, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			gw, store := setupShadowGateway(t, func(c *GatewayConfig, _ *PolicyOverride) {
				c.Mode = tc.mode
			})
			rr := makeGatewayRequest(gw, requestWithPII())
			assert.Equal(t, tc.wantStatus, rr.Code,
				"PII block is observable: enforce blocks, shadow/log_only forward")
			ev := latestEvidence(t, store)
			require.NotNil(t, ev)
			if tc.mode == ModeEnforce {
				assert.False(t, ev.PolicyDecision.Allowed)
			}
		})
	}
}
