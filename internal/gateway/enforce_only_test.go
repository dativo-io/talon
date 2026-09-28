package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
)

// Enforce-only gateway tests (#442). The live shadow/log_only postures were
// removed: every governance control now denies, and a denial must be proven
// by the provider call counter, not by the response status alone (AGENTS.md
// "Preventive-control proof").

const (
	enforceTestAgentKey    = "talon-gw-openclaw-001"
	enforceTestChatPath    = "/v1/proxy/openai/v1/chat/completions"
	enforceUnknownAgentKey = "talon-gw-not-a-real-key"
)

// enforceGatewayOpts customizes setupEnforceGateway. The zero value is the
// standard fixture: burst-1 rate limits, PII block, delete_* forbidden,
// built-in regex scanner, the real OPA gateway engine, and an enabled agent.
type enforceGatewayOpts struct {
	configure     func(cfg *GatewayConfig, override *PolicyOverride)
	scanner       classifier.Facade      // nil = built-in regex scanner
	policy        GatewayPolicyEvaluator // nil = policy.NewGatewayEngine
	agentDisabled bool
}

// relaxGovernance turns off the controls that would otherwise fire before
// policy evaluation, so a test can isolate the control it targets.
func relaxGovernance(cfg *GatewayConfig, override *PolicyOverride) {
	cfg.OrganizationPolicy.Constraints.ForbiddenTools = nil
	cfg.OrganizationPolicy.Defaults.PIIAction = "warn"
	override.PIIAction = "warn"
	cfg.RateLimits.GlobalRequestsPerMin = 300
	cfg.RateLimits.PerAgentRequestsPerMin = 60
}

// setupEnforceGateway wires an enforce gateway to a counting mock upstream and
// returns the gateway, the upstream call counter, and the evidence store.
func setupEnforceGateway(t *testing.T, opts enforceGatewayOpts) (*Gateway, *atomic.Int64, *evidence.Store) {
	t.Helper()

	upstream, calls := testutil.NewCountingOpenAICompatibleServer("enforce test response", 10, 20)
	t.Cleanup(upstream.Close)
	dir := t.TempDir()

	cfg := &GatewayConfig{
		Enabled:      true,
		ListenPrefix: "/v1/proxy",
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
	if opts.configure != nil {
		opts.configure(cfg, override)
	}
	identity := testIdentity("openclaw-main", "test-tenant", enforceTestAgentKey, override)
	if opts.agentDisabled {
		identity.Enabled = false
	}
	registry := testRegistry(identity)

	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })

	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })

	require.NoError(t, secStore.Set(context.Background(), "openai-api-key",
		[]byte("sk-test-enforce-key"),
		secrets.ACL{Tenants: []string{"test-tenant"}, Agents: []string{"*"}}))

	cls := opts.scanner
	if cls == nil {
		cls = classifier.MustNewScanner()
	}
	pol := opts.policy
	if pol == nil {
		engine, err := policy.NewGatewayEngine(context.Background())
		require.NoError(t, err)
		pol = engine
	}

	gw, err := NewGateway(cfg, NewRegistryHolder(registry), cls, evStore, secStore, pol, nil)
	require.NoError(t, err)

	return gw, calls, evStore
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

// providerErrorType decodes error.type from the provider-native envelope
// (both the OpenAI and Anthropic shapes carry the machine code there).
func providerErrorType(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), "body: %s", rr.Body.String())
	return body.Error.Type
}

// assertNoPostureFields pins that a record written by the enforce-only
// gateway never carries the removed posture fields (#442). The fields remain
// on the evidence type only so historical records still decode.
func assertNoPostureFields(t *testing.T, ev *evidence.Evidence) {
	t.Helper()
	assert.False(t, ev.ObservationModeOverride, "enforce-only gateway never writes observation_mode_override")
	assert.Empty(t, ev.ShadowViolations, "enforce-only gateway never writes shadow_violations")
}

// assertEnforcedDenial is the evidence half of a preventive-control proof:
// the record says denied and carries no posture override.
func assertEnforcedDenial(t *testing.T, ev *evidence.Evidence) {
	t.Helper()
	assert.False(t, ev.PolicyDecision.Allowed, "denied request must be recorded as denied")
	assertNoPostureFields(t, ev)
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

func TestGateway_EnforceOnly_PIIBlock_ZeroDispatch(t *testing.T) {
	gw, calls, evStore := setupEnforceGateway(t, enforceGatewayOpts{})

	rr := makeGatewayRequest(gw, requestWithPII())

	assert.Equal(t, http.StatusBadRequest, rr.Code, "PII block must deny; body: %s", rr.Body.String())
	assert.Equal(t, "pii_policy_violation", providerErrorType(t, rr))
	assert.Equal(t, int64(0), calls.Load(), "PII-blocked request must never reach the provider")

	ev := latestEvidence(t, evStore)
	assertEnforcedDenial(t, ev)
	assert.Contains(t, ev.PolicyDecision.Reasons, "PII block")
}

func TestGateway_EnforceOnly_RateLimit_ZeroDispatch(t *testing.T) {
	gw, calls, evStore := setupEnforceGateway(t, enforceGatewayOpts{})

	// First request consumes the burst-1 token and is dispatched exactly once.
	rr1 := makeGatewayRequest(gw, requestClean())
	require.Equal(t, http.StatusOK, rr1.Code, rr1.Body.String())
	require.Equal(t, int64(1), calls.Load())

	// Second request exceeds the limit and must not add a provider call.
	rr2 := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code, rr2.Body.String())
	assert.Equal(t, "rate_limited", providerErrorType(t, rr2))
	assert.Equal(t, int64(1), calls.Load(), "rate-limited request must not reach the provider")

	ev := latestEvidence(t, evStore)
	assertEnforcedDenial(t, ev)
	assert.Contains(t, ev.PolicyDecision.Reasons, "rate limit exceeded")
}

func TestGateway_EnforceOnly_ToolBlock_ZeroDispatch(t *testing.T) {
	gw, calls, evStore := setupEnforceGateway(t, enforceGatewayOpts{})

	rr := makeGatewayRequest(gw, requestWithForbiddenTool())

	assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	assert.Equal(t, "tool_policy_violation", providerErrorType(t, rr))
	assert.Equal(t, int64(0), calls.Load(), "forbidden-tool request must never reach the provider")

	ev := latestEvidence(t, evStore)
	assertEnforcedDenial(t, ev)
	assert.Contains(t, ev.PolicyDecision.Reasons, "tool governance block")
}

func TestGateway_EnforceOnly_PolicyDeny_ZeroDispatch(t *testing.T) {
	gw, calls, evStore := setupEnforceGateway(t, enforceGatewayOpts{
		configure: relaxGovernance,
		policy:    &denyAllPolicy{},
	})

	rr := makeGatewayRequest(gw, requestClean())

	assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	assert.Equal(t, int64(0), calls.Load(), "policy-denied request must never reach the provider")

	ev := latestEvidence(t, evStore)
	assertEnforcedDenial(t, ev)
	assert.Contains(t, ev.PolicyDecision.Reasons, "test: always denied")
}

// A policy evaluation error fails closed: 500, no dispatch, denied evidence.
func TestGateway_EnforceMode_PolicyErrorStillReturns500(t *testing.T) {
	gw, calls, evStore := setupEnforceGateway(t, enforceGatewayOpts{
		configure: relaxGovernance,
		policy:    &errorPolicy{},
	})

	rr := makeGatewayRequest(gw, requestClean())

	assert.Equal(t, http.StatusInternalServerError, rr.Code, "policy errors must fail closed")
	assert.Contains(t, rr.Body.String(), "Policy evaluation failed")
	assert.Equal(t, int64(0), calls.Load(), "a request Talon could not evaluate must never reach the provider")

	ev := latestEvidence(t, evStore)
	assertEnforcedDenial(t, ev)
	assert.Contains(t, ev.PolicyDecision.Reasons, "policy evaluation error")
}

// The signed deny record carries no posture fields at all: neither the
// struct nor its JSON form mentions the removed shadow machinery.
func TestGateway_EnforceOnly_DenyEvidenceHasNoPostureFields(t *testing.T) {
	gw, calls, evStore := setupEnforceGateway(t, enforceGatewayOpts{})

	rr := makeGatewayRequest(gw, requestWithPII())
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	require.Equal(t, int64(0), calls.Load())

	ev := latestEvidence(t, evStore)
	assertEnforcedDenial(t, ev)
	assert.True(t, evStore.VerifyRecord(ev), "deny record must be signature-verifiable")

	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"shadow_violations"`)
	assert.NotContains(t, string(raw), `"observation_mode_override"`)
}

func TestGateway_EnforceMode_StillBlocks(t *testing.T) {
	gw, calls, _ := setupEnforceGateway(t, enforceGatewayOpts{})

	rr := makeGatewayRequest(gw, requestWithPII())
	assert.Equal(t, http.StatusBadRequest, rr.Code, "enforce mode should block PII requests")
	assert.Contains(t, rr.Body.String(), "PII")
	assert.Equal(t, int64(0), calls.Load(), "blocked request must never reach the provider")
}

func TestGateway_EnforceMode_ToolBlockStillBlocks(t *testing.T) {
	gw, calls, _ := setupEnforceGateway(t, enforceGatewayOpts{})

	rr := makeGatewayRequest(gw, requestWithForbiddenTool())
	assert.Equal(t, http.StatusForbidden, rr.Code, "enforce mode should block forbidden tools")
	assert.Contains(t, rr.Body.String(), "forbidden")
	assert.Equal(t, int64(0), calls.Load(), "blocked request must never reach the provider")
}

func TestEnforceMode_RateLimitStillBlocks(t *testing.T) {
	gw, calls, _ := setupEnforceGateway(t, enforceGatewayOpts{})
	rr1 := makeGatewayRequest(gw, requestClean())
	require.Equal(t, http.StatusOK, rr1.Code)
	rr2 := makeGatewayRequest(gw, requestClean())
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code, "enforce must return 429 when rate limited")
	assert.Equal(t, int64(1), calls.Load(), "only the admitted request may reach the provider")
}

// The positive half of the proof: a clean request is dispatched exactly once
// and its allow record carries no posture fields either.
func TestGateway_EnforceOnly_CleanRequestDispatchesOnce(t *testing.T) {
	gw, calls, evStore := setupEnforceGateway(t, enforceGatewayOpts{configure: relaxGovernance})

	rr := makeGatewayRequest(gw, requestClean())

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, int64(1), calls.Load(), "an allowed request is dispatched exactly once")

	ev := latestEvidence(t, evStore)
	assert.True(t, ev.PolicyDecision.Allowed)
	assertNoPostureFields(t, ev)
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"shadow_violations"`)
	assert.NotContains(t, string(raw), `"observation_mode_override"`)
}

// Authentication is a hard platform boundary: an unknown key is rejected
// before any governance runs and nothing reaches the provider.
func TestGateway_UnknownKey_ZeroDispatch(t *testing.T) {
	gw, calls, _ := setupEnforceGateway(t, enforceGatewayOpts{})

	rr := postGateway(gw, enforceTestChatPath, enforceUnknownAgentKey, requestClean())

	assert.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
	assert.Equal(t, "invalid_agent_key", providerErrorType(t, rr))
	assert.Equal(t, int64(0), calls.Load(), "unauthenticated request must never reach the provider")
}

// TestEnforceOnly_ControlMatrix_ZeroDispatch pins the single-posture model
// (#442): every control that denies does so with zero provider dispatch and,
// where the request was attributed, a denied evidence record without posture
// fields. There is no mode under which any row forwards.
func TestEnforceOnly_ControlMatrix_ZeroDispatch(t *testing.T) {
	cases := []struct {
		name         string
		opts         func(t *testing.T) enforceGatewayOpts
		prime        func(t *testing.T, gw *Gateway)
		key          string // "" = the fixture's valid agent key
		body         string
		wantStatus   int
		wantCode     string // "" = the error contract defines no machine code
		wantEvidence bool   // false when the request is denied before attribution
	}{
		{
			name:         "pii_block",
			opts:         func(*testing.T) enforceGatewayOpts { return enforceGatewayOpts{} },
			body:         requestWithPII(),
			wantStatus:   http.StatusBadRequest,
			wantCode:     "pii_policy_violation",
			wantEvidence: true,
		},
		{
			name: "rate_limit",
			opts: func(*testing.T) enforceGatewayOpts { return enforceGatewayOpts{} },
			prime: func(t *testing.T, gw *Gateway) {
				require.Equal(t, http.StatusOK, makeGatewayRequest(gw, requestClean()).Code)
			},
			body:         requestClean(),
			wantStatus:   http.StatusTooManyRequests,
			wantCode:     "rate_limited",
			wantEvidence: true,
		},
		{
			name:         "tool_block",
			opts:         func(*testing.T) enforceGatewayOpts { return enforceGatewayOpts{} },
			body:         requestWithForbiddenTool(),
			wantStatus:   http.StatusForbidden,
			wantCode:     "tool_policy_violation",
			wantEvidence: true,
		},
		{
			name: "policy_deny",
			opts: func(*testing.T) enforceGatewayOpts {
				return enforceGatewayOpts{configure: relaxGovernance, policy: &denyAllPolicy{}}
			},
			body:         requestClean(),
			wantStatus:   http.StatusForbidden,
			wantEvidence: true,
		},
		{
			name: "scanner_unavailable",
			opts: func(t *testing.T) enforceGatewayOpts {
				return enforceGatewayOpts{scanner: failingExternalScanner(t, testutil.ScannerFailStatus)}
			},
			body:         requestClean(),
			wantStatus:   http.StatusBadGateway,
			wantCode:     "scanner_unavailable",
			wantEvidence: true,
		},
		{
			name:       "unknown_key",
			opts:       func(*testing.T) enforceGatewayOpts { return enforceGatewayOpts{} },
			key:        enforceUnknownAgentKey,
			body:       requestClean(),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_agent_key",
		},
		{
			name:         "disabled_agent",
			opts:         func(*testing.T) enforceGatewayOpts { return enforceGatewayOpts{agentDisabled: true} },
			body:         requestClean(),
			wantStatus:   http.StatusForbidden,
			wantCode:     "agent_disabled",
			wantEvidence: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw, calls, evStore := setupEnforceGateway(t, tc.opts(t))
			if tc.prime != nil {
				tc.prime(t, gw)
			}
			before := calls.Load()
			key := tc.key
			if key == "" {
				key = enforceTestAgentKey
			}

			rr := postGateway(gw, enforceTestChatPath, key, tc.body)

			assert.Equal(t, tc.wantStatus, rr.Code, "body: %s", rr.Body.String())
			if tc.wantCode != "" {
				assert.Equal(t, tc.wantCode, providerErrorType(t, rr))
			}
			assert.Equal(t, before, calls.Load(), "denied request must not reach the provider")
			if tc.wantEvidence {
				assertEnforcedDenial(t, latestEvidence(t, evStore))
			}
		})
	}
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
