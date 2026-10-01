package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/testutil"
	"github.com/dativo-io/talon/internal/workload"
)

const (
	delegatedSubject = "spiffe://openshell/sandbox/sb-42"
	delegatedIssuer  = "openshell-gateway:gw-1"
)

func delegatedPrincipal(subject string) *workload.Principal {
	return &workload.Principal{
		PrincipalID: subject, Subject: subject, Issuer: delegatedIssuer,
		Audience: "urn:openshell:extension:middleware:talon", AuthMethod: workload.AuthMethodJWTEdDSA,
		Claims:     map[string]string{"sandbox_id": strings.TrimPrefix(subject, "spiffe://openshell/sandbox/"), "caller_kind": "supervisor"},
		VerifiedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute),
	}
}

// setupDelegatedGateway wires a gateway whose openai provider points at the
// real provider host (never reached: the delegated path does not dispatch)
// and one agent bound to the sandbox subject.
func setupDelegatedGateway(t *testing.T, piiAction string, override *PolicyOverride) (*Gateway, *evidence.Store) {
	t.Helper()
	dir := t.TempDir()
	cfg := &GatewayConfig{
		Enabled: true, ListenPrefix: "/v1/proxy",
		Providers: map[string]ProviderConfig{
			"openai": {Enabled: true, BaseURL: "https://api.openai.com", SecretName: "openai-api-key"},
		},
		OrganizationPolicy: OrganizationPolicy{Defaults: OrgDefaults{PIIAction: piiAction, DailyCost: 100, MonthlyCost: 2000}},
		Timeouts:           TimeoutsConfig{ConnectTimeout: "5s", RequestTimeout: "30s", StreamIdleTimeout: "60s"},
	}
	require.NoError(t, cfg.ApplyDefaults())
	bound := testIdentity("sandboxed-agent", "acme", "tk-sandboxed", override)
	bound.workloadBindings = []WorkloadBinding{{Runtime: "openshell", Subject: delegatedSubject}}
	stopped := testIdentity("stopped-agent", "acme", "tk-stopped", nil)
	stopped.Enabled = false
	stopped.workloadBindings = []WorkloadBinding{{Runtime: "openshell", Subject: "spiffe://openshell/sandbox/sb-stopped"}}
	registry := testRegistry(bound, stopped)
	registry.byWorkload = map[workloadKey]*ResolvedIdentity{
		{"openshell", delegatedSubject}:                        bound,
		{"openshell", "spiffe://openshell/sandbox/sb-stopped"}: stopped,
	}
	evStore, err := evidence.NewStore(filepath.Join(dir, "e.db"), testutil.TestSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = evStore.Close() })
	secStore, err := secrets.NewSecretStore(filepath.Join(dir, "s.db"), testutil.TestEncryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secStore.Close() })
	gw, err := NewGateway(cfg, NewRegistryHolder(registry), classifier.MustNewScanner(), evStore, secStore, testGatewayPolicy(t), nil)
	require.NoError(t, err)
	return gw, evStore
}

func delegatedReq(principal *workload.Principal, body string) DelegatedRequest {
	return DelegatedRequest{
		Runtime: "openshell", RuntimeID: delegatedIssuer, Principal: principal,
		Host: "api.openai.com", Path: "/v1/chat/completions", Method: "POST", Body: []byte(body),
		PolicyRef: "talon-governance", Reference: "sb-42", RequestID: "req-1",
	}
}

func listDelegated(t *testing.T, store *evidence.Store, agent string) []evidence.Evidence {
	t.Helper()
	recs, err := store.List(context.Background(), "acme", agent, time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	return recs
}

func TestEvaluateDelegated_AllowRecordsProvenanceAndIdentity(t *testing.T) {
	gw, store := setupDelegatedGateway(t, "warn", nil)
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`
	dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), body))
	require.True(t, dec.Allowed, "decision: %+v", dec)
	require.False(t, dec.BodyChanged)
	require.Equal(t, "sandboxed-agent", dec.Agent)
	require.Equal(t, "openai", dec.Provider)
	require.NotEmpty(t, dec.EvidenceID)

	recs := listDelegated(t, store, "sandboxed-agent")
	require.Len(t, recs, 1)
	ev := recs[0]
	require.True(t, store.VerifyRecord(&ev), "signed record must verify")
	require.True(t, ev.PolicyDecision.Allowed)
	require.Equal(t, UpstreamAuthModeExternalRuntime, ev.UpstreamAuthMode, "provider credential is owned by the runtime")
	require.Contains(t, ev.GatewayAnnotations, "delegated_dispatch")
	require.NotNil(t, ev.Enforcement)
	require.Equal(t, evidence.MechanismDelegate, ev.Enforcement.Mechanism)
	require.Equal(t, evidence.BoundaryExternalRuntime, ev.Enforcement.Boundary)
	require.Equal(t, evidence.BoundaryTalon, ev.Enforcement.DecisionAuthority)
	require.Equal(t, evidence.ProvenanceDelegatedExpected, ev.Enforcement.Provenance)
	require.Equal(t, "openshell_middleware", ev.Enforcement.DecisionReturnedVia, "Talon returned the verdict; it did not observe enforcement")
	require.Equal(t, "openshell", ev.Enforcement.Runtime.Type)
	require.Equal(t, delegatedIssuer, ev.Enforcement.Runtime.ID)
	require.Equal(t, "talon-governance", ev.Enforcement.Runtime.PolicyRef)
	require.Equal(t, "sb-42", ev.Enforcement.Runtime.Reference)
	require.Equal(t, "req-1", ev.Enforcement.Runtime.RequestID)
	require.NotNil(t, ev.WorkloadIdentity)
	require.Equal(t, evidence.WorkloadIdentityVerified, ev.WorkloadIdentity.Status)
	require.Equal(t, delegatedSubject, ev.WorkloadIdentity.Subject)
	require.Equal(t, delegatedIssuer, ev.WorkloadIdentity.Issuer)
	require.Equal(t, workload.AuthMethodJWTEdDSA, ev.WorkloadIdentity.AuthMethod)
	require.Equal(t, evidence.WorkloadIdentityBindingAgentConfig, ev.WorkloadIdentity.Binding)
	require.Equal(t, "", ev.WorkloadIdentity.FailureCode)
	// Usage is unobserved on this path: the record carries the estimate.
	require.Equal(t, 0, ev.Execution.Tokens.Input)
	require.Greater(t, ev.Execution.Cost, 0.0)
	require.Empty(t, ev.SecretsAccessed, "no provider secret is read on the delegated path")
}

func TestEvaluateDelegated_RedactionReturnsExactlyTheRedactedBody(t *testing.T) {
	gw, store := setupDelegatedGateway(t, "redact", nil)
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"contact me at jane.doe@example.com please"}]}`
	dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), body))
	require.True(t, dec.Allowed, "decision: %+v", dec)
	require.True(t, dec.BodyChanged)
	require.True(t, dec.Redacted)
	require.NotContains(t, string(dec.Body), "jane.doe@example.com", "the runtime must receive the redacted representation")
	require.Contains(t, string(dec.Body), "gpt-4o-mini")
	require.Contains(t, dec.PIITypes, "email")
	ev := listDelegated(t, store, "sandboxed-agent")[0]
	require.True(t, ev.Classification.PIIRedacted)
	require.True(t, ev.PolicyDecision.Allowed)
	require.NotContains(t, mustJSON(t, ev), "jane.doe@example.com", "evidence never carries raw PII")
}

func TestEvaluateDelegated_TalonDenyCodes(t *testing.T) {
	cases := []struct {
		name      string
		piiAction string
		override  *PolicyOverride
		body      string
		code      string
		status    int
		reason    string
	}{
		{
			"model not allowed", "warn", &PolicyOverride{AllowedModels: []string{"gpt-4o-mini"}},
			`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, "model_not_allowed", http.StatusForbidden, "model",
		},
		{
			"pii block", "block", nil,
			`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ssn 123-45-6789 email a@b.co"}]}`, "pii_policy_violation", http.StatusBadRequest, "PII block",
		},
		{
			"budget exceeded", "warn", &PolicyOverride{MaxDailyCost: 0.0000001},
			`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`, "budget_exceeded", http.StatusForbidden, "budget",
		},
		{
			"provider not allowed", "warn", &PolicyOverride{AllowedProviders: []string{"anthropic"}},
			`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`, "provider_not_allowed", http.StatusForbidden, "provider not allowed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw, store := setupDelegatedGateway(t, tc.piiAction, tc.override)
			dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), tc.body))
			require.False(t, dec.Allowed)
			require.Equal(t, tc.code, dec.Code, "message: %s", dec.Message)
			require.Equal(t, tc.status, dec.Status)
			require.Nil(t, dec.Body, "a denial never hands the runtime a body to forward")
			require.NotEmpty(t, dec.EvidenceID)
			recs := listDelegated(t, store, "sandboxed-agent")
			require.Len(t, recs, 1)
			ev := recs[0]
			require.True(t, store.VerifyRecord(&ev))
			require.False(t, ev.PolicyDecision.Allowed)
			require.Contains(t, strings.ToLower(strings.Join(ev.PolicyDecision.Reasons, " ")), strings.ToLower(tc.reason))
			require.Equal(t, evidence.MechanismDelegate, ev.Enforcement.Mechanism)
			require.Equal(t, evidence.WorkloadIdentityVerified, ev.WorkloadIdentity.Status)
		})
	}
}

func TestEvaluateDelegated_IdentityGatesBeforeEvaluation(t *testing.T) {
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	t.Run("no principal", func(t *testing.T) {
		gw, store := setupDelegatedGateway(t, "warn", nil)
		req := delegatedReq(nil, body)
		req.IdentityFailure = workload.FailureSignatureInvalid
		dec := gw.EvaluateDelegated(context.Background(), req)
		require.False(t, dec.Allowed)
		require.Equal(t, CodeWorkloadIdentityRequired, dec.Code)
		require.Equal(t, http.StatusUnauthorized, dec.Status)
		require.Contains(t, dec.Message, workload.FailureSignatureInvalid)
		require.Empty(t, listDelegated(t, store, "sandboxed-agent"), "an unattributable caller writes no tenant record")
	})
	t.Run("verified but unbound subject cannot pick a use case", func(t *testing.T) {
		gw, store := setupDelegatedGateway(t, "warn", nil)
		dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal("spiffe://openshell/sandbox/other"), body))
		require.False(t, dec.Allowed)
		require.Equal(t, CodeWorkloadIdentityUnbound, dec.Code)
		require.Empty(t, listDelegated(t, store, "sandboxed-agent"))
	})
	t.Run("disabled agent denies with attribution", func(t *testing.T) {
		gw, store := setupDelegatedGateway(t, "warn", nil)
		dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal("spiffe://openshell/sandbox/sb-stopped"), body))
		require.False(t, dec.Allowed)
		require.Equal(t, CodeAgentDisabled, dec.Code)
		recs := listDelegated(t, store, "stopped-agent")
		require.Len(t, recs, 1)
		require.False(t, recs[0].PolicyDecision.Allowed)
	})
	t.Run("ungoverned destination fails closed", func(t *testing.T) {
		gw, store := setupDelegatedGateway(t, "warn", nil)
		req := delegatedReq(delegatedPrincipal(delegatedSubject), body)
		req.Host = "api.example-llm.com"
		dec := gw.EvaluateDelegated(context.Background(), req)
		require.False(t, dec.Allowed)
		require.Equal(t, CodeDestinationNotGoverned, dec.Code)
		recs := listDelegated(t, store, "sandboxed-agent")
		require.Len(t, recs, 1)
		require.Contains(t, recs[0].PolicyDecision.Reasons[0], "api.example-llm.com")
	})
	t.Run("session id is attribution only and bounded", func(t *testing.T) {
		gw, store := setupDelegatedGateway(t, "warn", nil)
		req := delegatedReq(delegatedPrincipal(delegatedSubject), body)
		req.SessionID = "sess-abc"
		dec := gw.EvaluateDelegated(context.Background(), req)
		require.True(t, dec.Allowed)
		require.Equal(t, "sess-abc", listDelegated(t, store, "sandboxed-agent")[0].SessionID)
	})
}

func TestProviderForHost(t *testing.T) {
	cfg := &GatewayConfig{Providers: map[string]ProviderConfig{
		"openai":    {Enabled: true, BaseURL: "https://api.openai.com/v1"},
		"anthropic": {Enabled: true, BaseURL: "https://api.anthropic.com"},
		"disabled":  {Enabled: false, BaseURL: "https://api.disabled.example"},
		"dupe-a":    {Enabled: true, BaseURL: "https://shared.example:8443"},
		"dupe-b":    {Enabled: true, BaseURL: "https://shared.example"},
	}}
	for host, want := range map[string]string{
		"api.openai.com": "openai", "API.OPENAI.COM": "openai", "api.anthropic.com": "anthropic",
		"api.disabled.example": "", "shared.example": "", "unknown.example": "", "": "",
	} {
		got, ok := cfg.providerForHost(host)
		require.Equal(t, want, got, host)
		require.Equal(t, want != "", ok, host)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}
