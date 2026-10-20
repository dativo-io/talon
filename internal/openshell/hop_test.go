package openshell

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/gateway"
	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
	"github.com/dativo-io/talon/internal/workload"
)

const selfHost = "talon.fixture.internal"

func selfEval(method, path, body string, headers ...*middlewarev1.HttpHeader) *middlewarev1.HttpRequestEvaluation {
	return &middlewarev1.HttpRequestEvaluation{
		Phase:          middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		Context:        &middlewarev1.RequestContext{RequestId: "req-hop-1", SandboxId: testSandbox},
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "http", Host: selfHost, Port: 8080, Method: method, Path: path},
		Headers:        append([]*middlewarev1.HttpHeader{{Name: "content-type", Value: "application/json"}}, headers...),
		Body:           []byte(body),
		MiddlewareName: "talon-governance",
	}
}

func hopHarness(t *testing.T, s *signer) (*harness, *workload.HopSigner) {
	t.Helper()
	h := startHarness(t, s, func(c *gateway.OpenShellConfig) {
		c.SelfDestination = &gateway.OpenShellSelfDestinationConfig{Hosts: []string{selfHost}, AssertionTTL: "30s"}
	})
	hs, err := workload.NewHopSigner("hop-root-key-for-tests-0123456789abcdef", 30e9)
	require.NoError(t, err)
	h.svc.hop = hs
	return h, hs
}

func hopHeader(res *middlewarev1.HttpRequestResult) (*middlewarev1.WriteHeader, bool) {
	for _, m := range res.GetHeaderMutations() {
		if w := m.GetWrite(); w != nil && w.GetName() == workload.HopAssertionHeader {
			return w, true
		}
	}
	return nil, false
}

// A verified sandbox addressing Talon's own Action Gateway is admitted with
// a request-bound assertion: the model decider is never consulted, the
// assertion verifies only for the exact method/path/body the hop saw, and a
// header value the sandbox wrote itself is overwritten, not appended to.
func TestHop_VerifiedSandboxGetsRequestBoundAssertion(t *testing.T) {
	s := newSigner(t, "k1")
	h, hs := hopHarness(t, s)
	body := `{"operation_id":"op-1","action":"create_refund_request","arguments":{"ticket_id":"T-1"}}`
	res := h.evaluate(t, s.token(t, nil), selfEval("POST", "/v1/action-operations", body,
		&middlewarev1.HttpHeader{Name: workload.HopAssertionHeader, Value: "v1.forged.by-sandbox"},
		&middlewarev1.HttpHeader{Name: "x-talon-session-id", Value: "sess-42"}))
	require.Equal(t, middlewarev1.Decision_DECISION_ALLOW, res.GetDecision(), "%v", res)
	assert.False(t, res.GetHasBody(), "the hop never rewrites an action request")
	assert.Equal(t, "allow", res.GetMetadata()["talon_decision"])
	assert.Equal(t, hopMetadataKind, res.GetMetadata()["talon_kind"])
	assert.Equal(t, "sandboxed-agent", res.GetMetadata()["talon_agent"])
	assert.Equal(t, 0, h.gw.calls, "model decider not consulted for self traffic")
	require.Len(t, h.gw.hopRequests, 1)
	assert.Equal(t, sandboxSubjectPrefix+testSandbox, h.gw.hopRequests[0].Principal.Subject)

	w, ok := hopHeader(res)
	require.True(t, ok, "assertion header mutation missing: %v", res.GetHeaderMutations())
	assert.Equal(t, middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_OVERWRITE, w.GetOnExisting())
	assert.NotEqual(t, "v1.forged.by-sandbox", w.GetValue())
	for _, m := range res.GetHeaderMutations() {
		assert.Nil(t, m.GetRemove(), "no protected header is touched")
	}

	claims, err := hs.Verify(w.GetValue(), "POST", "/v1/action-operations", workload.BodyDigest([]byte(body)))
	require.NoError(t, err)
	assert.Equal(t, "sandboxed-agent", claims.Agent)
	assert.Equal(t, "default", claims.Tenant)
	assert.Equal(t, RuntimeType, claims.Runtime)
	assert.Equal(t, testIssuer, claims.RuntimeIssuer)
	assert.Equal(t, sandboxSubjectPrefix+testSandbox, claims.Subject)
	assert.Equal(t, testSandbox, claims.SandboxRef)
	assert.Equal(t, "req-hop-1", claims.RequestID)
	assert.Equal(t, "sess-42", claims.SessionID)
	_, err = hs.Verify(w.GetValue(), "POST", "/v1/action-operations", workload.BodyDigest([]byte(body+" ")))
	assert.Equal(t, workload.FailureHopBindingMismatch, workload.FailureCode(err), "another body cannot reuse the assertion")
	_, err = hs.Verify(w.GetValue(), "POST", "/v1/action-operations/op-1/attempts", workload.BodyDigest([]byte(body)))
	assert.Equal(t, workload.FailureHopBindingMismatch, workload.FailureCode(err), "another route cannot reuse the assertion")
}

// Identity failures and unbound principals are denied at the hop with the
// same codes as the model path; nothing is minted and the decider is not
// asked to bind anything it cannot verify.
func TestHop_IdentityFailuresDenyWithoutAssertion(t *testing.T) {
	s := newSigner(t, "k1")
	forger := newSigner(t, "k1")
	h, _ := hopHarness(t, s)
	for name, tc := range map[string]struct {
		token     string
		hop       gateway.WorkloadHopDecision
		code      string
		principal bool // whether the hop request carried a verified principal
	}{
		"no token":     {"", gateway.WorkloadHopDecision{}, gateway.CodeWorkloadIdentityRequired, false},
		"forged token": {forger.token(t, nil), gateway.WorkloadHopDecision{}, gateway.CodeWorkloadIdentityRequired, false},
		"unbound":      {s.token(t, nil), gateway.WorkloadHopDecision{Status: 403, Code: gateway.CodeWorkloadIdentityUnbound, Message: "unbound"}, gateway.CodeWorkloadIdentityUnbound, true},
		"disabled":     {s.token(t, nil), gateway.WorkloadHopDecision{Status: 403, Code: gateway.CodeAgentDisabled, Message: "disabled", Agent: "sandboxed-agent"}, gateway.CodeAgentDisabled, true},
	} {
		t.Run(name, func(t *testing.T) {
			h.gw.hop = tc.hop
			res := h.evaluate(t, tc.token, selfEval("POST", "/v1/action-operations", `{}`))
			assert.Equal(t, middlewarev1.Decision_DECISION_DENY, res.GetDecision())
			assert.Equal(t, reasonCode(tc.code), res.GetReasonCode())
			_, ok := hopHeader(res)
			assert.False(t, ok, "no assertion on a denial")
			assert.Equal(t, 0, h.gw.calls)
			last := h.gw.hopRequests[len(h.gw.hopRequests)-1]
			assert.Equal(t, tc.principal, last.Principal != nil, "an unverified token never yields a principal")
		})
	}
}

// Only the agent-facing Action Gateway routes are reachable through the hop:
// reviewer decisions, the model proxy and unknown paths are denied before
// any binding is resolved.
func TestHop_RouteAllowlist(t *testing.T) {
	s := newSigner(t, "k1")
	h, _ := hopHarness(t, s)
	for _, tc := range []struct {
		method, path string
		ok           bool
	}{
		{"POST", "/v1/action-operations", true},
		{"GET", "/v1/action-operations/op-1", true},
		{"POST", "/v1/action-operations/op-1/attempts", true},
		{"GET", "/v1/approvals/apr-1", true},
		{"POST", "/v1/approvals/apr-1/decisions", false},
		{"GET", "/v1/action-operations", false},
		{"POST", "/v1/action-operations/op-1", false},
		{"DELETE", "/v1/action-operations/op-1", false},
		{"POST", "/v1/proxy/v1/chat/completions", false},
		{"GET", "/v1/action-operations/../approvals", false},
		{"POST", "/v1/action-operations/" + string(make([]byte, 200)), false},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			before := len(h.gw.hopRequests)
			res := h.evaluate(t, s.token(t, nil), selfEval(tc.method, tc.path, "{}"))
			if tc.ok {
				assert.Equal(t, middlewarev1.Decision_DECISION_ALLOW, res.GetDecision(), "%v", res)
				return
			}
			assert.Equal(t, middlewarev1.Decision_DECISION_DENY, res.GetDecision())
			assert.Equal(t, CodeSelfDestinationPathNotGoverned, res.GetReasonCode())
			assert.Equal(t, before, len(h.gw.hopRequests), "binding is not resolved for an ungoverned route")
		})
	}
}

// Without a root key there is no assertion; self traffic is denied rather
// than forwarded unattributed. A non-self, non-provider host keeps the
// model path's destination_not_governed outcome.
func TestHop_NoSignerDeniesSelfTraffic(t *testing.T) {
	s := newSigner(t, "k1")
	h := startHarness(t, s, func(c *gateway.OpenShellConfig) {
		c.SelfDestination = &gateway.OpenShellSelfDestinationConfig{Hosts: []string{selfHost}}
	})
	res := h.evaluate(t, s.token(t, nil), selfEval("POST", "/v1/action-operations", "{}"))
	assert.Equal(t, middlewarev1.Decision_DECISION_DENY, res.GetDecision())
	assert.Equal(t, CodeWorkloadAssertionUnavailable, res.GetReasonCode())
	assert.Equal(t, 0, h.gw.calls)
}

func TestSelfDestinationConfig_Validation(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg gateway.OpenShellSelfDestinationConfig
		ok  bool
	}{
		"ok":          {gateway.OpenShellSelfDestinationConfig{Hosts: []string{"talon.internal", "host.openshell.internal:8080"}}, true},
		"empty":       {gateway.OpenShellSelfDestinationConfig{}, false},
		"scheme":      {gateway.OpenShellSelfDestinationConfig{Hosts: []string{"http://talon.internal"}}, false},
		"bad port":    {gateway.OpenShellSelfDestinationConfig{Hosts: []string{"talon.internal:0"}}, false},
		"huge port":   {gateway.OpenShellSelfDestinationConfig{Hosts: []string{"talon.internal:70000"}}, false},
		"path":        {gateway.OpenShellSelfDestinationConfig{Hosts: []string{"talon.internal/v1"}}, false},
		"uppercase":   {gateway.OpenShellSelfDestinationConfig{Hosts: []string{"Talon.Internal"}}, false},
		"duplicate":   {gateway.OpenShellSelfDestinationConfig{Hosts: []string{"a.b", "a.b"}}, false},
		"ttl too low": {gateway.OpenShellSelfDestinationConfig{Hosts: []string{"a.b"}, AssertionTTL: "1s"}, false},
		"ttl too big": {gateway.OpenShellSelfDestinationConfig{Hosts: []string{"a.b"}, AssertionTTL: "1h"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := gateway.OpenShellConfig{
				Enabled: true, Listen: "127.0.0.1:1", AllowInsecureTransport: true,
				Identity: gateway.OpenShellIdentityConfig{Issuer: "i", Audience: "a", JWKSFile: "/dev/null"},
			}
			c := tc.cfg
			cfg.SelfDestination = &c
			gc := gateway.GatewayConfig{ListenPrefix: "/v1/proxy", OpenShell: &cfg}
			err := gc.Validate()
			if tc.ok {
				assert.NoError(t, err)
				assert.True(t, cfg.SelfDestination.IsSelfHost("TALON.internal", 443), "a port-less entry matches any port")
				assert.True(t, cfg.SelfDestination.IsSelfHost("host.openshell.internal", 8080))
				assert.False(t, cfg.SelfDestination.IsSelfHost("host.openshell.internal", 9000), "a port entry matches only its port")
				assert.False(t, cfg.SelfDestination.IsSelfHost("api.openai.com", 443))
			} else {
				assert.Error(t, err)
			}
		})
	}
	// A self entry on a provider's host must carry its own port: a
	// destination is either Talon or a provider, never both.
	withSelf := func(entry string) error {
		gc := gateway.GatewayConfig{ListenPrefix: "/v1/proxy", Providers: map[string]gateway.ProviderConfig{
			"openai": {Enabled: true, BaseURL: "http://host.openshell.internal:9000", SecretName: "openai-api-key"},
		}, OpenShell: &gateway.OpenShellConfig{
			Enabled: true, Listen: "127.0.0.1:1", AllowInsecureTransport: true,
			Identity:        gateway.OpenShellIdentityConfig{Issuer: "i", Audience: "a", JWKSFile: "/dev/null"},
			SelfDestination: &gateway.OpenShellSelfDestinationConfig{Hosts: []string{entry}},
		}}
		return gc.Validate()
	}
	assert.Error(t, withSelf("host.openshell.internal"), "port-less entry on a provider host is ambiguous")
	assert.Error(t, withSelf("host.openshell.internal:9000"), "same host and port as the provider")
	assert.NoError(t, withSelf("host.openshell.internal:8080"), "same host, Talon's own port")
}
