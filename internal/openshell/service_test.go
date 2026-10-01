package openshell

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/dativo-io/talon/internal/gateway"
	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
	"github.com/dativo-io/talon/internal/workload"
)

const (
	testIssuer   = "openshell-gateway:gw-test"
	testAudience = "urn:openshell:extension:middleware:talon"
	testSandbox  = "sb-0001"
)

// fakeGateway is an OpenShell-agnostic decider that records what the
// adapter handed it and answers a scripted decision.
type fakeGateway struct {
	last     *gateway.DelegatedRequest
	decision gateway.DelegatedDecision
	calls    int
}

func (f *fakeGateway) EvaluateDelegated(_ context.Context, req gateway.DelegatedRequest) gateway.DelegatedDecision {
	f.calls++
	r := req
	f.last = &r
	return f.decision
}

type signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

func newSigner(t *testing.T, kid string) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &signer{priv: priv, pub: pub, kid: kid}
}

func (s *signer) jwksFile(t *testing.T) string {
	t.Helper()
	doc := map[string]any{"keys": []map[string]any{{"kty": "OKP", "crv": "Ed25519", "kid": s.kid, "x": base64.RawURLEncoding.EncodeToString(s.pub)}}}
	b, _ := json.Marshal(doc)
	p := filepath.Join(t.TempDir(), "jwks.json")
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}

// token mints an OpenShell-shaped extension JWT (typ openshell-ext+jwt,
// alg EdDSA, sub spiffe://openshell/sandbox/<id>, caller_kind, sandbox_id).
func (s *signer) token(t *testing.T, overrides map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": testIssuer, "aud": testAudience, "sub": sandboxSubjectPrefix + testSandbox,
		"caller_kind": "supervisor", "sandbox_id": testSandbox, "jti": "j-1",
		"iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(),
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	h, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": ExtensionTokenType, "kid": s.kid})
	c, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, []byte(signing)))
}

type harness struct {
	svc    *Service
	gw     *fakeGateway
	client *http.Client
	url    string
}

// startHarness serves the adapter over h2c and returns a gRPC-protocol
// client, proving the wire contract end to end (framing, trailers,
// procedure paths) rather than calling Go methods directly.
func startHarness(t *testing.T, s *signer, cfgMut func(*gateway.OpenShellConfig)) *harness {
	t.Helper()
	cfg := gateway.OpenShellConfig{
		Enabled: true, Listen: "127.0.0.1:0", AllowInsecureTransport: true,
		Identity:       gateway.OpenShellIdentityConfig{Issuer: testIssuer, Audience: testAudience, JWKSFile: s.jwksFile(t)},
		MiddlewareName: "talon", MaxPayloadBytes: 1 << 20, RequestTimeout: "5s",
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	fg := &fakeGateway{decision: gateway.DelegatedDecision{Allowed: true, Status: 200, EvidenceID: "ev_1", Agent: "sandboxed-agent"}}
	svc, err := NewService(fg, cfg, "test")
	require.NoError(t, err)
	srv := httptest.NewServer(h2c.NewHandler(svc.Handler(), &http2.Server{}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	return &harness{svc: svc, gw: fg, client: client, url: srv.URL}
}

func (h *harness) evaluate(t *testing.T, token string, msg *middlewarev1.HttpRequestEvaluation) *middlewarev1.HttpRequestResult {
	t.Helper()
	c := connect.NewClient[middlewarev1.HttpRequestEvaluation, middlewarev1.HttpRequestResult](h.client, h.url+procEvaluateHTTP, connect.WithGRPC())
	req := connect.NewRequest(msg)
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	res, err := c.CallUnary(context.Background(), req)
	require.NoError(t, err)
	return res.Msg
}

func chatEval(body string) *middlewarev1.HttpRequestEvaluation {
	return &middlewarev1.HttpRequestEvaluation{
		Phase:          middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		Context:        &middlewarev1.RequestContext{RequestId: "req-7", SandboxId: testSandbox, Sandbox: "display-name-only"},
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "https", Host: "api.openai.com", Port: 443, Method: "POST", Path: "/v1/chat/completions"},
		Headers:        []*middlewarev1.HttpHeader{{Name: "content-type", Value: "application/json"}, {Name: "x-talon-session-id", Value: "sess-9"}},
		Body:           []byte(body),
		MiddlewareName: "talon-governance",
	}
}

func TestDescribe_ManifestBindsHTTPRequestPreCredentialsOnly(t *testing.T) {
	s := newSigner(t, "k1")
	h := startHarness(t, s, nil)
	c := connect.NewClient[middlewarev1.MiddlewareDescribeRequest, middlewarev1.MiddlewareManifest](h.client, h.url+procDescribe, connect.WithGRPC())
	res, err := c.CallUnary(context.Background(), connect.NewRequest(&middlewarev1.MiddlewareDescribeRequest{}))
	require.NoError(t, err)
	m := res.Msg
	require.Equal(t, "talon", m.GetName())
	require.Equal(t, testAudience, m.GetExpectedAudience())
	require.Len(t, m.GetBindings(), 1)
	b := m.GetBindings()[0]
	require.Equal(t, middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST, b.GetOperation())
	require.Equal(t, middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS, b.GetPhase())
	require.Equal(t, uint64(1<<20), b.GetMaxPayloadBytes())
	require.Equal(t, 5*time.Second, b.GetRequestTimeout().AsDuration())
	require.Equal(t, "talon", m.GetExtension().GetImplementationName())
}

func TestValidateConfig_RejectsPolicyLocalConfig(t *testing.T) {
	s := newSigner(t, "k1")
	h := startHarness(t, s, nil)
	c := connect.NewClient[middlewarev1.ValidateConfigRequest, middlewarev1.ValidateConfigResponse](h.client, h.url+procValidateConfig, connect.WithGRPC())
	ok, err := c.CallUnary(context.Background(), connect.NewRequest(&middlewarev1.ValidateConfigRequest{MiddlewareName: "talon"}))
	require.NoError(t, err)
	require.True(t, ok.Msg.GetValid())
	cfg, _ := structpb.NewStruct(map[string]any{"talon_agent": "finance-bot"})
	bad, err := c.CallUnary(context.Background(), connect.NewRequest(&middlewarev1.ValidateConfigRequest{Config: cfg}))
	require.NoError(t, err)
	require.False(t, bad.Msg.GetValid(), "an OpenShell policy must not be able to select a Talon use case")
	require.Contains(t, bad.Msg.GetReason(), "workload_identity.bindings")
}

func TestEvaluate_VerifiedSupervisorReachesDecider(t *testing.T) {
	s := newSigner(t, "k1")
	h := startHarness(t, s, nil)
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	res := h.evaluate(t, s.token(t, nil), chatEval(body))
	require.Equal(t, middlewarev1.Decision_DECISION_ALLOW, res.GetDecision())
	require.False(t, res.GetHasBody(), "unchanged body: no replacement")
	require.Equal(t, "allow", res.GetMetadata()["talon_decision"])
	require.Equal(t, "ev_1", res.GetMetadata()["talon_evidence_id"])
	require.Equal(t, 1, h.gw.calls)
	got := h.gw.last
	require.NotNil(t, got.Principal)
	require.Equal(t, sandboxSubjectPrefix+testSandbox, got.Principal.Subject)
	require.Equal(t, RuntimeType, got.Runtime)
	require.Equal(t, testIssuer, got.RuntimeID)
	require.Equal(t, "api.openai.com", got.Host)
	require.Equal(t, "/v1/chat/completions", got.Path)
	require.Equal(t, "POST", got.Method)
	require.Equal(t, body, string(got.Body))
	require.Equal(t, "sess-9", got.SessionID)
	require.Equal(t, "talon-governance", got.PolicyRef)
	require.Equal(t, testSandbox, got.Reference)
	require.Equal(t, "req-7", got.RequestID)
	require.Equal(t, "", got.IdentityFailure)
}

func TestEvaluate_TransformedBodyIsReturnedAsReplacement(t *testing.T) {
	s := newSigner(t, "k1")
	h := startHarness(t, s, nil)
	h.gw.decision = gateway.DelegatedDecision{Allowed: true, Status: 200, Body: []byte(`{"redacted":true}`), BodyChanged: true, Redacted: true, PIITypes: []string{"email"}, EvidenceID: "ev_2"}
	res := h.evaluate(t, s.token(t, nil), chatEval(`{"orig":true}`))
	require.Equal(t, middlewarev1.Decision_DECISION_ALLOW, res.GetDecision())
	require.True(t, res.GetHasBody())
	require.Equal(t, `{"redacted":true}`, string(res.GetBody()))
	require.Len(t, res.GetFindings(), 1)
	require.Equal(t, "talon.pii.email", res.GetFindings()[0].GetType())
	require.Equal(t, "redacted", res.GetFindings()[0].GetLabel())
}

func TestEvaluate_TalonDenyIsRelayedWithReasonCode(t *testing.T) {
	s := newSigner(t, "k1")
	h := startHarness(t, s, nil)
	h.gw.decision = gateway.DelegatedDecision{Allowed: false, Code: "pii_policy_violation", Status: 400, Message: "pii_policy_violation: Request contains PII that is not allowed", EvidenceID: "ev_3", Agent: "sandboxed-agent"}
	res := h.evaluate(t, s.token(t, nil), chatEval(`{}`))
	require.Equal(t, middlewarev1.Decision_DECISION_DENY, res.GetDecision())
	require.Equal(t, "pii_policy_violation", res.GetReasonCode())
	require.False(t, res.GetHasBody())
	require.Equal(t, "deny", res.GetMetadata()["talon_decision"])
	require.Equal(t, "ev_3", res.GetMetadata()["talon_evidence_id"])
	require.Equal(t, "sandboxed-agent", res.GetMetadata()["talon_agent"])
}

func TestEvaluate_IdentityFailuresNeverProduceAPrincipal(t *testing.T) {
	s := newSigner(t, "k1")
	forger := newSigner(t, "k1")
	cases := []struct {
		name  string
		token func(h *harness) string
		ctx   func(e *middlewarev1.HttpRequestEvaluation)
		code  string
	}{
		{"no token", func(*harness) string { return "" }, nil, workload.FailureMissing},
		{"forged key", func(*harness) string { return forger.token(t, nil) }, nil, workload.FailureSignatureInvalid},
		{"wrong audience", func(*harness) string {
			return s.token(t, map[string]any{"aud": "urn:openshell:extension:middleware:other"})
		}, nil, workload.FailureAudienceMismatch},
		{"wrong issuer", func(*harness) string { return s.token(t, map[string]any{"iss": "openshell-gateway:rogue"}) }, nil, workload.FailureIssuerMismatch},
		{"expired", func(*harness) string {
			return s.token(t, map[string]any{"exp": time.Now().Add(-5 * time.Minute).Unix(), "iat": time.Now().Add(-20 * time.Minute).Unix()})
		}, nil, workload.FailureExpired},
		{"gateway caller kind", func(*harness) string {
			return s.token(t, map[string]any{"caller_kind": "gateway", "sub": "openshell-gateway:gw-test", "sandbox_id": nil})
		}, nil, CodeIdentityCallerKind},
		{"sandbox claim vs subject mismatch", func(*harness) string {
			return s.token(t, map[string]any{"sandbox_id": "sb-other"})
		}, nil, CodeIdentityContextMismatch},
		{
			"request context names another sandbox", func(*harness) string { return s.token(t, nil) },
			func(e *middlewarev1.HttpRequestEvaluation) { e.Context.SandboxId = "sb-victim" }, CodeIdentityContextMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := startHarness(t, s, nil)
			// The decider answers deny for a nil principal exactly like the
			// real gateway; the assertion is on what the adapter handed it.
			h.gw.decision = gateway.DelegatedDecision{Allowed: false, Code: gateway.CodeWorkloadIdentityRequired, Status: 401, Message: "workload_identity_required: x"}
			e := chatEval(`{}`)
			if tc.ctx != nil {
				tc.ctx(e)
			}
			res := h.evaluate(t, tc.token(h), e)
			require.Equal(t, middlewarev1.Decision_DECISION_DENY, res.GetDecision())
			require.Equal(t, 1, h.gw.calls)
			require.Nil(t, h.gw.last.Principal, "no principal may reach the decider")
			require.Equal(t, tc.code, h.gw.last.IdentityFailure)
		})
	}
}

func TestEvaluate_DisplayNameAndConfigCannotSelectAgent(t *testing.T) {
	s := newSigner(t, "k1")
	h := startHarness(t, s, nil)
	e := chatEval(`{}`)
	e.Context.Sandbox = "finance-bot"
	cfg, _ := structpb.NewStruct(map[string]any{"talon_agent": "finance-bot"})
	e.Config = cfg
	res := h.evaluate(t, s.token(t, nil), e)
	require.Equal(t, middlewarev1.Decision_DECISION_ALLOW, res.GetDecision())
	// Only the verified subject travels; neither the display name nor the
	// policy-local config is part of the delegated request at all.
	require.Equal(t, sandboxSubjectPrefix+testSandbox, h.gw.last.Principal.Subject)
	require.Equal(t, testSandbox, h.gw.last.Reference)
}

func TestEvaluate_ProtocolGuardsDenyWithoutEvaluation(t *testing.T) {
	s := newSigner(t, "k1")
	t.Run("wrong phase", func(t *testing.T) {
		h := startHarness(t, s, nil)
		e := chatEval(`{}`)
		e.Phase = middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN
		res := h.evaluate(t, s.token(t, nil), e)
		require.Equal(t, middlewarev1.Decision_DECISION_DENY, res.GetDecision())
		require.Equal(t, CodePhaseUnsupported, res.GetReasonCode())
		require.Equal(t, 0, h.gw.calls)
	})
	t.Run("missing target", func(t *testing.T) {
		h := startHarness(t, s, nil)
		e := chatEval(`{}`)
		e.Target = nil
		res := h.evaluate(t, s.token(t, nil), e)
		require.Equal(t, CodeTargetMissing, res.GetReasonCode())
		require.Equal(t, 0, h.gw.calls)
	})
	t.Run("oversized body", func(t *testing.T) {
		h := startHarness(t, s, func(c *gateway.OpenShellConfig) { c.MaxPayloadBytes = 64 })
		res := h.evaluate(t, s.token(t, nil), chatEval(strings.Repeat("x", 65)))
		require.Equal(t, CodePayloadTooLarge, res.GetReasonCode())
		require.Equal(t, 0, h.gw.calls)
	})
}

func TestEvaluate_UnimplementedProceduresAreNotServed(t *testing.T) {
	s := newSigner(t, "k1")
	h := startHarness(t, s, nil)
	c := connect.NewClient[middlewarev1.WebSocketSessionEvent, middlewarev1.WebSocketSessionEventResult](h.client, h.url+"/openshell.middleware.v1.SupervisorMiddleware/EvaluateWebSocketSession", connect.WithGRPC())
	_, err := c.CallUnary(context.Background(), connect.NewRequest(&middlewarev1.WebSocketSessionEvent{}))
	require.Error(t, err)
}

func TestReasonCode(t *testing.T) {
	for in, want := range map[string]string{
		"pii_policy_violation":  "pii_policy_violation",
		"Model-Not Allowed":     "model_not_allowed",
		"":                      "talon_",
		"9bad":                  "talon_9bad",
		strings.Repeat("a", 80): strings.Repeat("a", 64),
	} {
		require.Equal(t, want, reasonCode(in), in)
	}
}
