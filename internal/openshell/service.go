// Package openshell is the transport adapter that lets Talon act as an
// NVIDIA OpenShell supervisor middleware (#482).
//
// Pinned upstream contract: OpenShell v0.1.2, proto package
// openshell.middleware.v1 (internal/openshell/proto/v0.1.2). OpenShell
// checks its own network policy first, calls this service for admitted
// HTTP requests to the destinations its policy binds Talon to, and injects
// the provider credential only AFTER Talon answers ALLOW. A DENY always
// blocks; middleware unavailability blocks by default (fail closed).
//
// Boundary discipline: this package owns OpenShell wire parsing, caller
// authentication (the gateway-signed extension JWT), and result encoding.
// The model-governance decision, the identity binding and the signed
// record are gateway/evidence domain code that never sees an OpenShell
// type.
package openshell

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dativo-io/talon/internal/gateway"
	extensionv1 "github.com/dativo-io/talon/internal/openshell/proto/gen/extensionv1"
	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
	"github.com/dativo-io/talon/internal/workload"
)

// Pinned upstream facts.
const (
	// UpstreamVersion is the OpenShell release whose proto this adapter
	// implements.
	UpstreamVersion = "v0.1.2"
	// RuntimeType is the runtime name used in agent bindings and evidence.
	RuntimeType = "openshell"
	// ExtensionTokenType is the JOSE typ of the supervisor's caller token.
	ExtensionTokenType = "openshell-ext+jwt" //nolint:gosec // G101: a JOSE type label, not a credential
	// procedure paths (gRPC full method names).
	procDescribe       = "/openshell.middleware.v1.SupervisorMiddleware/Describe"
	procValidateConfig = "/openshell.middleware.v1.SupervisorMiddleware/ValidateConfig"
	procEvaluateHTTP   = "/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest"

	claimCallerKind      = "caller_kind"
	claimSandboxID       = "sandbox_id"
	callerSupervisor     = "supervisor"
	sandboxSubjectPrefix = "spiffe://openshell/sandbox/"

	// sessionHeader is the client-asserted session correlation Talon reads
	// from the sandboxed agent's request (attribution only, #194).
	sessionHeader = "x-talon-session-id"
)

// Stable adapter reason codes (OpenShell relays reason_code to the sandbox).
const (
	CodeIdentityContextMismatch = "workload_identity_context_mismatch"
	CodeIdentityCallerKind      = "workload_identity_caller_kind"
	CodePhaseUnsupported        = "phase_unsupported"
	CodePayloadTooLarge         = "payload_too_large"
	CodeTargetMissing           = "target_missing"
)

// Decider is the gateway seam this adapter needs.
type Decider interface {
	EvaluateDelegated(ctx context.Context, req gateway.DelegatedRequest) gateway.DelegatedDecision
}

// Service implements the pinned SupervisorMiddleware contract over Talon.
type Service struct {
	decider  Decider
	verifier *workload.JWTVerifier
	cfg      gateway.OpenShellConfig
	version  string
	// maxPayload is the validated, non-negative manifest bound.
	maxPayload uint64
}

// NewService wires the adapter. The verifier's key set comes from the
// config (static JWKS file or the OpenShell gateway's JWKS URL).
func NewService(decider Decider, cfg gateway.OpenShellConfig, talonVersion string) (*Service, error) {
	var keys workload.KeySet
	switch {
	case cfg.Identity.JWKSFile != "":
		ks, err := workload.LoadJWKSFile(cfg.Identity.JWKSFile)
		if err != nil {
			return nil, err
		}
		keys = ks
	case cfg.Identity.JWKSURL != "":
		keys = workload.NewRemoteKeySet(cfg.Identity.JWKSURL, nil)
	default:
		return nil, fmt.Errorf("openshell identity: jwks_url or jwks_file is required")
	}
	if cfg.MiddlewareName == "" {
		cfg.MiddlewareName = gateway.DefaultOpenShellMiddlewareName
	}
	if cfg.MaxPayloadBytes == 0 {
		cfg.MaxPayloadBytes = gateway.DefaultOpenShellMaxPayloadBytes
	}
	// Fail closed on a negative or oversized bound before any conversion.
	if cfg.MaxPayloadBytes < 0 || cfg.MaxPayloadBytes > gateway.DefaultOpenShellMaxPayloadBytes {
		return nil, fmt.Errorf("openshell max_payload_bytes must be between 1 and %d", gateway.DefaultOpenShellMaxPayloadBytes)
	}
	return &Service{
		decider:    decider,
		cfg:        cfg,
		version:    talonVersion,
		maxPayload: uint64(cfg.MaxPayloadBytes),
		verifier: &workload.JWTVerifier{
			Issuer:      cfg.Identity.Issuer,
			Audience:    cfg.Identity.Audience,
			Type:        ExtensionTokenType,
			Keys:        keys,
			SafeClaims:  []string{claimCallerKind, claimSandboxID},
			MaxLifetime: time.Hour, // OpenShell mints extension tokens with exp ≤ 1h
		},
	}, nil
}

// Handler serves the gRPC procedures. Unregistered procedures (WebSocket
// sessions, response hooks) answer 404, which gRPC clients read as
// Unimplemented; the manifest never advertises them.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(procDescribe, connect.NewUnaryHandler(procDescribe, s.describe))
	mux.Handle(procValidateConfig, connect.NewUnaryHandler(procValidateConfig, s.validateConfig))
	mux.Handle(procEvaluateHTTP, connect.NewUnaryHandler(procEvaluateHTTP, s.evaluateHTTPRequest, connect.WithReadMaxBytes(int(s.cfg.MaxPayloadBytes)+1024*1024)))
	return mux
}

func (s *Service) describe(_ context.Context, _ *connect.Request[middlewarev1.MiddlewareDescribeRequest]) (*connect.Response[middlewarev1.MiddlewareManifest], error) {
	return connect.NewResponse(&middlewarev1.MiddlewareManifest{
		Name:             s.cfg.MiddlewareName,
		ExpectedAudience: s.cfg.Identity.Audience,
		Bindings: []*middlewarev1.MiddlewareBinding{{
			Operation:       middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST,
			Phase:           middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
			MaxPayloadBytes: s.maxPayload,
			RequestTimeout:  durationpb.New(s.cfg.RequestTimeoutDuration()),
		}},
		Extension: &extensionv1.PeerMetadata{
			ImplementationName:    "talon",
			ImplementationVersion: s.version,
		},
	}), nil
}

// validateConfig rejects any policy-local config: Talon takes no
// per-policy parameters, so nothing in an OpenShell policy can steer which
// use case or policy applies — that binding lives in Talon configuration.
func (s *Service) validateConfig(_ context.Context, req *connect.Request[middlewarev1.ValidateConfigRequest]) (*connect.Response[middlewarev1.ValidateConfigResponse], error) {
	if c := req.Msg.GetConfig(); c != nil && len(c.GetFields()) > 0 {
		return connect.NewResponse(&middlewarev1.ValidateConfigResponse{
			Valid:  false,
			Reason: "talon middleware accepts no policy-local config: bind sandboxes to Talon AI use cases in agent.talon.yaml (agent.workload_identity.bindings)",
		}), nil
	}
	return connect.NewResponse(&middlewarev1.ValidateConfigResponse{Valid: true}), nil
}

func (s *Service) evaluateHTTPRequest(ctx context.Context, req *connect.Request[middlewarev1.HttpRequestEvaluation]) (*connect.Response[middlewarev1.HttpRequestResult], error) {
	msg := req.Msg
	deny := func(code, reason string) (*connect.Response[middlewarev1.HttpRequestResult], error) {
		return connect.NewResponse(&middlewarev1.HttpRequestResult{
			Decision:   middlewarev1.Decision_DECISION_DENY,
			Reason:     reason,
			ReasonCode: reasonCode(code),
			Metadata:   map[string]string{"talon_decision": "deny"},
		}), nil
	}
	if msg.GetPhase() != middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS {
		return deny(CodePhaseUnsupported, "talon evaluates HTTP_REQUEST/PRE_CREDENTIALS only")
	}
	target := msg.GetTarget()
	if target == nil || target.GetHost() == "" {
		return deny(CodeTargetMissing, "request target missing")
	}
	if int64(len(msg.GetBody())) > s.cfg.MaxPayloadBytes {
		return deny(CodePayloadTooLarge, "request body exceeds the configured Talon payload bound")
	}

	principal, failure := s.authenticate(req.Header(), msg.GetContext())
	dreq := gateway.DelegatedRequest{
		Runtime:         RuntimeType,
		RuntimeID:       s.cfg.Identity.Issuer,
		Principal:       principal,
		IdentityFailure: failure,
		Host:            target.GetHost(),
		Path:            target.GetPath(),
		Method:          target.GetMethod(),
		Body:            msg.GetBody(),
		SessionID:       headerValue(msg.GetHeaders(), sessionHeader),
		PolicyRef:       msg.GetMiddlewareName(),
		Reference:       msg.GetContext().GetSandboxId(),
		RequestID:       msg.GetContext().GetRequestId(),
	}
	dec := s.decider.EvaluateDelegated(ctx, dreq)
	res := &middlewarev1.HttpRequestResult{
		Metadata: map[string]string{},
	}
	if dec.EvidenceID != "" {
		res.Metadata["talon_evidence_id"] = dec.EvidenceID
	}
	if dec.Agent != "" {
		res.Metadata["talon_agent"] = dec.Agent
	}
	if !dec.Allowed {
		res.Decision = middlewarev1.Decision_DECISION_DENY
		res.Reason = dec.Message
		res.ReasonCode = reasonCode(dec.Code)
		res.Metadata["talon_decision"] = "deny"
		res.Findings = findings(dec)
		return connect.NewResponse(res), nil
	}
	res.Decision = middlewarev1.Decision_DECISION_ALLOW
	res.Metadata["talon_decision"] = "allow"
	if dec.BodyChanged {
		// The replacement body is exactly what Talon evaluated as safe to
		// egress; OpenShell forwards it in place of the original.
		res.Body = dec.Body
		res.HasBody = true
	}
	res.Findings = findings(dec)
	return connect.NewResponse(res), nil
}

// authenticate verifies the supervisor's extension token and cross-checks
// it against the request context. It returns either a principal or a
// stable failure code; both outcomes are attribution-safe.
func (s *Service) authenticate(h http.Header, rc *middlewarev1.RequestContext) (principal *workload.Principal, failureCode string) {
	auth := h.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, workload.FailureMissing
	}
	p, err := s.verifier.Verify(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		code := workload.FailureCode(err)
		log.Warn().Str("failure", code).Msg("openshell_caller_token_rejected")
		return nil, code
	}
	// Only a sandbox supervisor may present model traffic; a gateway-kind
	// token is a valid OpenShell credential for a different purpose.
	if p.Claim(claimCallerKind) != callerSupervisor {
		return nil, CodeIdentityCallerKind
	}
	// The token binds ONE sandbox. The request context names a sandbox
	// too; they must agree, and the subject must be that sandbox's
	// identity — otherwise a supervisor could evaluate traffic on behalf
	// of another sandbox's use case.
	sandboxID := p.Claim(claimSandboxID)
	if sandboxID == "" || p.Subject != sandboxSubjectPrefix+sandboxID {
		return nil, CodeIdentityContextMismatch
	}
	if ctxID := rc.GetSandboxId(); ctxID != "" && ctxID != sandboxID {
		return nil, CodeIdentityContextMismatch
	}
	return p, ""
}

func headerValue(headers []*middlewarev1.HttpHeader, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.GetName(), name) {
			return h.GetValue()
		}
	}
	return ""
}

func findings(dec gateway.DelegatedDecision) []*middlewarev1.Finding {
	if len(dec.PIITypes) == 0 {
		return nil
	}
	out := make([]*middlewarev1.Finding, 0, len(dec.PIITypes))
	for _, t := range dec.PIITypes {
		label := "detected"
		if dec.Redacted {
			label = "redacted"
		}
		out = append(out, &middlewarev1.Finding{Type: "talon.pii." + strings.ToLower(t), Label: label, Count: 1, Severity: "medium", Confidence: "high"})
	}
	return out
}

var reasonCodeRe = regexp.MustCompile(`[^a-z0-9_]`)

// reasonCode fits a Talon machine code into OpenShell's
// ^[a-z][a-z0-9_]{0,63}$ constraint; OpenShell may relay it to the sandbox.
func reasonCode(code string) string {
	c := reasonCodeRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(code)), "_")
	if c == "" || c[0] < 'a' || c[0] > 'z' {
		c = "talon_" + c
	}
	if len(c) > 64 {
		c = c[:64]
	}
	return c
}

// ReceiptDigest is the sha256 hex of raw external receipt bytes.
func ReceiptDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
