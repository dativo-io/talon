// Package openshell is the transport adapter that lets Talon act as an
// NVIDIA OpenShell supervisor middleware (#482).
//
// Pinned upstream contract: OpenShell v0.1.3, proto package
// openshell.middleware.v1 (internal/openshell/proto/v0.1.3, byte-identical to
// the v0.1.2 wire contract; see PROVENANCE.md). OpenShell
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
	"unicode"

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
	// implements and was tested against.
	UpstreamVersion = "v0.1.3"
	// Extension protocol (openshell.extension.v1) this adapter speaks. The
	// gateway refuses an extension with another major or without a version;
	// Talon refuses a gateway likewise (reciprocal, fail closed).
	ProtocolMajor uint32 = 1
	ProtocolMinor uint32 = 0
	// ContractCapability is the one capability both peers require of each
	// other for the supervisor-middleware family.
	ContractCapability = "openshell.supervisor-middleware.contract"
	// ImplementationName is Talon's stable extension identity (diagnostic).
	ImplementationName = "talon"
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

// describe answers the gateway's startup probe. Negotiation is reciprocal
// and fails closed: a gateway without peer metadata, with another protocol
// major, requiring a capability Talon lacks, or lacking a capability Talon
// requires is refused with FailedPrecondition — the gateway then refuses to
// start rather than run against an incompatible middleware. The manifest
// advertises ONLY what this adapter implements: one binding,
// HTTP_REQUEST/PRE_CREDENTIALS. Response (PRE_RETURN) and WebSocket bindings
// exist in the v0.1.3 contract and are deliberately absent here.
func (s *Service) describe(_ context.Context, req *connect.Request[middlewarev1.MiddlewareDescribeRequest]) (*connect.Response[middlewarev1.MiddlewareManifest], error) {
	if err := NegotiatePeer(req.Msg.GetGateway()); err != nil {
		log.Warn().Str("reason", err.Code).Msg("openshell_gateway_negotiation_refused")
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return connect.NewResponse(&middlewarev1.MiddlewareManifest{
		Name:             s.cfg.MiddlewareName,
		ExpectedAudience: s.cfg.Identity.Audience,
		Bindings: []*middlewarev1.MiddlewareBinding{{
			Operation:       middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST,
			Phase:           middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
			MaxPayloadBytes: s.maxPayload,
			RequestTimeout:  durationpb.New(s.cfg.RequestTimeoutDuration()),
		}},
		Extension: PeerMetadata(s.version),
	}), nil
}

// PeerMetadata is the extension metadata Talon presents: protocol 1.0, its
// identity, and the family contract capability as both supported and
// required (OpenShell's own extension_metadata shape).
func PeerMetadata(version string) *extensionv1.PeerMetadata {
	return &extensionv1.PeerMetadata{
		ProtocolVersion:       &extensionv1.ProtocolVersion{Major: ProtocolMajor, Minor: ProtocolMinor},
		ImplementationName:    ImplementationName,
		ImplementationVersion: version,
		SupportedCapabilities: []string{ContractCapability},
		RequiredCapabilities:  []string{ContractCapability},
	}
}

// NegotiationError is a stable, secret-free negotiation refusal.
type NegotiationError struct {
	Code    string
	Message string
}

func (e *NegotiationError) Error() string { return e.Code + ": " + e.Message }

// Negotiation refusal codes.
const (
	CodePeerMetadataMissing   = "peer_metadata_missing"
	CodePeerProtocolVersion   = "peer_protocol_version_incompatible"
	CodePeerCapabilityMissing = "peer_capability_missing"
	CodePeerMetadataInvalid   = "peer_metadata_invalid"
)

// Bounds and grammar ported from OpenShell v0.1.3
// crates/openshell-core/src/extension_protocol.rs (validate_text,
// normalize_capabilities, valid_capability). Kept local on purpose: no
// dependency on OpenShell source, just the same contract.
const (
	maxPeerCapabilities   = 128
	maxPeerCapabilityByte = 128
	maxPeerTextBytes      = 128
	capabilityPrefix      = "openshell."
)

// NegotiatePeer applies the extension-protocol handshake rules to the
// gateway's metadata from the extension's side (the mirror of
// openshell_core::extension_protocol::negotiate): metadata and protocol
// version required, same major (minor skew allowed), implementation
// name/version non-blank, ≤128 bytes and control-free, capability lists
// ≤128 well-formed unique entries, every capability the gateway requires
// must be one Talon supports, and every capability Talon requires must be
// one the gateway supports. Implementation identity is diagnostic only and
// is never compared against a fixed name.
func NegotiatePeer(gw *extensionv1.PeerMetadata) *NegotiationError {
	if gw == nil {
		return &NegotiationError{Code: CodePeerMetadataMissing, Message: "gateway did not provide extension protocol metadata; upgrade the gateway and Talon together"}
	}
	pv := gw.GetProtocolVersion()
	if pv == nil {
		return &NegotiationError{Code: CodePeerMetadataMissing, Message: "gateway did not provide an extension protocol version"}
	}
	if pv.GetMajor() != ProtocolMajor {
		return &NegotiationError{Code: CodePeerProtocolVersion, Message: fmt.Sprintf("gateway speaks extension protocol %d.%d; talon supports %d.%d", pv.GetMajor(), pv.GetMinor(), ProtocolMajor, ProtocolMinor)}
	}
	if err := validateText("implementation_name", gw.GetImplementationName()); err != nil {
		return err
	}
	if err := validateText("implementation_version", gw.GetImplementationVersion()); err != nil {
		return err
	}
	supported, err := normalizeCapabilities("supported_capabilities", gw.GetSupportedCapabilities())
	if err != nil {
		return err
	}
	required, err := normalizeCapabilities("required_capabilities", gw.GetRequiredCapabilities())
	if err != nil {
		return err
	}
	talonSupports := map[string]bool{ContractCapability: true}
	for cap := range required {
		if !talonSupports[cap] {
			return &NegotiationError{Code: CodePeerCapabilityMissing, Message: "gateway requires capability " + cap + ", which talon does not implement"}
		}
	}
	if !supported[ContractCapability] {
		return &NegotiationError{Code: CodePeerCapabilityMissing, Message: "gateway does not advertise the required capability " + ContractCapability}
	}
	return nil
}

// validateText mirrors validate_text: not blank after trimming, at most
// maxPeerTextBytes bytes, no control characters.
func validateText(field, value string) *NegotiationError {
	switch {
	case strings.TrimSpace(value) == "":
		return &NegotiationError{Code: CodePeerMetadataInvalid, Message: "gateway " + field + " must not be empty"}
	case len(value) > maxPeerTextBytes:
		return &NegotiationError{Code: CodePeerMetadataInvalid, Message: fmt.Sprintf("gateway %s must be at most %d bytes", field, maxPeerTextBytes)}
	case strings.ContainsFunc(value, unicode.IsControl):
		return &NegotiationError{Code: CodePeerMetadataInvalid, Message: "gateway " + field + " must not contain control characters"}
	}
	return nil
}

// normalizeCapabilities mirrors normalize_capabilities: at most
// maxPeerCapabilities entries, each a valid capability, no duplicates.
func normalizeCapabilities(field string, list []string) (map[string]bool, *NegotiationError) {
	if len(list) > maxPeerCapabilities {
		return nil, &NegotiationError{Code: CodePeerMetadataInvalid, Message: fmt.Sprintf("gateway %s must contain at most %d entries", field, maxPeerCapabilities)}
	}
	out := make(map[string]bool, len(list))
	for _, c := range list {
		if !validCapability(c) {
			return nil, &NegotiationError{Code: CodePeerMetadataInvalid, Message: fmt.Sprintf("gateway %s: %q must be a lowercase namespaced identifier (openshell.<family>.<name>, segments of a-z, 0-9, -)", field, c)}
		}
		if out[c] {
			return nil, &NegotiationError{Code: CodePeerMetadataInvalid, Message: fmt.Sprintf("gateway %s contains duplicate %q", field, c)}
		}
		out[c] = true
	}
	return out, nil
}

func capabilityByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-'
}

// validCapability mirrors valid_capability: non-empty, ≤128 bytes, starts
// with "openshell.", at least three dot-separated segments, every segment
// non-empty and made of lowercase ASCII letters, digits or '-'.
func validCapability(value string) bool {
	if value == "" || len(value) > maxPeerCapabilityByte || !strings.HasPrefix(value, capabilityPrefix) {
		return false
	}
	segments := strings.Split(value, ".")
	if len(segments) < 3 {
		return false
	}
	for _, seg := range segments {
		if seg == "" {
			return false
		}
		for i := 0; i < len(seg); i++ {
			if !capabilityByte(seg[i]) {
				return false
			}
		}
	}
	return true
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
