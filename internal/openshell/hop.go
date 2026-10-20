package openshell

import (
	"context"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/gateway"
	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
	"github.com/dativo-io/talon/internal/workload"
)

// Self-destination hop (#457/#482): a sandbox request whose destination is
// Talon's own Action Gateway. See workload.HopSigner for the trust model.
const (
	CodeSelfDestinationPathNotGoverned = "self_destination_path_not_governed"
	CodeWorkloadAssertionUnavailable   = "workload_assertion_unavailable"

	// hopMetadataKind marks the result so operators can tell a hop
	// admission from a model decision in OpenShell's logs.
	hopMetadataKind = "workload_hop"
)

// selfHopPaths are the agent-facing Action Gateway routes a sandbox may
// reach through the hop. Reviewer decisions are deliberately absent: a
// sandbox is never a reviewer, whatever credential it may hold.
var selfHopPaths = regexp.MustCompile(`^/v1/(action-operations(/[A-Za-z0-9._:-]{1,128}(/attempts)?)?|approvals/[A-Za-z0-9._:-]{1,128})$`)

func selfHopRouteAllowed(method, path string) bool {
	if !selfHopPaths.MatchString(path) {
		return false
	}
	switch strings.ToUpper(method) {
	case "GET":
		return !strings.HasSuffix(path, "/attempts") && path != "/v1/action-operations"
	case "POST":
		return path == "/v1/action-operations" || strings.HasSuffix(path, "/attempts")
	}
	return false
}

func (s *Service) admitSelfHop(ctx context.Context, msg *middlewarev1.HttpRequestEvaluation, principal *workload.Principal, failure string) (*connect.Response[middlewarev1.HttpRequestResult], error) {
	deny := func(code, reason string) (*connect.Response[middlewarev1.HttpRequestResult], error) {
		return connect.NewResponse(&middlewarev1.HttpRequestResult{
			Decision:   middlewarev1.Decision_DECISION_DENY,
			Reason:     reason,
			ReasonCode: reasonCode(code),
			Metadata:   map[string]string{"talon_decision": "deny", "talon_kind": hopMetadataKind},
		}), nil
	}
	target := msg.GetTarget()
	if s.hop == nil {
		log.Warn().Str("host", target.GetHost()).Msg("openshell_self_hop_without_signer")
		return deny(CodeWorkloadAssertionUnavailable, "talon cannot mint a workload assertion (no root key)")
	}
	if !selfHopRouteAllowed(target.GetMethod(), target.GetPath()) {
		return deny(CodeSelfDestinationPathNotGoverned, "only the agent-facing Action Gateway routes are reachable through the runtime hop")
	}
	dec := s.decider.ResolveWorkloadHop(ctx, gateway.WorkloadHopRequest{
		Runtime: RuntimeType, Principal: principal, IdentityFailure: failure,
		Host: target.GetHost(), Method: target.GetMethod(), Path: target.GetPath(),
	})
	if !dec.Allowed {
		res, _ := deny(dec.Code, dec.Message)
		if dec.Agent != "" {
			res.Msg.Metadata["talon_agent"] = dec.Agent
		}
		return res, nil
	}
	token, err := s.hop.Mint(workload.HopClaims{
		Runtime: RuntimeType, RuntimeIssuer: principal.Issuer, Subject: principal.Subject, PrincipalID: principal.PrincipalID,
		SandboxRef: principal.Claim(claimSandboxID), RequestID: msg.GetContext().GetRequestId(),
		Agent: dec.Agent, Tenant: dec.Tenant,
		Method: target.GetMethod(), Path: target.GetPath(), BodySHA256: workload.BodyDigest(msg.GetBody()),
		SessionID: headerValue(msg.GetHeaders(), sessionHeader),
	})
	if err != nil {
		log.Error().Err(err).Msg("openshell_self_hop_mint_failed")
		return deny(CodeWorkloadAssertionUnavailable, "talon could not mint the workload assertion")
	}
	// OVERWRITE: a value the sandbox put in this header itself is replaced,
	// never appended to — ingress sees exactly one assertion, Talon's.
	return connect.NewResponse(&middlewarev1.HttpRequestResult{
		Decision: middlewarev1.Decision_DECISION_ALLOW,
		HeaderMutations: []*middlewarev1.HeaderMutation{{
			Operation: &middlewarev1.HeaderMutation_Write{Write: &middlewarev1.WriteHeader{
				Name: workload.HopAssertionHeader, Value: token,
				OnExisting: middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_OVERWRITE,
			}},
		}},
		Metadata: map[string]string{
			"talon_decision": "allow", "talon_kind": hopMetadataKind, "talon_agent": dec.Agent,
			"talon_assertion_ttl": s.hop.TTL().Round(time.Second).String(),
		},
	}), nil
}
