package openshell

import (
	"context"
	"errors"
	"io"
	"strings"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
	"github.com/dativo-io/talon/internal/workload"
)

// HTTP_RESPONSE / PRE_RETURN (#482 response side).
//
// OpenShell opens one bidirectional stream per provider response: a
// preflight (status, headers, permitted body modes), then — if Talon asks to
// inspect — the body as one unit (WHOLE_BODY_BYTES, held until Talon
// answers) or ordered units (STREAM_BYTES, delivered as Talon passes them),
// then trailers and a session end. Talon's answers are what OpenShell
// enforces: pass, transform (replacement bytes) or block_delivery. The
// settlement itself (usage, cost, session budget, signed record) is the
// gateway's; this file is the wire adapter.
const (
	procResponseEvaluate = "/openshell.middleware.v1.HttpResponsePreReturn/Evaluate"

	CodeResponseProtocol = "response_protocol_error"
	// CodeSelfDestinationResponse: a response from Talon's own API (the
	// Action Gateway hop), not a provider response; skipped.
	CodeSelfDestinationResponse = "self_destination_response"
)

// responseStream is the subset of the connect bidi stream the adapter uses
// (narrow seam for tests).
type responseStream interface {
	Receive() (*middlewarev1.HttpResponseEvent, error)
	Send(*middlewarev1.HttpResponseEventResult) error
}

func (s *Service) evaluateHTTPResponse(ctx context.Context, stream *connect.BidiStream[middlewarev1.HttpResponseEvent, middlewarev1.HttpResponseEventResult]) error {
	return s.serveResponse(ctx, stream.RequestHeader().Get("Authorization"), stream)
}

// serveResponse runs one response exchange to completion.
//
//nolint:gocyclo // the exchange is one ordered protocol sequence; the branches are its states
func (s *Service) serveResponse(ctx context.Context, authorization string, stream responseStream) error {
	first, err := stream.Receive()
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("response exchange opened without a preflight"))
	}
	pf := first.GetPreflight()
	if pf == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first response event must be a preflight"))
	}
	var principal *workload.Principal
	failure := workload.FailureMissing
	if strings.HasPrefix(authorization, "Bearer ") {
		principal, failure = s.authenticateToken(strings.TrimPrefix(authorization, "Bearer "), pf.GetContext())
	}
	headers := pf.GetHeaders()
	modes := pf.GetPermittedBodyModes()
	if s.cfg.SelfDestination.IsSelfHost(pf.GetTarget().GetHost(), pf.GetTarget().GetPort()) {
		// OpenShell selects middleware by host, so when Talon's own Action
		// Gateway shares a host with a provider the gateway also offers
		// Talon's own responses here. They are not model responses: nothing
		// to settle, nothing to scan — skip without consulting the decider.
		if err := stream.Send(&middlewarev1.HttpResponseEventResult{Result: &middlewarev1.HttpResponseEventResult_PreflightResult{PreflightResult: &middlewarev1.HttpResponsePreflightResult{
			Action: &middlewarev1.HttpResponsePreflightResult_Skip{Skip: &middlewarev1.HttpResponsePreflightSkip{}}, ReasonCode: reasonCode(CodeSelfDestinationResponse),
			Metadata: map[string]string{"talon_kind": "response", "talon_decision": "skip"},
		}}}); err != nil {
			return err
		}
		return drain(stream)
	}
	preflight := gateway.DelegatedResponsePreflight{
		Runtime: RuntimeType, RuntimeID: s.cfg.Identity.Issuer, Principal: principal, IdentityFailure: failure,
		Host: pf.GetTarget().GetHost(), SandboxRef: pf.GetContext().GetSandboxId(), RequestID: pf.GetContext().GetRequestId(),
		Status: int(pf.GetStatusCode()), ContentType: headerValue(headers, "content-type"), ContentEncoding: headerValue(headers, "content-encoding"),
		BodyInspectable: modePermitted(modes, middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES),
		StreamPermitted: modePermitted(modes, middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES),
	}
	plan := s.decider.PlanDelegatedResponse(ctx, preflight)
	meta := map[string]string{"talon_kind": "response"}
	if plan.Agent != "" {
		meta["talon_agent"] = plan.Agent
	}
	if plan.Block {
		meta["talon_decision"] = "block"
		if err := stream.Send(&middlewarev1.HttpResponseEventResult{Result: &middlewarev1.HttpResponseEventResult_PreflightResult{PreflightResult: &middlewarev1.HttpResponsePreflightResult{
			Action: &middlewarev1.HttpResponsePreflightResult_BlockDelivery{BlockDelivery: &middlewarev1.HttpResponseBlockDelivery{}},
			Reason: plan.Message, ReasonCode: reasonCode(plan.Code), Metadata: meta,
		}}}); err != nil {
			return err
		}
		return drain(stream)
	}
	if plan.Mode == gateway.ResponseModeSkip {
		meta["talon_decision"] = "skip"
		if err := stream.Send(&middlewarev1.HttpResponseEventResult{Result: &middlewarev1.HttpResponseEventResult_PreflightResult{PreflightResult: &middlewarev1.HttpResponsePreflightResult{
			Action: &middlewarev1.HttpResponsePreflightResult_Skip{Skip: &middlewarev1.HttpResponsePreflightSkip{}}, ReasonCode: reasonCode(plan.Code), Metadata: meta,
		}}}); err != nil {
			return err
		}
		return drain(stream)
	}
	bodyMode := middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES
	switch plan.Mode {
	case gateway.ResponseModeHeadersOnly:
		bodyMode = middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY
	case gateway.ResponseModeStream:
		bodyMode = middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES
	}
	meta["talon_decision"] = "inspect"
	if err := stream.Send(&middlewarev1.HttpResponseEventResult{Result: &middlewarev1.HttpResponseEventResult_PreflightResult{PreflightResult: &middlewarev1.HttpResponsePreflightResult{
		Action: &middlewarev1.HttpResponsePreflightResult_Inspect{Inspect: &middlewarev1.HttpResponsePreflightInspect{BodyMode: bodyMode}}, Metadata: meta,
	}}}); err != nil {
		return err
	}

	in := gateway.DelegatedResponseBody{Preflight: preflight, Mode: plan.Mode, CaptureCap: s.captureCap()}
	if plan.Mode == gateway.ResponseModeHeadersOnly {
		// Nothing more arrives for the body; settle from the headers now so
		// usage-less and error responses still close the exchange.
		st := s.decider.SettleDelegatedResponse(ctx, in)
		log.Debug().Str("evidence_id", st.EvidenceID).Msg("openshell_response_settled_headers_only")
		return drain(stream)
	}

	var capture []byte
	settled := false
	for {
		ev, err := stream.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// The runtime went away mid-body: settle what was seen as an
			// incomplete observation so usage and cost are not lost.
			if !settled {
				in.Body, in.Incomplete = capture, evidence.ResponseScanIncompleteClientCancelled
				s.decider.SettleDelegatedResponse(ctx, in)
			}
			return nil
		}
		switch e := ev.GetEvent().(type) {
		case *middlewarev1.HttpResponseEvent_Body:
			unit := e.Body
			data := unit.GetData()
			in.BytesSeen += int64(len(data))
			if int64(len(capture))+int64(len(data)) <= in.CaptureCap {
				capture = append(capture, data...)
			} else {
				in.Truncated = true
				if plan.Mode == gateway.ResponseModeWholeBody {
					// A whole body beyond the bound cannot be scanned; a
					// preventive policy fails closed in the gateway's settlement.
					capture = append(capture, data[:max(0, int(in.CaptureCap)-len(capture))]...)
				}
			}
			if plan.Mode == gateway.ResponseModeStream && !unit.GetEndOfStream() {
				// Observation: every unit is passed as it arrives.
				if err := stream.Send(bodyResult(unit.GetSequence(), &middlewarev1.HttpResponseBodyResult_PassThrough{PassThrough: &middlewarev1.HttpResponseBodyPassThrough{}}, "", nil)); err != nil {
					return err
				}
				continue
			}
			if !unit.GetEndOfStream() && plan.Mode == gateway.ResponseModeWholeBody {
				// WHOLE_BODY delivers exactly one unit; a continuation is a
				// protocol violation — fail closed.
				return connect.NewError(connect.CodeInvalidArgument, errors.New("whole-body inspection received more than one body unit"))
			}
			in.Body = capture
			if in.Truncated && plan.Mode == gateway.ResponseModeWholeBody {
				in.Incomplete = evidence.ResponseScanIncompleteCaptureLimitExceeded
			}
			st := s.decider.SettleDelegatedResponse(ctx, in)
			settled = true
			res := settlementBodyResult(unit.GetSequence(), plan.Mode, in.Truncated, st)
			if err := stream.Send(res); err != nil {
				return err
			}
		case *middlewarev1.HttpResponseEvent_Trailers:
			if err := stream.Send(&middlewarev1.HttpResponseEventResult{Result: &middlewarev1.HttpResponseEventResult_TrailersResult{TrailersResult: &middlewarev1.HttpResponseTrailersResult{}}}); err != nil {
				return err
			}
		case *middlewarev1.HttpResponseEvent_SessionEnd:
			if !settled {
				in.Body, in.Incomplete = capture, sessionEndIncompleteReason(e.SessionEnd.GetReason())
				s.decider.SettleDelegatedResponse(ctx, in)
			}
			return nil
		case *middlewarev1.HttpResponseEvent_Preflight:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("second preflight on one response exchange"))
		}
	}
	if !settled {
		in.Body, in.Incomplete = capture, evidence.ResponseScanIncompleteClientCancelled
		s.decider.SettleDelegatedResponse(ctx, in)
	}
	return nil
}

// settlementBodyResult maps the gateway's settlement to the wire answer.
// Whole-body: block → block_delivery, changed → transform, else pass.
// Stream (observation): the final unit passes; a truncated or blocked
// observation can no longer change delivered bytes and says so in evidence.
func settlementBodyResult(seq uint64, mode string, truncated bool, st gateway.DelegatedSettlement) *middlewarev1.HttpResponseEventResult {
	meta := map[string]string{"talon_kind": "response"}
	if st.EvidenceID != "" {
		meta["talon_evidence_id"] = st.EvidenceID
	}
	if st.Basis != "" {
		meta["talon_pricing_basis"] = st.Basis
	}
	if mode == gateway.ResponseModeWholeBody {
		switch {
		case st.Block:
			meta["talon_decision"] = "block"
			return bodyResult(seq, &middlewarev1.HttpResponseBodyResult_BlockDelivery{BlockDelivery: &middlewarev1.HttpResponseBlockDelivery{}}, reasonCode(st.Code), meta)
		case truncated:
			// The bound was hit on a whole body: the gateway settled with
			// what it saw; a preventive policy already blocked above, so
			// this is an observed-only pass of the ORIGINAL bytes.
			meta["talon_decision"] = "pass"
			return bodyResult(seq, &middlewarev1.HttpResponseBodyResult_PassThrough{PassThrough: &middlewarev1.HttpResponseBodyPassThrough{}}, "", meta)
		case st.BodyChanged:
			meta["talon_decision"] = "transform"
			return bodyResult(seq, &middlewarev1.HttpResponseBodyResult_Transform{Transform: &middlewarev1.HttpResponseBodyTransform{Replacement: &middlewarev1.HttpResponseBodyTransform_Data{Data: st.Body}}}, "", meta)
		}
	}
	meta["talon_decision"] = "pass"
	return bodyResult(seq, &middlewarev1.HttpResponseBodyResult_PassThrough{PassThrough: &middlewarev1.HttpResponseBodyPassThrough{}}, "", meta)
}

func bodyResult(seq uint64, action any, code string, meta map[string]string) *middlewarev1.HttpResponseEventResult {
	r := &middlewarev1.HttpResponseBodyResult{Sequence: seq, ReasonCode: code, Metadata: meta}
	switch a := action.(type) {
	case *middlewarev1.HttpResponseBodyResult_PassThrough:
		r.Action = a
	case *middlewarev1.HttpResponseBodyResult_Transform:
		r.Action = a
	case *middlewarev1.HttpResponseBodyResult_BlockDelivery:
		r.Action = a
	}
	return &middlewarev1.HttpResponseEventResult{Result: &middlewarev1.HttpResponseEventResult_BodyResult{BodyResult: r}}
}

// drain reads the rest of an exchange Talon has already answered, so the
// runtime's session end never surfaces as a transport error.
func drain(stream responseStream) error {
	for {
		ev, err := stream.Receive()
		if err != nil {
			return nil
		}
		if ev.GetSessionEnd() != nil {
			return nil
		}
	}
}

func modePermitted(modes []middlewarev1.HttpResponseBodyMode, want middlewarev1.HttpResponseBodyMode) bool {
	if len(modes) == 0 {
		// An older gateway that lists nothing permits everything the proto
		// defines; the gateway's settlement still handles a failed inspection.
		return true
	}
	for _, m := range modes {
		if m == want {
			return true
		}
	}
	return false
}

func sessionEndIncompleteReason(r middlewarev1.MiddlewareSessionEndReason) string {
	switch r {
	case middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL:
		return ""
	case middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_UPSTREAM_FAILURE,
		middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_UPSTREAM_DISCONNECT:
		return evidence.ResponseScanIncompleteUpstreamError
	default:
		return evidence.ResponseScanIncompleteClientCancelled
	}
}

func (s *Service) captureCap() int64 {
	if s.cfg.ResponseGovernance != nil && s.cfg.ResponseGovernance.MaxCaptureBytes > 0 {
		return s.cfg.ResponseGovernance.MaxCaptureBytes
	}
	return gateway.DefaultOpenShellMaxCaptureBytes
}
