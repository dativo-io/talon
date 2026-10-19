package openshell

import (
	"context"
	"io"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	middlewarev1 "github.com/dativo-io/talon/internal/openshell/proto/gen/middlewarev1"
)

func responseHarness(t *testing.T, s *signer) *harness {
	t.Helper()
	return startHarness(t, s, func(c *gateway.OpenShellConfig) {
		c.ResponseGovernance = &gateway.OpenShellResponseGovernanceConfig{Enabled: true, SettlementTimeout: "30s", MaxCaptureBytes: 4096}
	})
}

type responseExchange struct {
	stream *connect.BidiStreamForClient[middlewarev1.HttpResponseEvent, middlewarev1.HttpResponseEventResult]
	cancel context.CancelFunc
}

func (h *harness) openResponse(t *testing.T, token string) *responseExchange {
	t.Helper()
	c := connect.NewClient[middlewarev1.HttpResponseEvent, middlewarev1.HttpResponseEventResult](h.client, h.url+procResponseEvaluate, connect.WithGRPC())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	st := c.CallBidiStream(ctx)
	if token != "" {
		st.RequestHeader().Set("Authorization", "Bearer "+token)
	}
	return &responseExchange{stream: st, cancel: cancel}
}

func preflightEvent(status uint32, contentType string, headers ...*middlewarev1.HttpHeader) *middlewarev1.HttpResponseEvent {
	hs := append([]*middlewarev1.HttpHeader{{Name: "content-type", Value: contentType}}, headers...)
	return &middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_Preflight{Preflight: &middlewarev1.HttpResponsePreflight{
		Context:        &middlewarev1.RequestContext{RequestId: "req-7", SandboxId: testSandbox},
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "https", Host: "api.openai.com", Port: 443, Method: "POST", Path: "/v1/chat/completions"},
		StatusCode:     status,
		Headers:        hs,
		MiddlewareName: "talon-governance",
		PermittedBodyModes: []middlewarev1.HttpResponseBodyMode{
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY,
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES,
		},
	}}}
}

func bodyEvent(seq uint64, data string, end bool) *middlewarev1.HttpResponseEvent {
	return &middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_Body{Body: &middlewarev1.HttpResponseBodyUnit{
		Sequence: seq, Payload: &middlewarev1.HttpResponseBodyUnit_Data{Data: []byte(data)}, EndOfStream: end,
	}}}
}

func sessionEnd(reason middlewarev1.MiddlewareSessionEndReason) *middlewarev1.HttpResponseEvent {
	return &middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_SessionEnd{SessionEnd: &middlewarev1.MiddlewareSessionEnd{Reason: reason}}}
}

func TestDescribe_AdvertisesResponseBindingOnlyWhenEnabled(t *testing.T) {
	s := newSigner(t, "k1")
	off := startHarness(t, s, nil)
	dc := connect.NewClient[middlewarev1.MiddlewareDescribeRequest, middlewarev1.MiddlewareManifest](off.client, off.url+procDescribe, connect.WithGRPC())
	m, err := dc.CallUnary(context.Background(), connect.NewRequest(&middlewarev1.MiddlewareDescribeRequest{Gateway: PeerMetadata("gateway-test")}))
	require.NoError(t, err)
	require.Len(t, m.Msg.GetBindings(), 1)

	on := responseHarness(t, s)
	dc = connect.NewClient[middlewarev1.MiddlewareDescribeRequest, middlewarev1.MiddlewareManifest](on.client, on.url+procDescribe, connect.WithGRPC())
	m, err = dc.CallUnary(context.Background(), connect.NewRequest(&middlewarev1.MiddlewareDescribeRequest{Gateway: PeerMetadata("gateway-test")}))
	require.NoError(t, err)
	require.Len(t, m.Msg.GetBindings(), 2)
	b := m.Msg.GetBindings()[1]
	assert.Equal(t, middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_RESPONSE, b.GetOperation())
	assert.Equal(t, middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN, b.GetPhase())
	assert.Equal(t, uint64(4096), b.GetMaxPayloadBytes())

	// Disabled: the procedure is not served at all (Unimplemented), so an
	// old registration can never make OpenShell hold responses on Talon.
	ex := off.openResponse(t, s.token(t, nil))
	defer ex.cancel()
	// The server may close the stream before or after the first Send
	// lands; connect reports a closed stream as io.EOF on Send and the
	// server's error on Receive.
	if err := ex.stream.Send(preflightEvent(200, "application/json")); err != nil {
		require.ErrorIs(t, err, io.EOF)
	}
	_, err = ex.stream.Receive()
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))
}

// Whole-body: the runtime holds the body; Talon's settlement decides pass,
// transform or block; the body result carries the evidence id.
func TestResponse_WholeBodyTransformAndBlock(t *testing.T) {
	s := newSigner(t, "k1")
	h := responseHarness(t, s)
	for name, tc := range map[string]struct {
		settle gateway.DelegatedSettlement
		check  func(t *testing.T, r *middlewarev1.HttpResponseBodyResult)
	}{
		"pass": {gateway.DelegatedSettlement{EvidenceID: "ev_p", Basis: "table"}, func(t *testing.T, r *middlewarev1.HttpResponseBodyResult) {
			assert.NotNil(t, r.GetPassThrough())
			assert.Equal(t, "pass", r.GetMetadata()["talon_decision"])
		}},
		"transform": {gateway.DelegatedSettlement{EvidenceID: "ev_t", Basis: "table", BodyChanged: true, Body: []byte(`{"redacted":true}`)}, func(t *testing.T, r *middlewarev1.HttpResponseBodyResult) {
			require.NotNil(t, r.GetTransform())
			assert.Equal(t, `{"redacted":true}`, string(r.GetTransform().GetData()))
			assert.Equal(t, "transform", r.GetMetadata()["talon_decision"])
		}},
		"block": {gateway.DelegatedSettlement{EvidenceID: "ev_b", Block: true, Code: "output_pii_blocked", Message: "blocked"}, func(t *testing.T, r *middlewarev1.HttpResponseBodyResult) {
			assert.NotNil(t, r.GetBlockDelivery())
			assert.Equal(t, "output_pii_blocked", r.GetReasonCode())
			assert.Equal(t, "block", r.GetMetadata()["talon_decision"])
		}},
	} {
		t.Run(name, func(t *testing.T) {
			h.gw.settle = func(gateway.DelegatedResponseBody) gateway.DelegatedSettlement { return tc.settle }
			ex := h.openResponse(t, s.token(t, nil))
			defer ex.cancel()
			require.NoError(t, ex.stream.Send(preflightEvent(200, "application/json")))
			res, err := ex.stream.Receive()
			require.NoError(t, err)
			pr := res.GetPreflightResult()
			require.NotNil(t, pr)
			require.NotNil(t, pr.GetInspect(), "%v", pr)
			assert.Equal(t, middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES, pr.GetInspect().GetBodyMode())
			assert.Equal(t, "sandboxed-agent", pr.GetMetadata()["talon_agent"])

			require.NoError(t, ex.stream.Send(bodyEvent(1, `{"usage":{"prompt_tokens":1}}`, true)))
			res, err = ex.stream.Receive()
			require.NoError(t, err)
			br := res.GetBodyResult()
			require.NotNil(t, br)
			assert.Equal(t, uint64(1), br.GetSequence())
			assert.Equal(t, tc.settle.EvidenceID, br.GetMetadata()["talon_evidence_id"])
			tc.check(t, br)
			require.NoError(t, ex.stream.Send(sessionEnd(middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL)))
			require.NoError(t, ex.stream.CloseRequest())

			h.gw.mu.Lock()
			last := h.gw.settlements[len(h.gw.settlements)-1]
			pf := h.gw.preflights[len(h.gw.preflights)-1]
			h.gw.mu.Unlock()
			assert.Equal(t, gateway.ResponseModeWholeBody, last.Mode)
			assert.Equal(t, `{"usage":{"prompt_tokens":1}}`, string(last.Body))
			assert.Equal(t, "", last.Incomplete)
			assert.Equal(t, "req-7", pf.RequestID)
			assert.Equal(t, testSandbox, pf.SandboxRef)
			assert.Equal(t, 200, pf.Status)
			assert.Equal(t, "application/json", pf.ContentType)
			assert.True(t, pf.BodyInspectable)
			require.NotNil(t, pf.Principal)
			assert.Equal(t, sandboxSubjectPrefix+testSandbox, pf.Principal.Subject)
		})
	}
}

// Stream: every unit is passed as it arrives; the final unit settles the
// accumulated capture as an observation; a bound hit is reported as such.
func TestResponse_StreamPassesUnitsAndSettlesOnce(t *testing.T) {
	s := newSigner(t, "k1")
	h := responseHarness(t, s)
	h.gw.plan = func(pf gateway.DelegatedResponsePreflight) gateway.DelegatedResponsePlan {
		return gateway.DelegatedResponsePlan{Mode: gateway.ResponseModeStream, Matched: true, Agent: "sandboxed-agent"}
	}
	ex := h.openResponse(t, s.token(t, nil))
	defer ex.cancel()
	require.NoError(t, ex.stream.Send(preflightEvent(200, "text/event-stream")))
	res, err := ex.stream.Receive()
	require.NoError(t, err)
	assert.Equal(t, middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES, res.GetPreflightResult().GetInspect().GetBodyMode())
	chunks := []string{"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n", "data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n", "data: {\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1}}\n\ndata: [DONE]\n\n"}
	for i, c := range chunks {
		require.NoError(t, ex.stream.Send(bodyEvent(uint64(i+1), c, i == len(chunks)-1)))
		res, err = ex.stream.Receive()
		require.NoError(t, err)
		br := res.GetBodyResult()
		require.NotNil(t, br)
		assert.Equal(t, uint64(i+1), br.GetSequence())
		assert.NotNil(t, br.GetPassThrough(), "observation never changes bytes")
	}
	require.NoError(t, ex.stream.Send(sessionEnd(middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL)))
	require.NoError(t, ex.stream.CloseRequest())
	time.Sleep(50 * time.Millisecond)
	h.gw.mu.Lock()
	defer h.gw.mu.Unlock()
	require.Len(t, h.gw.settlements, 1, "exactly one settlement per exchange")
	st := h.gw.settlements[0]
	assert.Equal(t, gateway.ResponseModeStream, st.Mode)
	assert.Equal(t, chunks[0]+chunks[1]+chunks[2], string(st.Body))
	assert.False(t, st.Truncated)
	assert.Equal(t, int64(len(st.Body)), st.BytesSeen)
	assert.Equal(t, int64(4096), st.CaptureCap)
}

func TestResponse_CaptureBoundAndAbnormalEnd(t *testing.T) {
	s := newSigner(t, "k1")
	h := responseHarness(t, s)
	h.gw.plan = func(gateway.DelegatedResponsePreflight) gateway.DelegatedResponsePlan {
		return gateway.DelegatedResponsePlan{Mode: gateway.ResponseModeStream, Matched: true}
	}
	ex := h.openResponse(t, s.token(t, nil))
	defer ex.cancel()
	require.NoError(t, ex.stream.Send(preflightEvent(200, "text/event-stream")))
	_, err := ex.stream.Receive()
	require.NoError(t, err)
	big := make([]byte, 3000)
	for i := range big {
		big[i] = 'x'
	}
	for i := 1; i <= 2; i++ {
		require.NoError(t, ex.stream.Send(bodyEvent(uint64(i), string(big), false)))
		_, err = ex.stream.Receive()
		require.NoError(t, err)
	}
	// The upstream died before the end of the stream.
	require.NoError(t, ex.stream.Send(sessionEnd(middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_UPSTREAM_DISCONNECT)))
	require.NoError(t, ex.stream.CloseRequest())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.gw.mu.Lock()
		n := len(h.gw.settlements)
		h.gw.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.gw.mu.Lock()
	defer h.gw.mu.Unlock()
	require.Len(t, h.gw.settlements, 1)
	st := h.gw.settlements[0]
	assert.True(t, st.Truncated, "capture bound (4096) exceeded by 6000 bytes")
	assert.LessOrEqual(t, len(st.Body), 4096)
	assert.Equal(t, int64(6000), st.BytesSeen)
	assert.Equal(t, evidence.ResponseScanIncompleteUpstreamError, st.Incomplete)
}

// Identity failures and plan-level blocks answer the preflight with
// block_delivery; nothing is inspected or settled.
func TestResponse_IdentityFailureBlocksDelivery(t *testing.T) {
	s := newSigner(t, "k1")
	forger := newSigner(t, "k1")
	h := responseHarness(t, s)
	for name, token := range map[string]string{"no token": "", "forged": forger.token(t, nil)} {
		t.Run(name, func(t *testing.T) {
			ex := h.openResponse(t, token)
			defer ex.cancel()
			require.NoError(t, ex.stream.Send(preflightEvent(200, "application/json")))
			res, err := ex.stream.Receive()
			require.NoError(t, err)
			pr := res.GetPreflightResult()
			require.NotNil(t, pr)
			assert.NotNil(t, pr.GetBlockDelivery())
			assert.Equal(t, reasonCode(gateway.CodeWorkloadIdentityRequired), pr.GetReasonCode())
			require.NoError(t, ex.stream.Send(sessionEnd(middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_MIDDLEWARE_DENIAL)))
			require.NoError(t, ex.stream.CloseRequest())
		})
	}
	h.gw.mu.Lock()
	defer h.gw.mu.Unlock()
	assert.Empty(t, h.gw.settlements)
	for _, pf := range h.gw.preflights {
		assert.Nil(t, pf.Principal)
	}
}

// Allowed model requests ask the provider for an uncompressed response when
// a settlement is pending, so the response hook can inspect the body.
func TestEvaluate_SettlingRequestAsksForIdentityEncoding(t *testing.T) {
	s := newSigner(t, "k1")
	h := responseHarness(t, s)
	h.gw.decision = gateway.DelegatedDecision{Allowed: true, Status: 200, EvidenceID: "ev_1", Agent: "sandboxed-agent", ResponseGovernance: true}
	res := h.evaluate(t, s.token(t, nil), chatEval(`{"model":"gpt-4o-mini","messages":[]}`))
	require.Equal(t, middlewarev1.Decision_DECISION_ALLOW, res.GetDecision())
	var found bool
	for _, m := range res.GetHeaderMutations() {
		if w := m.GetWrite(); w != nil && w.GetName() == "Accept-Encoding" {
			found = true
			assert.Equal(t, "identity", w.GetValue())
			assert.Equal(t, middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_OVERWRITE, w.GetOnExisting())
		}
	}
	assert.True(t, found, "Accept-Encoding mutation missing: %v", res.GetHeaderMutations())
	assert.Equal(t, "pending", res.GetMetadata()["talon_response_governance"])
}

// Responses from Talon's own Action Gateway (self-destination host) reach
// the hook because OpenShell selects middleware by host; they are skipped
// without consulting the decider — they are not model responses.
func TestResponse_SelfDestinationIsSkipped(t *testing.T) {
	s := newSigner(t, "k1")
	h := startHarness(t, s, func(c *gateway.OpenShellConfig) {
		c.ResponseGovernance = &gateway.OpenShellResponseGovernanceConfig{Enabled: true, SettlementTimeout: "30s", MaxCaptureBytes: 4096}
		c.SelfDestination = &gateway.OpenShellSelfDestinationConfig{Hosts: []string{"api.openai.com:8080"}}
	})
	ex := h.openResponse(t, s.token(t, nil))
	defer ex.cancel()
	pf := preflightEvent(201, "application/json")
	pf.GetPreflight().Target.Port = 8080
	require.NoError(t, ex.stream.Send(pf))
	res, err := ex.stream.Receive()
	require.NoError(t, err)
	pr := res.GetPreflightResult()
	require.NotNil(t, pr)
	assert.NotNil(t, pr.GetSkip(), "%v", pr)
	assert.Equal(t, CodeSelfDestinationResponse, pr.GetReasonCode())
	require.NoError(t, ex.stream.Send(sessionEnd(middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL)))
	require.NoError(t, ex.stream.CloseRequest())
	h.gw.mu.Lock()
	defer h.gw.mu.Unlock()
	assert.Empty(t, h.gw.preflights, "the decider is not consulted")
	assert.Empty(t, h.gw.settlements)
}
