package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
)

func responseGoverned(cfg *GatewayConfig) {
	cfg.OpenShell = &OpenShellConfig{
		Enabled: true, Listen: "127.0.0.1:0", AllowInsecureTransport: true,
		Identity:           OpenShellIdentityConfig{Issuer: delegatedIssuer, Audience: "urn:openshell:extension:middleware:talon", JWKSFile: "/dev/null"},
		ResponseGovernance: &OpenShellResponseGovernanceConfig{Enabled: true, SettlementTimeout: "30s", MaxCaptureBytes: 1 << 20},
	}
	require.NoError(nil, nil)
}

func preflightFor(status int, contentType string) DelegatedResponsePreflight {
	return DelegatedResponsePreflight{
		Runtime: "openshell", RuntimeID: delegatedIssuer, Principal: delegatedPrincipal(delegatedSubject),
		Host: "api.openai.com", SandboxRef: "sb-42", RequestID: "req-1", Status: status, ContentType: contentType,
		BodyInspectable: true, StreamPermitted: true,
	}
}

func recordsOfType(t *testing.T, store *evidence.Store, typ string) []evidence.Evidence {
	t.Helper()
	var out []evidence.Evidence
	all := listDelegated(t, store, "sandboxed-agent")
	for i := range all {
		if all[i].InvocationType == typ {
			out = append(out, all[i])
		}
	}
	return out
}

const chatBody = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`

// With response governance the decision record books no cost: the cost is
// carried by the settlement. The pending estimate still counts toward the
// budget caps, and the hop is told to request an uncompressed response.
func TestDelegatedResponse_DecisionParksSettlement(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody))
	require.True(t, dec.Allowed, "%+v", dec)
	assert.True(t, dec.ResponseGovernance)

	recs := recordsOfType(t, store, "gateway")
	require.Len(t, recs, 1)
	ev := recs[0]
	assert.Equal(t, 0.0, ev.Execution.Cost, "no cost booked before the response")
	assert.Greater(t, ev.Execution.EstimatedCost, 0.0)
	assert.Equal(t, PricingBasisAwaitingSettlement, ev.Execution.PricingBasis)
	assert.False(t, ev.Execution.PricingKnown)
	assert.Contains(t, ev.GatewayAnnotations, annotationSettlementPending)
	assert.Equal(t, 1, gw.delegatedPending.len())

	agent, ok := gw.registry.Current().ResolveWorkload("openshell", delegatedSubject)
	require.True(t, ok)
	daily, monthly, unavailable := gw.agentCostTotals(context.Background(), agent)
	assert.False(t, unavailable)
	assert.InDelta(t, ev.Execution.EstimatedCost, daily, 1e-9, "the pending estimate counts against the daily cap")
	assert.InDelta(t, ev.Execution.EstimatedCost, monthly, 1e-9)
}

// The settlement observes actual usage, prices it, and commits a second
// record under the same correlation id; the decision record is untouched.
func TestDelegatedResponse_SettlesUsageAndCost(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody))
	require.True(t, dec.Allowed)
	body := `{"id":"cmpl-1","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"all good"}}],"usage":{"prompt_tokens":120,"completion_tokens":30,"total_tokens":150}}`
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(body)})
	assert.False(t, st.Block)
	assert.False(t, st.BodyChanged)
	assert.NotEmpty(t, st.EvidenceID)
	assert.Equal(t, TokenUsage{Input: 120, Output: 30}, st.Tokens)
	assert.Greater(t, st.Cost, 0.0)
	assert.NotEqual(t, PricingBasisAwaitingSettlement, st.Basis)
	assert.NotEqual(t, PricingBasisEstimateNoUsage, st.Basis, "usage was observed, so the cost is priced, not estimated")
	assert.Equal(t, 0, gw.delegatedPending.len())

	decisions := recordsOfType(t, store, "gateway")
	settlements := recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, decisions, 1)
	require.Len(t, settlements, 1)
	s := settlements[0]
	require.True(t, store.VerifyRecord(&s))
	assert.Equal(t, decisions[0].CorrelationID, s.CorrelationID, "same correlation id joins decision and settlement")
	assert.Equal(t, decisions[0].SessionID, s.SessionID)
	assert.Equal(t, 120, s.Execution.Tokens.Input)
	assert.Equal(t, 30, s.Execution.Tokens.Output)
	assert.InDelta(t, st.Cost, s.Execution.Cost, 1e-12)
	assert.Equal(t, decisions[0].Execution.EstimatedCost, s.Execution.EstimatedCost, "the estimate stays visible next to the actual")
	assert.Contains(t, s.GatewayAnnotations, annotationResponseObserved)
	assert.NotContains(t, s.GatewayAnnotations, annotationDecisionUnmatched)
	assert.Equal(t, UpstreamAuthModeExternalRuntime, s.UpstreamAuthMode)
	require.NotNil(t, s.Enforcement)
	assert.Equal(t, evidence.ProvenanceDelegatedExpected, s.Enforcement.Provenance)
	assert.Equal(t, "sb-42", s.Enforcement.Runtime.Reference)
	require.NotNil(t, s.WorkloadIdentity)
	assert.Equal(t, delegatedSubject, s.WorkloadIdentity.Subject)
	assert.Equal(t, 0.0, decisions[0].Execution.Cost, "the decision record is never rewritten")

	// A second settlement for the same request id has no request half: it
	// is still observed (usage) but labelled unmatched.
	st2 := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(body)})
	assert.NotEmpty(t, st2.EvidenceID)
	settlements = recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, settlements, 2)
	var unmatched int
	for _, r := range settlements {
		if contains(r.GatewayAnnotations, annotationDecisionUnmatched) {
			unmatched++
			assert.NotEqual(t, decisions[0].CorrelationID, r.CorrelationID)
			assert.Equal(t, 120, r.Execution.Tokens.Input)
		}
	}
	assert.Equal(t, 1, unmatched)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// The agent's response PII policy is applied to the held body: redact
// transforms, block refuses delivery, warn passes and records.
func TestDelegatedResponse_PIIPolicy(t *testing.T) {
	const email = "jane.doe@example.com"
	body := `{"id":"cmpl-1","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"contact ` + email + ` for the refund"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`
	for _, tc := range []struct {
		action  string
		block   bool
		changed bool
	}{
		{"redact", false, true},
		{"block", true, false},
		{"warn", false, false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			gw, store := setupDelegatedGatewayWith(t, tc.action, nil, responseGoverned)
			require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
			st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(body)})
			assert.Equal(t, tc.block, st.Block, "%+v", st)
			assert.Equal(t, tc.changed, st.BodyChanged)
			assert.Contains(t, st.PIITypes, "email")
			if tc.changed {
				assert.NotContains(t, string(st.Body), email, "the replacement body no longer carries the value")
				assert.Contains(t, string(st.Body), "usage", "the envelope is preserved")
			}
			if tc.block {
				assert.Equal(t, "output_pii_blocked", st.Code)
			}
			recs := recordsOfType(t, store, InvocationTypeGatewayResponse)
			require.Len(t, recs, 1)
			r := recs[0]
			assert.Equal(t, !tc.block, r.PolicyDecision.Allowed)
			assert.True(t, r.Classification.OutputPIIDetected)
			assert.Contains(t, r.Classification.OutputPIITypes, "email")
			require.NotNil(t, r.Classification.ResponseScan)
			if tc.action == "warn" {
				assert.Equal(t, evidence.ResponseScanEnforcementObservation, r.Classification.ResponseScan.Enforcement)
			} else {
				assert.Equal(t, evidence.ResponseScanEnforcementPreventive, r.Classification.ResponseScan.Enforcement)
			}
			assert.Equal(t, 10, r.Execution.Tokens.Input, "usage is settled whatever the PII verdict")
			js := mustJSON(t, r)
			assert.NotContains(t, js, email, "the signed record never carries the value")
		})
	}
}

// Streamed responses under an observational policy are passed as they
// arrive and observed after delivery: usage from the final chunk, PII
// detection recorded as post-delivery, never a prevention claim.
func TestDelegatedResponse_StreamObservation(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	sse := "data: {\"id\":\"c1\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"mail jane.doe@example.com\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\" now\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":4}}\n\n" +
		"data: [DONE]\n\n"
	plan := gw.PlanDelegatedResponse(context.Background(), preflightFor(200, "text/event-stream"))
	assert.Equal(t, ResponseModeStream, plan.Mode)
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "text/event-stream"), Mode: ResponseModeStream, Body: []byte(sse), BytesSeen: int64(len(sse)), CaptureCap: 1 << 20})
	assert.False(t, st.Block)
	assert.False(t, st.BodyChanged)
	assert.Equal(t, TokenUsage{Input: 7, Output: 4}, st.Tokens)
	recs := recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, recs, 1)
	rs := recs[0].Classification.ResponseScan
	require.NotNil(t, rs)
	assert.Equal(t, evidence.ResponseScanEnforcementPostDelivery, rs.Enforcement)
	assert.True(t, recs[0].Classification.OutputPIIDetected)
	assert.Equal(t, 7, recs[0].Execution.Tokens.Input)

	// Preventive policy on a stream: the plan holds the whole body instead.
	gw2, _ := setupDelegatedGatewayWith(t, "redact", nil, responseGoverned)
	require.True(t, gw2.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	assert.Equal(t, ResponseModeWholeBody, gw2.PlanDelegatedResponse(context.Background(), preflightFor(200, "text/event-stream")).Mode)
}

// The plan: identity failures block; provider errors and non-model bodies
// settle from headers; an uninspectable body blocks under a preventive
// policy and is observed-only otherwise.
func TestDelegatedResponse_PlanMatrix(t *testing.T) {
	gw, _ := setupDelegatedGatewayWith(t, "redact", nil, responseGoverned)
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	noID := preflightFor(200, "application/json")
	noID.Principal, noID.IdentityFailure = nil, "workload_identity_signature_invalid"
	gz := preflightFor(200, "application/json")
	gz.ContentEncoding = "gzip"
	noBody := preflightFor(200, "application/json")
	noBody.BodyInspectable = false
	for name, tc := range map[string]struct {
		pf    DelegatedResponsePreflight
		mode  string
		block bool
		code  string
	}{
		"identity failure":       {noID, "", true, CodeWorkloadIdentityRequired},
		"provider error":         {preflightFor(502, "application/json"), ResponseModeHeadersOnly, false, ""},
		"non-model body":         {preflightFor(200, "text/html"), ResponseModeHeadersOnly, false, ""},
		"compressed + redact":    {gz, "", true, CodeResponseScanUnavailable},
		"uninspectable + redact": {noBody, "", true, CodeResponseScanUnavailable},
		"json":                   {preflightFor(200, "application/json"), ResponseModeWholeBody, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			p := gw.PlanDelegatedResponse(context.Background(), tc.pf)
			assert.Equal(t, tc.block, p.Block, "%+v", p)
			assert.Equal(t, tc.mode, p.Mode)
			if tc.code != "" {
				assert.Equal(t, tc.code, p.Code)
			}
		})
	}
	assert.Equal(t, 1, gw.delegatedPending.len(), "planning never consumes the pending entry")

	// Observational policy + compressed body: observe from headers only.
	gw2, _ := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw2.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	p := gw2.PlanDelegatedResponse(context.Background(), gz)
	assert.False(t, p.Block)
	assert.Equal(t, ResponseModeHeadersOnly, p.Mode)
}

// A provider error settles with zero cost and a failed status; a response
// without usage keeps the estimate and says so.
func TestDelegatedResponse_ProviderErrorAndNoUsage(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(500, "application/json"), Mode: ResponseModeHeadersOnly})
	assert.Equal(t, 0.0, st.Cost)
	recs := recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, recs, 1)
	assert.Equal(t, evidence.StatusFailed, recs[0].Status)
	assert.Equal(t, evidence.FailureReasonProviderTransient, recs[0].FailureReason)
	assert.Contains(t, recs[0].GatewayAnnotations, "provider_error")

	gw2, store2 := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw2.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	st = gw2.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(`{"id":"x","choices":[{"message":{"content":"ok"}}]}`)})
	assert.Equal(t, PricingBasisEstimateNoUsage, st.Basis)
	assert.Greater(t, st.Cost, 0.0, "the estimate stands when the provider sent no usage")
	recs = recordsOfType(t, store2, InvocationTypeGatewayResponse)
	require.Len(t, recs, 1)
	assert.Equal(t, PricingBasisEstimateNoUsage, recs[0].Execution.PricingBasis)
	assert.False(t, recs[0].Execution.PricingKnown)
}

// A response that never arrives is settled by the sweeper as UNOBSERVED
// with the estimate — never silently as a success, never dropped.
func TestDelegatedResponse_SweeperSettlesUnobserved(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	assert.Equal(t, 0, gw.SweepDelegatedPending(context.Background(), time.Now()), "nothing expired yet")
	assert.Equal(t, 1, gw.SweepDelegatedPending(context.Background(), time.Now().Add(31*time.Second)))
	assert.Equal(t, 0, gw.delegatedPending.len())
	recs := recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, recs, 1)
	r := recs[0]
	require.True(t, store.VerifyRecord(&r))
	assert.Equal(t, evidence.StatusUnknown, r.Status)
	assert.Equal(t, FailureReasonResponseUnobserved, r.FailureReason)
	assert.Equal(t, PricingBasisEstimateUnsettled, r.Execution.PricingBasis)
	assert.Greater(t, r.Execution.Cost, 0.0)
	assert.Equal(t, r.Execution.EstimatedCost, r.Execution.Cost)
	assert.Contains(t, r.GatewayAnnotations, annotationResponseUnseen)
	require.NotEmpty(t, r.Explanations)
	assert.Equal(t, "EXECUTION_OUTCOME_UNKNOWN", r.Explanations[0].Code)

	// The late response is still observed, as unmatched.
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1},"choices":[{"message":{"content":"late"}}]}`)})
	assert.NotEmpty(t, st.EvidenceID)
}

// Without response governance the decision books the estimate exactly as
// before and nothing is parked.
func TestDelegatedResponse_DisabledKeepsEstimateBooking(t *testing.T) {
	gw, store := setupDelegatedGateway(t, "warn", nil)
	dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody))
	require.True(t, dec.Allowed)
	assert.False(t, dec.ResponseGovernance)
	assert.Nil(t, gw.delegatedPending)
	recs := recordsOfType(t, store, "gateway")
	require.Len(t, recs, 1)
	assert.Greater(t, recs[0].Execution.Cost, 0.0)
	assert.NotEqual(t, PricingBasisAwaitingSettlement, recs[0].Execution.PricingBasis)
	assert.NotContains(t, strings.Join(recs[0].GatewayAnnotations, ","), annotationSettlementPending)
}

func TestDelegatedPendingSet_Bound(t *testing.T) {
	p := newDelegatedPendingSet(time.Minute)
	base := time.Now()
	for i := 0; i < maxPendingSettlements+5; i++ {
		p.add(&delegatedPending{key: pendingKey{"gw", "sb", string(rune('a'+i%26)) + string(rune(i))}, startedAt: base.Add(time.Duration(i) * time.Millisecond), agent: &ResolvedIdentity{Name: "a", TenantID: "t"}, estimate: 1})
	}
	assert.Equal(t, maxPendingSettlements, p.len(), "oldest entries are evicted, never unbounded growth")
	assert.InDelta(t, float64(maxPendingSettlements), p.estimateFor("t", "a"), 1e-9)
	assert.Equal(t, 0.0, p.estimateFor("t", "other"))
	_ = http.StatusOK
}
