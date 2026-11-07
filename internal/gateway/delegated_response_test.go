package gateway

import (
	"context"
	"net/http"
	"strconv"
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

func pendingSettlements(t *testing.T, gw *Gateway) int {
	t.Helper()
	require.NotNil(t, gw.settlements)
	n, err := gw.settlements.countPending(context.Background())
	require.NoError(t, err)
	return n
}

func settlementCostTotal(t *testing.T, store *evidence.Store) float64 {
	t.Helper()
	var total float64
	recs := listDelegated(t, store, "sandboxed-agent")
	for i := range recs {
		total += recs[i].Execution.Cost
	}
	return total
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
	assert.Equal(t, 1, pendingSettlements(t, gw))

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
	assert.Equal(t, 0, pendingSettlements(t, gw))

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

	// A repeated callback for the same runtime exchange is a REPLAY: the
	// recorded verdict and evidence id come back, nothing is written, the
	// cost is not counted twice.
	before := settlementCostTotal(t, store)
	st2 := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(body)})
	assert.True(t, st2.Replayed)
	assert.False(t, st2.Block)
	assert.Equal(t, st.EvidenceID, st2.EvidenceID)
	assert.Equal(t, CodeSettlementReplayed, st2.Code)
	assert.Equal(t, 0.0, st2.Cost)
	require.Len(t, recordsOfType(t, store, InvocationTypeGatewayResponse), 1, "a duplicate callback writes no record")
	assert.InDelta(t, before, settlementCostTotal(t, store), 1e-12, "a duplicate callback books no cost")
	assert.Equal(t, 0, pendingSettlements(t, gw))
}

// Duplicate callbacks under a preventive policy reproduce the verdict: a
// redacted body is redacted again (same bytes), a blocked one stays
// blocked; neither writes a second record.
func TestDelegatedResponse_DuplicateCallbackReplaysPreventiveVerdict(t *testing.T) {
	const email = "jane.doe@example.com"
	body := `{"id":"cmpl-1","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"contact ` + email + `"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`
	for _, action := range []string{"redact", "block"} {
		t.Run(action, func(t *testing.T) {
			gw, store := setupDelegatedGatewayWith(t, action, nil, responseGoverned)
			require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
			in := DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(body)}
			first := gw.SettleDelegatedResponse(context.Background(), in)
			second := gw.SettleDelegatedResponse(context.Background(), in)
			assert.True(t, second.Replayed)
			assert.Equal(t, first.Block, second.Block)
			assert.Equal(t, first.EvidenceID, second.EvidenceID)
			if action == "redact" {
				assert.True(t, second.BodyChanged)
				assert.Equal(t, string(first.Body), string(second.Body))
				assert.NotContains(t, string(second.Body), email)
			} else {
				assert.Equal(t, "output_pii_blocked", second.Code)
				plan := gw.PlanDelegatedResponse(context.Background(), preflightFor(200, "application/json"))
				assert.True(t, plan.Block, "the plan of a replayed blocked response blocks before any body is sent")
			}
			require.Len(t, recordsOfType(t, store, InvocationTypeGatewayResponse), 1)
		})
	}
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

// count_tokens on the delegated Anthropic path is settled like any other
// exchange — the runtime presents its response to PRE_RETURN too — at cost 0
// on both records, with no session consumption, and never as a
// decision_unmatched settlement. Regression for #528: the allow path parked
// no ledger row for count_tokens, so every count_tokens response was
// recorded as a response Talon had no request half for.
func TestDelegatedResponse_CountTokensSettlesAtZero(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "redact", nil, func(c *GatewayConfig) {
		responseGoverned(c)
		c.Providers["anthropic"] = ProviderConfig{Enabled: true, BaseURL: "https://api.anthropic.com", SecretName: "anthropic-api-key"}
	})
	req := delegatedReq(delegatedPrincipal(delegatedSubject), `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"count me"}]}`)
	req.Host, req.Path, req.RequestID = "api.anthropic.com", "/v1/messages/count_tokens", "req-count-1"
	dec := gw.EvaluateDelegated(context.Background(), req)
	require.True(t, dec.Allowed, "%+v", dec)
	require.Equal(t, 1, pendingSettlements(t, gw), "the count_tokens decision parks its settlement row")
	pf := preflightFor(200, "application/json")
	pf.Host, pf.RequestID = "api.anthropic.com", "req-count-1"
	require.Equal(t, ResponseModeWholeBody, gw.PlanDelegatedResponse(context.Background(), pf).Mode)
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: pf, Mode: ResponseModeWholeBody, Body: []byte(`{"input_tokens":42}`)})
	assert.False(t, st.Block, "%+v", st)
	assert.Equal(t, 0.0, st.Cost)
	assert.Equal(t, 0, pendingSettlements(t, gw))
	decisions := recordsOfType(t, store, "gateway_count_tokens")
	require.Len(t, decisions, 1)
	assert.Equal(t, 0.0, decisions[0].Execution.Cost)
	settlements := recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, settlements, 1)
	assert.Equal(t, decisions[0].CorrelationID, settlements[0].CorrelationID, "the settlement joins its count_tokens decision")
	assert.Equal(t, 0.0, settlements[0].Execution.Cost)
	assert.NotContains(t, settlements[0].GatewayAnnotations, "decision_unmatched")
	assert.Contains(t, settlements[0].GatewayAnnotations, "response_observed")
	assert.Equal(t, 0.0, settlementCostTotal(t, store), "count_tokens never bills")
}

// A streamed response HELD whole under a preventive policy (every streaming
// client — Claude Code streams always — under redact/block) is settled from
// the held SSE bytes: usage from the final chunk, PII redacted into an SSE
// replacement, a clean stream delivered unchanged. Regression for #528: the
// held-SSE path built its capture without a writer and panicked on the
// first streamed response, which OpenShell then failed closed on.
func TestDelegatedResponse_StreamHeldWholeUnderPreventivePolicy(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "redact", nil, responseGoverned)
	pf := preflightFor(200, "text/event-stream")
	clean := "data: {\"id\":\"c1\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"all good\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":4}}\n\n" +
		"data: [DONE]\n\n"
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	require.Equal(t, ResponseModeWholeBody, gw.PlanDelegatedResponse(context.Background(), pf).Mode)
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: pf, Mode: ResponseModeWholeBody, Body: []byte(clean)})
	assert.False(t, st.Block, "%+v", st)
	assert.False(t, st.BodyChanged)
	assert.Equal(t, TokenUsage{Input: 7, Output: 4}, st.Tokens)

	pii := "data: {\"id\":\"c2\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"mail jane.doe@example.com\"}}]}\n\n" +
		"data: {\"id\":\"c2\",\"choices\":[{\"delta\":{\"content\":\" now\"}}]}\n\n" +
		"data: {\"id\":\"c2\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":5}}\n\n" +
		"data: [DONE]\n\n"
	pf2 := pf
	pf2.RequestID = "req-2"
	req2 := delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)
	req2.RequestID = "req-2"
	require.True(t, gw.EvaluateDelegated(context.Background(), req2).Allowed)
	st = gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: pf2, Mode: ResponseModeWholeBody, Body: []byte(pii)})
	assert.False(t, st.Block, "%+v", st)
	assert.True(t, st.BodyChanged, "a held stream with PII is replaced, not passed")
	assert.NotContains(t, string(st.Body), "jane.doe@example.com")
	assert.Contains(t, string(st.Body), "data: ", "the replacement is still an SSE body")
	assert.Equal(t, TokenUsage{Input: 9, Output: 5}, st.Tokens)
	recs := recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, recs, 2)
	for _, r := range recs {
		require.NotNil(t, r.Classification.ResponseScan)
		assert.Equal(t, evidence.ResponseScanEnforcementPreventive, r.Classification.ResponseScan.Enforcement)
		assert.NotContains(t, mustJSON(t, r), "jane.doe@example.com")
	}
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
	sseStreamOnly := preflightFor(200, "text/event-stream")
	sseStreamOnly.BodyInspectable = false
	sseHeadersOnly := sseStreamOnly
	sseHeadersOnly.StreamPermitted = false
	sseStreamOnlyGz := sseStreamOnly
	sseStreamOnlyGz.ContentEncoding = "gzip"
	for name, tc := range map[string]struct {
		pf    DelegatedResponsePreflight
		mode  string
		block bool
		code  string
	}{
		"identity failure":       {noID, "", true, CodeWorkloadIdentityRequired},
		"provider error":         {preflightFor(502, "application/json"), ResponseModeWholeBody, false, ""},
		"provider error (html)":  {preflightFor(502, "text/html"), ResponseModeWholeBody, false, ""},
		"provider error (octet)": {preflightFor(502, "application/octet-stream"), "", true, CodeResponseContentUnsupported},
		"text body + redact":     {preflightFor(200, "text/html"), ResponseModeWholeBody, false, ""},
		"binary body + redact":   {preflightFor(200, "application/octet-stream"), "", true, CodeResponseContentUnsupported},
		"compressed + redact":    {gz, "", true, CodeResponseScanUnavailable},
		"uninspectable + redact": {noBody, "", true, CodeResponseScanUnavailable},
		"json":                   {preflightFor(200, "application/json"), ResponseModeWholeBody, false, ""},
		// SSE: a runtime that offers WHOLE_BODY gets the held body; OpenShell
		// v0.1.3 never offers it for text/event-stream (open-ended), only
		// STREAM_BYTES — the guarded per-unit mode; neither → fail closed.
		"sse + redact, whole offered":           {preflightFor(200, "text/event-stream"), ResponseModeWholeBody, false, ""},
		"sse + redact, stream only (v0.1.3)":    {sseStreamOnly, ResponseModeStreamGuarded, false, ""},
		"sse + redact, headers only":            {sseHeadersOnly, "", true, CodeResponseScanUnavailable},
		"sse + redact, stream only, compressed": {sseStreamOnlyGz, "", true, CodeResponseScanUnavailable},
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
	assert.Equal(t, 1, pendingSettlements(t, gw), "planning never consumes the pending entry")

	// Observational policy + compressed body: observe from headers only.
	gw2, _ := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gw2.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	p := gw2.PlanDelegatedResponse(context.Background(), gz)
	assert.False(t, p.Block)
	assert.Equal(t, ResponseModeHeadersOnly, p.Mode)
	// Observational policy + stream-only SSE: post-delivery observation,
	// never the guard (nothing to withhold under warn).
	assert.Equal(t, ResponseModeStream, gw2.PlanDelegatedResponse(context.Background(), sseStreamOnly).Mode)
	// Compressed provider ERROR body under a preventive policy: blocked.
	gzErr := preflightFor(502, "application/json")
	gzErr.ContentEncoding = "gzip"
	p = gw.PlanDelegatedResponse(context.Background(), gzErr)
	assert.True(t, p.Block)
	assert.Equal(t, CodeResponseScanUnavailable, p.Code)
	// Policy "allow": error bodies settle from the headers.
	gw3, _ := setupDelegatedGatewayWith(t, "allow", nil, responseGoverned)
	require.True(t, gw3.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	assert.Equal(t, ResponseModeHeadersOnly, gw3.PlanDelegatedResponse(context.Background(), preflightFor(502, "application/json")).Mode)
}

// Provider error bodies are not exempt from the response policy: a 4xx/5xx
// body echoing PII is blocked under a preventive policy and observed under
// warn; nothing is billed for an error either way.
func TestDelegatedResponse_ErrorBodyWithPII(t *testing.T) {
	const email = "jane.doe@example.com"
	errBody := `{"error":{"message":"invalid request: the input mentions ` + email + `","type":"invalid_request_error"}}`
	for _, tc := range []struct {
		action string
		block  bool
	}{{"redact", true}, {"block", true}, {"warn", false}} {
		t.Run(tc.action, func(t *testing.T) {
			gw, store := setupDelegatedGatewayWith(t, tc.action, nil, responseGoverned)
			require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
			plan := gw.PlanDelegatedResponse(context.Background(), preflightFor(400, "application/json"))
			require.Equal(t, ResponseModeWholeBody, plan.Mode, "an inspectable error body is held and scanned: %+v", plan)
			st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(400, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(errBody)})
			assert.Equal(t, tc.block, st.Block, "%+v", st)
			assert.Contains(t, st.PIITypes, "email")
			assert.Equal(t, 0.0, st.Cost)
			if tc.block {
				assert.Equal(t, "output_pii_blocked", st.Code)
			}
			recs := recordsOfType(t, store, InvocationTypeGatewayResponse)
			require.Len(t, recs, 1)
			r := recs[0]
			assert.Equal(t, evidence.StatusFailed, r.Status)
			assert.Equal(t, evidence.FailureReasonProviderPermanent, r.FailureReason)
			assert.Equal(t, !tc.block, r.PolicyDecision.Allowed)
			assert.True(t, r.Classification.OutputPIIDetected)
			assert.Contains(t, r.GatewayAnnotations, annotationErrorBodyScanned)
			assert.Contains(t, r.GatewayAnnotations, "provider_error")
			assert.NotContains(t, mustJSON(t, r), email)
		})
	}
}

// A Talon restart while a preventive response is in flight: the ledger row
// (and the policy in force at decision time) survives in the evidence
// store, so the new process still holds and scans the body and blocks on
// PII — it never degrades to "skip". A response with no row at all from a
// provider host is governed under the CURRENT policy, and an unbound
// principal is refused rather than skipped.
func TestDelegatedResponse_RestartKeepsPreventivePolicy(t *testing.T) {
	const email = "jane.doe@example.com"
	body := `{"id":"cmpl-1","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"mail ` + email + `"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`
	gw1, store := setupDelegatedGatewayWith(t, "block", nil, responseGoverned)
	dec := gw1.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody))
	require.True(t, dec.Allowed)

	// Restart: a new gateway over the same evidence store, configured
	// permissively — the decision-time policy (block) must still apply.
	gw2 := setupDelegatedGatewayOn(t, "warn", nil, responseGoverned, store)
	assert.Equal(t, 1, pendingSettlements(t, gw2), "the obligation survived the restart")
	plan := gw2.PlanDelegatedResponse(context.Background(), preflightFor(200, "application/json"))
	assert.True(t, plan.Matched)
	assert.Equal(t, ResponseModeWholeBody, plan.Mode, "%+v", plan)
	st := gw2.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(body)})
	assert.True(t, st.Block, "%+v", st)
	assert.Equal(t, "output_pii_blocked", st.Code)
	settlements := recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, settlements, 1)
	assert.Equal(t, recordsOfType(t, store, "gateway")[0].CorrelationID, settlements[0].CorrelationID, "joined to the pre-restart decision")
	assert.NotContains(t, settlements[0].GatewayAnnotations, annotationDecisionUnmatched)
	assert.Equal(t, 0, pendingSettlements(t, gw2))

	// No row (decided before any ledger existed): the current policy
	// governs the response; it is observed once and labelled unmatched.
	gw3 := setupDelegatedGatewayOn(t, "redact", nil, responseGoverned, store)
	pf := preflightFor(200, "application/json")
	pf.RequestID = "req-before-ledger"
	plan = gw3.PlanDelegatedResponse(context.Background(), pf)
	assert.False(t, plan.Matched)
	assert.Equal(t, ResponseModeWholeBody, plan.Mode)
	st = gw3.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: pf, Mode: ResponseModeWholeBody, Body: []byte(body)})
	assert.False(t, st.Block)
	assert.True(t, st.BodyChanged, "the current redact policy transformed the body")
	assert.NotContains(t, string(st.Body), email)
	settlements = recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, settlements, 2)
	again := gw3.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: pf, Mode: ResponseModeWholeBody, Body: []byte(body)})
	assert.True(t, again.Replayed, "an unmatched response is observed once; its repeat replays")
	require.Len(t, recordsOfType(t, store, InvocationTypeGatewayResponse), 2)

	// No row and an unbound principal on a provider host: refused, never skipped.
	unbound := preflightFor(200, "application/json")
	unbound.RequestID, unbound.Principal = "req-unbound", delegatedPrincipal("spiffe://openshell/sandbox/sb-nobody")
	plan = gw3.PlanDelegatedResponse(context.Background(), unbound)
	assert.True(t, plan.Block)
	assert.Equal(t, CodeWorkloadIdentityUnbound, plan.Code)
	st = gw3.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: unbound, Mode: ResponseModeWholeBody, Body: []byte(body)})
	assert.True(t, st.Block)
	assert.Equal(t, CodeWorkloadIdentityUnbound, st.Code)
	require.Len(t, recordsOfType(t, store, InvocationTypeGatewayResponse), 2, "a refused unbound response is not settled")
}

// The ledger is bounded by refusing NEW delegated requests when it is full
// — never by discarding an obligation. Settling one frees one slot.
func TestDelegatedResponse_CapacityRefusesNewRequests(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, func(cfg *GatewayConfig) {
		responseGoverned(cfg)
		cfg.OpenShell.ResponseGovernance.MaxPending = 100
	})
	for i := 0; i < 100; i++ {
		req := delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)
		req.RequestID = "req-" + strconv.Itoa(i)
		require.True(t, gw.EvaluateDelegated(context.Background(), req).Allowed, "request %d", i)
	}
	assert.Equal(t, 100, pendingSettlements(t, gw))
	over := delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)
	over.RequestID = "req-over"
	dec := gw.EvaluateDelegated(context.Background(), over)
	assert.False(t, dec.Allowed)
	assert.Equal(t, CodeSettlementCapacityExhausted, dec.Code)
	assert.Equal(t, http.StatusServiceUnavailable, dec.Status)
	assert.Equal(t, 100, pendingSettlements(t, gw), "no obligation was evicted to make room")
	denied := 0
	for _, r := range recordsOfType(t, store, "gateway") {
		if !r.PolicyDecision.Allowed {
			denied++
		}
	}
	assert.Equal(t, 1, denied, "the refusal is evidenced")

	pf := preflightFor(200, "application/json")
	pf.RequestID = "req-7"
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: pf, Mode: ResponseModeWholeBody, Body: []byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1},"choices":[{"message":{"content":"ok"}}]}`)})
	require.NotEmpty(t, st.EvidenceID)
	assert.Equal(t, 99, pendingSettlements(t, gw))

	// A runtime request id that is still pending is refused, never
	// overwritten (the slot stays with the first exchange).
	dup := delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)
	dup.RequestID = "req-3"
	dec = gw.EvaluateDelegated(context.Background(), dup)
	assert.False(t, dec.Allowed)
	assert.Equal(t, CodeSettlementUnavailable, dec.Code)
	assert.Equal(t, http.StatusConflict, dec.Status)
	assert.Equal(t, 99, pendingSettlements(t, gw))

	assert.True(t, gw.EvaluateDelegated(context.Background(), over).Allowed, "a settled slot admits a new request")
	assert.Equal(t, 100, pendingSettlements(t, gw))
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
	assert.Equal(t, 0, pendingSettlements(t, gw))
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

	// The late response RECONCILES against the booked estimate: a record
	// under the same correlation id whose cost is only the excess of the
	// actual over the estimate, so the total is max(estimate, actual) —
	// never estimate plus actual, never decision_unmatched.
	estimate := r.Execution.Cost
	late := DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(`{"model":"gpt-4o-mini","usage":{"prompt_tokens":100000,"completion_tokens":50000},"choices":[{"message":{"content":"late"}}]}`)}
	st := gw.SettleDelegatedResponse(context.Background(), late)
	require.NotEmpty(t, st.EvidenceID)
	assert.False(t, st.Replayed)
	assert.Equal(t, PricingBasisLateReconciliation, st.Basis)
	actual := gw.costEstimate("openai", "gpt-4o-mini", Usage{Input: 100000, Output: 50000}).Amount
	require.Greater(t, actual, estimate, "the fixture's actual exceeds the estimate")
	assert.InDelta(t, actual-estimate, st.Cost, 1e-9)
	settlements := recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, settlements, 2)
	assert.InDelta(t, actual, settlementCostTotal(t, store), 1e-9, "records sum to the actual, not estimate+actual")
	for _, s := range settlements {
		assert.Equal(t, r.CorrelationID, s.CorrelationID)
		assert.NotContains(t, s.GatewayAnnotations, annotationDecisionUnmatched)
		if s.Execution.PricingBasis == PricingBasisLateReconciliation {
			assert.Contains(t, s.GatewayAnnotations, annotationResponseLate)
			assert.Equal(t, 100000, s.Execution.Tokens.Input)
		}
	}
	// A third callback replays; a late response BELOW the estimate books 0.
	assert.True(t, gw.SettleDelegatedResponse(context.Background(), late).Replayed)
	require.Len(t, recordsOfType(t, store, InvocationTypeGatewayResponse), 2)

	gwB, storeB := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	require.True(t, gwB.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	require.Equal(t, 1, gwB.SweepDelegatedPending(context.Background(), time.Now().Add(31*time.Second)))
	booked := settlementCostTotal(t, storeB)
	stB := gwB.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: preflightFor(200, "application/json"), Mode: ResponseModeWholeBody, Body: []byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1},"choices":[{"message":{"content":"late"}}]}`)})
	assert.Equal(t, 0.0, stB.Cost)
	assert.Equal(t, PricingBasisLateReconciliation, stB.Basis)
	assert.InDelta(t, booked, settlementCostTotal(t, storeB), 1e-12, "the booked estimate stands when the actual is lower")
}

// Without response governance the decision books the estimate exactly as
// before and nothing is parked.
func TestDelegatedResponse_DisabledKeepsEstimateBooking(t *testing.T) {
	gw, store := setupDelegatedGateway(t, "warn", nil)
	dec := gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody))
	require.True(t, dec.Allowed)
	assert.False(t, dec.ResponseGovernance)
	assert.Nil(t, gw.settlements)
	recs := recordsOfType(t, store, "gateway")
	require.Len(t, recs, 1)
	assert.Greater(t, recs[0].Execution.Cost, 0.0)
	assert.NotEqual(t, PricingBasisAwaitingSettlement, recs[0].Execution.PricingBasis)
	assert.NotContains(t, strings.Join(recs[0].GatewayAnnotations, ","), annotationSettlementPending)
}

// A response with no request half from a host Talon has no provider for
// (Talon's own API behind the same hostname, or a runtime misbinding) is
// skipped and never settled: no decision_unmatched record exists for it.
func TestDelegatedResponse_UnknownHostWithoutRequestHalfIsSkipped(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "warn", nil, responseGoverned)
	pf := preflightFor(201, "application/json")
	pf.Host, pf.RequestID = "host.openshell.internal", "req-action-1"
	plan := gw.PlanDelegatedResponse(context.Background(), pf)
	assert.Equal(t, ResponseModeSkip, plan.Mode)
	assert.Equal(t, CodeDestinationNotGoverned, plan.Code)
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: pf, Mode: ResponseModeWholeBody, Body: []byte(`{"created":true}`)})
	assert.Empty(t, st.EvidenceID)
	assert.Equal(t, CodeDestinationNotGoverned, st.Code)
	assert.Empty(t, recordsOfType(t, store, InvocationTypeGatewayResponse), "no settlement is booked for a non-provider response")
}

func TestOpenShellResponseGovernanceConfig_MaxPendingBounds(t *testing.T) {
	for _, tc := range []struct {
		in   int
		ok   bool
		want int
	}{{0, true, DefaultOpenShellMaxPendingSettlements}, {100, true, 100}, {99, false, 0}, {1000000, true, 1000000}, {1000001, false, 0}} {
		c := &OpenShellResponseGovernanceConfig{Enabled: true, SettlementTimeout: "5m", MaxCaptureBytes: 1 << 20, MaxPending: tc.in}
		err := c.validate(4 << 20)
		if tc.ok {
			require.NoError(t, err, "max_pending=%d", tc.in)
			assert.Equal(t, tc.want, c.MaxPendingSettlements())
		} else {
			require.Error(t, err, "max_pending=%d", tc.in)
		}
	}
}

// anthropicSSEUnits is the Anthropic Messages stream as OpenShell hands it
// to the guard: one unit per provider flush (one event each), usage split
// across message_start and message_delta.
func anthropicSSEUnits(deltas ...string) []string {
	quote := strconv.Quote
	units := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-5\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
	}
	for _, d := range deltas {
		units = append(units, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":"+quote(d)+"}}\n\n")
	}
	return append(units,
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":3}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	)
}

// The guarded stream (OpenShell v0.1.3 offers only STREAM_BYTES for SSE): a
// clean Anthropic stream is released unit by unit and settled with the
// usage the guard parsed; a unit carrying PII is withheld together with
// everything after it, under redact and under block alike; a value split
// across units is caught at the unit completing it; a frame cut between
// units is parsed whole; the evidence says preventive_per_unit, never
// preventive or redacted. Without the guarded mode every one of these
// exchanges was blocked at preflight with output_scan_unavailable (#528).
func TestDelegatedResponse_GuardedStreamWithholdsFromPIIUnit(t *testing.T) {
	const email = "jane.doe@example.com"
	for _, action := range []string{"redact", "block"} {
		t.Run(action, func(t *testing.T) {
			gw, store := setupDelegatedGatewayWith(t, action, nil, responseGoverned)
			pf := preflightFor(200, "text/event-stream")
			pf.BodyInspectable = false // the real v0.1.3 offer for text/event-stream
			exchange := func(reqID string, units []string) (DelegatedSettlement, *StreamGuardSummary, int) {
				req := delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)
				req.RequestID = reqID
				require.True(t, gw.EvaluateDelegated(context.Background(), req).Allowed)
				p := pf
				p.RequestID = reqID
				require.Equal(t, ResponseModeStreamGuarded, gw.PlanDelegatedResponse(context.Background(), p).Mode)
				guard, refused := gw.GuardDelegatedStream(context.Background(), p)
				require.Nil(t, refused)
				var capture []byte
				released := 0
				for _, u := range units {
					capture = append(capture, u...)
					if v := guard.Inspect(context.Background(), []byte(u)); v.Block {
						break
					}
					released++
				}
				sum := guard.Summary()
				st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: p, Mode: ResponseModeStreamGuarded, Body: capture, BytesSeen: int64(len(capture)), CaptureCap: 1 << 20, Guard: sum})
				return st, sum, released
			}

			clean := anthropicSSEUnits("all ", "good")
			st, sum, released := exchange("req-clean", clean)
			assert.False(t, st.Block, "%+v", st)
			assert.Equal(t, len(clean), released, "every unit of a clean stream is released")
			assert.False(t, sum.Blocked)
			assert.Equal(t, TokenUsage{Input: 12, Output: 3}, st.Tokens, "usage parsed by the guard from message_start/message_delta")
			assert.Greater(t, st.Cost, 0.0)

			pii := anthropicSSEUnits("please mail ", email, " today")
			st, sum, released = exchange("req-pii", pii)
			assert.True(t, st.Block, "%+v", st)
			assert.Equal(t, "output_pii_blocked", st.Code)
			assert.Equal(t, 3, released, "units before the e-mail delta were released; the e-mail unit and everything after it were not")
			assert.True(t, sum.Blocked)
			assert.Equal(t, 4, sum.BlockedAt)
			assert.Contains(t, sum.PIITypes, "email")

			split := anthropicSSEUnits("write to jane.doe@exa", "mple.com please")
			st, sum, released = exchange("req-split", split)
			assert.True(t, st.Block, "a value split across two deltas is caught at the unit completing it: %+v", st)
			assert.Equal(t, 3, released, "the first half was already released (documented per-unit limit)")
			assert.Equal(t, 4, sum.BlockedAt)

			// One SSE frame cut by the transport between two units: nothing to
			// scan in the first half, the whole frame in the second.
			frame := anthropicSSEUnits("contact " + email)[2]
			cut := len(frame) / 2
			cutUnits := append(append(anthropicSSEUnits()[:2], frame[:cut], frame[cut:]), anthropicSSEUnits()[2:]...)
			st, sum, released = exchange("req-cut", cutUnits)
			assert.True(t, st.Block, "%+v", st)
			assert.Equal(t, 3, released)
			assert.Equal(t, 4, sum.BlockedAt, "the frame is complete in the second half; that unit is withheld")

			recs := recordsOfType(t, store, InvocationTypeGatewayResponse)
			require.Len(t, recs, 4)
			for _, r := range recs {
				require.NotNil(t, r.Classification.ResponseScan, r.ID)
				assert.Equal(t, evidence.ResponseScanEnforcementPreventivePerUnit, r.Classification.ResponseScan.Enforcement)
				assert.True(t, r.Classification.ResponseScan.Streamed)
				assert.Contains(t, r.GatewayAnnotations, annotationStreamUnitGuarded)
				assert.NotContains(t, mustJSON(t, r), email)
				assert.False(t, r.Classification.ResponsePIIRedacted(r.DataFlow), "withheld is not redacted")
				assert.False(t, r.Classification.ResponsePIIObserved(r.DataFlow), "withheld is not observed-only")
				if r.Classification.OutputPIIDetected {
					assert.False(t, r.PolicyDecision.Allowed, "a withheld stream settles as blocked: %s", r.ID)
					assert.Equal(t, "output_pii_blocked", r.PolicyDecision.Reasons[0])
				} else {
					assert.True(t, r.PolicyDecision.Allowed)
				}
			}
		})
	}
	// No scanner at all: the guard withholds every unit that carries text.
	sg := &DelegatedStreamGuard{action: "redact"}
	assert.False(t, sg.Inspect(context.Background(), []byte(anthropicSSEUnits("x")[0])).Block, "a unit without content text has nothing to scan")
	v := sg.Inspect(context.Background(), []byte(anthropicSSEUnits("x")[2]))
	assert.True(t, v.Block)
	assert.Equal(t, "output_scanner_unavailable", v.Code)
	assert.Equal(t, "output_scanner_unavailable", sg.Summary().Code)
}

// A guarded stream the provider cut before OpenShell delivered any unit
// (observed on v0.1.3, PR #531 run 42388578162: the exchange ends with no
// body at all) still settles under its decision and says so: nothing
// released or withheld, no usage (the estimate stands), the scan recorded as
// incomplete with the abnormal-end reason — never a silent "observed".
func TestDelegatedResponse_GuardedStreamCutBeforeFirstUnit(t *testing.T) {
	gw, store := setupDelegatedGatewayWith(t, "redact", nil, responseGoverned)
	require.True(t, gw.EvaluateDelegated(context.Background(), delegatedReq(delegatedPrincipal(delegatedSubject), chatBody)).Allowed)
	pf := preflightFor(200, "text/event-stream")
	pf.BodyInspectable = false
	require.Equal(t, ResponseModeStreamGuarded, gw.PlanDelegatedResponse(context.Background(), pf).Mode)
	guard, refused := gw.GuardDelegatedStream(context.Background(), pf)
	require.Nil(t, refused)
	st := gw.SettleDelegatedResponse(context.Background(), DelegatedResponseBody{Preflight: pf, Mode: ResponseModeStreamGuarded, Incomplete: evidence.ResponseScanIncompleteUpstreamError, CaptureCap: 1 << 20, Guard: guard.Summary()})
	assert.False(t, st.Block, "%+v", st)
	assert.Equal(t, TokenUsage{}, st.Tokens)
	assert.Equal(t, PricingBasisEstimateNoUsage, st.Basis)
	recs := recordsOfType(t, store, InvocationTypeGatewayResponse)
	require.Len(t, recs, 1)
	r := recs[0]
	require.NotNil(t, r.Classification.ResponseScan, "the abnormal end must be in the signed record")
	assert.Equal(t, evidence.ResponseScanEnforcementPreventivePerUnit, r.Classification.ResponseScan.Enforcement)
	assert.Equal(t, evidence.ResponseScanStatusIncomplete, r.Classification.ResponseScan.Status)
	assert.Equal(t, evidence.ResponseScanIncompleteUpstreamError, r.Classification.ResponseScan.IncompleteReason)
	assert.Contains(t, r.GatewayAnnotations, annotationStreamUnitGuarded)
	assert.True(t, r.PolicyDecision.Allowed)
	assert.False(t, r.Classification.OutputPIIDetected)
}

// Review of PR #531 (P1): a preventive per-unit mode must never release a
// unit it did not inspect. The guard scans every unit in full — complete
// frames by every string value of the event (text, thinking, tool-use
// input JSON, populated content_block_start fields), a trailing cut
// fragment as raw text with JSON escapes decoded — recognises CR/CRLF
// line endings, and fails closed on a content-bearing frame it cannot
// parse or a carried fragment beyond the bound.
func TestDelegatedStreamGuard_InspectsEveryUnitAndFailsClosed(t *testing.T) {
	gw, _ := setupDelegatedGatewayWith(t, "redact", nil, responseGoverned)
	const email = "jane.doe@example.com"
	newGuard := func() *DelegatedStreamGuard { return &DelegatedStreamGuard{action: "redact", scanner: gw.classifier} }
	// cutInside splits a frame n bytes into the first occurrence of marker.
	cutInside := func(frame, marker string, n int) []string {
		i := strings.Index(frame, marker) + n
		return []string{frame[:i], frame[i:]}
	}
	delta := func(kind, field, value string) string {
		return `event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"` + kind + `","` + field + `":` + strconv.Quote(value) + `}}`
	}
	for name, tc := range map[string]struct {
		units []string
		code  string // "" = every unit released
		at    int
	}{
		"complete value in an unterminated frame": {
			units: []string{delta("text_delta", "text", "mail "+email), "\n\n"}, code: "output_pii_blocked", at: 1,
		},
		"unterminated frame cut inside the value": {
			units: cutInside(delta("text_delta", "text", "mail "+email)+"\n\n", "example.com", 3), code: "output_pii_blocked", at: 2,
		},
		"CRLF frame": {
			units: []string{strings.ReplaceAll(delta("text_delta", "text", email), "\n", "\r\n") + "\r\n\r\n"}, code: "output_pii_blocked", at: 1,
		},
		"CR-only frame": {
			units: []string{strings.ReplaceAll(delta("text_delta", "text", email), "\n", "\r") + "\r\r"}, code: "output_pii_blocked", at: 1,
		},
		"tool-use input (input_json_delta.partial_json)": {
			units: []string{delta("input_json_delta", "partial_json", `{"email":"`+email+`"}`) + "\n\n"}, code: "output_pii_blocked", at: 1,
		},
		"thinking delta": {
			units: []string{delta("thinking_delta", "thinking", "the user is "+email) + "\n\n"}, code: "output_pii_blocked", at: 1,
		},
		"populated content_block_start text": {
			units: []string{`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":"` + email + `"}}` + "\n\n"}, code: "output_pii_blocked", at: 1,
		},
		"populated content_block_start tool_use input": {
			units: []string{`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"send","input":{"to":"` + email + `"}}}` + "\n\n"}, code: "output_pii_blocked", at: 1,
		},
		"JSON-escaped value in a cut fragment": {
			units: []string{`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"jane.doe@example.com`}, code: "output_pii_blocked", at: 1,
		},
		"unparseable content-bearing frame": {
			units: []string{"data: {not json at all\n\n"}, code: CodeResponseContentUnsupported, at: 1,
		},
		"carried fragment beyond the bound": {
			units: []string{"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"" + strings.Repeat("x", streamGuardFrameCarryLimit)}, code: CodeResponseScanIncomplete, at: 1,
		},
		"benign frames and a benign cut fragment": {
			units: []string{": keep-alive\n\n", "event: ping\ndata: {\"type\":\"ping\"}\n\n", "data: [DONE]\n\n", delta("text_delta", "text", "all good") + "\n\n", "event: content_block_delta\ndata: {\"type\":\"content_block_de"}, code: "",
		},
		"OpenAI tool call arguments": {
			units: []string{`data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"send","arguments":"{\"to\":\"` + email + `\"}"}}]}}]}` + "\n\n"}, code: "output_pii_blocked", at: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			sg := newGuard()
			blockedAt, code := 0, ""
			for i, u := range tc.units {
				if v := sg.Inspect(context.Background(), []byte(u)); v.Block {
					blockedAt, code = i+1, v.Code
					break
				}
			}
			assert.Equal(t, tc.code, code, "verdict code")
			assert.Equal(t, tc.at, blockedAt, "unit withheld (0 = none)")
			if tc.code == "" {
				assert.False(t, sg.Summary().Blocked)
			}
		})
	}
}
