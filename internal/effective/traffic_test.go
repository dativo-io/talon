package effective

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

const uc = "hr-analytics-assistant"

func (f fixture) put(t *testing.T, id, typ string, at time.Time, mod func(*evidence.Evidence)) {
	t.Helper()
	ev := &evidence.Evidence{
		ID: id, CorrelationID: "c-" + id, TenantID: "default", AgentID: uc, Timestamp: at, InvocationType: typ,
		PolicyDecision: evidence.PolicyDecision{Allowed: true, Action: "allow"},
	}
	if mod != nil {
		mod(ev)
	}
	require.NoError(t, f.store.Store(context.Background(), ev))
}

// currentDigests returns the agent policy digest and the effective digest
// toward openai that the fixture's current files compile to.
func (f fixture) currentDigests(t *testing.T) (agent, effective string) {
	t.Helper()
	ctx := context.Background()
	scan, err := fleetview.Scan(ctx, f.agents, "")
	require.NoError(t, err)
	gw, err := gateway.LoadGatewayConfig(f.gw)
	require.NoError(t, err)
	override := agentbridge.LoadedAgentFromPolicy(scan.Agents[0].Policy, scan.Agents[0].Path).Override
	return scan.Agents[0].PolicyDigest, gateway.EffectivePolicyDigest(gw.OrganizationPolicy, gw.Providers["openai"], override)
}

func observation(t *testing.T, r *Report, boundary string) TrafficObservation {
	t.Helper()
	require.NotNil(t, r.Verification)
	for i := range r.Verification.Traffic {
		if r.Verification.Traffic[i].Boundary == boundary {
			return r.Verification.Traffic[i]
		}
	}
	t.Fatalf("no %s observation", boundary)
	return TrafficObservation{}
}

func loadedView(f fixture, t *testing.T) *runtimestatus.View {
	t.Helper()
	first, err := Build(context.Background(), f.inputs())
	require.NoError(t, err)
	return &runtimestatus.View{Processes: []runtimestatus.Process{
		runningRecord("gw1", []string{runtimestatus.RoleGateway}, first.CurrentFiles.PolicyDigest, first.CurrentFiles.GatewayConfig.Digest, ""),
	}}
}

// A use case that was registered, enabled, reloaded and warned about its
// budget has sent no traffic: none of those records is application traffic
// or a decision. Neither are provider sub-attempts, imported external
// events, native runs or a reviewer's approval decision.
func TestVerification_OperatorAndOtherRecordsAreNotTraffic(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	now := time.Now().UTC()
	i := 0
	for _, typ := range []string{
		"agent_registration_intent", "agent_registered", "agent_registration_rolled_back", "agent_enabled", "agent_disabled",
		"config_reload", evidence.InvocationTypeBudgetThreshold, "control_plane", "gateway_failover_attempt", "llm_failover_attempt",
		"gateway_count_tokens", evidence.InvocationTypeExternalRuntimeEvent, "manual", "api", "http", "scheduled", "graph_run", "plan_review",
	} {
		i++
		f.put(t, "op"+strings.ReplaceAll(typ, "_", ""), typ, now.Add(time.Duration(i)*time.Second), nil)
	}
	// A reviewer's decision is recorded under the use case; the application
	// did not send it.
	f.put(t, "reviewer", evidence.InvocationTypeActionLifecycle, now.Add(time.Minute), func(ev *evidence.Evidence) {
		ev.ActionLifecycle = &evidence.ActionLifecycle{Event: evidence.ActionEventApprovalDecided, OperationID: "op-1", PolicyDigest: "x"}
	})

	r, err := Build(ctx, f.inputs())
	require.NoError(t, err)
	assert.Nil(t, r.LastDecision, "an operator event is never the last decision")
	for _, o := range r.Verification.Traffic {
		assert.Equal(t, TrafficNone, o.State, o.Boundary)
		assert.Empty(t, o.EvidenceID, o.Boundary)
		assert.NotEmpty(t, o.Establishes)
	}
	assert.Equal(t, ReadingLoadUnknown, r.Verification.Reading.Code, "no runtime records were given")
	assert.Contains(t, r.Verification.Reading.Text, "no authenticated traffic observed")
	assert.Contains(t, strings.Join(r.Verification.NotEstablished, "\n"), "no authenticated LLM gateway request of this use case is recorded")
	assert.Contains(t, strings.Join(r.Verification.NotEstablished, "\n"), "that all of this application's requests go through Talon")

	// The same facts with a running gateway that loaded the file: loaded,
	// and still no traffic.
	in := f.inputs()
	in.Runtime, in.RuntimeReadable = loadedView(f, t), true
	r, err = Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, ReadingLoadedNoTraffic, r.Verification.Reading.Code)
	assert.Nil(t, r.LastDecision)

	// Runtime records exist but cannot be read: activation is unknown, never
	// "not loaded" and never "loaded".
	in.Runtime, in.RuntimeReadable = &runtimestatus.View{}, false
	r, err = Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, runtimestatus.LoadedUnknown, r.Loaded.State)
	assert.Equal(t, ReadingLoadUnknown, r.Verification.Reading.Code)
	assert.Contains(t, r.Verification.Reading.Text, "is not known")
	in.RuntimeReadable = true

	// Running, but another version of the file: registered, not loaded.
	in.Runtime = &runtimestatus.View{Processes: []runtimestatus.Process{runningRecord("gw1", []string{runtimestatus.RoleGateway}, "another-digest", "x", "")}}
	r, err = Build(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, ReadingNotLoaded, r.Verification.Reading.Code)
	assert.Contains(t, r.Verification.Reading.Text, "DIFFERENT version")
}

// An authenticated request that Talon denied establishes the connection and
// the policy evaluation, with the matching policy, and nothing about a
// provider.
func TestVerification_DeniedAuthenticatedRequest(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	agentDigest, effDigest := f.currentDigests(t)
	now := time.Now().UTC()
	f.put(t, "registered", "agent_registered", now, nil) // newer than the request
	f.put(t, "denied", "gateway", now.Add(-time.Minute), func(ev *evidence.Evidence) {
		ev.PolicyDecision = evidence.PolicyDecision{Allowed: false, Action: "deny", PolicyDigests: &evidence.PolicyDigests{Agent: agentDigest, Effective: effDigest}}
	})
	in := f.inputs()
	in.Runtime, in.RuntimeReadable = loadedView(f, t), true
	r, err := Build(ctx, in)
	require.NoError(t, err)
	o := observation(t, r, BoundaryLLMGateway)
	assert.Equal(t, TrafficObserved, o.State)
	assert.Equal(t, "denied", o.EvidenceID)
	assert.Equal(t, "valid", o.Verification)
	assert.Equal(t, PolicyMatchesCurrent, o.Policy)
	assert.Equal(t, "denied", o.Outcome.Decision)
	assert.NotEqual(t, evidence.DispatchDispatched, o.Outcome.Dispatch)
	assert.Contains(t, o.Identity, "Talon key")
	assert.True(t, o.IdentityProven)
	assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
	assert.Contains(t, strings.Join(r.Verification.NotEstablished, "\n"), "that a provider was reached")
	require.NotNil(t, r.LastDecision)
	assert.Equal(t, "denied", r.LastDecision.EvidenceID, "the registration record, though newer, is not the last decision")
	assert.Equal(t, TrafficNone, observation(t, r, BoundaryActionGateway).State)
	assert.Equal(t, TrafficNone, observation(t, r, BoundaryMCPProxy).State)
}

// Stale policy, a missing digest and a tampered record never read as
// verified; the store being unreadable is "unavailable", not "none".
func TestVerification_StaleMissingTamperedUnavailable(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("recorded under another policy revision", func(t *testing.T) {
		f := peopleAnalytics(t)
		f.put(t, "stale", "gateway", now, func(ev *evidence.Evidence) {
			ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: "an-older-file", Effective: "an-older-effective"}
		})
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		o := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, PolicyDiffers, o.Policy)
		assert.Equal(t, ReadingTrafficDiffers, r.Verification.Reading.Code)
		assert.Equal(t, "different", r.LastDecision.AgentFile)
	})

	t.Run("no policy digest on the record", func(t *testing.T) {
		f := peopleAnalytics(t)
		f.put(t, "nodigest", "gateway", now, nil)
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		o := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, PolicyNotRecorded, o.Policy)
		assert.Equal(t, ReadingTrafficNotProven, r.Verification.Reading.Code)
		assert.NotContains(t, r.Verification.Reading.Text, "under the expected policy")
	})

	t.Run("only the agent digest is recorded", func(t *testing.T) {
		f := peopleAnalytics(t)
		agentDigest, _ := f.currentDigests(t)
		f.put(t, "half", "gateway", now, func(ev *evidence.Evidence) {
			ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: agentDigest}
		})
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		assert.Equal(t, PolicyNotRecorded, observation(t, r, BoundaryLLMGateway).Policy, "a partial match is not a match")
	})

	t.Run("changed after signing", func(t *testing.T) {
		f := peopleAnalytics(t)
		agentDigest, effDigest := f.currentDigests(t)
		f.put(t, "tampered", "gateway", now, func(ev *evidence.Evidence) {
			ev.PolicyDecision = evidence.PolicyDecision{Allowed: false, Action: "deny", PolicyDigests: &evidence.PolicyDigests{Agent: agentDigest, Effective: effDigest}}
		})
		db, err := sql.Open("sqlite3", filepath.Join(f.dir, "evidence.db"))
		require.NoError(t, err)
		defer db.Close()
		_, err = db.ExecContext(ctx, `UPDATE evidence SET evidence_json = replace(evidence_json, '"allowed":false', '"allowed":true') WHERE id = 'tampered'`)
		require.NoError(t, err)
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		o := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, "invalid", o.Verification)
		assert.Equal(t, PolicyUnverified, o.Policy, "digests that happen to match are not compared on an unauthenticated record")
		assert.False(t, o.IdentityProven, "nothing is established by a record that fails verification")
		assert.Equal(t, ReadingTrafficUnverified, r.Verification.Reading.Code)
	})

	t.Run("evidence store unreadable", func(t *testing.T) {
		f := peopleAnalytics(t)
		f.put(t, "x", "gateway", now, nil)
		require.NoError(t, f.store.Close())
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		for _, o := range r.Verification.Traffic {
			assert.Equal(t, TrafficUnavailable, o.State, o.Boundary)
			assert.NotEmpty(t, o.Error)
		}
		assert.Equal(t, ReadingEvidenceUnknown, r.Verification.Reading.Code)
		assert.Nil(t, r.LastDecision)
		assert.NotContains(t, strings.Join(r.Notes, "\n"), "no request of this use case is recorded yet", "unavailable is not 'none'")
	})

	t.Run("no evidence store", func(t *testing.T) {
		f := peopleAnalytics(t)
		in := f.inputs()
		in.Evidence = nil
		r, err := Build(ctx, in)
		require.NoError(t, err)
		assert.Equal(t, ReadingEvidenceUnknown, r.Verification.Reading.Code)
	})

	t.Run("disabled in the file", func(t *testing.T) {
		f := peopleAnalytics(t)
		p := filepath.Join(f.agents, uc, "agent.talon.yaml")
		raw := mustRead(t, p)
		mustWrite(t, p, strings.Replace(raw, "agent:\n", "agent:\n  enabled: false\n", 1))
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		assert.Equal(t, "disabled", r.Verification.Configured)
		assert.Equal(t, ReadingDisabled, r.Verification.Reading.Code)
	})
}

// An action-only use case is observed at the Action Gateway and is never
// presented as LLM traffic; establishing an operation is not dispatching it.
func TestVerification_ActionOnlyUseCase(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	now := time.Now().UTC()
	life(f, t, "established", evidence.ActionEventOperationEstablished, now.Add(-3*time.Minute), nil)
	life(f, t, "requested", evidence.ActionEventApprovalRequested, now.Add(-3*time.Minute+time.Second), nil)
	life(f, t, "decided", evidence.ActionEventApprovalDecided, now.Add(-2*time.Minute), nil)

	r, err := Build(ctx, f.inputs())
	require.NoError(t, err)
	a := observation(t, r, BoundaryActionGateway)
	assert.Equal(t, TrafficObserved, a.State)
	assert.Equal(t, "established", a.EvidenceID, "the reviewer's later decision is not the application's request")
	assert.Equal(t, evidence.ActionEventOperationEstablished, a.Event)
	assert.Nil(t, a.LastDispatch, "nothing was dispatched")
	assert.Equal(t, PolicyNotRecorded, a.Policy, "this use case's files declare no action policy to compare with")
	assert.Equal(t, TrafficNone, observation(t, r, BoundaryLLMGateway).State, "an action-only use case is not an LLM application")
	ne := strings.Join(r.Verification.NotEstablished, "\n")
	assert.Contains(t, ne, "no authenticated LLM gateway request of this use case is recorded")
	assert.Contains(t, ne, "that a governed action reached its destination")
	assert.Contains(t, r.Verification.Reading.Text, "Action Gateway")

	// The application claims and Talon dispatches: now a dispatch is recorded.
	life(f, t, "claimed", evidence.ActionEventAttemptClaimed, now.Add(-time.Minute), nil)
	f.put(t, "completed", evidence.InvocationTypeActionLifecycle, now, func(ev *evidence.Evidence) {
		ev.ActionLifecycle = &evidence.ActionLifecycle{Event: evidence.ActionEventAttemptCompleted, OperationID: "op-1", OperationRef: "op_1", PolicyDigest: "recorded-digest", OperationStatus: "succeeded", ResultProvenance: "observed", AttemptStatus: "completed"}
	})
	r, err = Build(ctx, f.inputs())
	require.NoError(t, err)
	a = observation(t, r, BoundaryActionGateway)
	assert.Equal(t, "claimed", a.EvidenceID, "the application's claim is its newest request; the execution record is not connectivity")
	assert.Equal(t, evidence.ActionEventAttemptClaimed, a.Event)
	require.NotNil(t, a.LastDispatch, "the execution outcome is reported on its own")
	assert.Equal(t, "completed", a.LastDispatch.EvidenceID)
	assert.NotContains(t, strings.Join(r.Verification.NotEstablished, "\n"), "that a governed action reached its destination")
}

func life(f fixture, t *testing.T, id, event string, at time.Time, mod func(*evidence.ActionLifecycle)) {
	t.Helper()
	f.put(t, id, evidence.InvocationTypeActionLifecycle, at, func(ev *evidence.Evidence) {
		ev.ActionLifecycle = &evidence.ActionLifecycle{Event: event, OperationID: "op-1", OperationRef: "op_1", Action: "create_refund_request", PolicyDigest: "bound-digest", OperationStatus: "awaiting_approval"}
		if mod != nil {
			mod(ev.ActionLifecycle)
		}
	})
}

// #567 review. Only records that unambiguously establish a request of the
// application count as its Action Gateway traffic. An authorization refusal
// is written for an application's refused claim AND for a reviewer who was
// not allowed to decide, so it never counts; neither does a reviewer's
// decision, Talon closing an approval, or an execution record. None of them
// advances the application's last authenticated request, however many are
// written after it: the lookup selects qualifying events directly, so more
// than the earlier window of 25 records cannot hide the application's
// request, and a completed dispatch is found the same way.
func TestVerification_ActionGatewayCountsOnlyApplicationRequests(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	now := time.Now().UTC()
	t0 := now.Add(-time.Hour)
	life(f, t, "established", evidence.ActionEventOperationEstablished, t0, nil)
	life(f, t, "requested", evidence.ActionEventApprovalRequested, t0.Add(time.Second), nil)
	life(f, t, "dispatched-earlier", evidence.ActionEventAttemptCompleted, t0.Add(2*time.Second), func(a *evidence.ActionLifecycle) { a.AttemptStatus = "completed" })

	// A reviewer who is not authorized tries to decide; an authorized
	// reviewer decides; Talon expires another approval; the application's
	// own claim is refused. All newer than the establishment.
	life(f, t, "reviewer-refused", evidence.ActionEventAuthorizationRefused, t0.Add(time.Minute), func(a *evidence.ActionLifecycle) {
		a.ReviewerPrincipal, a.RefusalCode = "apr_intruder", "approval_not_authorized"
	})
	life(f, t, "reviewer-decided", evidence.ActionEventApprovalDecided, t0.Add(2*time.Minute), func(a *evidence.ActionLifecycle) { a.ReviewerPrincipal = "apr_lead" })
	life(f, t, "system-expired", evidence.ActionEventApprovalDecided, t0.Add(3*time.Minute), func(a *evidence.ActionLifecycle) { a.ApprovalStatus = "expired" })
	life(f, t, "claim-refused", evidence.ActionEventAuthorizationRefused, t0.Add(4*time.Minute), func(a *evidence.ActionLifecycle) { a.RefusalCode = "approval_pending" })
	life(f, t, "reconciled-armed", evidence.ActionEventAttemptArmed, t0.Add(5*time.Minute), nil)
	// ...and more reviewer and system records than the earlier lookup read.
	for i := 0; i < 40; i++ {
		event := evidence.ActionEventApprovalDecided
		if i%2 == 0 {
			event = evidence.ActionEventAuthorizationRefused
		}
		life(f, t, "noise-"+string(rune('a'+i%26))+string(rune('a'+i/26)), event, t0.Add(6*time.Minute+time.Duration(i)*time.Second), func(a *evidence.ActionLifecycle) { a.ReviewerPrincipal = "apr_other" })
	}

	r, err := Build(ctx, f.inputs())
	require.NoError(t, err)
	a := observation(t, r, BoundaryActionGateway)
	require.Equal(t, TrafficObserved, a.State, "48 later records do not hide the application's request")
	assert.Equal(t, "established", a.EvidenceID)
	assert.True(t, a.Timestamp.Equal(t0), "no reviewer or system record advanced the application's last authenticated request")
	assert.True(t, a.IdentityProven)
	assert.Contains(t, a.Identity, "the use case's agent key")
	assert.Contains(t, a.Establishes, "A reviewer's decision, an expiry, a refused authorization and an execution record are not counted")
	require.NotNil(t, a.LastDispatch, "the recorded execution outcome stays available, on its own")
	assert.Equal(t, "dispatched-earlier", a.LastDispatch.EvidenceID)
	assert.Equal(t, "established", r.LastDecision.EvidenceID, "the last decision is a request, never a reviewer or system record")
	assert.Equal(t, TrafficNone, observation(t, r, BoundaryLLMGateway).State, "an action-only use case is not LLM-connected")

	// The lookups are index searches for exactly the event asked for.
	rows, err := f.store.DB().QueryContext(ctx, `EXPLAIN QUERY PLAN SELECT evidence_json FROM evidence
		 WHERE invocation_type = 'action_lifecycle' AND tenant_id = ? AND agent_id = ?
		   AND json_extract(evidence_json, '$.action_lifecycle.event') = ?
		 ORDER BY timestamp DESC, id DESC LIMIT 1`, "default", uc, evidence.ActionEventOperationEstablished)
	require.NoError(t, err)
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &unused, &detail))
		plan = append(plan, detail)
	}
	require.NoError(t, rows.Close())
	assert.Contains(t, strings.Join(plan, " | "), "idx_evidence_action_event", strings.Join(plan, " | "))
	assert.NotContains(t, strings.Join(plan, " | "), "SCAN", strings.Join(plan, " | "))

	// The application claims: THAT is a request of the application.
	life(f, t, "claimed", evidence.ActionEventAttemptClaimed, now, nil)
	r, err = Build(ctx, f.inputs())
	require.NoError(t, err)
	a = observation(t, r, BoundaryActionGateway)
	assert.Equal(t, "claimed", a.EvidenceID)
	assert.True(t, a.IdentityProven)

	// A record whose signature fails establishes nothing: no identity, no
	// policy, and a dispatch record that fails is not a dispatch.
	_, err = f.store.DB().ExecContext(ctx, `UPDATE evidence SET evidence_json = replace(evidence_json, '"operation_id":"op-1"', '"operation_id":"op-2"') WHERE id IN ('claimed', 'dispatched-earlier')`)
	require.NoError(t, err)
	r, err = Build(ctx, f.inputs())
	require.NoError(t, err)
	a = observation(t, r, BoundaryActionGateway)
	assert.Equal(t, "invalid", a.Verification)
	assert.False(t, a.IdentityProven, "an invalid signature never establishes authenticated identity")
	assert.Equal(t, PolicyUnverified, a.Policy)
	assert.Empty(t, a.Credential)
	require.NotNil(t, a.LastDispatch)
	assert.Equal(t, "invalid", a.LastDispatch.Verification)
	assert.Contains(t, strings.Join(r.Verification.NotEstablished, "\n"), "the newest dispatch record does not verify")
	assert.Equal(t, ReadingTrafficUnverified, r.Verification.Reading.Code)

	// A store that cannot be read is "unavailable", never "none".
	require.NoError(t, f.store.Close())
	r, err = Build(ctx, f.inputs())
	require.NoError(t, err)
	a = observation(t, r, BoundaryActionGateway)
	assert.Equal(t, TrafficUnavailable, a.State)
	assert.NotEmpty(t, a.Error)
}

// The policy digest on an Action Gateway record is the one the operation was
// BOUND to at establishment. Only the establishment record evaluated it; a
// later record of the operation repeats it and is reported as "bound", never
// as "evaluated under the expected policy" (#567 review).
func TestComparePolicy_ActionBoundVersusEvaluated(t *testing.T) {
	in := verificationInputs{action: &ActionBoundary{PolicyDigest: "current"}}
	at := func(event, digest string) TrafficObservation {
		o := TrafficObservation{Boundary: BoundaryActionGateway, Verification: "valid"}
		comparePolicy(&o, &evidence.Evidence{ActionLifecycle: &evidence.ActionLifecycle{Event: event, PolicyDigest: digest}}, in)
		return o
	}
	assert.Equal(t, PolicyMatchesCurrent, at(evidence.ActionEventOperationEstablished, "current").Policy, "the establishment evaluated this policy")
	assert.Equal(t, PolicyDiffers, at(evidence.ActionEventOperationEstablished, "older").Policy)

	claim := at(evidence.ActionEventAttemptClaimed, "current")
	assert.Equal(t, PolicyBoundOnly, claim.Policy)
	assert.Contains(t, claim.PolicyNote, "bound to when it was established (it equals what the current files compile to), not a policy evaluated for this event")
	conflict := at(evidence.ActionEventOperationConflict, "older")
	assert.Equal(t, PolicyBoundOnly, conflict.Policy)
	assert.Contains(t, conflict.PolicyNote, "it differs from what the current files compile to")

	assert.Equal(t, PolicyNotRecorded, at(evidence.ActionEventAttemptClaimed, "").Policy, "nothing recorded stays 'not recorded'")
	unverified := TrafficObservation{Boundary: BoundaryActionGateway, Verification: "invalid"}
	comparePolicy(&unverified, &evidence.Evidence{ActionLifecycle: &evidence.ActionLifecycle{Event: evidence.ActionEventOperationEstablished, PolicyDigest: "current"}}, in)
	assert.Equal(t, PolicyUnverified, unverified.Policy, "an invalid signature never verifies a policy")
}

// The request's session id stays on the last decision (#567 review: the new
// projection dropped a field the effective report had before) and is the
// same on the boundary's observation.
func TestVerification_LastDecisionKeepsTheSessionID(t *testing.T) {
	f := peopleAnalytics(t)
	f.put(t, "with-session", "gateway", time.Now().UTC(), func(ev *evidence.Evidence) { ev.SessionID = "sess-4711" })
	r, err := Build(context.Background(), f.inputs())
	require.NoError(t, err)
	require.NotNil(t, r.LastDecision)
	assert.Equal(t, "sess-4711", r.LastDecision.SessionID)
	assert.Equal(t, "sess-4711", observation(t, r, BoundaryLLMGateway).SessionID)
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"last_decision":{"evidence_id":"with-session"`)
	assert.Contains(t, string(raw), `"session_id":"sess-4711"`)

	// A request without a session carries none.
	g := peopleAnalytics(t)
	g.put(t, "no-session", "gateway", time.Now().UTC(), nil)
	r, err = Build(context.Background(), g.inputs())
	require.NoError(t, err)
	assert.Empty(t, r.LastDecision.SessionID)
}

// MCP proxy records do not record how the caller was identified (the proxy
// uses the presented agent key when there is one, and its own configured
// agent name on admin-key or development-open requests). They are shown as
// what they are and never establish an authenticated connection; a record
// that does establish the use case's credential is what the reading speaks
// about, and a newest record that fails verification is stated first.
func TestVerification_IdentityIsProvenOnlyWhereTheRecordEstablishesIt(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("MCP proxy records only", func(t *testing.T) {
		f := peopleAnalytics(t)
		f.put(t, "mcp", "proxy_tool_call", now, nil)
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		m := observation(t, r, BoundaryMCPProxy)
		assert.Equal(t, TrafficObserved, m.State)
		assert.False(t, m.IdentityProven)
		assert.Contains(t, m.Identity, "not recorded")
		assert.Contains(t, m.Establishes, "does not establish that the use case's key was presented")
		assert.Equal(t, PolicyNotRecorded, m.Policy)
		assert.Equal(t, ReadingTrafficIdentityUnknown, r.Verification.Reading.Code)
		assert.Contains(t, r.Verification.Reading.Text, "an authenticated connection is not established")
		assert.Contains(t, r.Verification.Reading.Text, "caller identity not recorded")
		assert.NotContains(t, r.Verification.Reading.Text, "Authenticated traffic observed")
		require.NotNil(t, r.LastDecision, "the newest decision at any boundary is still pointed at")
		assert.Equal(t, "mcp", r.LastDecision.EvidenceID)
	})

	t.Run("a record of the no-key quickstart profile", func(t *testing.T) {
		f := peopleAnalytics(t)
		agentDigest, effDigest := f.currentDigests(t)
		f.put(t, "quickstart", "gateway", now, func(ev *evidence.Evidence) {
			ev.GatewayAnnotations = []string{"quickstart_mode"}
			ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: agentDigest, Effective: effDigest}
		})
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		g := observation(t, r, BoundaryLLMGateway)
		assert.Equal(t, TrafficObserved, g.State)
		assert.False(t, g.IdentityProven, "the quickstart identity is the one LLM gateway identity without a key")
		assert.Contains(t, g.Identity, "no credential")
		assert.Equal(t, ReadingTrafficIdentityUnknown, r.Verification.Reading.Code)
		assert.Contains(t, r.Verification.Reading.Text, "caller identity no credential")
		assert.NotContains(t, r.Verification.Reading.Text, "Authenticated traffic observed")
	})

	t.Run("an authenticated LLM request and a newer MCP record", func(t *testing.T) {
		f := peopleAnalytics(t)
		agentDigest, effDigest := f.currentDigests(t)
		f.put(t, "llm", "gateway", now.Add(-time.Minute), func(ev *evidence.Evidence) {
			ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: agentDigest, Effective: effDigest}
		})
		f.put(t, "mcp", "proxy_tool_call", now, nil)
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		assert.True(t, observation(t, r, BoundaryLLMGateway).IdentityProven)
		assert.False(t, observation(t, r, BoundaryMCPProxy).IdentityProven)
		assert.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code, "the reading speaks about the record that establishes the credential")
		assert.Contains(t, r.Verification.Reading.Text, "(llm)")
		assert.Equal(t, "mcp", r.LastDecision.EvidenceID, "the last decision is the newest record at any boundary")
	})

	t.Run("a verified workload identity", func(t *testing.T) {
		f := peopleAnalytics(t)
		f.put(t, "delegated", "gateway", now, func(ev *evidence.Evidence) {
			ev.WorkloadIdentity = &evidence.WorkloadIdentity{Status: "verified", Runtime: "openshell", AuthMethod: "hop_assertion"}
		})
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		g := observation(t, r, BoundaryLLMGateway)
		assert.True(t, g.IdentityProven)
		assert.Contains(t, g.Identity, "verified workload identity (openshell hop_assertion)")
	})

	t.Run("a newest record that fails verification is stated first", func(t *testing.T) {
		f := peopleAnalytics(t)
		agentDigest, effDigest := f.currentDigests(t)
		f.put(t, "llm", "gateway", now.Add(-time.Minute), func(ev *evidence.Evidence) {
			ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: agentDigest, Effective: effDigest}
		})
		f.put(t, "mcp-tampered", "proxy_tool_blocked", now, func(ev *evidence.Evidence) {
			ev.PolicyDecision = evidence.PolicyDecision{Allowed: false, Action: "deny"}
		})
		db, err := sql.Open("sqlite3", filepath.Join(f.dir, "evidence.db"))
		require.NoError(t, err)
		defer db.Close()
		_, err = db.ExecContext(ctx, `UPDATE evidence SET evidence_json = replace(evidence_json, '"allowed":false', '"allowed":true') WHERE id = 'mcp-tampered'`)
		require.NoError(t, err)
		r, err := Build(ctx, f.inputs())
		require.NoError(t, err)
		m := observation(t, r, BoundaryMCPProxy)
		assert.Equal(t, "invalid", m.Verification)
		assert.False(t, m.IdentityProven)
		assert.Contains(t, m.Identity, "signature does not verify")
		assert.Equal(t, ReadingTrafficUnverified, r.Verification.Reading.Code)
		assert.Equal(t, PolicyMatchesCurrent, observation(t, r, BoundaryLLMGateway).Policy, "the valid record at another boundary keeps its own facts")
	})
}

// The lookup is an indexed range read per invocation type, and it is scoped
// to the tenant and the use case: another use case's or tenant's traffic is
// never this one's.
func TestVerification_BoundedAndScoped(t *testing.T) {
	f := peopleAnalytics(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.put(t, "other-uc", "gateway", now, func(ev *evidence.Evidence) { ev.AgentID = "another-use-case" })
	f.put(t, "other-tenant", "gateway", now, func(ev *evidence.Evidence) { ev.TenantID = "acme" })
	r, err := Build(ctx, f.inputs())
	require.NoError(t, err)
	assert.Equal(t, TrafficNone, observation(t, r, BoundaryLLMGateway).State)

	plan, err := f.store.ExplainQueryPlan(ctx,
		`SELECT evidence_json FROM evidence WHERE tenant_id = ? AND agent_id = ? AND invocation_type = ? ORDER BY timestamp DESC, id DESC LIMIT ?`, "default", uc, "gateway", 1)
	require.NoError(t, err)
	joined := strings.Join(plan, "\n")
	assert.Contains(t, joined, "idx_evidence_tenant_agent_type_ts", joined)
	assert.NotContains(t, joined, "SCAN evidence", joined)
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return string(b)
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
}
