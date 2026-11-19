package effective

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// Verification answers, for one AI use case, the questions an operator asks
// after connecting an application (#472). It is a set of INDEPENDENT
// observations, each from its own source, never a lifecycle:
//
//   - Configured: what the agent file says (enabled or stopped).
//   - Activation: Report.Loaded and the per-boundary proofs (runtime records).
//   - Traffic: per interception boundary, the newest signed record that an
//     authenticated request of this use case produced there.
//   - Policy: whether that record verifies and was evaluated under the policy
//     the current files compile to.
//
// Nothing here says the application is "governed" or that all of its traffic
// goes through Talon: Talon sees only what reaches an interception boundary.
// Unknown and unavailable are values; they are never read as zero or healthy.
type Verification struct {
	// Configured: enabled | disabled, from the agent file.
	Configured string `json:"configured"`
	// Traffic has one entry per boundary, in a fixed order.
	Traffic []TrafficObservation `json:"traffic"`
	// Reading is a presentation summary of the facts above for a person. It
	// is derived here, once, so the CLI and the console say the same thing;
	// it is not a stored or canonical state.
	Reading Reading `json:"reading"`
	// NotEstablished lists what these observations do not prove.
	NotEstablished []string `json:"not_established"`
}

// Reading is a one-line description with a stable code.
type Reading struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

// Reading codes.
const (
	ReadingDisabled          = "disabled"
	ReadingEvidenceUnknown   = "evidence_unavailable"
	ReadingNotLoaded         = "registered_not_loaded"
	ReadingLoadUnknown       = "registered_activation_unknown"
	ReadingLoadedNoTraffic   = "loaded_no_traffic_observed"
	ReadingTrafficMatches    = "traffic_observed_policy_matches"
	ReadingTrafficDiffers    = "traffic_observed_policy_differs"
	ReadingTrafficNotProven  = "traffic_observed_policy_not_proven"
	ReadingTrafficUnverified = "traffic_record_unverified"
	// ReadingTrafficIdentityUnknown: records attributed to the use case
	// exist, but none establishes that its own credential was presented
	// (MCP proxy records, records of the no-key quickstart profile).
	ReadingTrafficIdentityUnknown = "traffic_observed_identity_not_established"
)

// Interception boundaries an observation can belong to.
const (
	BoundaryLLMGateway    = "llm_gateway"
	BoundaryMCPProxy      = "mcp_proxy"
	BoundaryActionGateway = "action_gateway"
)

// Traffic states.
const (
	TrafficObserved    = "observed"
	TrafficNone        = "none"
	TrafficUnavailable = "unavailable"
)

// Policy comparison states of an observed record.
const (
	PolicyMatchesCurrent = "matches_current"
	PolicyDiffers        = "differs_from_current"
	PolicyNotRecorded    = "not_recorded"
	PolicyUnverified     = "unverified"
)

// TrafficObservation is the newest qualifying record at one boundary.
type TrafficObservation struct {
	Boundary string `json:"boundary"`
	// State: observed | none | unavailable.
	State string `json:"state"`
	// Establishes says what an observation at this boundary does and does
	// not prove.
	Establishes string `json:"establishes"`

	EvidenceID     string     `json:"evidence_id,omitempty"`
	Timestamp      *time.Time `json:"timestamp,omitempty"`
	InvocationType string     `json:"invocation_type,omitempty"`
	// Event is the Action Gateway lifecycle event of the record.
	Event string `json:"event,omitempty"`
	// Identity says how the request was tied to this use case, and
	// IdentityProven whether the record establishes that the use case's own
	// credential (its Talon key, or a verified workload identity) was
	// presented. MCP proxy records do not record it: the proxy attributes a
	// call to the presented agent key when there is one, and to its own
	// configured agent name on an admin-key or development-open request.
	Identity       string `json:"identity,omitempty"`
	IdentityProven bool   `json:"identity_proven"`
	// Outcome separates Talon's decision from dispatch and the destination's
	// answer (evidence.OutcomeOf).
	Outcome *evidence.Outcome `json:"outcome,omitempty"`
	// Verification is the record's signature check: valid | invalid.
	Verification string `json:"verification,omitempty"`
	// Policy compares the policy recorded on the record with the current
	// files: matches_current | differs_from_current | not_recorded |
	// unverified. PolicyNote says which digests were compared.
	Policy     string `json:"policy,omitempty"`
	PolicyNote string `json:"policy_note,omitempty"`
	// LastDispatch (Action Gateway only) is the newest completed dispatch
	// attempt: establishing or authorizing an action is not dispatching it.
	LastDispatch *DispatchObservation `json:"last_dispatch,omitempty"`
	Error        string               `json:"error,omitempty"`

	primaryCode, primaryReason       string
	recordedAgent, recordedEffective string
	agentFile, effectivePolicy       string
}

// DispatchObservation is one completed Action Gateway dispatch attempt.
type DispatchObservation struct {
	EvidenceID   string           `json:"evidence_id"`
	Timestamp    time.Time        `json:"timestamp"`
	Outcome      evidence.Outcome `json:"outcome"`
	Verification string           `json:"verification"`
}

// boundarySpec names the invocation types whose records an AUTHENTICATED
// request of the use case produces at a boundary. It is an explicit list,
// not "every request-class record": operator and configuration events
// (registration, enable/disable, reload, budget thresholds), provider
// attempts, imported external events and native runs establish nothing
// about an application's connection to a boundary. A request with an
// unknown or invalid key is rejected before any record is written, so it
// cannot appear under a use case at all.
type boundarySpec struct {
	boundary    string
	types       []string
	establishes string
	// keyAuthenticated: every record of these types under a use case was
	// produced by a request that presented that use case's credential.
	// True for the LLM gateway (a key resolves to exactly one use case or
	// the request is rejected; a delegated request carries a verified
	// workload identity; the one keyless identity, the quickstart profile,
	// is marked on its records and excluded in identityOf) and the Action
	// Gateway (the agent key is required; admin keys and development-open
	// requests are refused). False for the MCP proxy, whose records do not
	// say how the caller was identified.
	keyAuthenticated bool
}

var boundarySpecs = []boundarySpec{
	{
		boundary:         BoundaryLLMGateway,
		types:            []string{"gateway"},
		keyAuthenticated: true,
		establishes:      "a request that presented this use case's Talon key reached the LLM gateway and Talon recorded its decision. A denied request establishes the connection and the policy evaluation, not that a provider was reached or answered",
	},
	{
		boundary:    BoundaryMCPProxy,
		types:       []string{"proxy_tool_call", "proxy_tool_blocked", "proxy_upstream_error"},
		establishes: "a tool call attributed to this use case reached the MCP proxy and Talon recorded its decision. MCP proxy records do not record how the caller was identified, so this does not establish that the use case's key was presented. It says nothing about model traffic",
	},
	{
		boundary:         BoundaryActionGateway,
		types:            []string{evidence.InvocationTypeActionLifecycle},
		keyAuthenticated: true,
		establishes:      "the application established a governed action operation with this use case's identity. Establishing or authorizing an operation is not dispatching it: see the last dispatch. It says nothing about model traffic",
	},
}

// actionApplicationEvents are the lifecycle events an application request
// causes. A reviewer's decision, an expiry or a sweep is recorded under the
// use case too, and is not application traffic.
var actionApplicationEvents = map[string]bool{
	evidence.ActionEventOperationEstablished: true,
	evidence.ActionEventOperationConflict:    true,
	evidence.ActionEventAttemptClaimed:       true,
	evidence.ActionEventAttemptArmed:         true,
	evidence.ActionEventAttemptCompleted:     true,
	evidence.ActionEventAuthorizationRefused: true,
}

// actionLookback bounds how many of the newest lifecycle records are read
// to find one an application request caused.
const actionLookback = 25

type verificationInputs struct {
	store     *evidence.Store
	tenant    string
	name      string
	agent     *policy.Policy
	digest    string // current agent file policy digest
	providers []ProviderEffective
	action    *ActionBoundary
	loaded    runtimestatus.Loaded
}

// buildVerification reads at most a handful of indexed rows per boundary
// (evidence.Store.NewestByType) and verifies the signature of each record
// it presents (evidence.Store.Detail).
func buildVerification(ctx context.Context, in verificationInputs) *Verification {
	v := &Verification{Configured: "enabled", Traffic: []TrafficObservation{}}
	if in.agent != nil && !in.agent.Agent.IsEnabled() {
		v.Configured = "disabled"
	}
	for _, spec := range boundarySpecs {
		v.Traffic = append(v.Traffic, observeBoundary(ctx, in, spec))
	}
	v.Reading = readingOf(v, in.loaded)
	v.NotEstablished = notEstablished(v)
	return v
}

func observeBoundary(ctx context.Context, in verificationInputs, spec boundarySpec) TrafficObservation {
	o := TrafficObservation{Boundary: spec.boundary, State: TrafficNone, Establishes: spec.establishes}
	if in.store == nil {
		o.State, o.Error = TrafficUnavailable, "no evidence store was given"
		return o
	}
	newest, dispatch, err := newestQualifying(ctx, in, spec)
	if err != nil {
		o.State, o.Error = TrafficUnavailable, err.Error()
		return o
	}
	if newest == nil {
		return o
	}
	// Re-read through the verifying path before anything on the record is
	// presented as history.
	det, err := in.store.Detail(ctx, newest.ID)
	if err != nil {
		o.State, o.Error = TrafficUnavailable, err.Error()
		return o
	}
	ev := det.Record
	ts := ev.Timestamp
	out := det.Outcome
	o.State, o.EvidenceID, o.Timestamp, o.InvocationType = TrafficObserved, ev.ID, &ts, ev.InvocationType
	o.Outcome, o.Verification = &out, det.Verification.State
	o.Identity, o.IdentityProven = identityOf(ev, spec, det.Verification.State == "valid")
	if ev.ActionLifecycle != nil {
		o.Event = ev.ActionLifecycle.Event
	}
	comparePolicy(&o, ev, in)
	if dispatch != nil {
		if dd, err := in.store.Detail(ctx, dispatch.ID); err == nil {
			o.LastDispatch = &DispatchObservation{EvidenceID: dd.Record.ID, Timestamp: dd.Record.Timestamp, Outcome: dd.Outcome, Verification: dd.Verification.State}
		}
	}
	return o
}

// newestQualifying returns the newest record an authenticated application
// request produced at the boundary and, for the Action Gateway, the newest
// completed dispatch attempt. One bounded indexed read per invocation type.
func newestQualifying(ctx context.Context, in verificationInputs, spec boundarySpec) (newest, dispatch *evidence.Evidence, err error) {
	isAction := spec.boundary == BoundaryActionGateway
	limit := 1
	if isAction {
		limit = actionLookback
	}
	for _, typ := range spec.types {
		recs, err := in.store.NewestByType(ctx, in.tenant, in.name, typ, limit)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range recs {
			if isAction && (r.ActionLifecycle == nil || !actionApplicationEvents[r.ActionLifecycle.Event]) {
				continue
			}
			if isAction && dispatch == nil && r.ActionLifecycle.Event == evidence.ActionEventAttemptCompleted {
				dispatch = r
			}
			if newest == nil || r.Timestamp.After(newest.Timestamp) {
				newest = r
			}
		}
	}
	return newest, dispatch, nil
}

// identityOf says how the record's request was tied to the use case and
// whether the record establishes that the use case's own credential was
// presented. Nothing is established by a record whose signature fails.
func identityOf(ev *evidence.Evidence, spec boundarySpec, verified bool) (text string, proven bool) {
	switch {
	case !verified:
		return "not established: the record's signature does not verify", false
	case hasAnnotation(ev, annotationQuickstart):
		// The one LLM gateway identity that is not backed by a key
		// (gateway.NewQuickstartIdentity): the no-key quickstart profile.
		return "no credential: the request came through the no-key quickstart profile, which serves one synthetic identity without a key", false
	case ev.WorkloadIdentity != nil && ev.WorkloadIdentity.Status == "verified":
		return "verified workload identity (" + strings.TrimSpace(ev.WorkloadIdentity.Runtime+" "+ev.WorkloadIdentity.AuthMethod) + ")", true
	case spec.keyAuthenticated:
		return "the use case's Talon key (at this boundary a request with an unknown key is rejected before any record is written)", true
	}
	return "not recorded: the MCP proxy attributes a call to the presented agent key when there is one, and to its own configured agent name on an admin-key or development-open request; the record does not say which", false
}

// annotationQuickstart is the gateway annotation every record of the no-key
// quickstart profile carries (gateway.gatewayAnnotationsForEvidence).
const annotationQuickstart = "quickstart_mode"

func hasAnnotation(ev *evidence.Evidence, name string) bool {
	for _, a := range ev.GatewayAnnotations {
		if a == name {
			return true
		}
	}
	return false
}

// comparePolicy compares what the record says it was evaluated under with
// what the current files compile to. A record whose signature does not
// verify is never compared: nothing on it is authenticated.
func comparePolicy(o *TrafficObservation, ev *evidence.Evidence, in verificationInputs) {
	o.agentFile, o.effectivePolicy = "not_recorded", "not_recorded"
	if o.Verification != "valid" {
		o.Policy, o.agentFile, o.effectivePolicy = PolicyUnverified, "unverified", "unverified"
		o.PolicyNote = "the record's signature does not verify: it was changed after signing, so its decision and recorded digests are not authenticated and are not compared with the current files"
		return
	}
	if p, ok := explanation.Primary(ev.Explanations); ok {
		o.primaryCode, o.primaryReason = p.Code, p.Reason
	}
	switch {
	case ev.ActionLifecycle != nil:
		compareActionPolicy(o, ev.ActionLifecycle.PolicyDigest, in.action)
	case o.Boundary == BoundaryMCPProxy:
		o.Policy, o.PolicyNote = PolicyNotRecorded, "MCP proxy records carry no policy digest: which policy revision decided is not recorded"
	default:
		compareGatewayPolicy(o, ev.PolicyDecision.PolicyDigests, in)
	}
}

func compareActionPolicy(o *TrafficObservation, recorded string, b *ActionBoundary) {
	switch {
	case recorded == "":
		o.Policy, o.PolicyNote = PolicyNotRecorded, "the record carries no action policy digest"
	case b == nil || b.Error != "" || b.PolicyDigest == "":
		o.Policy, o.PolicyNote = PolicyNotRecorded, "the current action policy cannot be compiled from the files, so there is nothing to compare the recorded digest with"
	case recorded == b.PolicyDigest:
		o.Policy, o.PolicyNote = PolicyMatchesCurrent, "the action policy digest on the record equals the one the current files compile to"
	default:
		o.Policy, o.PolicyNote = PolicyDiffers, "the action policy digest on the record differs from the one the current files compile to: the policy changed since, or the process ran another configuration"
	}
}

func compareGatewayPolicy(o *TrafficObservation, d *evidence.PolicyDigests, in verificationInputs) {
	if d == nil || (d.Agent == "" && d.Effective == "") {
		o.Policy, o.PolicyNote = PolicyNotRecorded, "the record carries no policy digests: which policy revision decided is not recorded"
		return
	}
	o.recordedAgent, o.recordedEffective = d.Agent, d.Effective
	if d.Agent != "" {
		o.agentFile = "different"
		if d.Agent == in.digest {
			o.agentFile = "same"
		}
	}
	if d.Effective != "" {
		o.effectivePolicy = "differs_from_current"
		for _, p := range in.providers {
			if p.EffectiveDigest == d.Effective {
				o.effectivePolicy = "matches_current:" + p.Name
				break
			}
		}
	}
	switch {
	case o.agentFile == "different" || o.effectivePolicy == "differs_from_current":
		o.Policy = PolicyDiffers
		o.PolicyNote = fmt.Sprintf("recorded agent policy vs current file: %s; recorded effective policy: %s. The policy changed since this request, or the process ran another configuration", o.agentFile, o.effectivePolicy)
	case o.agentFile == "same" && strings.HasPrefix(o.effectivePolicy, "matches_current"):
		o.Policy = PolicyMatchesCurrent
		o.PolicyNote = "the agent policy digest and the effective policy digest on the record equal the ones the current files compile to (" + o.effectivePolicy + ")"
	default:
		o.Policy = PolicyNotRecorded
		o.PolicyNote = fmt.Sprintf("only part of the policy is recorded (agent policy: %s; effective policy: %s), so a match with the current files is not established", o.agentFile, o.effectivePolicy)
	}
}

// observe fills sections 4 and 5 of the report: the observed traffic (the
// newest request record per interception boundary, each re-read through the
// verifying path, with whether it establishes the use case's own credential)
// and the last decision taken from it.
func (r *Report) observe(ctx context.Context, in Inputs, vin verificationInputs) {
	r.Verification = buildVerification(ctx, vin)
	un := r.Verification.unavailable()
	switch {
	case in.Evidence == nil:
		r.Notes = append(r.Notes, "no evidence store was read: observed traffic and the last decision are unknown")
	case len(un) > 0:
		r.Notes = append(r.Notes, "last decision unavailable: the evidence could not be read for "+strings.Join(un, ", "))
	}
	if r.LastDecision = lastDecisionOf(r.Verification); r.LastDecision == nil && in.Evidence != nil && len(un) == 0 {
		r.Notes = append(r.Notes, "no request of this use case is recorded yet at any interception boundary (registration, enable/disable and reload records are operator events, not decisions)")
	}
}

// newestObserved returns the newest observed record across boundaries.
func (v *Verification) newestObserved() *TrafficObservation {
	var newest *TrafficObservation
	for i := range v.Traffic {
		o := &v.Traffic[i]
		if o.State != TrafficObserved || o.Timestamp == nil {
			continue
		}
		if newest == nil || o.Timestamp.After(*newest.Timestamp) {
			newest = o
		}
	}
	return newest
}

// newestProven returns the newest observed record whose request is
// established to have presented the use case's own credential.
func (v *Verification) newestProven() *TrafficObservation {
	var newest *TrafficObservation
	for i := range v.Traffic {
		o := &v.Traffic[i]
		if o.State != TrafficObserved || o.Timestamp == nil || !o.IdentityProven {
			continue
		}
		if newest == nil || o.Timestamp.After(*newest.Timestamp) {
			newest = o
		}
	}
	return newest
}

func (v *Verification) unavailable() []string {
	var out []string
	for i := range v.Traffic {
		if v.Traffic[i].State == TrafficUnavailable {
			out = append(out, v.Traffic[i].Boundary)
		}
	}
	return out
}

// readingOf words the independent facts for a person. Activation and
// traffic are stated side by side: traffic recorded earlier does not prove
// the use case is loaded now, and a loaded use case proves no traffic.
func readingOf(v *Verification, loaded runtimestatus.Loaded) Reading {
	activation := map[string]string{
		runtimestatus.LoadedMatchesFile:     "a running Talon process has loaded this agent file",
		runtimestatus.LoadedDiffersFromFile: "a running Talon process has loaded a DIFFERENT version of this agent file",
		runtimestatus.NotInActiveGeneration: "no running Talon process has this use case in its active generation",
		runtimestatus.LoadedUnknown:         "whether a running Talon process has loaded this agent file is not known",
	}[loaded.State]
	if activation == "" {
		activation = "whether a running Talon process has loaded this agent file is not known"
	}
	if v.Configured == "disabled" {
		return Reading{ReadingDisabled, "Configured as disabled (agent.enabled: false): new work is refused once a running process has loaded this file; " + activation + "."}
	}
	latest := v.newestObserved()
	if latest == nil {
		if un := v.unavailable(); len(un) > 0 {
			return Reading{ReadingEvidenceUnknown, "Whether authenticated traffic was observed is not known: the evidence could not be read for " + strings.Join(un, ", ") + "; " + activation + "."}
		}
		switch loaded.State {
		case runtimestatus.LoadedMatchesFile:
			return Reading{ReadingLoadedNoTraffic, "Loaded, no authenticated traffic observed: " + activation + ", and no request of this use case has been recorded at the LLM gateway, the MCP proxy or the Action Gateway."}
		case runtimestatus.LoadedUnknown, "":
			return Reading{ReadingLoadUnknown, "Registered; activation unknown and no authenticated traffic observed: " + activation + "."}
		}
		return Reading{ReadingNotLoaded, "Registered, not loaded: " + activation + ", and no authenticated traffic has been observed."}
	}
	// A newest record that fails verification is stated first, whatever
	// older or other records say.
	if latest.Verification != "valid" {
		return Reading{ReadingTrafficUnverified, fmt.Sprintf("A record exists but does not verify: the newest record is at the %s at %s (%s), and its signature is invalid, so nothing on it is established; %s.",
			boundaryLabel(latest.Boundary), latest.Timestamp.UTC().Format(time.RFC3339), latest.EvidenceID, activation)}
	}
	// Otherwise the reading speaks about the newest record that establishes
	// the use case's own credential. Records that do not (MCP proxy records)
	// are described as what they are.
	newest := v.newestProven()
	if newest == nil {
		return Reading{ReadingTrafficIdentityUnknown, fmt.Sprintf("Traffic attributed to this use case was observed, but an authenticated connection is not established: the newest record is at the %s at %s (%s); caller identity %s; %s.",
			boundaryLabel(latest.Boundary), latest.Timestamp.UTC().Format(time.RFC3339), latest.EvidenceID, latest.Identity, activation)}
	}
	where := fmt.Sprintf("the newest authenticated request was recorded at the %s at %s (%s)", boundaryLabel(newest.Boundary), newest.Timestamp.UTC().Format(time.RFC3339), newest.EvidenceID)
	switch newest.Policy {
	case PolicyMatchesCurrent:
		return Reading{ReadingTrafficMatches, "Authenticated traffic observed under the expected policy: " + where + "; its signature verifies and its recorded policy equals what the current files compile to; " + activation + "."}
	case PolicyDiffers:
		return Reading{ReadingTrafficDiffers, "Authenticated traffic observed under a DIFFERENT policy than the current files: " + where + "; its signature verifies; " + activation + "."}
	}
	return Reading{ReadingTrafficNotProven, "Authenticated traffic observed; the policy it was evaluated under is not proven: " + where + "; its signature verifies, and " + newest.PolicyNote + "; " + activation + "."}
}

func boundaryLabel(b string) string {
	switch b {
	case BoundaryLLMGateway:
		return "LLM gateway"
	case BoundaryMCPProxy:
		return "MCP proxy"
	case BoundaryActionGateway:
		return "Action Gateway"
	}
	return b
}

// notEstablished lists, for a reader, what the observations cannot prove.
func notEstablished(v *Verification) []string {
	out := []string{
		"that all of this application's requests go through Talon: only what reaches an interception boundary is recorded, and calls the application sends directly to a provider or a tool are not seen",
	}
	observed := map[string]*TrafficObservation{}
	for i := range v.Traffic {
		if v.Traffic[i].State == TrafficObserved {
			observed[v.Traffic[i].Boundary] = &v.Traffic[i]
		}
	}
	if g := observed[BoundaryLLMGateway]; g == nil {
		out = append(out, "that the application can reach a model through Talon: no authenticated LLM gateway request of this use case is recorded")
	} else if g.Outcome == nil || g.Outcome.Dispatch != evidence.DispatchDispatched {
		out = append(out, "that a provider was reached: the newest LLM gateway request was not recorded as dispatched to a provider")
	}
	if a := observed[BoundaryActionGateway]; a != nil && a.LastDispatch == nil {
		out = append(out, "that a governed action reached its destination: no completed dispatch attempt is among the newest action records")
	}
	out = append(out, "any business outcome in the application or at the destination beyond the recorded answer")
	return out
}

// lastDecisionOf converts the newest observed record into the report's
// LastDecision. An operator or configuration event is never a decision: a
// use case that was only registered, enabled or reloaded has none.
func lastDecisionOf(v *Verification) *LastDecision {
	o := v.newestObserved()
	if o == nil {
		return nil
	}
	ld := &LastDecision{
		EvidenceID: o.EvidenceID, Timestamp: *o.Timestamp, InvocationType: o.InvocationType,
		Verification: o.Verification, AgentFile: o.agentFile, EffectivePolicy: o.effectivePolicy,
		PrimaryCode: o.primaryCode, PrimaryReason: o.primaryReason,
		RecordedAgent: o.recordedAgent, RecordedEffective: o.recordedEffective,
		Note: "a historical decision: the policy recorded on this signed record applied to it; the current files are compared only by recorded digests",
	}
	if o.Outcome != nil {
		ld.Outcome = *o.Outcome
	}
	if o.Verification != "valid" {
		ld.Note = o.PolicyNote
	}
	return ld
}
