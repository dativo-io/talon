package effective

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/registration"
	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/secrets"
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
	// Credential is what is known about the credential the use case
	// presents NOW: when its current value was stored, whether another
	// value ever existed under its name, and whether the running process
	// holds the current one. Traffic observations are attributed against
	// it: a record of an earlier registration or of a replaced key is
	// history, not proof that the current credential works.
	Credential *Credential `json:"credential"`
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
	// ReadingTrafficHistorical: authenticated traffic exists, all of it from
	// before the credential stored now was written (an earlier registration
	// of the name, or a key that was replaced since), or no credential of
	// the use case is stored at all any more (its key was removed).
	ReadingTrafficHistorical = "traffic_predates_current_credential"
	// ReadingTrafficCredentialUnproven: authenticated traffic exists since
	// the credential stored now was written, but the process that served it
	// had started before that write, so it is not established which
	// credential the request presented.
	ReadingTrafficCredentialUnproven = "traffic_observed_current_credential_not_established"
)

// Credential attribution of one observed record.
const (
	// CredentialCurrent: the request was authenticated with the credential
	// stored now.
	CredentialCurrent = "current"
	// CredentialPrevious: the record predates the credential stored now.
	CredentialPrevious = "previous"
	// CredentialNotEstablished: recorded after the credential stored now was
	// written, by a process that had started before that write (or that no
	// runtime record covers): it may have accepted the earlier credential.
	CredentialNotEstablished = "not_established"
	// CredentialUnknown: nothing is known about the credential (no vault
	// could be read, the agent file binds no key, or the vault's log holds
	// no write for the secret name).
	CredentialUnknown = "unknown"
	// CredentialNotApplicable: the request was not authenticated with the
	// use case's key at all (a verified workload identity).
	CredentialNotApplicable = "not_applicable"
)

// States of what is known about the credential stored now.
const (
	CredentialKnown  = "known"
	CredentialAbsent = "absent"  // the vault was read and holds no key under the name the agent file binds
	CredentialNoKey  = "no_key"  // the agent file binds no key
	CredentialUnread = "unknown" // the vault could not be read, or no vault file is visible to this process
)

// What the running process(es) hold.
const (
	// RuntimeHoldsCurrent: every running process started after the value
	// stored now was written; a process reads its keys when it starts.
	RuntimeHoldsCurrent = "holds_current"
	// RuntimePredatesCurrent: a running process built its active generation
	// before that write and holds an earlier value.
	RuntimePredatesCurrent = "predates_current"
	// RuntimeNotEstablished: a running process started before that write and
	// has rebuilt its generation since; whether the rebuild read the vault
	// or kept the previous key is not recorded.
	RuntimeNotEstablished    = "not_established"
	RuntimeNotRunning        = "not_running"
	RuntimeCredentialUnknown = "unknown"
)

// Credential is what is known about the credential the use case presents
// now. Every fact has a source: the vault's own record of when a value was
// written under the secret name (never a value), the signed registration
// record, and the runtime records of the processes.
type Credential struct {
	// State: known | absent | no_key | unknown.
	State string `json:"state"`
	// SecretName is the vault secret the agent file binds as the key.
	SecretName string `json:"secret_name,omitempty"`
	// Since is when the value stored now was written to the vault.
	Since *time.Time `json:"since,omitempty"`
	// Writes is how many values were ever written under the secret name
	// (replaced and deleted ones included). 1: no other credential has ever
	// existed under this name.
	Writes int `json:"writes"`
	// Registration is the newest signed `talon agents add` completion record
	// of this tenant and name; absent for a use case configured by hand.
	Registration *RegistrationFact `json:"registration,omitempty"`
	// Runtime: holds_current | predates_current | not_established |
	// not_running | unknown — what is established about the value the
	// running processes hold (see the constants).
	Runtime     string `json:"runtime"`
	RuntimeNote string `json:"runtime_note"`
	Note        string `json:"note,omitempty"`
}

// RegistrationFact is a signed registration completion record.
type RegistrationFact struct {
	EvidenceID   string    `json:"evidence_id"`
	At           time.Time `json:"at"`
	Verification string    `json:"verification"`
}

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
	// PolicyBoundOnly: the record carries the policy the Action Gateway
	// operation was BOUND to when it was established, not a policy evaluated
	// for this event (a claim re-checks the then-current policy, whose
	// digest the record does not carry).
	PolicyBoundOnly = "bound_at_establishment"
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
	// Credential attributes the record to the credential stored now:
	// current | previous | not_established | unknown | not_applicable. Empty
	// when the record does not establish the use case's credential at all.
	Credential     string `json:"credential,omitempty"`
	CredentialNote string `json:"credential_note,omitempty"`
	// SessionID is the client-asserted session of the request, when it
	// carried one (attribution, not authentication).
	SessionID string `json:"session_id,omitempty"`
	// Outcome separates Talon's decision from dispatch and the destination's
	// answer (evidence.OutcomeOf).
	Outcome *evidence.Outcome `json:"outcome,omitempty"`
	// Verification is the record's signature check: valid | invalid.
	Verification string `json:"verification,omitempty"`
	// Policy compares the policy recorded on the record with the current
	// files: matches_current | differs_from_current | not_recorded |
	// unverified | bound_at_establishment. PolicyNote says which digests
	// were compared.
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

// boundarySpec names the records an AUTHENTICATED request of the use case
// produces at a boundary. It is an explicit list, not "every request-class
// record": operator and configuration events (registration, enable/disable,
// reload, budget thresholds), provider attempts, imported external events
// and native runs establish nothing about an application's connection to a
// boundary. A request with an unknown or invalid key is rejected before any
// record is written, so it cannot appear under a use case at all.
type boundarySpec struct {
	boundary string
	// types are invocation types, each read as "the newest record of this
	// type" (LLM gateway, MCP proxy).
	types []string
	// events are Action Gateway lifecycle events, each read as "the newest
	// record of this event": see actionRequestEvents.
	events      []string
	establishes string
	// keyAuthenticated: every record selected above under a use case was
	// produced by a request that presented that use case's credential.
	// True for the LLM gateway (a key resolves to exactly one use case or
	// the request is rejected; a delegated request carries a verified
	// workload identity; the one keyless identity, the quickstart profile,
	// is marked on its records and excluded in identityOf) and for the
	// Action Gateway events listed in actionRequestEvents. False for the MCP
	// proxy, whose records do not say how the caller was identified.
	keyAuthenticated bool
}

// actionRequestEvents are the Action Gateway lifecycle events that
// UNAMBIGUOUSLY record a request of the application, which the gateway
// accepts only with the use case's agent key (admin keys and
// development-open requests are refused):
//
//   - operation_established: the application asked for an action; the
//     policy was evaluated and the verdict recorded;
//   - operation_conflict: the application re-sent an operation id with
//     other arguments;
//   - attempt_claimed: the application claimed an authorized operation.
//
// Everything else is deliberately NOT application traffic (#567 review):
//
//   - authorization_refused is written for an application's refused claim
//     AND for a reviewer who was not authorized to decide: the event alone
//     does not say whose request it was, so it never counts;
//   - approval_requested is written by Talon inside the establishment;
//   - approval_decided is a reviewer's decision, or Talon closing an
//     approval (expiry, invalidation);
//   - attempt_armed and attempt_completed are execution records, also
//     written by reconciliation. They are reported as the last dispatch,
//     never as connectivity.
var actionRequestEvents = []string{
	evidence.ActionEventOperationEstablished,
	evidence.ActionEventOperationConflict,
	evidence.ActionEventAttemptClaimed,
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
		events:           actionRequestEvents,
		keyAuthenticated: true,
		establishes:      "the application, with this use case's agent key, established a governed action operation, re-sent one or claimed one. A reviewer's decision, an expiry, a refused authorization and an execution record are not counted: they do not establish a request of the application. Establishing or claiming an operation is not dispatching it: see the last dispatch. It says nothing about model traffic",
	},
}

type verificationInputs struct {
	store     *evidence.Store
	tenant    string
	name      string
	agent     *policy.Policy
	digest    string // current agent file policy digest
	providers []ProviderEffective
	action    *ActionBoundary
	loaded    runtimestatus.Loaded
	// secretsDB is the vault file, read for metadata only ("" = not given).
	secretsDB       string
	runtime         *runtimestatus.View
	runtimeReadable bool
}

// buildVerification reads at most a handful of indexed rows per boundary
// (evidence.Store.NewestByType) and verifies the signature of each record
// it presents (evidence.Store.Detail).
func buildVerification(ctx context.Context, in verificationInputs) *Verification {
	v := &Verification{Configured: "enabled", Traffic: []TrafficObservation{}}
	if in.agent != nil && !in.agent.Agent.IsEnabled() {
		v.Configured = "disabled"
	}
	v.Credential = credentialOf(ctx, in)
	for _, spec := range boundarySpecs {
		o := observeBoundary(ctx, in, spec)
		attributeCredential(&o, v.Credential, in.runtime, in.runtimeReadable)
		v.Traffic = append(v.Traffic, o)
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
	o.Outcome, o.Verification, o.SessionID = &out, det.Verification.State, ev.SessionID
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
// completed dispatch attempt. Every lookup selects exactly what it asks for
// by index (the newest record of one invocation type, or of one lifecycle
// event): the answer does not depend on how many other records were written
// since, and "none" means that no such record exists.
func newestQualifying(ctx context.Context, in verificationInputs, spec boundarySpec) (newest, dispatch *evidence.Evidence, err error) {
	keep := func(r *evidence.Evidence) {
		if r != nil && (newest == nil || r.Timestamp.After(newest.Timestamp)) {
			newest = r
		}
	}
	for _, typ := range spec.types {
		recs, err := in.store.NewestByType(ctx, in.tenant, in.name, typ, 1)
		if err != nil {
			return nil, nil, err
		}
		if len(recs) == 1 {
			keep(recs[0])
		}
	}
	for _, event := range spec.events {
		r, err := in.store.NewestActionEvent(ctx, in.tenant, in.name, event)
		if err != nil {
			return nil, nil, err
		}
		keep(r)
	}
	if len(spec.events) > 0 {
		if dispatch, err = in.store.NewestActionEvent(ctx, in.tenant, in.name, evidence.ActionEventAttemptCompleted); err != nil {
			return nil, nil, err
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
	case spec.boundary == BoundaryActionGateway:
		return "the use case's agent key (the Action Gateway accepts this request with it only; reviewer decisions, refused authorizations, expiries and execution records are not counted)", true
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
		if ev.ActionLifecycle.Event != evidence.ActionEventOperationEstablished && o.Policy != PolicyNotRecorded {
			// Only the establishment evaluates the policy this digest
			// names. Every later record of the operation repeats the digest
			// the operation was bound to; a claim re-checks the policy the
			// process runs THEN, which the record does not carry.
			bound := "equals"
			if o.Policy == PolicyDiffers {
				bound = "differs from"
			}
			o.Policy = PolicyBoundOnly
			o.PolicyNote = "this record carries the policy the operation was bound to when it was established (it " + bound + " what the current files compile to), not a policy evaluated for this event"
		}
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
// established to have presented the use case's own credential (any value
// of it) and that also satisfies keep (nil = every such record).
func (v *Verification) newestProven(keep func(*TrafficObservation) bool) *TrafficObservation {
	var newest *TrafficObservation
	for i := range v.Traffic {
		o := &v.Traffic[i]
		if o.State != TrafficObserved || o.Timestamp == nil || !o.IdentityProven || (keep != nil && !keep(o)) {
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
	activation := activationClause(v, loaded)
	if v.Configured == "disabled" {
		return Reading{ReadingDisabled, "Configured as disabled (agent.enabled: false): new work is refused once a running process has loaded this file; " + activation + "."}
	}
	latest := v.newestObserved()
	if latest == nil {
		return noTrafficReading(v, loaded, activation)
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
	if v.newestProven(nil) == nil {
		return Reading{ReadingTrafficIdentityUnknown, fmt.Sprintf("Traffic attributed to this use case was observed, but an authenticated connection is not established: the newest record is at the %s at %s (%s); caller identity %s; %s.",
			boundaryLabel(latest.Boundary), latest.Timestamp.UTC().Format(time.RFC3339), latest.EvidenceID, latest.Identity, activation)}
	}
	return authenticatedReading(v, activation)
}

// activationClause words what the runtime records establish about the
// running processes: whether one has loaded the agent file and, apart from
// that, what is established about the credential it holds.
func activationClause(v *Verification, loaded runtimestatus.Loaded) string {
	activation := map[string]string{
		runtimestatus.LoadedMatchesFile:     "a running Talon process has loaded this agent file",
		runtimestatus.LoadedDiffersFromFile: "a running Talon process has loaded a DIFFERENT version of this agent file",
		runtimestatus.NotInActiveGeneration: "no running Talon process has this use case in its active generation",
		runtimestatus.LoadedUnknown:         "whether a running Talon process has loaded this agent file is not known",
	}[loaded.State]
	if activation == "" {
		activation = "whether a running Talon process has loaded this agent file is not known"
	}
	if c := v.Credential; c != nil && c.Runtime == RuntimePredatesCurrent {
		// The file can be loaded while the process still holds an earlier
		// value of the key: both are stated.
		activation += ", but it does NOT hold the credential stored now (" + c.RuntimeNote + ")"
	} else if c != nil && c.Runtime == RuntimeNotEstablished {
		activation += ", and that it holds the credential stored now is not established (" + c.RuntimeNote + ")"
	}
	return activation
}

// noTrafficReading is the reading when no boundary holds a record.
func noTrafficReading(v *Verification, loaded runtimestatus.Loaded, activation string) Reading {
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

// authenticatedReading is the reading when at least one record establishes
// the use case's own credential. A record authenticated with a credential
// that is not the one stored now (an earlier registration of the name, a
// key replaced since) is history: it does not show that the current
// credential works.
func authenticatedReading(v *Verification, activation string) Reading {
	newest := v.newestProven(func(o *TrafficObservation) bool {
		return o.Credential == CredentialCurrent || o.Credential == CredentialNotApplicable || o.Credential == CredentialUnknown
	})
	if newest == nil {
		if un := v.newestProven(func(o *TrafficObservation) bool { return o.Credential == CredentialNotEstablished }); un != nil {
			return Reading{ReadingTrafficCredentialUnproven, fmt.Sprintf("Authenticated traffic was observed since the current credential was stored, but use of the CURRENT credential is not established: the newest such request is at the %s at %s (%s); %s; %s.",
				boundaryLabel(un.Boundary), un.Timestamp.UTC().Format(time.RFC3339), un.EvidenceID, un.CredentialNote, activation)}
		}
		old := v.newestProven(nil)
		head := "No authenticated traffic since the current credential was stored"
		if v.Credential != nil && v.Credential.State == CredentialAbsent {
			head = "No credential of this use case is stored now, so no authenticated traffic is attributed to one"
		}
		return Reading{ReadingTrafficHistorical, fmt.Sprintf("%s: the newest authenticated request is at the %s at %s (%s), and %s; %s.",
			head, boundaryLabel(old.Boundary), old.Timestamp.UTC().Format(time.RFC3339), old.EvidenceID, old.CredentialNote, activation)}
	}
	where := fmt.Sprintf("the newest authenticated request was recorded at the %s at %s (%s)", boundaryLabel(newest.Boundary), newest.Timestamp.UTC().Format(time.RFC3339), newest.EvidenceID)
	caveat := ""
	if newest.Credential == CredentialUnknown {
		caveat = "; which credential it was authenticated with is not established (" + newest.CredentialNote + ")"
	}
	switch newest.Policy {
	case PolicyMatchesCurrent:
		return Reading{ReadingTrafficMatches, "Authenticated traffic observed under the expected policy: " + where + "; its signature verifies and its recorded policy equals what the current files compile to" + caveat + "; " + activation + "."}
	case PolicyDiffers:
		return Reading{ReadingTrafficDiffers, "Authenticated traffic observed under a DIFFERENT policy than the current files: " + where + "; its signature verifies" + caveat + "; " + activation + "."}
	}
	return Reading{ReadingTrafficNotProven, "Authenticated traffic observed; the policy it was evaluated under is not proven: " + where + "; its signature verifies, and " + newest.PolicyNote + caveat + "; " + activation + "."}
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
	if a := observed[BoundaryActionGateway]; a != nil {
		switch {
		case a.LastDispatch == nil:
			out = append(out, "that a governed action reached its destination: no completed dispatch attempt of this use case is recorded")
		case a.LastDispatch.Verification != "valid":
			out = append(out, "that a governed action reached its destination: the newest dispatch record does not verify, so nothing on it is established")
		}
	}
	if c := v.Credential; c != nil && c.State == CredentialKnown {
		if n := v.newestProven(nil); n != nil && n.Credential != CredentialCurrent && n.Credential != CredentialNotApplicable {
			out = append(out, "that the application uses the credential stored now (written "+c.Since.UTC().Format(time.RFC3339)+"): no request is established to have been authenticated with it. Evidence does not record which credential a request presented; this is inferred from when the credential was written and when the serving process built its generation")
		}
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
		EvidenceID: o.EvidenceID, Timestamp: *o.Timestamp, InvocationType: o.InvocationType, SessionID: o.SessionID,
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

// keySecretName is the vault secret the agent file binds as the use case's
// Talon key ("" when it binds none).
func keySecretName(agent *policy.Policy) string {
	if agent == nil || agent.Agent.Key == nil {
		return ""
	}
	return agent.Agent.Key.SecretName
}

// credentialOf collects what is known about the credential the use case
// presents now. It reads the vault's metadata only (never a value, no
// decryption key), the newest signed registration record and the runtime
// records. What cannot be read is "unknown"; it is never assumed.
func credentialOf(ctx context.Context, in verificationInputs) *Credential {
	c := &Credential{State: CredentialUnread, Runtime: RuntimeCredentialUnknown, SecretName: keySecretName(in.agent)}
	if in.store != nil {
		if recs, err := in.store.NewestByType(ctx, in.tenant, in.name, registration.TypeRegistered, 1); err == nil && len(recs) == 1 {
			if det, err := in.store.Detail(ctx, recs[0].ID); err == nil {
				c.Registration = &RegistrationFact{EvidenceID: det.Record.ID, At: det.Record.Timestamp, Verification: det.Verification.State}
			}
		}
	}
	switch {
	case c.SecretName == "":
		c.State, c.Note = CredentialNoKey, "the agent file binds no Talon key (agent.key.secret_name)"
		c.RuntimeNote = "there is no key to hold"
		return c
	case in.secretsDB == "":
		c.Note = "no vault was read, so when the current credential was stored is not known"
		c.RuntimeNote = c.Note
		return c
	}
	if _, err := os.Stat(in.secretsDB); err != nil {
		// A vault file this process cannot see is not a vault without the
		// secret: a reader on another host or in another container (the
		// console) may simply not have it. Nothing is concluded from it.
		c.Note = "no vault file is visible to this process at " + in.secretsDB + " (no secret was stored in this installation yet, or this process cannot read the vault), so when the current credential was stored is not known"
		c.RuntimeNote = c.Note
		return c
	}
	w, err := secrets.CredentialWritesReadOnly(ctx, in.secretsDB, c.SecretName)
	switch {
	case err != nil:
		c.Note = "the vault could not be read (" + err.Error() + "), so when the current credential was stored is not known"
		c.RuntimeNote = c.Note
		return c
	case !w.Exists:
		c.State, c.Writes = CredentialAbsent, w.Writes
		c.Note = fmt.Sprintf("the vault holds no secret %q: no credential of this use case is stored now. A process that loaded the key before it was removed keeps accepting it until that process reloads the use case or restarts", c.SecretName)
		c.RuntimeNote = "no credential is stored that a process could hold"
		return c
	}
	since := w.LastWrittenAt
	c.State, c.Since, c.Writes = CredentialKnown, &since, w.Writes
	switch {
	case w.Writes == 1:
		c.Note = "the only value ever stored under this secret name"
	case w.Writes > 1:
		c.Note = fmt.Sprintf("%d values were stored under this secret name over time (an earlier registration of the name, or a replaced key): records from before %s were authenticated with an earlier one", w.Writes, since.UTC().Format(time.RFC3339))
	default:
		c.Note = "the vault's log holds no write for this secret name, so whether an earlier value existed is not known"
	}
	c.Runtime, c.RuntimeNote = runtimeHolds(in, since)
	return c
}

// startedSince reports whether the process started at or after t. A process
// reads every agent key from the vault when it starts and has no earlier
// generation to carry a key over from, so such a process cannot hold a value
// that was replaced before t.
//
// A RELOAD is deliberately not accepted as the same proof. A rebuilt
// generation normally reads the vault again, but it keeps the previous
// generation's key when that read fails for a reason other than "the secret
// is gone" (gateway.resolveAgentKey), and a runtime record does not say
// whether that happened. A process that was already running when the value
// was stored may therefore still accept the earlier key.
func startedSince(p *runtimestatus.Process, t time.Time) bool {
	return !p.StartedAt.Before(t)
}

// runtimeHolds states what is established about the credential the running
// processes hold, given that the one stored now was written at since.
func runtimeHolds(in verificationInputs, since time.Time) (state, note string) {
	if in.runtime == nil || !in.runtimeReadable {
		return RuntimeCredentialUnknown, "runtime records were not read, so which credential a running process holds is not known"
	}
	at := since.UTC().Format(time.RFC3339)
	var running, stale, reloaded []string
	for i := range in.runtime.Processes {
		p := &in.runtime.Processes[i]
		if p.Assessed != runtimestatus.Running || p.Catalog == nil {
			continue
		}
		running = append(running, p.InstanceID)
		switch {
		case startedSince(p, since):
		case p.Catalog.ActivatedAt.Before(since):
			stale = append(stale, fmt.Sprintf("%s (generation activated %s)", p.InstanceID, p.Catalog.ActivatedAt.UTC().Format(time.RFC3339)))
		default:
			reloaded = append(reloaded, p.InstanceID)
		}
	}
	switch {
	case len(running) == 0:
		return RuntimeNotRunning, "no Talon process of this installation is running"
	case len(stale) > 0:
		return RuntimePredatesCurrent, "the running process " + strings.Join(stale, ", ") + " built its active generation before the credential stored now was written at " + at + ": it reads keys when it builds a generation, and a change of the secret alone triggers no reload. Restart it to load the credential stored now"
	case len(reloaded) > 0:
		return RuntimeNotEstablished, "the running process " + strings.Join(reloaded, ", ") + " was already running when the credential stored now was written at " + at + " and has rebuilt its generation since. A rebuild normally reads the vault again, but it keeps the previous key when that read fails, and the runtime record does not say which happened: that it holds the credential stored now is not established. A process started after " + at + " can only hold that credential"
	}
	return RuntimeHoldsCurrent, "every running Talon process started after the credential stored now was written at " + at + ", and a process reads its keys from the vault when it starts"
}

// attributeCredential says which credential an observed record's request
// was authenticated with, as far as that can be established. Evidence does
// not record the credential a request presented, so this is an inference
// from recorded times, and it is conservative:
//
//   - a record from before the current value was stored used an earlier one;
//   - when no other value ever existed under the secret name, any
//     authenticated record used the current one;
//   - otherwise a record counts for the current credential only when every
//     process that was running at that moment had STARTED after the value
//     was stored (startedSince). A request served by a process that was
//     already running may have presented the earlier key, and is not
//     counted: the time of a record alone never proves the current
//     credential.
func attributeCredential(o *TrafficObservation, c *Credential, view *runtimestatus.View, readable bool) {
	if o.State != TrafficObserved || !o.IdentityProven || o.Timestamp == nil {
		return
	}
	ts := *o.Timestamp
	switch {
	case strings.HasPrefix(o.Identity, "verified workload identity"):
		o.Credential, o.CredentialNote = CredentialNotApplicable, "the request was authenticated by a verified workload identity, not by the use case's key"
	case c != nil && c.State == CredentialAbsent:
		// The vault is readable and holds no key for this use case: whatever
		// authenticated this request is not a credential that exists now.
		o.Credential = CredentialPrevious
		o.CredentialNote = "the vault holds no secret " + c.SecretName + " now, so it was authenticated with a credential that is no longer stored (removed since). It is historical evidence, not a connection of a current credential"
	case c == nil || c.State != CredentialKnown:
		o.Credential = CredentialUnknown
		o.CredentialNote = "nothing is known about the credential stored now"
		if c != nil && c.Note != "" {
			o.CredentialNote = c.Note
		}
	case ts.Before(*c.Since):
		o.Credential = CredentialPrevious
		o.CredentialNote = "it was recorded before the credential stored now was written at " + c.Since.UTC().Format(time.RFC3339) + ", so it was authenticated with an earlier credential of this use-case name (an earlier registration, or a key replaced since). It is historical evidence, not a connection of the current credential"
	case c.Writes == 1:
		o.Credential, o.CredentialNote = CredentialCurrent, "no other credential has ever been stored under "+c.SecretName+", so the request presented the one stored now"
	case c.Writes < 1:
		// The vault's log holds no write for the name: when the value stored
		// now replaced an earlier one, if it did, is not known.
		o.Credential, o.CredentialNote = CredentialUnknown, c.Note
	default:
		o.Credential, o.CredentialNote = servedByCurrent(ts, *c.Since, view, readable)
	}
}

// servedByCurrent decides, for a record written at ts after the current
// credential was stored at since, whether every process that could have
// served it could only hold that credential.
func servedByCurrent(ts, since time.Time, view *runtimestatus.View, readable bool) (state, note string) {
	at := since.UTC().Format(time.RFC3339)
	if view == nil || !readable {
		return CredentialNotEstablished, "runtime records were not read, so it is not established that the process that served it held the credential stored at " + at
	}
	var covering, earlier []string
	for i := range view.Processes {
		p := &view.Processes[i]
		if p.Catalog == nil || p.StartedAt.After(ts) {
			continue
		}
		end := p.WrittenAt
		if p.StoppedAt != nil {
			end = *p.StoppedAt
		}
		if p.Assessed != runtimestatus.Running && end.Before(ts) {
			continue // it was no longer running when the record was written
		}
		covering = append(covering, p.InstanceID)
		if !startedSince(p, since) {
			earlier = append(earlier, p.InstanceID)
		}
	}
	switch {
	case len(covering) == 0:
		return CredentialNotEstablished, "it was recorded after the credential stored now was written at " + at + ", but no runtime record covers that moment (records of stopped processes are kept for a limited time), so it is not established which credential the serving process held"
	case len(earlier) > 0:
		return CredentialNotEstablished, "it was recorded after the credential stored now was written at " + at + ", but the process " + strings.Join(earlier, ", ") + " that was running then had started before that write. A running process keeps the key it holds until it reads the vault again, and the records do not establish that it had: a request with the earlier key would look the same. A request served by a process started after " + at + " establishes the current credential"
	}
	return CredentialCurrent, "it was recorded after the credential stored now was written at " + at + ", while every process running then (" + strings.Join(covering, ", ") + ") had started after that write, and a process reads its keys from the vault when it starts"
}
