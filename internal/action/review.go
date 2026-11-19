package action

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// This file is the ONE projection of an approval for people (#433, #565):
// the authenticated reviewer API, `talon approvals` and the read-only
// Operations Console all render ApprovalView / ApprovalSummary built here
// from the same rows by the same rules. The surfaces differ only in two
// inputs:
//
//   - CurrentConfig: what "the configuration now" means for the caller. The
//     deciding process passes the catalog and policy it enforces; the
//     console passes what the current files compile to, and says whether a
//     running process is proven to have loaded them.
//   - Disclosure: which fields the caller may see. An authenticated approver
//     who could decide the approval reads the exact review values and the
//     decision's free-text reason; the console reads argument names only and
//     that a reason was recorded, never its text.
//
// Nothing here authorizes, expires, invalidates or decides anything. The
// decision path (Service.Decide) stays the only authority; a view says what
// that path would do, never the other way round.

// Disclosure selects the fields a surface may read.
type Disclosure int

const (
	// DiscloseReviewer: an authenticated approver credential that shares a
	// group with the approval. Exact review values and the argument digest.
	DiscloseReviewer Disclosure = iota + 1
	// DiscloseOperational: the read-only Operations Console. A paired
	// browser is not a reviewer, and its tenant selection is a filter, not
	// authorization: argument NAMES only, no value, no digest of values, a
	// destination reduced to scheme and host, and no free text a reviewer
	// wrote (a decision reason can quote the exact arguments).
	DiscloseOperational
)

func (d Disclosure) String() string {
	if d == DiscloseReviewer {
		return "reviewer"
	}
	return "operational"
}

// Bases of a statement about the current configuration.
const (
	// CurrentRuntime: the process that would take the decision.
	CurrentRuntime = "runtime"
	// CurrentFilesConfirmed: compiled from the current files, and every
	// running `talon serve` is proven to have loaded exactly these files.
	CurrentFilesConfirmed = "runtime_confirmed"
	// CurrentFiles: compiled from the current files only. Not a statement
	// about what a running process enforces.
	CurrentFiles = "current_files"
)

// CurrentConfig is the configuration an approval is compared with.
type CurrentConfig struct {
	// Basis is CurrentRuntime, CurrentFilesConfirmed or CurrentFiles.
	Basis string
	// NotServed: the deciding process does not serve the use case (runtime
	// basis). A decision would be refused there.
	NotServed bool
	// Unavailable says why nothing can be established (files unreadable,
	// policy does not compile, use case not in the files). Eligibility is
	// then unknown, never assumed.
	Unavailable string
	// Policy is the effective action policy; nil when unknown.
	Policy *ApprovalPolicy
	// Definition returns the current trusted definition of an action.
	// known=false: it cannot be established here (an action discovered
	// from an MCP source that this reader does not discover). known=true
	// with a nil definition: the action is not catalogued.
	Definition func(action string) (def *Definition, known bool)
	// Note explains the basis for a reader (for example why the files are
	// not proven to be what a process runs).
	Note string
}

// CatalogDefinitions adapts a compiled catalog to CurrentConfig.Definition:
// every action of a compiled catalog is known.
func CatalogDefinitions(c *Catalog) func(string) (*Definition, bool) {
	return func(name string) (*Definition, bool) {
		if c == nil {
			return nil, false
		}
		d, _ := c.Lookup(name)
		return d, true
	}
}

// Eligibility states: whether a decision on an approval would be accepted.
const (
	EligibilityEligible        = "eligible"
	EligibilityExpired         = "expired"
	EligibilityStaleDefinition = "stale_definition"
	EligibilityStalePolicy     = "stale_policy"
	EligibilityNotServed       = "use_case_not_served"
	EligibilityUnknown         = "unknown"
	EligibilityDecided         = "decided"
)

// Classes group eligibility for discovery. They never merge "per current
// files" with "confirmed by the runtime", or "unknown" with either.
const (
	// ClassActionable: unresolved, and a decision would be accepted now
	// according to the deciding runtime (or files proven loaded by it).
	ClassActionable = "actionable"
	// ClassPotentiallyActionable: unresolved and eligible according to the
	// current configuration FILES; no running process is proven to enforce
	// them.
	ClassPotentiallyActionable = "potentially_actionable"
	// ClassNotDecidable: unresolved in the store, but a decision would be
	// refused: the lifetime elapsed, or the configuration a process RUNS
	// (the deciding runtime, or files proven loaded by every running
	// process) no longer matches the binding or no longer serves the use
	// case. Never inferred from files alone.
	ClassNotDecidable = "not_decidable"
	// ClassUnknown: unresolved; whether the deciding process would accept a
	// decision cannot be established. That includes files that differ from
	// the binding while no process is proven to run them.
	ClassUnknown = "unknown"
	// ClassDecided: a completed decision (approved, rejected) or an
	// approval the system closed (expired, invalidated). History.
	ClassDecided = "decided"
)

// Comparison of a bound digest with the current configuration.
const (
	BindingUnchanged = "unchanged"
	BindingChanged   = "changed"
	BindingUnknown   = "unknown"
)

// Eligibility is the answer to "can this still be decided", with the basis
// the answer rests on.
type Eligibility struct {
	State string `json:"state"`
	Class string `json:"class"`
	// Basis: runtime | runtime_confirmed | current_files (configuration),
	// lifetime (the clock alone), record (the stored decision), none.
	Basis       string `json:"basis"`
	Explanation string `json:"explanation"`
	// Policy and Definition compare the digests bound at establish with
	// the current configuration: unchanged | changed | unknown.
	Policy     string `json:"policy"`
	Definition string `json:"definition"`
}

// Decidable reports whether the deciding runtime would accept a decision.
// Only a runtime-based answer can be decidable.
func (e Eligibility) Decidable() bool { return e.Class == ClassActionable }

// NeedsAttention: unresolved and not known to be undecidable. The default
// selection of every listing.
func (e Eligibility) NeedsAttention() bool {
	return e.Class == ClassActionable || e.Class == ClassPotentiallyActionable || e.Class == ClassUnknown
}

// bindingFacts are the stored facts eligibility is derived from.
type bindingFacts struct {
	Status           string
	ExpiresAt        time.Time
	Action           string
	PolicyDigest     string
	DefinitionDigest string
}

// classifyApproval mirrors the order of the decision path (Decide): a
// closed approval, then lifetime, then the trusted definition, then the
// approval-relevant policy. Where the current configuration is not known a
// certain refusal is still reported (a changed digest is stale whatever the
// unknown part is); otherwise the answer is unknown, never eligible.
//
// A refusal is certain only on a basis that is what a process runs: the
// deciding runtime itself, or files every running process is proven to have
// loaded. Files that no process is proven to run (CurrentFiles) can differ
// from the binding while the deciding process still holds the configuration
// the approval was established under and would accept the decision. That is
// "unknown", never "not decidable"; the comparison of the binding with the
// files stays in Policy and Definition as its own fact (#565 review).
func classifyApproval(f bindingFacts, cfg CurrentConfig, now time.Time) Eligibility {
	if f.Status != ApprovalPending {
		return Eligibility{
			State: EligibilityDecided, Class: ClassDecided, Basis: "record", Policy: BindingUnknown, Definition: BindingUnknown,
			Explanation: "this approval is already " + f.Status + "; no further decision is possible",
		}
	}
	e := Eligibility{Basis: cfg.Basis, Policy: BindingUnknown, Definition: BindingUnknown}
	if cfg.Unavailable == "" && !cfg.NotServed {
		e.Policy, e.Definition = comparePolicy(f, cfg), compareDefinition(f, cfg)
	}
	switch {
	case !now.Before(f.ExpiresAt):
		e.State, e.Class, e.Basis = EligibilityExpired, ClassNotDecidable, "lifetime"
		e.Explanation = "the approval lifetime elapsed at " + f.ExpiresAt.UTC().Format(time.RFC3339) + "; a decision would be refused (approval_expired). The application must create a new operation"
	case cfg.NotServed:
		e.State, e.Class = EligibilityNotServed, ClassNotDecidable
		e.Explanation = "the AI use case that owns this approval is not served by this Talon process (removed, or without an action catalog); a decision would be refused"
	case cfg.Unavailable != "":
		e.State, e.Class, e.Basis = EligibilityUnknown, ClassUnknown, "none"
		e.Explanation = "whether this can still be decided cannot be established here: " + cfg.Unavailable
	case cfg.Basis == CurrentFiles && (e.Definition == BindingChanged || e.Policy == BindingChanged):
		e.State, e.Class = EligibilityUnknown, ClassUnknown
		e.Explanation = "the current configuration files compile to another " + changedPart(e) + " than this operation was established under, but no running Talon process is proven to enforce these files. The deciding process may still hold the configuration this was established under and has the final word; a process that runs these files refuses a decision (approval_binding_stale)"
	case e.Definition == BindingChanged:
		e.State, e.Class = EligibilityStaleDefinition, ClassNotDecidable
		e.Explanation = "the trusted action definition changed since this operation was established; a decision would be refused (approval_binding_stale). The application must create a new operation"
	case e.Policy == BindingChanged:
		e.State, e.Class = EligibilityStalePolicy, ClassNotDecidable
		e.Explanation = "the approval-relevant policy changed since this operation was established; a decision would be refused (approval_binding_stale). The application must create a new operation"
	case e.Definition == BindingUnknown || e.Policy == BindingUnknown:
		e.State, e.Class = EligibilityUnknown, ClassUnknown
		e.Explanation = "whether this can still be decided cannot be established here: the current " + unknownPart(e) + " cannot be compared with the one bound at establish"
	default:
		e.State = EligibilityEligible
		e.Class, e.Explanation = eligibleClass(cfg.Basis)
	}
	return e
}

func changedPart(e Eligibility) string {
	switch {
	case e.Definition == BindingChanged && e.Policy == BindingChanged:
		return "action definition and policy"
	case e.Definition == BindingChanged:
		return "action definition"
	}
	return "policy"
}

func eligibleClass(basis string) (class, explanation string) {
	switch basis {
	case CurrentRuntime:
		return ClassActionable, "an eligible reviewer can approve or reject this now"
	case CurrentFilesConfirmed:
		return ClassActionable, "an eligible reviewer can approve or reject this now: every running Talon process loaded the configuration this was established under"
	}
	return ClassPotentiallyActionable, "eligible according to the current configuration files; no running Talon process is proven to enforce them, and the deciding process has the final word"
}

func unknownPart(e Eligibility) string {
	switch {
	case e.Definition == BindingUnknown && e.Policy == BindingUnknown:
		return "action definition and policy"
	case e.Definition == BindingUnknown:
		return "action definition"
	}
	return "policy"
}

func comparePolicy(f bindingFacts, cfg CurrentConfig) string {
	switch {
	case cfg.Policy == nil:
		return BindingUnknown
	case cfg.Policy.Digest == f.PolicyDigest:
		return BindingUnchanged
	}
	return BindingChanged
}

func compareDefinition(f bindingFacts, cfg CurrentConfig) string {
	if cfg.Definition == nil {
		return BindingUnknown
	}
	d, known := cfg.Definition(f.Action)
	switch {
	case !known:
		return BindingUnknown
	case d != nil && d.DefinitionDigest == f.DefinitionDigest:
		return BindingUnchanged
	}
	return BindingChanged
}

// afterApprovalText is fixed: approval authorizes, it never dispatches.
const afterApprovalText = "An approval authorizes this exact operation and dispatches nothing. The AI use case's application must then claim the operation; Talon re-checks the policy and the action definition at that claim and dispatches at most once. A rejection closes the operation."

// ApprovalRecord is one approval with its operation and latest attempt, as
// read in a single snapshot (Reader.ApprovalRecord).
type ApprovalRecord struct {
	Approval      *Approval
	Operation     *Operation
	LatestAttempt *Attempt
}

// ApprovalView is what a person reads about one approval. It keeps apart
// what the operation record carries from establish (Bound), what the
// configuration is now (Current, with its basis) and what happened since
// (Decision, Operation).
type ApprovalView struct {
	ApprovalID string `json:"approval_id"`
	Tenant     string `json:"tenant"`
	// UseCase is the AI use case that asked for the action.
	UseCase string `json:"use_case"`
	Action  string `json:"action"`
	// ActionDescription is the catalog's description under Current.Basis;
	// empty when the action is not catalogued or the catalog is unknown.
	ActionDescription string `json:"action_description,omitempty"`
	// Status is the PERSISTED approval status (pending, approved,
	// rejected, expired, invalidated). Unresolved is Status == pending: a
	// stored fact, independent of any configuration.
	Status         string      `json:"status"`
	Unresolved     bool        `json:"unresolved"`
	Eligibility    Eligibility `json:"eligibility"`
	ApproverGroups []string    `json:"approver_groups"`
	CreatedAt      time.Time   `json:"created_at"`
	ExpiresAt      time.Time   `json:"expires_at"`
	// Disclosure names the profile this view was built for; Arguments
	// carry values only under "reviewer".
	Disclosure    string            `json:"disclosure"`
	Arguments     []ReviewArgument  `json:"arguments"`
	Bound         ApprovalBound     `json:"bound"`
	Current       ApprovalCurrent   `json:"current"`
	Decision      *ApprovalDecision `json:"decision,omitempty"`
	Operation     ApprovalOperation `json:"operation"`
	AfterApproval string            `json:"after_approval"`
}

// ReviewArgument is one declared material argument. Value is the exact
// stored review value and is present only for the reviewer disclosure.
type ReviewArgument struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ApprovalBound are the facts the operation record carries from establish.
// They are read from the record and never recomputed.
type ApprovalBound struct {
	RuleID     string `json:"rule_id,omitempty"`
	RuleSource string `json:"rule_source,omitempty"` // company | use_case
	// Destination is the trusted destination bound into the operation: for
	// the reviewer the method and URL, for the operational disclosure the
	// method, scheme and host.
	Destination string `json:"destination"`
	// ArgumentsDigest binds the exact arguments; reviewer disclosure only.
	ArgumentsDigest  string    `json:"arguments_digest,omitempty"`
	DefinitionDigest string    `json:"definition_digest"`
	PolicyDigest     string    `json:"policy_digest"`
	EstablishedAt    time.Time `json:"established_at"`
}

// ApprovalCurrent is the configuration now, with the basis it is known on.
type ApprovalCurrent struct {
	Basis string `json:"basis"`
	Note  string `json:"note,omitempty"`
	// Rule states the rule with the bound id as the CURRENT policy defines
	// it. It is the rule that required this approval only where
	// Eligibility.Policy is unchanged; a historical rule text that the
	// record does not carry is not reconstructed.
	Rule        string `json:"rule,omitempty"`
	RulePresent bool   `json:"rule_present"`
	// Destination of the action in the current catalog.
	Destination string `json:"destination,omitempty"`
}

// ApprovalDecision is the stored outcome of an approval that is no longer
// pending. DecidedBy is an approver principal id, or "system" when Talon
// closed it (expired, invalidated).
type ApprovalDecision struct {
	Status       string     `json:"status"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	DecidedGroup string     `json:"decided_group,omitempty"`
	// Reason is the reviewer's free text, present only for the reviewer
	// disclosure: a reviewer can quote the exact material arguments in it,
	// so for the operational disclosure it is a value like any other.
	Reason string `json:"reason,omitempty"`
	// ReasonRecorded says that the decision carries a reason, under every
	// disclosure.
	ReasonRecorded bool `json:"reason_recorded"`
}

// ApprovalOperation is what happened to the operation the approval is for.
type ApprovalOperation struct {
	OperationID       string            `json:"operation_id"`
	OperationRef      string            `json:"operation_ref"`
	Status            string            `json:"status"`
	Verdict           string            `json:"verdict"`
	AttemptCount      int               `json:"attempt_count"`
	OutcomeCode       string            `json:"outcome_code,omitempty"`
	OutcomeProvenance string            `json:"outcome_provenance,omitempty"`
	LatestAttempt     *ApprovalAttempt  `json:"latest_attempt,omitempty"`
	UpdatedAt         time.Time         `json:"updated_at"`
	Origin            map[string]string `json:"origin,omitempty"`
}

// ApprovalAttempt is the dispatch facts of the latest execution attempt.
type ApprovalAttempt struct {
	Ordinal          int        `json:"ordinal"`
	Status           string     `json:"status"`
	StartedAt        time.Time  `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	RequestWritten   bool       `json:"request_written"`
	ResponseObserved bool       `json:"response_observed"`
	HTTPStatus       int        `json:"http_status,omitempty"`
	ResultProvenance string     `json:"result_provenance,omitempty"`
	OutcomeCode      string     `json:"outcome_code,omitempty"`
}

// ApprovalSummary is one row of an approval listing. It never carries an
// argument name or value: a listing is for finding an approval.
type ApprovalSummary struct {
	ApprovalID     string      `json:"approval_id"`
	Tenant         string      `json:"tenant"`
	UseCase        string      `json:"use_case"`
	Action         string      `json:"action"`
	Status         string      `json:"status"`
	Unresolved     bool        `json:"unresolved"`
	Eligibility    Eligibility `json:"eligibility"`
	ApproverGroups []string    `json:"approver_groups"`
	RuleID         string      `json:"rule_id,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
	ExpiresAt      time.Time   `json:"expires_at"`
	DecidedAt      *time.Time  `json:"decided_at,omitempty"`
	DecidedBy      string      `json:"decided_by,omitempty"`
}

// BuildApprovalView projects one approval record. It is a pure function of
// the record, the current configuration, the disclosure and the clock.
func BuildApprovalView(rec *ApprovalRecord, cfg CurrentConfig, disclosure Disclosure, now time.Time) *ApprovalView {
	ap, op := rec.Approval, rec.Operation
	v := &ApprovalView{
		ApprovalID: ap.ID, Tenant: op.TenantID, UseCase: op.AgentID, Action: op.Action,
		Status: ap.Status, Unresolved: ap.Status == ApprovalPending,
		Eligibility:    classifyApproval(bindingOf(ap, op), cfg, now),
		ApproverGroups: append([]string{}, ap.Groups...),
		CreatedAt:      ap.CreatedAt, ExpiresAt: ap.ExpiresAt,
		Disclosure: disclosure.String(), Arguments: reviewArguments(op.ReviewJSON, disclosure),
		Bound: ApprovalBound{
			RuleID: op.RuleID, RuleSource: RuleSource(op.RuleID),
			Destination:      disclosedDestination(strings.TrimPrefix(op.DestinationID, "http:"), disclosure),
			DefinitionDigest: op.DefinitionDigest, PolicyDigest: op.PolicyDigest, EstablishedAt: op.CreatedAt,
		},
		Current: ApprovalCurrent{Basis: cfg.Basis, Note: cfg.Note},
		Operation: ApprovalOperation{
			OperationID: op.OperationID, OperationRef: op.Ref, Status: op.Status, Verdict: op.Verdict,
			AttemptCount: op.AttemptCount, OutcomeCode: op.OutcomeCode, OutcomeProvenance: op.OutcomeProvenance,
			UpdatedAt: op.UpdatedAt, Origin: originOf(op.OriginJSON),
		},
		AfterApproval: afterApprovalText,
	}
	if disclosure == DiscloseReviewer {
		v.Bound.ArgumentsDigest = op.Digest
	}
	describeCurrent(v, op, cfg, disclosure)
	if ap.Status != ApprovalPending {
		v.Decision = &ApprovalDecision{Status: ap.Status, DecidedAt: ap.DecidedAt, DecidedBy: ap.DecidedBy, DecidedGroup: ap.DecidedGroup, ReasonRecorded: ap.Reason != ""}
		if disclosure == DiscloseReviewer {
			v.Decision.Reason = ap.Reason
		}
	}
	if at := rec.LatestAttempt; at != nil {
		v.Operation.LatestAttempt = &ApprovalAttempt{
			Ordinal: at.Ordinal, Status: at.Status, StartedAt: at.StartedAt, CompletedAt: at.CompletedAt,
			RequestWritten: at.RequestWritten, ResponseObserved: at.ResponseObserved, HTTPStatus: at.HTTPStatus,
			ResultProvenance: at.ResultProvenance, OutcomeCode: at.OutcomeCode,
		}
	}
	return v
}

// describeCurrent fills what the current configuration says about the
// bound rule and action. Nothing is stated when it is not known.
func describeCurrent(v *ApprovalView, op *Operation, cfg CurrentConfig, disclosure Disclosure) {
	switch {
	case cfg.Unavailable != "":
		v.Current.Basis, v.Current.Note = "none", cfg.Unavailable
		return
	case cfg.NotServed:
		v.Current.Note = "the AI use case is not served by this Talon process"
		return
	}
	v.Current.Rule, v.Current.RulePresent = cfg.Policy.DescribeRule(op.RuleID)
	if cfg.Definition == nil {
		return
	}
	if d, known := cfg.Definition(op.Action); known && d != nil {
		v.ActionDescription = d.Description
		v.Current.Destination = disclosedDestination(strings.TrimSpace(d.Destination.Method+" "+d.Destination.URL), disclosure)
	}
}

// SummarizeApproval projects one listing row from the stored facts.
func SummarizeApproval(ap *Approval, op *Operation, cfg CurrentConfig, now time.Time) ApprovalSummary {
	return ApprovalSummary{
		ApprovalID: ap.ID, Tenant: op.TenantID, UseCase: op.AgentID, Action: op.Action,
		Status: ap.Status, Unresolved: ap.Status == ApprovalPending,
		Eligibility:    classifyApproval(bindingOf(ap, op), cfg, now),
		ApproverGroups: append([]string{}, ap.Groups...), RuleID: op.RuleID,
		CreatedAt: ap.CreatedAt, ExpiresAt: ap.ExpiresAt, DecidedAt: ap.DecidedAt, DecidedBy: ap.DecidedBy,
	}
}

func bindingOf(ap *Approval, op *Operation) bindingFacts {
	return bindingFacts{Status: ap.Status, ExpiresAt: ap.ExpiresAt, Action: op.Action, PolicyDigest: op.PolicyDigest, DefinitionDigest: op.DefinitionDigest}
}

// reviewArguments lists the declared material arguments in name order. The
// stored reviewer projection is the only source; values are copied only
// for the reviewer disclosure, so a view built for the console holds no
// value anywhere in memory or on the wire.
func reviewArguments(reviewJSON []byte, disclosure Disclosure) []ReviewArgument {
	out := []ReviewArgument{}
	if len(reviewJSON) == 0 {
		return out
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(reviewJSON, &fields); err != nil {
		return out
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		a := ReviewArgument{Name: k}
		if disclosure == DiscloseReviewer {
			a.Value = fields[k]
		}
		out = append(out, a)
	}
	return out
}

// disclosedDestination renders "METHOD URL" (or a bare URL). The
// operational disclosure keeps the method, scheme and host: a path or
// query of an operator-configured URL can carry identifiers.
func disclosedDestination(dest string, disclosure Disclosure) string {
	if disclosure == DiscloseReviewer || dest == "" {
		return dest
	}
	parts := strings.Fields(dest)
	u, err := url.Parse(parts[len(parts)-1])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.Join(parts[:len(parts)-1], " ")
	}
	parts[len(parts)-1] = u.Scheme + "://" + u.Host
	return strings.Join(parts, " ")
}

// originOf returns the attribution facts stored with the operation (the
// client-asserted session and the runtime's own references). Never a token.
func originOf(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var f struct {
		Runtime    string
		SandboxRef string
		SessionID  string
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range map[string]string{"runtime": f.Runtime, "sandbox_ref": f.SandboxRef, "session_id": f.SessionID} {
		if v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DescribeRule states a compiled rule of the effective policy in plain
// language: what it matches and what it requires. present is false when
// the policy has no rule with that id (nothing is stated then).
func (ap *ApprovalPolicy) DescribeRule(ruleID string) (text string, present bool) {
	if ap == nil || ruleID == "" {
		return "", false
	}
	for i := range ap.ArgumentRules {
		r := &ap.ArgumentRules[i]
		if r.ID != ruleID {
			continue
		}
		effect := "is denied"
		if r.Effect == EffectRequireApproval {
			effect = "requires approval by " + strings.Join(r.ApproverGroups, " or ")
		}
		return fmt.Sprintf("%s argument rule %s: a call of %s where %s (%s) %s", r.Source, r.ID, strings.Join(r.Actions, ", "), r.Condition(), r.Type, effect), true
	}
	for _, r := range ap.Rules {
		if r.ID == ruleID {
			return fmt.Sprintf("%s approval rule %s: every call of %s requires approval by %s", r.Source, r.ID, strings.Join(r.Actions, ", "), strings.Join(r.ApproverGroups, " or ")), true
		}
	}
	return "", false
}

// CurrentConfig is the configuration this service decides with.
func (s *Service) CurrentConfig() CurrentConfig {
	return CurrentConfig{Basis: CurrentRuntime, Policy: s.Policy, Definition: CatalogDefinitions(s.Catalog)}
}
