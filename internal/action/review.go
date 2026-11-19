package action

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ReviewerView is what an authenticated reviewer reads before deciding
// (#433). It keeps two kinds of statement apart:
//
//   - Bound: facts stored with the operation when it was established (the
//     matched rule's id and layer, the destination, the digests). They are
//     read from the operation record and never recomputed.
//   - Current: the configuration this server enforces now (the rule as the
//     current policy states it, the catalog's destination and description).
//     It is what was bound only where the matching digest is unchanged; the
//     view says so instead of presenting today's configuration as history.
//     A historical rule text that the record does not carry is not
//     reconstructed.
//
// Actionable and Actionability are computed by the same conditions, in the
// same order, as the decision path; the decision path stays authoritative.
type ReviewerView struct {
	Operation *Projection `json:"operation"`
	// UseCase and Tenant name the AI use case that asked for the action.
	UseCase string `json:"use_case"`
	Tenant  string `json:"tenant"`
	// Actionable is true when a decision by an eligible reviewer would be
	// accepted now. Actionability says why not otherwise.
	Actionable    bool   `json:"actionable"`
	Actionability string `json:"actionability"`
	// Explanation states the actionability in one sentence.
	Explanation string `json:"explanation"`
	// AfterApproval states what an approval does and does not do.
	AfterApproval string        `json:"after_approval"`
	Bound         ReviewBound   `json:"bound"`
	Current       ReviewCurrent `json:"current"`
}

// ReviewBound are the facts the operation record carries from establish.
type ReviewBound struct {
	RuleID     string `json:"rule_id,omitempty"`
	RuleSource string `json:"rule_source,omitempty"` // company | use_case
	// Destination is the trusted destination bound into the operation
	// (for an HTTP action: method and URL).
	Destination      string    `json:"destination"`
	ArgumentsDigest  string    `json:"arguments_digest"`
	DefinitionDigest string    `json:"definition_digest"`
	PolicyDigest     string    `json:"policy_digest"`
	EstablishedAt    time.Time `json:"established_at"`
}

// ReviewCurrent is the configuration enforced now, next to whether it is
// still the one the operation was bound under.
type ReviewCurrent struct {
	// PolicyUnchanged: the approval-relevant policy digest equals the bound
	// one, so Rule below is exactly the rule that required this approval.
	PolicyUnchanged bool `json:"policy_unchanged"`
	// DefinitionUnchanged: the trusted action definition (schema, reviewer
	// projection, destination, success contract) equals the bound one.
	DefinitionUnchanged bool `json:"definition_unchanged"`
	// Rule states the rule with the bound id as the CURRENT policy defines
	// it; empty when the current policy has no rule with that id.
	Rule        string `json:"rule,omitempty"`
	RulePresent bool   `json:"rule_present"`
	// Destination and ActionDescription come from the current catalog;
	// empty when the action is no longer catalogued.
	Destination       string `json:"destination,omitempty"`
	ActionDescription string `json:"action_description,omitempty"`
}

// Actionability values of a reviewer view and of a queue entry.
const (
	ReviewActionable      = "actionable"
	ReviewExpired         = "expired"
	ReviewStaleDefinition = "stale_definition"
	ReviewStalePolicy     = "stale_policy"
)

// afterApprovalText is fixed: approval authorizes, it never dispatches.
const afterApprovalText = "An approval authorizes this exact operation and dispatches nothing. The AI use case's application must then claim the operation; Talon re-checks the policy and the action definition at that claim and dispatches at most once. A rejection closes the operation."

// approvalActionability mirrors the order of the decision path (Decide):
// an already closed approval, then lifetime, then the trusted definition,
// then the approval-relevant policy.
func approvalActionability(status string, expiresAt, now time.Time, definitionCurrent, policyCurrent bool) (state, explanation string) {
	switch {
	case status != ApprovalPending:
		return status, "this approval is already " + status + "; no further decision is possible"
	case !now.Before(expiresAt):
		return ReviewExpired, "the approval lifetime elapsed at " + expiresAt.UTC().Format(time.RFC3339) + "; a decision would be refused (approval_expired). The application must create a new operation"
	case !definitionCurrent:
		return ReviewStaleDefinition, "the trusted action definition changed since this operation was established; a decision would be refused (approval_binding_stale). The application must create a new operation"
	case !policyCurrent:
		return ReviewStalePolicy, "the approval-relevant policy changed since this operation was established; a decision would be refused (approval_binding_stale). The application must create a new operation"
	}
	return ReviewActionable, "an eligible reviewer can approve or reject this now"
}

// Review returns the reviewer view of one approval of this service's
// tenant and agent. An approval of another agent or tenant is not found.
func (s *Service) Review(ctx context.Context, approvalID string) (*ReviewerView, error) {
	ap, err := getApproval(ctx, s.repo.db, approvalID)
	if err != nil {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
	}
	if ap == nil {
		return nil, newErr(CodeNotFound, "approval not found")
	}
	op, err := getOperationByRef(ctx, s.repo.db, ap.OperationRef)
	if err != nil || op == nil || op.TenantID != s.TenantID || op.AgentID != s.AgentID {
		return nil, newErr(CodeNotFound, "approval not found")
	}
	proj, err := s.project(ctx, s.repo.db, op)
	if err != nil {
		return nil, err
	}
	v := &ReviewerView{
		Operation:     proj,
		UseCase:       op.AgentID,
		Tenant:        op.TenantID,
		AfterApproval: afterApprovalText,
		Bound: ReviewBound{
			RuleID:           op.RuleID,
			RuleSource:       proj.MatchedRuleSource,
			Destination:      boundDestination(op.DestinationID),
			ArgumentsDigest:  op.Digest,
			DefinitionDigest: op.DefinitionDigest,
			PolicyDigest:     op.PolicyDigest,
			EstablishedAt:    op.CreatedAt,
		},
		Current: ReviewCurrent{
			PolicyUnchanged:     s.Policy.Digest == op.PolicyDigest,
			DefinitionUnchanged: s.definitionCurrent(op),
		},
	}
	v.Current.Rule, v.Current.RulePresent = s.Policy.DescribeRule(op.RuleID)
	if d, ok := s.Catalog.Lookup(op.Action); ok {
		v.Current.Destination = strings.TrimSpace(d.Destination.Method + " " + d.Destination.URL)
		v.Current.ActionDescription = d.Description
	}
	v.Actionability, v.Explanation = approvalActionability(ap.Status, ap.ExpiresAt, s.now(), v.Current.DefinitionUnchanged, v.Current.PolicyUnchanged)
	v.Actionable = v.Actionability == ReviewActionable
	return v, nil
}

// boundDestination renders the destination identity stored with the
// operation ("http:POST https://…" for the HTTP adapter) for a reader.
func boundDestination(id string) string {
	return strings.TrimPrefix(id, "http:")
}

// PendingState is the actionability of a queue entry, computed from the
// digests stored with its operation against this service's current policy
// and catalog: the same conditions Review and the decision path apply.
func (s *Service) PendingState(p *PendingApproval) string {
	d, ok := s.Catalog.Lookup(p.Action)
	state, _ := approvalActionability(ApprovalPending, p.ExpiresAt, s.now(), ok && d.DefinitionDigest == p.DefinitionDigest, s.Policy.Digest == p.PolicyDigest)
	return state
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

// PendingApproval is one entry of the reviewer queue: a persisted pending
// approval with the facts needed to say whether it can still be decided.
type PendingApproval struct {
	ID               string
	TenantID         string
	AgentID          string
	Action           string
	PolicyDigest     string
	DefinitionDigest string
	Groups           []string
	ExpiresAt        time.Time
	// State is the actionability the query established (ReviewActionable,
	// ReviewExpired, ReviewStaleDefinition, ReviewStalePolicy).
	State string
}

// MaxPendingList bounds one pending-approvals listing.
const MaxPendingList = 200

// PendingQuery selects a reviewer's queue.
type PendingQuery struct {
	// Limit bounds the answer (1..MaxPendingList).
	Limit int
	// State returns the actionability of an entry; "" drops it (its use
	// case is not served). nil treats lifetime as the only condition.
	State func(*PendingApproval) string
	// IncludeNonActionable also returns pending approvals that can no
	// longer be decided (expired, stale), after the actionable ones.
	IncludeNonActionable bool
	// Now is the clock for lifetimes (zero: the wall clock).
	Now time.Time
}

// PendingApprovals lists the persisted pending approvals of one tenant that
// at least one of groups may decide, oldest first.
//
// The bound never hides an approval that can be decided behind ones that
// cannot (#565 review): the group filter and the actionability are applied
// BEFORE the bound, and the answer holds the actionable entries first. An
// approval whose lifetime elapsed, or whose policy or definition changed,
// stays "pending" in the store until someone touches it; without this
// order 200 of them would fill every listing forever. more reports that
// entries of the requested selection exist beyond limit.
func (r *Repository) PendingApprovals(ctx context.Context, tenantID string, groups []string, q PendingQuery) (list []PendingApproval, more bool, err error) {
	sel := pendingSelection{limit: q.Limit, includeRest: q.IncludeNonActionable}
	if sel.limit <= 0 || sel.limit > MaxPendingList {
		sel.limit = MaxPendingList
	}
	mine := map[string]bool{}
	for _, g := range groups {
		mine[g] = true
	}
	now := q.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := r.db.QueryContext(ctx, `SELECT a.id, o.tenant_id, o.agent_id, o.action, o.policy_digest, o.definition_digest, a.groups_json, a.expires_at
		FROM action_approvals a JOIN action_operations o ON o.ref = a.operation_ref
		WHERE o.tenant_id = ? AND a.status = ? ORDER BY a.created_at, a.id`, tenantID, ApprovalPending)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() && !sel.full() {
		var p PendingApproval
		var raw string
		if err := rows.Scan(&p.ID, &p.TenantID, &p.AgentID, &p.Action, &p.PolicyDigest, &p.DefinitionDigest, &raw, &p.ExpiresAt); err != nil {
			return nil, false, err
		}
		_ = json.Unmarshal([]byte(raw), &p.Groups)
		if !anyGroup(mine, p.Groups) {
			continue
		}
		// Lifetime first: it needs no policy or catalog, so a long tail of
		// expired approvals costs one comparison each.
		switch {
		case !now.Before(p.ExpiresAt):
			p.State = ReviewExpired
		case q.State != nil:
			p.State = q.State(&p)
		default:
			p.State = ReviewActionable
		}
		sel.add(p)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	list, more = sel.result()
	return list, more, nil
}

func anyGroup(mine map[string]bool, groups []string) bool {
	for _, g := range groups {
		if mine[g] {
			return true
		}
	}
	return false
}

// pendingSelection collects a bounded queue answer: actionable entries
// first, then (when asked for) the ones that can no longer be decided.
type pendingSelection struct {
	limit       int
	includeRest bool
	actionable  []PendingApproval
	rest        []PendingApproval
	more        bool
}

func (s *pendingSelection) add(p PendingApproval) {
	switch {
	case p.State == "":
	case p.State == ReviewActionable:
		if len(s.actionable) == s.limit {
			s.more = true
			return
		}
		s.actionable = append(s.actionable, p)
	case s.includeRest:
		if len(s.rest) == s.limit {
			s.more = true
			return
		}
		s.rest = append(s.rest, p)
	}
}

// full: the answer holds limit actionable entries and is known to be
// incomplete; nothing further can change it.
func (s *pendingSelection) full() bool {
	return s.more && len(s.actionable) == s.limit
}

func (s *pendingSelection) result() ([]PendingApproval, bool) {
	rest := s.rest
	if room := s.limit - len(s.actionable); len(rest) > room {
		rest, s.more = rest[:room], true
	}
	return append(s.actionable, rest...), s.more
}
