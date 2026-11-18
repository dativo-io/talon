package action

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ReviewerView is what an authenticated reviewer reads before deciding
// (#433): the exact operation projection (action, verdict, matched rule,
// digest, the reviewer projection of the material arguments, approval
// state), the trusted destination the action would be dispatched to, a
// plain-language statement of the policy rule that requires the decision,
// and whether the policy and definition are still the ones the operation
// was bound under. It is built from the same projection the caller reads;
// nothing is added that the record does not carry.
type ReviewerView struct {
	Operation *Projection `json:"operation"`
	// UseCase and Tenant name the AI use case that asked for the action.
	UseCase string `json:"use_case"`
	Tenant  string `json:"tenant"`
	// Target is the trusted catalog destination (method and URL), the
	// endpoint Talon itself calls when the operation is claimed.
	Target string `json:"target"`
	// Rule describes the matched rule as the CURRENT policy defines it.
	Rule string `json:"rule"`
	// PolicyCurrent is false when the approval-relevant policy changed
	// since the operation was established: an approval granted now could
	// not be used (approval_binding_stale); a new operation is needed.
	PolicyCurrent bool `json:"policy_current"`
	// DefinitionCurrent is false when the trusted action definition
	// changed since the operation was established.
	DefinitionCurrent bool `json:"definition_current"`
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
		Operation:         proj,
		UseCase:           op.AgentID,
		Tenant:            op.TenantID,
		Rule:              s.Policy.DescribeRule(op.RuleID),
		PolicyCurrent:     s.Policy.Digest == op.PolicyDigest,
		DefinitionCurrent: s.definitionCurrent(op),
	}
	if d, ok := s.Catalog.Lookup(op.Action); ok {
		v.Target = strings.TrimSpace(d.Destination.Method + " " + d.Destination.URL)
	}
	return v, nil
}

// DescribeRule states a compiled rule of the effective policy in plain
// language ("" for an unknown id): what it matches and what it requires.
func (ap *ApprovalPolicy) DescribeRule(ruleID string) string {
	if ap == nil || ruleID == "" {
		return ""
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
		return fmt.Sprintf("%s argument rule %s: a call of %s where %s (%s) %s", r.Source, r.ID, strings.Join(r.Actions, ", "), r.Condition(), r.Type, effect)
	}
	for _, r := range ap.Rules {
		if r.ID == ruleID {
			return fmt.Sprintf("%s approval rule %s: every call of %s requires approval by %s", r.Source, r.ID, strings.Join(r.Actions, ", "), strings.Join(r.ApproverGroups, " or "))
		}
	}
	return "rule " + ruleID + " is not part of the current policy"
}

// PendingApproval locates one pending approval (adapter routing only).
type PendingApproval struct {
	ID        string
	TenantID  string
	AgentID   string
	Groups    []string
	ExpiresAt time.Time
}

// MaxPendingList bounds one pending-approvals listing.
const MaxPendingList = 200

// PendingApprovals lists the pending approvals of one tenant that at least
// one of groups may decide, oldest first, at most limit (1..MaxPendingList).
// The group filter is applied BEFORE the bound, so approvals of other groups
// can never push an eligible one out of the listing. more reports that
// further eligible approvals exist beyond limit: the listing is then the
// oldest part of the queue, not all of it.
func (r *Repository) PendingApprovals(ctx context.Context, tenantID string, groups []string, limit int) (list []PendingApproval, more bool, err error) {
	if limit <= 0 || limit > MaxPendingList {
		limit = MaxPendingList
	}
	mine := map[string]bool{}
	for _, g := range groups {
		mine[g] = true
	}
	rows, err := r.db.QueryContext(ctx, `SELECT a.id, o.tenant_id, o.agent_id, a.groups_json, a.expires_at
		FROM action_approvals a JOIN action_operations o ON o.ref = a.operation_ref
		WHERE o.tenant_id = ? AND a.status = ? ORDER BY a.created_at, a.id`, tenantID, ApprovalPending)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var p PendingApproval
		var raw string
		if err := rows.Scan(&p.ID, &p.TenantID, &p.AgentID, &raw, &p.ExpiresAt); err != nil {
			return nil, false, err
		}
		_ = json.Unmarshal([]byte(raw), &p.Groups)
		eligible := false
		for _, g := range p.Groups {
			if mine[g] {
				eligible = true
				break
			}
		}
		if !eligible {
			continue
		}
		if len(list) == limit {
			return list, true, rows.Err()
		}
		list = append(list, p)
	}
	return list, false, rows.Err()
}
