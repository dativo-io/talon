package action

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/policy"
)

// Verdict outcomes. DENY > REQUIRE_APPROVAL > ALLOW (#425).
const (
	VerdictAllow           = "ALLOW"
	VerdictDeny            = "DENY"
	VerdictRequireApproval = "REQUIRE_APPROVAL"
)

// DefaultApprovalLifetime applies when policies.approvals.expires_after is unset.
const DefaultApprovalLifetime = time.Hour

// ApprovalRule is one compiled approval requirement.
type ApprovalRule struct {
	ID             string
	Actions        []string // exact names or trailing-* prefix globs
	ApproverGroups []string
}

// ApprovalPolicy is the compiled, approval-relevant policy of one agent.
type ApprovalPolicy struct {
	Rules          []ApprovalRule // sorted by ID
	ForbiddenTools []string       // DENY source (capabilities.forbidden_tools)
	ExpiresAfter   time.Duration
	// Digest is the approval-relevant policy digest: rules, groups, forbidden
	// actions and lifetime — nothing descriptive.
	Digest string
}

// CompileApprovalPolicy derives the approval-relevant policy from the agent
// file. It fails closed on malformed rules.
func CompileApprovalPolicy(pol *policy.Policy) (*ApprovalPolicy, error) {
	ap := &ApprovalPolicy{ExpiresAfter: DefaultApprovalLifetime}
	if pol == nil {
		ap.Digest = Digest([]byte("{}"))
		return ap, nil
	}
	if pol.Capabilities != nil {
		ap.ForbiddenTools = append(ap.ForbiddenTools, pol.Capabilities.ForbiddenTools...)
		sort.Strings(ap.ForbiddenTools)
	}
	if ac := pol.Policies.Approvals; ac != nil {
		if ac.ExpiresAfter != "" {
			d, err := time.ParseDuration(ac.ExpiresAfter)
			if err != nil || d <= 0 || d > 30*24*time.Hour {
				return nil, fmt.Errorf("policies.approvals.expires_after: invalid duration %q", ac.ExpiresAfter)
			}
			ap.ExpiresAfter = d
		}
		ids := make([]string, 0, len(ac.Rules))
		for id := range ac.Rules {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			r := ac.Rules[id]
			if len(r.Actions) == 0 || len(r.ApproverGroups) == 0 {
				return nil, fmt.Errorf("policies.approvals.rules.%s: actions and approver_groups are required", id)
			}
			rule := ApprovalRule{ID: id, Actions: append([]string(nil), r.Actions...), ApproverGroups: append([]string(nil), r.ApproverGroups...)}
			sort.Strings(rule.Actions)
			sort.Strings(rule.ApproverGroups)
			for _, a := range rule.Actions {
				if !actionNameRe.MatchString(strings.TrimSuffix(a, "*")) {
					return nil, fmt.Errorf("policies.approvals.rules.%s: invalid action pattern %q", id, a)
				}
			}
			ap.Rules = append(ap.Rules, rule)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "expires_after=%s\n", ap.ExpiresAfter)
	fmt.Fprintf(&b, "forbidden=%s\n", strings.Join(ap.ForbiddenTools, ","))
	for _, r := range ap.Rules {
		fmt.Fprintf(&b, "rule %s actions=%s groups=%s\n", r.ID, strings.Join(r.Actions, ","), strings.Join(r.ApproverGroups, ","))
	}
	ap.Digest = Digest([]byte(b.String()))
	return ap, nil
}

// Verdict is the authoritative policy outcome for one catalogued action.
type Verdict struct {
	Outcome        string
	RuleID         string
	ApproverGroups []string
	Reason         string
}

// Evaluate applies DENY > REQUIRE_APPROVAL > ALLOW for a catalog action.
func (ap *ApprovalPolicy) Evaluate(action string) Verdict {
	for _, f := range ap.ForbiddenTools {
		if matchAction(f, action) {
			return Verdict{Outcome: VerdictDeny, Reason: "action forbidden by capabilities.forbidden_tools: " + f}
		}
	}
	for _, r := range ap.Rules {
		for _, pat := range r.Actions {
			if matchAction(pat, action) {
				return Verdict{Outcome: VerdictRequireApproval, RuleID: r.ID, ApproverGroups: append([]string(nil), r.ApproverGroups...), Reason: "approval rule " + r.ID}
			}
		}
	}
	return Verdict{Outcome: VerdictAllow, Reason: "no approval rule matches; action is catalogued"}
}

// MatchingRules lists every approval rule whose pattern matches the action,
// in rule-id order (inspection; Evaluate uses the first match).
func (ap *ApprovalPolicy) MatchingRules(action string) []ApprovalRule {
	if ap == nil {
		return nil
	}
	var out []ApprovalRule
	for _, r := range ap.Rules {
		for _, pat := range r.Actions {
			if matchAction(pat, action) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func matchAction(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}
