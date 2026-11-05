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

// Policy provenance (#425): every restriction in the effective action policy
// names the layer that declared it, so a verdict, an approval and its
// evidence can say whether the company or the use case made the decision.
const (
	PolicySourceCompany = "company"
	PolicySourceUseCase = "use_case"
)

// companyRulePrefix namespaces company rule ids inside the effective policy
// so a company rule and a use-case rule can never collide and the rule id
// alone (in projections, approvals and evidence) carries its provenance.
const companyRulePrefix = PolicySourceCompany + ":"

// DefaultApprovalLifetime applies when policies.approvals.expires_after is unset.
const DefaultApprovalLifetime = time.Hour

// CompanyActionPolicy is the operator-owned company action policy as the
// compiler consumes it: plain data, derived from
// gateway.organization_policy.constraints (forbidden_tools and
// action_approvals.rules) by the configuration layer. nil means "no company
// policy is configured" and leaves per-use-case behaviour exactly as it was;
// a loaded-but-invalid company policy is a compile error, never an absence.
type CompanyActionPolicy struct {
	// Source is the stable identifier of where the policy was loaded from
	// (descriptive provenance; never material to any digest).
	Source string
	// ForbiddenActions are company-wide DENY patterns (exact names or
	// trailing-* prefixes) no use case can lift.
	ForbiddenActions []string
	// Rules are the company-wide approval requirements by operator-chosen id.
	Rules map[string]CompanyApprovalRule
}

// CompanyApprovalRule requires approval for matching catalogued actions by
// one of the approver groups. Same vocabulary as the use-case rule.
type CompanyApprovalRule struct {
	Actions        []string
	ApproverGroups []string
}

// Validate fails closed on a malformed company policy: a rule needs actions
// and approver groups, every pattern must be a legal action pattern, and two
// company rules that can match one action must name the same groups.
func (c *CompanyActionPolicy) Validate() error {
	if c == nil {
		return nil
	}
	for _, f := range c.ForbiddenActions {
		if !actionNameRe.MatchString(strings.TrimSuffix(f, "*")) {
			return fmt.Errorf("forbidden_tools: invalid action pattern %q", f)
		}
	}
	rules, err := c.compiledRules()
	if err != nil {
		return err
	}
	return rejectIncompatibleOverlaps(rules)
}

// Digest is the deterministic digest of the material company rules ("" for
// nil): forbidden patterns and approval rules with their groups, in
// canonical order. Source is descriptive and excluded.
func (c *CompanyActionPolicy) Digest() string {
	if c == nil {
		return ""
	}
	rules, err := c.compiledRules()
	if err != nil {
		return ""
	}
	var b strings.Builder
	writeCompanyLines(&b, c, rules)
	return Digest([]byte(b.String()))
}

func (c *CompanyActionPolicy) compiledRules() ([]ApprovalRule, error) {
	ids := make([]string, 0, len(c.Rules))
	for id := range c.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ApprovalRule, 0, len(ids))
	for _, id := range ids {
		r := c.Rules[id]
		rule, err := compileRule(companyRulePrefix+id, PolicySourceCompany, "organization_policy.constraints.action_approvals.rules."+id, r.Actions, r.ApproverGroups)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

func sortedUnique(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func writeCompanyLines(b *strings.Builder, c *CompanyActionPolicy, rules []ApprovalRule) {
	fmt.Fprintf(b, "company forbidden=%s\n", strings.Join(sortedUnique(c.ForbiddenActions), ","))
	for _, r := range rules {
		fmt.Fprintf(b, "company rule %s actions=%s groups=%s\n", r.ID, strings.Join(r.Actions, ","), strings.Join(r.ApproverGroups, ","))
	}
}

// ApprovalRule is one compiled approval requirement.
type ApprovalRule struct {
	ID string
	// Source is PolicySourceCompany or PolicySourceUseCase.
	Source         string
	Actions        []string // exact names or trailing-* prefix globs
	ApproverGroups []string
}

// forbiddenPattern is one compiled DENY pattern with its provenance.
type forbiddenPattern struct {
	Pattern string
	Source  string
}

// ApprovalPolicy is the compiled, approval-relevant EFFECTIVE policy of one
// agent: the company action policy (when configured) composed with the use
// case's own rules. DENY > REQUIRE_APPROVAL > ALLOW; a company restriction
// is never weakened by the use case; the use case may only add restrictions.
type ApprovalPolicy struct {
	// Rules are company rules first (by id), then use-case rules (by id).
	Rules []ApprovalRule
	// ForbiddenTools is the union of company and use-case DENY patterns
	// (sorted); forbidden keeps each pattern's provenance for verdicts.
	ForbiddenTools []string
	forbidden      []forbiddenPattern
	ExpiresAfter   time.Duration
	// Digest is the approval-relevant policy digest: rules, groups, forbidden
	// actions and lifetime of BOTH layers — nothing descriptive. Without a
	// company policy it is byte-identical to the pre-#425 use-case digest.
	Digest string
	// CompanyDigest is the digest of the company part alone ("" when no
	// company policy is configured); the runtime generation folds it in.
	CompanyDigest string
	// CompanySource is the descriptive identifier of the company policy's
	// origin ("" when none).
	CompanySource string
}

// CompileApprovalPolicy derives the approval-relevant policy from the agent
// file alone (no company policy). It is CompileEffectiveActionPolicy(pol, nil).
func CompileApprovalPolicy(pol *policy.Policy) (*ApprovalPolicy, error) {
	return CompileEffectiveActionPolicy(pol, nil)
}

// CompileEffectiveActionPolicy is the ONE effective action-policy compiler
// (#425): company (operator-owned) ∘ use case (agent file) → one immutable
// policy with provenance. It fails closed on malformed rules and on
// overlapping approval requirements with incompatible approver groups, in
// either layer or across them; rule-id order never silently picks a winner.
func CompileEffectiveActionPolicy(pol *policy.Policy, company *CompanyActionPolicy) (*ApprovalPolicy, error) {
	ap := &ApprovalPolicy{ExpiresAfter: DefaultApprovalLifetime}
	if pol == nil && company == nil {
		ap.Digest = Digest([]byte("{}"))
		return ap, nil
	}
	var companyRules []ApprovalRule
	if company != nil {
		if err := company.Validate(); err != nil {
			return nil, fmt.Errorf("company action policy: %w", err)
		}
		companyRules, _ = company.compiledRules()
		for _, f := range sortedUnique(company.ForbiddenActions) {
			ap.forbidden = append(ap.forbidden, forbiddenPattern{Pattern: f, Source: PolicySourceCompany})
		}
		ap.Rules = append(ap.Rules, companyRules...)
		ap.CompanySource = company.Source
	}
	useCaseForbidden, err := compileUseCaseLayer(ap, pol)
	if err != nil {
		return nil, err
	}
	if err := rejectIncompatibleOverlaps(ap.Rules); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, f := range ap.forbidden {
		if !seen[f.Pattern] {
			seen[f.Pattern] = true
			ap.ForbiddenTools = append(ap.ForbiddenTools, f.Pattern)
		}
	}
	sort.Strings(ap.ForbiddenTools)

	// Digest: the use-case lines keep their pre-#425 byte layout so a
	// deployment without a company policy keeps every digest it has; the
	// company lines are appended only when a company policy exists.
	var b strings.Builder
	fmt.Fprintf(&b, "expires_after=%s\n", ap.ExpiresAfter)
	fmt.Fprintf(&b, "forbidden=%s\n", strings.Join(useCaseForbidden, ","))
	for _, r := range ap.Rules {
		if r.Source != PolicySourceUseCase {
			continue
		}
		fmt.Fprintf(&b, "rule %s actions=%s groups=%s\n", r.ID, strings.Join(r.Actions, ","), strings.Join(r.ApproverGroups, ","))
	}
	if company != nil {
		var cb strings.Builder
		writeCompanyLines(&cb, company, companyRules)
		b.WriteString(cb.String())
		ap.CompanyDigest = Digest([]byte(cb.String()))
	}
	ap.Digest = Digest([]byte(b.String()))
	return ap, nil
}

// compileUseCaseLayer appends the agent file's forbidden tools and approval
// rules to ap and returns the normalized use-case forbidden list (the digest
// keeps it separate from company-forbidden actions).
func compileUseCaseLayer(ap *ApprovalPolicy, pol *policy.Policy) ([]string, error) {
	if pol == nil {
		return nil, nil
	}
	var useCaseForbidden []string
	if pol.Capabilities != nil {
		useCaseForbidden = sortedUnique(pol.Capabilities.ForbiddenTools)
		for _, f := range useCaseForbidden {
			ap.forbidden = append(ap.forbidden, forbiddenPattern{Pattern: f, Source: PolicySourceUseCase})
		}
	}
	ac := pol.Policies.Approvals
	if ac == nil {
		return useCaseForbidden, nil
	}
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
		rule, err := compileRule(id, PolicySourceUseCase, "policies.approvals.rules."+id, r.Actions, r.ApproverGroups)
		if err != nil {
			return nil, err
		}
		ap.Rules = append(ap.Rules, rule)
	}
	return useCaseForbidden, nil
}

// compileRule validates and normalizes one approval rule of either layer.
func compileRule(id, source, where string, actions, groups []string) (ApprovalRule, error) {
	if len(actions) == 0 || len(groups) == 0 {
		return ApprovalRule{}, fmt.Errorf("%s: actions and approver_groups are required", where)
	}
	rule := ApprovalRule{ID: id, Source: source, Actions: sortedUnique(actions), ApproverGroups: sortedUnique(groups)}
	for _, a := range rule.Actions {
		if !actionNameRe.MatchString(strings.TrimSuffix(a, "*")) {
			return ApprovalRule{}, fmt.Errorf("%s: invalid action pattern %q", where, a)
		}
	}
	return rule, nil
}

// rejectIncompatibleOverlaps refuses two rules that can match the same
// action unless they name the same approver groups: an ambiguous
// authorization requirement is a configuration error, not a lexical pick.
func rejectIncompatibleOverlaps(rules []ApprovalRule) error {
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			a, b := rules[i], rules[j]
			if !rulesOverlap(a, b) || sameStrings(a.ApproverGroups, b.ApproverGroups) {
				continue
			}
			return fmt.Errorf("approval rules %q (%s, groups %s) and %q (%s, groups %s) both match the same actions with different approver groups; an ambiguous approval requirement is refused — give them the same approver_groups or disjoint actions",
				a.ID, a.Source, strings.Join(a.ApproverGroups, ","), b.ID, b.Source, strings.Join(b.ApproverGroups, ","))
		}
	}
	return nil
}

func rulesOverlap(a, b ApprovalRule) bool {
	for _, pa := range a.Actions {
		for _, pb := range b.Actions {
			if patternsOverlap(pa, pb) {
				return true
			}
		}
	}
	return false
}

// patternsOverlap reports whether some action name matches both patterns
// (exact names or trailing-* prefixes).
func patternsOverlap(a, b string) bool {
	ap, aPrefix := strings.CutSuffix(a, "*")
	bp, bPrefix := strings.CutSuffix(b, "*")
	switch {
	case aPrefix && bPrefix:
		return strings.HasPrefix(ap, bp) || strings.HasPrefix(bp, ap)
	case aPrefix:
		return strings.HasPrefix(b, ap)
	case bPrefix:
		return strings.HasPrefix(a, bp)
	default:
		return a == b
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Verdict is the authoritative policy outcome for one catalogued action.
type Verdict struct {
	Outcome string
	// Source names the layer whose rule produced a DENY or REQUIRE_APPROVAL
	// (PolicySourceCompany | PolicySourceUseCase); "" for ALLOW.
	Source         string
	RuleID         string
	ApproverGroups []string
	Reason         string
}

// Evaluate applies DENY > REQUIRE_APPROVAL > ALLOW for a catalog action.
// Company patterns are evaluated before use-case ones, so a restriction
// both layers declare is attributed to the company.
func (ap *ApprovalPolicy) Evaluate(action string) Verdict {
	for _, f := range ap.forbidden {
		if matchAction(f.Pattern, action) {
			return Verdict{Outcome: VerdictDeny, Source: f.Source, Reason: "action forbidden by " + f.Source + " policy (forbidden_tools: " + f.Pattern + ")"}
		}
	}
	for _, r := range ap.Rules {
		for _, pat := range r.Actions {
			if matchAction(pat, action) {
				return Verdict{Outcome: VerdictRequireApproval, Source: r.Source, RuleID: r.ID, ApproverGroups: append([]string(nil), r.ApproverGroups...), Reason: r.Source + " approval rule " + r.ID}
			}
		}
	}
	return Verdict{Outcome: VerdictAllow, Reason: "no approval rule matches; action is catalogued"}
}

// MatchingRules lists every approval rule whose pattern matches the action,
// company rules first then by id (inspection; Evaluate uses the first match).
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

// RuleSource reports the provenance a compiled rule id carries
// (PolicySourceCompany for company rules, PolicySourceUseCase otherwise, ""
// for no rule).
func RuleSource(ruleID string) string {
	switch {
	case ruleID == "":
		return ""
	case strings.HasPrefix(ruleID, companyRulePrefix):
		return PolicySourceCompany
	default:
		return PolicySourceUseCase
	}
}

func matchAction(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}
