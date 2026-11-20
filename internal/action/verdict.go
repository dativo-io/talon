package action

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/dativo-io/talon/internal/approver"
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
// Operator-chosen ids follow ruleIDRe and therefore never contain ":", so
// the provenance namespaces (company:, use_case:) cannot be claimed by a
// rule of either layer — provenance derived from a persisted rule id is
// authoritative, not a hint.
const companyRulePrefix = PolicySourceCompany + ":"

// Typed rule ids of a DENY: a forbidden-action verdict carries the layer that
// declared the pattern as its rule id, so a persisted operation, its
// projection and its signed evidence keep the structured provenance of the
// denial — not only the textual reason.
const (
	CompanyDenyRuleID = companyRulePrefix + "forbidden_tools"
	UseCaseDenyRuleID = PolicySourceUseCase + ":forbidden_tools"
)

// ruleIDRe is the grammar of an operator-chosen approval rule id in either
// layer (the agent-file schema's rule-id pattern): no ":" is possible.
var ruleIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

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
	// ForbiddenActions are company-wide DENY patterns no use case can lift.
	// They are gateway.organization_policy.constraints.forbidden_tools — the
	// list that also governs LLM-gateway tools — and keep that list's
	// established glob semantics (path.Match, case-insensitive): "*",
	// "delete_*", "*_customer", exact names.
	ForbiddenActions []string
	// Rules are the company-wide approval requirements by operator-chosen id.
	Rules map[string]CompanyApprovalRule
	// ArgumentRules are the company-wide argument rules (#205) by
	// operator-chosen id: no use case can lift their restriction.
	ArgumentRules map[string]policy.ArgumentRuleConfig
}

// CompanyApprovalRule requires approval for matching catalogued actions by
// one of the approver groups. Same vocabulary as the use-case rule.
type CompanyApprovalRule struct {
	Actions        []string
	ApproverGroups []string
}

// Validate fails closed on a malformed company policy: a rule needs actions
// and approver groups, every forbidden pattern must be a legal glob, every
// approval pattern a legal action pattern, and two company rules that can
// match one action must name the same groups.
func (c *CompanyActionPolicy) Validate() error {
	if c == nil {
		return nil
	}
	if err := validateForbiddenPatterns("forbidden_tools", c.ForbiddenActions); err != nil {
		return err
	}
	rules, err := c.compiledRules()
	if err != nil {
		return err
	}
	argRules, err := c.compiledArgumentRules()
	if err != nil {
		return err
	}
	if err := rejectIDCollisions(rules, argRules); err != nil {
		return err
	}
	return rejectIncompatibleOverlaps(withArgumentApprovals(rules, argRules))
}

func (c *CompanyActionPolicy) compiledArgumentRules() ([]ArgumentRule, error) {
	return compileArgumentRules(PolicySourceCompany, "organization_policy.constraints.action_approvals.argument_rules.", c.ArgumentRules)
}

// withArgumentApprovals appends each require_approval argument rule as an
// approval rule, for the overlap check only: two approval requirements that
// can apply to one action must name the same approver groups.
func withArgumentApprovals(rules []ApprovalRule, argRules []ArgumentRule) []ApprovalRule {
	out := append([]ApprovalRule(nil), rules...)
	for i := range argRules {
		if argRules[i].Effect == EffectRequireApproval {
			out = append(out, argRules[i].asApprovalRule())
		}
	}
	return out
}

// rejectIDCollisions refuses an argument rule whose (namespaced) id equals
// another rule's: a rule id in a verdict, an approval or evidence must name
// one thing.
func rejectIDCollisions(rules []ApprovalRule, argRules []ArgumentRule) error {
	ids := map[string]bool{}
	for _, r := range rules {
		ids[r.ID] = true
	}
	for i := range argRules {
		id := argRules[i].ID
		if ids[id] {
			return fmt.Errorf("argument rule %q has the same id as another rule of the same layer; ids must be unique", id)
		}
		ids[id] = true
	}
	return nil
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
	argRules, err := c.compiledArgumentRules()
	if err != nil {
		return ""
	}
	return Digest(companyCanonical(sortedUnique(c.ForbiddenActions), rules, argRules))
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
		rule, err := compileRule(id, PolicySourceCompany, "organization_policy.constraints.action_approvals.rules."+id, r.Actions, r.ApproverGroups)
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

// companyEncoding is the canonical, typed encoding of the material company
// rules (PR #526 review round 2). Lists are JSON arrays, never joined
// strings: joining with commas let ["a,b"] and ["a","b"] — one literal glob
// that matches nothing versus two patterns, or one impossible group versus
// two groups — hash identically, so a materially changed company policy
// could keep the digest an old approval was bound to. The encoding is
// versioned so a future change is a new digest, never a silent collision.
type companyEncoding struct {
	Version   int                   `json:"v"`
	Forbidden []string              `json:"forbidden"`
	Rules     []companyRuleEncoding `json:"rules"`
	// ArgumentRules (#205) are present only in version 2: a company policy
	// without argument rules keeps its version-1 bytes and every digest
	// bound to them.
	ArgumentRules []companyArgumentRuleEncoding `json:"argument_rules,omitempty"`
}

type companyRuleEncoding struct {
	ID      string   `json:"id"`
	Actions []string `json:"actions"`
	Groups  []string `json:"groups"`
}

// companyCanonical encodes already-normalized company rules (sorted unique
// forbidden patterns; rules sorted by id with sorted actions and groups) as
// deterministic JSON. encoding/json writes struct fields in declaration
// order and escapes every string, so the bytes are a function of the
// values alone and no value can imitate a delimiter. Empty lists encode as
// [] (never null) so "no patterns" has exactly one spelling.
func companyCanonical(forbidden []string, rules []ApprovalRule, argRules []ArgumentRule) []byte {
	enc := companyEncoding{Version: 1, Forbidden: nonNil(forbidden), Rules: make([]companyRuleEncoding, 0, len(rules))}
	if len(argRules) > 0 {
		enc.Version = 2
		enc.ArgumentRules = encodeCompanyArgumentRules(argRules)
	}
	for _, r := range rules {
		enc.Rules = append(enc.Rules, companyRuleEncoding{ID: r.ID, Actions: nonNil(r.Actions), Groups: nonNil(r.ApproverGroups)})
	}
	out, err := json.Marshal(enc)
	if err != nil {
		// Only invalid UTF-8 can fail here; such a string never passes
		// validation, and a digest of "" would still differ from any policy.
		panic("company policy encoding: " + err.Error())
	}
	return out
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
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
	// ArgumentRules are the argument rules (#205), company first then use
	// case, by id. Only EvaluateArguments applies them.
	ArgumentRules []ArgumentRule
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
	var companyArgRules []ArgumentRule
	if company != nil {
		if err := company.Validate(); err != nil {
			return nil, fmt.Errorf("company action policy: %w", err)
		}
		companyRules, _ = company.compiledRules()
		companyArgRules, _ = company.compiledArgumentRules()
		ap.ArgumentRules = append(ap.ArgumentRules, companyArgRules...)
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
	if err := rejectIDCollisions(ap.Rules, ap.ArgumentRules); err != nil {
		return nil, err
	}
	if err := rejectIncompatibleOverlaps(withArgumentApprovals(ap.Rules, ap.ArgumentRules)); err != nil {
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

	ap.Digest, ap.CompanyDigest = effectiveDigests(ap, useCaseForbidden, company, companyRules, companyArgRules)
	return ap, nil
}

// effectiveDigests computes the approval-relevant digest and the company
// digest. The use-case lines keep their pre-#425 byte layout so a
// deployment without a company policy keeps every digest it has; the
// company lines are appended only when a company policy exists.
func effectiveDigests(ap *ApprovalPolicy, useCaseForbidden []string, company *CompanyActionPolicy, companyRules []ApprovalRule, companyArgRules []ArgumentRule) (digest, companyDigest string) {
	var b strings.Builder
	fmt.Fprintf(&b, "expires_after=%s\n", ap.ExpiresAfter)
	fmt.Fprintf(&b, "forbidden=%s\n", strings.Join(useCaseForbidden, ","))
	for _, r := range ap.Rules {
		if r.Source != PolicySourceUseCase {
			continue
		}
		fmt.Fprintf(&b, "rule %s actions=%s groups=%s\n", r.ID, strings.Join(r.Actions, ","), strings.Join(r.ApproverGroups, ","))
	}
	// Use-case argument rules add lines only when present, so a policy
	// without them keeps its digest byte for byte.
	for i := range ap.ArgumentRules {
		if ap.ArgumentRules[i].Source == PolicySourceUseCase {
			b.WriteString(argumentRuleDigestLine(&ap.ArgumentRules[i]))
		}
	}
	if company != nil {
		cb := companyCanonical(sortedUnique(company.ForbiddenActions), companyRules, companyArgRules)
		b.WriteString("company=")
		b.Write(cb)
		b.WriteByte('\n')
		companyDigest = Digest(cb)
	}
	return Digest([]byte(b.String())), companyDigest
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
		if err := validateForbiddenPatterns("capabilities.forbidden_tools", pol.Capabilities.ForbiddenTools); err != nil {
			return nil, err
		}
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
	argRules, err := compileArgumentRules(PolicySourceUseCase, "policies.approvals.argument_rules.", ac.ArgumentRules)
	if err != nil {
		return nil, err
	}
	ap.ArgumentRules = append(ap.ArgumentRules, argRules...)
	return useCaseForbidden, nil
}

// compileRule validates and normalizes one approval rule of either layer.
// id is the operator-chosen id; a company rule is namespaced here.
func compileRule(id, source, where string, actions, groups []string) (ApprovalRule, error) {
	if !ruleIDRe.MatchString(id) {
		return ApprovalRule{}, fmt.Errorf("%s: invalid rule id %q (allowed: %s; the %q and %q prefixes are reserved provenance namespaces)", where, id, ruleIDRe.String(), companyRulePrefix, PolicySourceUseCase+":")
	}
	if len(actions) == 0 || len(groups) == 0 {
		return ApprovalRule{}, fmt.Errorf("%s: actions and approver_groups are required", where)
	}
	for _, g := range groups {
		if !approver.ValidGroup(g) {
			return ApprovalRule{}, fmt.Errorf("%s: invalid approver group %q (allowed: %s — the grammar of local approver principals' groups, so a rule can only name a group a reviewer can hold)", where, g, approver.GroupPattern)
		}
	}
	if source == PolicySourceCompany {
		id = companyRulePrefix + id
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
	// Code is the machine-readable reason of an argument-rule verdict
	// (Reason* constants); "" for name-only verdicts.
	Code string
}

// Machine-readable reasons of argument-rule verdicts (#205).
const (
	ReasonArgumentRuleDeny       = "argument_rule_deny"
	ReasonArgumentRuleApproval   = "argument_rule_approval"
	ReasonArgumentNotEstablished = "argument_not_established"
)

// Evaluate applies DENY > REQUIRE_APPROVAL > ALLOW for a catalog action.
// Company patterns are evaluated before use-case ones, so a restriction
// both layers declare is attributed to the company.
func (ap *ApprovalPolicy) Evaluate(action string) Verdict {
	for _, f := range ap.forbidden {
		if matchForbidden(f.Pattern, action) {
			return Verdict{Outcome: VerdictDeny, Source: f.Source, RuleID: denyRuleID(f.Source), Reason: "action forbidden by " + f.Source + " policy (forbidden_tools: " + f.Pattern + ")"}
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

// EvaluateArguments is the authorization verdict for one catalogued action
// with its canonical arguments: Evaluate's forbidden patterns and approval
// rules plus every argument rule (#205) that applies to the action. DENY >
// REQUIRE_APPROVAL > ALLOW across all of them; among restrictions of the
// same strength the company's is reported (company first, name rules before
// argument rules). A rule whose argument is not established denies; a rule
// whose condition does not hold adds nothing. Every path that authorizes,
// binds or dispatches an action must use this, not Evaluate.
func (ap *ApprovalPolicy) EvaluateArguments(action string, canonical []byte) Verdict {
	base := ap.Evaluate(action)
	if base.Outcome == VerdictDeny {
		return base
	}
	var approval *Verdict
	if base.Outcome == VerdictRequireApproval {
		approval = &base
	}
	var obj map[string]any
	decoded := false
	for i := range ap.ArgumentRules {
		r := &ap.ArgumentRules[i]
		if !r.matches(action) {
			continue
		}
		if !decoded {
			obj, decoded = decodeArguments(canonical), true
		}
		v, applies := r.evaluate(obj)
		if !applies {
			continue
		}
		if v.Outcome == VerdictDeny {
			return v
		}
		// The overlap check guarantees the same approver groups; keep the
		// first (company before use case, name rules before argument rules).
		if approval == nil || (approval.Source == PolicySourceUseCase && v.Source == PolicySourceCompany) {
			vv := v
			approval = &vv
		}
	}
	if approval != nil {
		return *approval
	}
	return base
}

// MatchingArgumentRules lists the argument rules that apply to the action
// (inspection).
func (ap *ApprovalPolicy) MatchingArgumentRules(action string) []ArgumentRule {
	if ap == nil {
		return nil
	}
	var out []ArgumentRule
	for i := range ap.ArgumentRules {
		if ap.ArgumentRules[i].matches(action) {
			out = append(out, ap.ArgumentRules[i])
		}
	}
	return out
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
// (PolicySourceCompany for company rules and company denials,
// PolicySourceUseCase otherwise, "" for no rule). Authoritative because no
// operator-chosen id can contain ":" (ruleIDRe), so only the compiler
// produces namespaced ids.
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

// matchAction matches an approval-rule pattern (exact name or trailing-*
// prefix; the vocabulary patternsOverlap reasons about).
func matchAction(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// matchForbidden matches a forbidden_tools pattern with the gateway tool
// filter's semantics (path.Match, case-insensitive): the same list denies
// gateway tools and catalogued actions, so it must mean the same thing on
// both. Patterns are validated at compile; a malformed one never reaches
// here.
func matchForbidden(pattern, name string) bool {
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(name))
	return err == nil && ok
}

// validateForbiddenPatterns fails closed on a malformed glob: a pattern that
// could never match would silently lift a denial.
func validateForbiddenPatterns(where string, patterns []string) error {
	for _, f := range patterns {
		if strings.TrimSpace(f) == "" {
			return fmt.Errorf("%s: empty pattern", where)
		}
		// No tool or action name contains a comma, so a comma in a pattern
		// is always a mistake (one literal pattern written as a list) — and
		// it keeps the use case's legacy comma-separated digest line
		// unambiguous without changing any existing digest.
		if strings.Contains(f, ",") {
			return fmt.Errorf("%s: pattern %q contains a comma; write one pattern per list entry", where, f)
		}
		// The legacy use-case digest lines are newline-delimited and
		// path.Match accepts a literal control character, so a pattern
		// spelling "x\nrule …" would serialize like a real approval rule
		// (PR #526 review round 3). No tool or action name contains one.
		if i := strings.IndexFunc(f, unicode.IsControl); i >= 0 {
			return fmt.Errorf("%s: pattern %q contains a control character (%U)", where, f, []rune(f[i:])[0])
		}
		if _, err := path.Match(f, ""); err != nil {
			return fmt.Errorf("%s: invalid glob pattern %q: %w", where, f, err)
		}
	}
	return nil
}

func denyRuleID(source string) string {
	if source == PolicySourceCompany {
		return CompanyDenyRuleID
	}
	return UseCaseDenyRuleID
}
