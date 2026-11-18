package action

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/policy"
)

// Argument rules (#205): one declarative, typed condition on ONE top-level
// argument of a catalogued action, with a RESTRICTIVE effect:
//
//	actions + argument + type + operator + value → require_approval | deny
//
// A rule never grants anything. The action being catalogued (and not
// forbidden) is the prerequisite; a rule whose condition does not hold adds
// no restriction; DENY > REQUIRE_APPROVAL > the baseline. It is not an
// expression language: no nesting, no conjunctions, no functions, no
// external data (broader forms are #570).
//
// Types and their wire representation (no implicit coercion between them):
//
//	integer  a JSON number without fraction or exponent, at most 18 digits
//	decimal  an exact decimal with at most 18 integer and 6 fractional
//	         digits, as a JSON number or a JSON string in the same spelling;
//	         compared exactly (never as a float)
//	string   a JSON string, compared byte for byte (case-sensitive)
//	boolean  a JSON boolean
//
// integer and decimal support eq, ne, gt, gte, lt, lte; string and boolean
// support eq and ne.
//
// Fail closed: when a rule applies to an action and its argument is missing,
// null, of another JSON type, or outside the type's bounds, the condition
// cannot be established and the call is DENIED — an unestablished material
// argument is never a silent non-match. Domain constraints (a refund must be
// in EUR, non-negative, with cent precision) belong to the action's trusted
// input schema or to explicit rules; this file has no notion of money.

// Argument types.
const (
	ArgTypeInteger = "integer"
	ArgTypeDecimal = "decimal"
	ArgTypeString  = "string"
	ArgTypeBoolean = "boolean"
)

// Operators.
const (
	OpEq  = "eq"
	OpNe  = "ne"
	OpGt  = "gt"
	OpGte = "gte"
	OpLt  = "lt"
	OpLte = "lte"
)

// Effects.
const (
	EffectRequireApproval = "require_approval"
	EffectDeny            = "deny"
)

const (
	decimalScale     = 6    // fractional digits kept exactly
	maxStringOperand = 1024 // bytes
)

// argumentNameRe is the grammar of the argument a rule reads: a top-level
// property of the action's arguments object.
var argumentNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

var (
	integerRe = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,17})$`)
	decimalRe = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,17})(\.[0-9]{1,6})?$`)
)

// ArgumentRule is one compiled argument rule of either layer.
type ArgumentRule struct {
	ID string
	// Source is PolicySourceCompany or PolicySourceUseCase.
	Source   string
	Actions  []string
	Argument string
	Type     string
	Operator string
	// Value is the operand in its normalized text form ("50" and "50.00"
	// are the same decimal; a string operand is kept verbatim).
	Value          string
	Effect         string
	ApproverGroups []string

	num *big.Int // integer and decimal operands, scaled
	b   bool     // boolean operand
}

// parseDecimal converts an exact decimal spelling into a scaled integer.
func parseDecimal(s string) (*big.Int, bool) {
	if !decimalRe.MatchString(s) {
		return nil, false
	}
	whole, frac, _ := strings.Cut(s, ".")
	for len(frac) < decimalScale {
		frac += "0"
	}
	v, ok := new(big.Int).SetString(whole+frac, 10)
	return v, ok
}

func parseInteger(s string) (*big.Int, bool) {
	if !integerRe.MatchString(s) {
		return nil, false
	}
	return new(big.Int).SetString(s, 10)
}

// formatDecimal renders a scaled decimal without trailing zeros.
func formatDecimal(v *big.Int) string {
	neg := v.Sign() < 0
	digits := new(big.Int).Abs(v).String()
	for len(digits) <= decimalScale {
		digits = "0" + digits
	}
	whole, frac := digits[:len(digits)-decimalScale], strings.TrimRight(digits[len(digits)-decimalScale:], "0")
	out := whole
	if frac != "" {
		out += "." + frac
	}
	if neg && v.Sign() != 0 {
		out = "-" + out
	}
	return out
}

func validOperator(typ, op string) bool {
	switch op {
	case OpEq, OpNe:
		return true
	case OpGt, OpGte, OpLt, OpLte:
		return typ == ArgTypeInteger || typ == ArgTypeDecimal
	}
	return false
}

// compileOperand validates the configured operand against the rule's type.
// The YAML value must already have that type: a decimal is written as a
// quoted string so it never passes through a float.
func compileOperand(r *ArgumentRule, v any) error {
	switch r.Type {
	case ArgTypeInteger:
		var text string
		switch x := v.(type) {
		case int:
			text = strconv.Itoa(x)
		case int64:
			text = strconv.FormatInt(x, 10)
		default:
			return fmt.Errorf("value must be an integer (got %T)", v)
		}
		n, ok := parseInteger(text)
		if !ok {
			return fmt.Errorf("value %s is outside the supported integer range (18 digits)", text)
		}
		r.num, r.Value = n, n.String()
	case ArgTypeDecimal:
		text, ok := v.(string)
		if !ok {
			return fmt.Errorf("value must be a quoted decimal string such as \"50.00\" (got %T): a decimal operand is never read through a float", v)
		}
		n, ok := parseDecimal(strings.TrimSpace(text))
		if !ok {
			return fmt.Errorf("value %q is not a decimal with at most 18 integer and %d fractional digits", text, decimalScale)
		}
		r.num, r.Value = n, formatDecimal(n)
	case ArgTypeString:
		text, ok := v.(string)
		if !ok {
			return fmt.Errorf("value must be a string (got %T)", v)
		}
		if len(text) > maxStringOperand || strings.ContainsAny(text, "\x00\n\r") {
			return fmt.Errorf("value must be at most %d bytes without control line breaks", maxStringOperand)
		}
		r.Value = text
	case ArgTypeBoolean:
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("value must be true or false (got %T)", v)
		}
		r.b, r.Value = b, strconv.FormatBool(b)
	default:
		return fmt.Errorf("type %q is not supported (integer, decimal, string, boolean)", r.Type)
	}
	return nil
}

// compileArgumentRule validates and normalizes one rule of either layer.
func compileArgumentRule(id, source, where string, c *policy.ArgumentRuleConfig) (ArgumentRule, error) {
	if !ruleIDRe.MatchString(id) {
		return ArgumentRule{}, fmt.Errorf("%s: invalid rule id %q (allowed: %s)", where, id, ruleIDRe.String())
	}
	if len(c.Actions) == 0 {
		return ArgumentRule{}, fmt.Errorf("%s: actions are required", where)
	}
	for _, a := range c.Actions {
		if !actionNameRe.MatchString(strings.TrimSuffix(a, "*")) {
			return ArgumentRule{}, fmt.Errorf("%s: invalid action pattern %q", where, a)
		}
	}
	if !argumentNameRe.MatchString(c.Argument) {
		return ArgumentRule{}, fmt.Errorf("%s: argument %q must name a top-level argument (%s)", where, c.Argument, argumentNameRe.String())
	}
	r := ArgumentRule{ID: id, Source: source, Actions: sortedUnique(c.Actions), Argument: c.Argument, Type: c.Type, Operator: c.Operator, Effect: c.Effect}
	if err := compileOperand(&r, c.Value); err != nil {
		return ArgumentRule{}, fmt.Errorf("%s: %w", where, err)
	}
	if !validOperator(r.Type, r.Operator) {
		return ArgumentRule{}, fmt.Errorf("%s: operator %q is not supported for type %s (integer and decimal: eq, ne, gt, gte, lt, lte; string and boolean: eq, ne)", where, c.Operator, r.Type)
	}
	switch r.Effect {
	case EffectRequireApproval:
		if len(c.ApproverGroups) == 0 {
			return ArgumentRule{}, fmt.Errorf("%s: approver_groups are required for effect require_approval", where)
		}
		for _, g := range c.ApproverGroups {
			if !approver.ValidGroup(g) {
				return ArgumentRule{}, fmt.Errorf("%s: invalid approver group %q (allowed: %s)", where, g, approver.GroupPattern)
			}
		}
		r.ApproverGroups = sortedUnique(c.ApproverGroups)
	case EffectDeny:
		if len(c.ApproverGroups) > 0 {
			return ArgumentRule{}, fmt.Errorf("%s: approver_groups have no meaning for effect deny", where)
		}
	default:
		return ArgumentRule{}, fmt.Errorf("%s: effect %q is not supported (require_approval, deny): a rule only restricts, it never grants", where, c.Effect)
	}
	if source == PolicySourceCompany {
		r.ID = companyRulePrefix + id
	}
	return r, nil
}

func compileArgumentRules(source, wherePrefix string, in map[string]policy.ArgumentRuleConfig) ([]ArgumentRule, error) {
	ids := make([]string, 0, len(in))
	for id := range in {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ArgumentRule, 0, len(ids))
	for _, id := range ids {
		c := in[id]
		r, err := compileArgumentRule(id, source, wherePrefix+id, &c)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (r *ArgumentRule) matches(action string) bool {
	for _, p := range r.Actions {
		if matchAction(p, action) {
			return true
		}
	}
	return false
}

// Condition is the rule's condition in its canonical text form. The operand
// is policy, not call data.
func (r *ArgumentRule) Condition() string {
	v := r.Value
	if r.Type == ArgTypeString {
		v = strconv.Quote(v)
	}
	return r.Argument + " " + r.Operator + " " + v
}

// established reads the rule's argument from canonical arguments. problem is
// non-empty when the value needed by the condition is not established.
func (r *ArgumentRule) established(obj map[string]any) (num *big.Int, str string, b bool, problem string) {
	raw, present := obj[r.Argument]
	if !present || raw == nil {
		return nil, "", false, fmt.Sprintf("argument %q is missing", r.Argument)
	}
	wrong := fmt.Sprintf("argument %q is not a valid %s", r.Argument, r.Type)
	switch r.Type {
	case ArgTypeInteger:
		n, isNumber := raw.(json.Number)
		if !isNumber {
			return nil, "", false, wrong
		}
		v, ok := parseInteger(n.String())
		if !ok {
			return nil, "", false, wrong
		}
		return v, "", false, ""
	case ArgTypeDecimal:
		var text string
		switch x := raw.(type) {
		case json.Number:
			text = x.String()
		case string:
			text = x
		default:
			return nil, "", false, wrong
		}
		v, ok := parseDecimal(text)
		if !ok {
			return nil, "", false, wrong
		}
		return v, "", false, ""
	case ArgTypeString:
		s, isString := raw.(string)
		if !isString || len(s) > maxStringOperand {
			return nil, "", false, wrong
		}
		return nil, s, false, ""
	default: // boolean
		v, isBool := raw.(bool)
		if !isBool {
			return nil, "", false, wrong
		}
		return nil, "", v, ""
	}
}

// holds reports whether the condition holds for established values.
func (r *ArgumentRule) holds(num *big.Int, str string, b bool) bool {
	var cmp int
	switch r.Type {
	case ArgTypeInteger, ArgTypeDecimal:
		cmp = num.Cmp(r.num)
	case ArgTypeString:
		cmp = strings.Compare(str, r.Value)
	default:
		if b != r.b {
			cmp = 1
		}
	}
	switch r.Operator {
	case OpEq:
		return cmp == 0
	case OpNe:
		return cmp != 0
	case OpGt:
		return cmp > 0
	case OpGte:
		return cmp >= 0
	case OpLt:
		return cmp < 0
	default:
		return cmp <= 0
	}
}

// evaluate applies the rule to decoded canonical arguments. applies is false
// when the condition does not hold (the rule adds no restriction). Reasons
// are written into signed lifecycle evidence, which outlives the sealed
// payload: they name the rule and its argument, never a value of the call.
func (r *ArgumentRule) evaluate(obj map[string]any) (v Verdict, applies bool) {
	label := r.Source + " argument rule " + r.ID
	if obj == nil {
		return Verdict{Outcome: VerdictDeny, Source: r.Source, RuleID: r.ID, Code: ReasonArgumentNotEstablished, Reason: label + ": the arguments are not available, so its condition cannot be established"}, true
	}
	num, str, b, problem := r.established(obj)
	if problem != "" {
		return Verdict{Outcome: VerdictDeny, Source: r.Source, RuleID: r.ID, Code: ReasonArgumentNotEstablished, Reason: label + ": " + problem + ", so its condition cannot be established"}, true
	}
	if !r.holds(num, str, b) {
		return Verdict{}, false
	}
	if r.Effect == EffectDeny {
		return Verdict{Outcome: VerdictDeny, Source: r.Source, RuleID: r.ID, Code: ReasonArgumentRuleDeny, Reason: label + ": its condition on argument \"" + r.Argument + "\" holds; the action is denied"}, true
	}
	return Verdict{
		Outcome: VerdictRequireApproval, Source: r.Source, RuleID: r.ID, ApproverGroups: append([]string(nil), r.ApproverGroups...), Code: ReasonArgumentRuleApproval,
		Reason: label + ": its condition on argument \"" + r.Argument + "\" holds; approval is required",
	}, true
}

// asApprovalRule lets the overlap check treat a require_approval argument
// rule like an approval rule: two approval requirements that can apply to
// one action must name the same approver groups, whatever their conditions.
func (r *ArgumentRule) asApprovalRule() ApprovalRule {
	return ApprovalRule{ID: r.ID, Source: r.Source, Actions: r.Actions, ApproverGroups: r.ApproverGroups}
}

// decodeArguments decodes canonical arguments into an object (nil when they
// are not a JSON object).
func decodeArguments(canonical []byte) map[string]any {
	if len(canonical) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil
	}
	return obj
}

// argumentRuleDigestLine is the use-case digest line of one rule. The
// operand is quoted, so no value can imitate a delimiter or another line.
func argumentRuleDigestLine(r *ArgumentRule) string {
	return fmt.Sprintf("argrule %s actions=%s arg=%s type=%s op=%s value=%s effect=%s groups=%s\n",
		r.ID, strings.Join(r.Actions, ","), r.Argument, r.Type, r.Operator, strconv.Quote(r.Value), r.Effect, strings.Join(r.ApproverGroups, ","))
}

type companyArgumentRuleEncoding struct {
	ID       string   `json:"id"`
	Actions  []string `json:"actions"`
	Argument string   `json:"argument"`
	Type     string   `json:"type"`
	Operator string   `json:"operator"`
	Value    string   `json:"value"`
	Effect   string   `json:"effect"`
	Groups   []string `json:"groups"`
}

func encodeCompanyArgumentRules(rules []ArgumentRule) []companyArgumentRuleEncoding {
	if len(rules) == 0 {
		return nil
	}
	out := make([]companyArgumentRuleEncoding, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		out = append(out, companyArgumentRuleEncoding{
			ID: r.ID, Actions: nonNil(r.Actions), Argument: r.Argument, Type: r.Type, Operator: r.Operator,
			Value: r.Value, Effect: r.Effect, Groups: nonNil(r.ApproverGroups),
		})
	}
	return out
}

// jsonTypesFor lists the JSON Schema types an argument of a rule type may be
// declared with in the trusted catalog.
func jsonTypesFor(ruleType string) []string {
	switch ruleType {
	case ArgTypeInteger:
		return []string{"integer"}
	case ArgTypeDecimal:
		return []string{"string", "number"}
	case ArgTypeString:
		return []string{"string"}
	default:
		return []string{"boolean"}
	}
}

// ValidateAgainstCatalog resolves every argument rule against the trusted
// catalog: for each catalogued action a rule applies to, the argument must
// be a declared top-level property, REQUIRED by the action's schema (so it
// is always established), with a JSON type that matches the rule's type. A
// rule that matches no catalogued action is allowed (the action may be
// added later); a rule that could never be evaluated truthfully is a load
// error.
func (ap *ApprovalPolicy) ValidateAgainstCatalog(cat *Catalog) error {
	if ap == nil || cat == nil {
		return nil
	}
	for i := range ap.ArgumentRules {
		r := &ap.ArgumentRules[i]
		for _, name := range cat.Names() {
			if !r.matches(name) {
				continue
			}
			def, _ := cat.Lookup(name)
			if err := checkRuleAgainstSchema(r, def); err != nil {
				return fmt.Errorf("%s argument rule %q on action %q: %w", r.Source, r.ID, name, err)
			}
		}
	}
	return nil
}

func checkRuleAgainstSchema(r *ArgumentRule, def *Definition) error {
	var schema struct {
		Properties map[string]struct {
			Type any `json:"type"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(def.Schema, &schema); err != nil {
		return fmt.Errorf("the action's input schema cannot be read: %w", err)
	}
	prop, declared := schema.Properties[r.Argument]
	if !declared {
		return fmt.Errorf("argument %q is not a declared top-level property of the action's input schema", r.Argument)
	}
	required := false
	for _, n := range schema.Required {
		if n == r.Argument {
			required = true
		}
	}
	if !required {
		return fmt.Errorf("argument %q must be required by the action's input schema: a rule's argument is always established, or the call is denied", r.Argument)
	}
	declaredType, _ := prop.Type.(string)
	for _, t := range jsonTypesFor(r.Type) {
		if declaredType == t {
			return nil
		}
	}
	return fmt.Errorf("argument %q is declared as %q in the input schema; a %s rule needs %s (no implicit coercion)", r.Argument, declaredType, r.Type, strings.Join(jsonTypesFor(r.Type), " or "))
}
