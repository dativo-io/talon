package action

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/policy"
)

// Amount limits (#205): one typed numeric comparison on a trusted material
// argument of a catalogued action. A limit splits an amount into three bands
// in one currency:
//
//	amount <= allow_up_to                 no restriction from this limit
//	allow_up_to < amount <= approval_up_to REQUIRE_APPROVAL by approver_groups
//	amount > approval_up_to               DENY
//
// It is not an expression language: one argument, one currency, two
// thresholds. Amounts are exact decimals with at most two fractional digits,
// compared as integer minor units (never floats). The argument may be a JSON
// string ("75.00") or a JSON number written the same way (75.00); exponents,
// signs, leading zeros and more than two fractional digits are refused. A
// limited action whose amount or currency argument is missing, malformed,
// negative, of the wrong type or in another currency is DENIED: the material
// argument the policy depends on is not established, so nothing is
// authorized (fail closed).

// argumentNameRe is the grammar of an argument a limit reads (a top-level
// property of the action's arguments object).
var argumentNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// currencyRe is an ISO 4217-shaped code. Only currencies with two minor
// digits are representable (see LIMITATIONS); the code is compared exactly.
var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

// decimalRe is the only accepted spelling of an amount, in configuration and
// in arguments alike: no sign, no exponent, no leading zeros, at most 15
// integer digits and 2 fractional digits (fits int64 minor units).
var decimalRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,14})(\.[0-9]{1,2})?$`)

// AmountLimit is one compiled amount limit of either layer.
type AmountLimit struct {
	ID string
	// Source is PolicySourceCompany or PolicySourceUseCase.
	Source           string
	Actions          []string
	AmountArgument   string
	CurrencyArgument string
	Currency         string
	AllowUpTo        int64 // minor units
	ApprovalUpTo     int64 // minor units
	ApproverGroups   []string
}

// parseMinorUnits converts an exact decimal spelling into minor units (two
// fractional digits). ok is false for every spelling decimalRe refuses.
func parseMinorUnits(s string) (int64, bool) {
	if !decimalRe.MatchString(s) {
		return 0, false
	}
	whole, frac, _ := strings.Cut(s, ".")
	for len(frac) < 2 {
		frac += "0"
	}
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, false
	}
	f, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return 0, false
	}
	return w*100 + f, true
}

// formatMinorUnits renders minor units as a two-digit decimal.
func formatMinorUnits(v int64) string {
	return fmt.Sprintf("%d.%02d", v/100, v%100)
}

// compileAmountLimit validates and normalizes one limit of either layer.
func compileAmountLimit(id, source, where string, c *policy.AmountLimitConfig) (AmountLimit, error) {
	if !ruleIDRe.MatchString(id) {
		return AmountLimit{}, fmt.Errorf("%s: invalid limit id %q (allowed: %s)", where, id, ruleIDRe.String())
	}
	if err := validateLimitTargets(where, c); err != nil {
		return AmountLimit{}, err
	}
	allow, ok := parseMinorUnits(strings.TrimSpace(c.AllowUpTo))
	if !ok {
		return AmountLimit{}, fmt.Errorf("%s: allow_up_to %q must be a non-negative decimal with at most two fractional digits", where, c.AllowUpTo)
	}
	approval, ok := parseMinorUnits(strings.TrimSpace(c.ApprovalUpTo))
	if !ok {
		return AmountLimit{}, fmt.Errorf("%s: approval_up_to %q must be a non-negative decimal with at most two fractional digits", where, c.ApprovalUpTo)
	}
	if approval < allow {
		return AmountLimit{}, fmt.Errorf("%s: approval_up_to (%s) must not be below allow_up_to (%s)", where, formatMinorUnits(approval), formatMinorUnits(allow))
	}
	if len(c.ApproverGroups) == 0 {
		return AmountLimit{}, fmt.Errorf("%s: approver_groups are required", where)
	}
	for _, g := range c.ApproverGroups {
		if !approver.ValidGroup(g) {
			return AmountLimit{}, fmt.Errorf("%s: invalid approver group %q (allowed: %s)", where, g, approver.GroupPattern)
		}
	}
	if source == PolicySourceCompany {
		id = companyRulePrefix + id
	}
	return AmountLimit{
		ID: id, Source: source, Actions: sortedUnique(c.Actions),
		AmountArgument: c.AmountArgument, CurrencyArgument: c.CurrencyArgument, Currency: c.Currency,
		AllowUpTo: allow, ApprovalUpTo: approval, ApproverGroups: sortedUnique(c.ApproverGroups),
	}, nil
}

// validateLimitTargets checks what a limit applies to and reads: action
// patterns, the two argument names and the currency code.
func validateLimitTargets(where string, c *policy.AmountLimitConfig) error {
	if len(c.Actions) == 0 {
		return fmt.Errorf("%s: actions are required", where)
	}
	for _, a := range c.Actions {
		if !actionNameRe.MatchString(strings.TrimSuffix(a, "*")) {
			return fmt.Errorf("%s: invalid action pattern %q", where, a)
		}
	}
	if !argumentNameRe.MatchString(c.AmountArgument) {
		return fmt.Errorf("%s: amount_argument %q must name a top-level argument (%s)", where, c.AmountArgument, argumentNameRe.String())
	}
	if !argumentNameRe.MatchString(c.CurrencyArgument) {
		return fmt.Errorf("%s: currency_argument %q must name a top-level argument (%s)", where, c.CurrencyArgument, argumentNameRe.String())
	}
	if c.AmountArgument == c.CurrencyArgument {
		return fmt.Errorf("%s: amount_argument and currency_argument must differ", where)
	}
	if !currencyRe.MatchString(c.Currency) {
		return fmt.Errorf("%s: currency %q must be a three-letter upper-case code", where, c.Currency)
	}
	return nil
}

func compileAmountLimits(source, wherePrefix string, in map[string]policy.AmountLimitConfig) ([]AmountLimit, error) {
	ids := make([]string, 0, len(in))
	for id := range in {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]AmountLimit, 0, len(ids))
	for _, id := range ids {
		c := in[id]
		l, err := compileAmountLimit(id, source, wherePrefix+id, &c)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

// asApprovalRule lets the overlap check reason about a limit's approval band
// with the same vocabulary as approval rules: a limit and a rule (or two
// limits) that can match one action must name the same approver groups.
func (l *AmountLimit) asApprovalRule() ApprovalRule {
	return ApprovalRule{ID: l.ID, Source: l.Source, Actions: l.Actions, ApproverGroups: l.ApproverGroups}
}

func (l *AmountLimit) matches(action string) bool {
	for _, p := range l.Actions {
		if matchAction(p, action) {
			return true
		}
	}
	return false
}

// band evaluates the limit over canonical arguments. It never returns
// ALLOW for an unestablished argument.
func (l *AmountLimit) band(canonical []byte) Verdict {
	// Reasons are written into signed lifecycle evidence, which outlives the
	// sealed payload: they name the band and the policy's thresholds, never
	// the argument values of the call.
	label := l.Source + " amount limit " + l.ID
	amount, currency, problem := materialAmount(canonical, l.AmountArgument, l.CurrencyArgument)
	if problem != "" {
		return Verdict{Outcome: VerdictDeny, Source: l.Source, RuleID: l.ID, Reason: label + ": " + problem + "; the amount this policy depends on is not established"}
	}
	if currency != l.Currency {
		return Verdict{Outcome: VerdictDeny, Source: l.Source, RuleID: l.ID, Reason: fmt.Sprintf("%s: the currency is not %s, the only currency this limit supports", label, l.Currency)}
	}
	switch {
	case amount <= l.AllowUpTo:
		return Verdict{Outcome: VerdictAllow, Reason: fmt.Sprintf("%s: the amount is within the allow band (up to %s %s)", label, formatMinorUnits(l.AllowUpTo), l.Currency)}
	case amount <= l.ApprovalUpTo:
		return Verdict{
			Outcome: VerdictRequireApproval, Source: l.Source, RuleID: l.ID, ApproverGroups: append([]string(nil), l.ApproverGroups...),
			Reason: fmt.Sprintf("%s: the amount is above %s and at most %s %s, so it requires approval", label, formatMinorUnits(l.AllowUpTo), formatMinorUnits(l.ApprovalUpTo), l.Currency),
		}
	default:
		return Verdict{Outcome: VerdictDeny, Source: l.Source, RuleID: l.ID, Reason: fmt.Sprintf("%s: the amount is above %s %s, the most this policy can authorize", label, formatMinorUnits(l.ApprovalUpTo), l.Currency)}
	}
}

// materialAmount reads the amount and currency arguments from canonical
// arguments. problem is non-empty when either is not established.
func materialAmount(canonical []byte, amountArg, currencyArg string) (amount int64, currency, problem string) {
	if len(canonical) == 0 {
		return 0, "", "arguments are not available"
	}
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return 0, "", "arguments are not a JSON object"
	}
	raw, present := obj[amountArg]
	if !present || raw == nil {
		return 0, "", fmt.Sprintf("argument %q is missing", amountArg)
	}
	var text string
	switch v := raw.(type) {
	case json.Number:
		text = v.String()
	case string:
		text = v
	default:
		return 0, "", fmt.Sprintf("argument %q must be a decimal string or number", amountArg)
	}
	amount, ok := parseMinorUnits(text)
	if !ok {
		return 0, "", fmt.Sprintf("argument %q is not a non-negative decimal with at most two fractional digits", amountArg)
	}
	cur, present := obj[currencyArg]
	if !present || cur == nil {
		return 0, "", fmt.Sprintf("argument %q is missing", currencyArg)
	}
	cs, isString := cur.(string)
	if !isString {
		return 0, "", fmt.Sprintf("argument %q must be a string", currencyArg)
	}
	return amount, cs, ""
}

// amountLimitDigestLine is the use-case digest line of one limit. Every
// field is validated against a grammar without spaces, "=" or newlines, so
// the line cannot imitate another.
func amountLimitDigestLine(l *AmountLimit) string {
	return fmt.Sprintf("limit %s actions=%s amount=%s currency_arg=%s currency=%s allow=%d approval=%d groups=%s\n",
		l.ID, strings.Join(l.Actions, ","), l.AmountArgument, l.CurrencyArgument, l.Currency, l.AllowUpTo, l.ApprovalUpTo, strings.Join(l.ApproverGroups, ","))
}

type companyLimitEncoding struct {
	ID           string   `json:"id"`
	Actions      []string `json:"actions"`
	Amount       string   `json:"amount_argument"`
	CurrencyArg  string   `json:"currency_argument"`
	Currency     string   `json:"currency"`
	AllowUpTo    int64    `json:"allow_up_to_minor"`
	ApprovalUpTo int64    `json:"approval_up_to_minor"`
	Groups       []string `json:"groups"`
}

func encodeCompanyLimits(limits []AmountLimit) []companyLimitEncoding {
	if len(limits) == 0 {
		return nil
	}
	out := make([]companyLimitEncoding, 0, len(limits))
	for i := range limits {
		l := &limits[i]
		out = append(out, companyLimitEncoding{
			ID: l.ID, Actions: nonNil(l.Actions), Amount: l.AmountArgument, CurrencyArg: l.CurrencyArgument,
			Currency: l.Currency, AllowUpTo: l.AllowUpTo, ApprovalUpTo: l.ApprovalUpTo, Groups: nonNil(l.ApproverGroups),
		})
	}
	return out
}
