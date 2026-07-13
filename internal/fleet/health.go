package fleet

import "fmt"

// Evaluate derives an agent's HEALTH and the ordered causes from its configured
// State and pre-windowed Signals. It is pure — no time math, no I/O — so every
// boundary is table-testable. This is the ONLY place health is decided; the
// server handler and the CLI both reach it through Project.
//
// Priority (highest wins, #270): BLOCKED > STOPPED > NEEDS ATTENTION > HEALTHY.
//   - BLOCKED is evaluated first and independent of State: a PERSISTENT
//     condition (current-period cap exhausted, or agent-wide policy invalidity)
//     prevents all new work. It outranks STOPPED per the fixed priority.
//   - STOPPED reflects the operator kill switch (State == StateStopped).
//   - NEEDS ATTENTION collects every matching cause in the fixed WHY order:
//     invalid config > budget warning > repeated fallbacks > elevated denial
//     rate > recent failed sessions.
//   - HEALTHY is the absence of all of the above for an enabled agent.
//
// A single request-specific denial (one PII block, one model-allowlist deny)
// must NEVER reach BLOCKED — that is why blocking is driven only by
// SpendPeriod>=Cap and PolicyDenyAll, never by the denial counters.
//
// currency is the ISO-4217 code the spend/cap amounts are denominated in; it is
// only used to render money in cause details, so evaluate() stays deterministic
// on its inputs.
func Evaluate(state State, s Signals, th Thresholds, currency string) (Health, []Cause) {
	if blocked := blockedCauses(s, currency); len(blocked) > 0 {
		return HealthBlocked, blocked
	}
	if state == StateStopped {
		return HealthStopped, []Cause{{Kind: "", Detail: "disabled by operator"}}
	}
	if causes := attentionCauses(s, th, currency); len(causes) > 0 {
		return HealthNeedsAttention, causes
	}
	return HealthHealthy, nil
}

// blockedCauses returns the persistent, agent-wide reasons the agent cannot do
// normal new work. Order: budget exhaustion before policy invalidity.
func blockedCauses(s Signals, currency string) []Cause {
	var causes []Cause
	if b, ok := exhaustedBudget(s.Budgets); ok {
		causes = append(causes, Cause{
			Kind:   CauseBudgetExhausted,
			Detail: fmt.Sprintf("%s budget exhausted (%s / %s)", b.Name, formatMoney(currency, b.Spend), formatMoney(currency, b.Cap)),
		})
	}
	if s.PolicyDenyAll {
		causes = append(causes, Cause{
			Kind:   CausePolicyDenyAll,
			Detail: "agent policy denies all new work",
		})
	}
	return causes
}

// exhaustedBudget returns the first capped period whose spend has reached its
// cap. Order follows the slice, so the projection lists periods worst-first.
func exhaustedBudget(budgets []BudgetPeriod) (BudgetPeriod, bool) {
	for _, b := range budgets {
		if b.Cap > 0 && b.Spend >= b.Cap {
			return b, true
		}
	}
	return BudgetPeriod{}, false
}

// warningBudget returns the most-utilized capped period whose spend has reached
// the warn ratio of its cap, so WHY names the period closest to its limit.
func warningBudget(budgets []BudgetPeriod, ratio float64) (BudgetPeriod, bool) {
	if ratio <= 0 {
		return BudgetPeriod{}, false
	}
	var worst BudgetPeriod
	found := false
	for _, b := range budgets {
		if b.Cap <= 0 || b.Spend < ratio*b.Cap {
			continue
		}
		if !found || b.Spend/b.Cap > worst.Spend/worst.Cap {
			worst, found = b, true
		}
	}
	return worst, found
}

// attentionCauses returns every matched NEEDS-ATTENTION cause in the fixed WHY
// order (#270): invalid config > budget warning > repeated fallbacks >
// elevated denial rate > recent failed sessions.
func attentionCauses(s Signals, th Thresholds, currency string) []Cause {
	var causes []Cause
	if s.ConfigRejected {
		causes = append(causes, Cause{
			Kind:   CauseInvalidConfig,
			Detail: "current config rejected",
		})
	}
	if b, ok := warningBudget(s.Budgets, th.BudgetWarnRatio); ok {
		causes = append(causes, Cause{
			Kind:   CauseBudgetWarning,
			Detail: fmt.Sprintf("%s budget %d%% of cap (%s / %s)", b.Name, int(b.Spend/b.Cap*100), formatMoney(currency, b.Spend), formatMoney(currency, b.Cap)),
		})
	}
	if th.FallbackMin > 0 && s.Fallbacks >= th.FallbackMin {
		causes = append(causes, Cause{
			Kind:   CauseRepeatedFallbacks,
			Detail: fmt.Sprintf("%d fallbacks in %s", s.Fallbacks, humanWindow(th.FallbackWindow)),
		})
	}
	if s.Requests >= th.DenialMinRequests && th.DenialRate > 0 &&
		float64(s.Denied) >= th.DenialRate*float64(s.Requests) {
		causes = append(causes, Cause{
			Kind:   CauseElevatedDenialRate,
			Detail: fmt.Sprintf("%d%% denials in %s (%d/%d)", int(float64(s.Denied)/float64(s.Requests)*100), humanWindow(th.DenialWindow), s.Denied, s.Requests),
		})
	}
	if th.FailedSessionMin > 0 && s.FailedSessions >= th.FailedSessionMin {
		causes = append(causes, Cause{
			Kind:   CauseRecentFailedSessions,
			Detail: fmt.Sprintf("%d failed sessions in %s", s.FailedSessions, humanWindow(th.FailedSessionWindow)),
		})
	}
	return causes
}
