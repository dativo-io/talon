package fleet

import (
	"testing"
)

// th is the #270 default threshold set used across the boundary tests.
func th() Thresholds { return DefaultThresholds() }

// monthly is a one-period Budgets slice for the common single-cap test cases.
func monthly(spend, cap float64) []BudgetPeriod {
	return []BudgetPeriod{{Name: "monthly", Spend: spend, Cap: cap}}
}

// TestEvaluate_Boundaries pins every NEEDS-ATTENTION cause at its exact
// threshold and one epsilon below it, so a defaults change can never silently
// shift a trigger (#270: "defaults configurable, one place").
func TestEvaluate_Boundaries(t *testing.T) {
	tests := []struct {
		name       string
		state      State
		sig        Signals
		wantHealth Health
		wantFirst  CauseKind // "" when no cause expected
		wantCauses int
	}{
		// budget warning: >= 80% of cap.
		{"budget just below warn (79.9%)", StateEnabled, Signals{Budgets: monthly(799, 1000)}, HealthHealthy, "", 0},
		{"budget exactly at warn (80%)", StateEnabled, Signals{Budgets: monthly(800, 1000)}, HealthNeedsAttention, CauseBudgetWarning, 1},
		{"budget uncapped never warns", StateEnabled, Signals{Budgets: monthly(9999, 0)}, HealthHealthy, "", 0},

		// repeated fallbacks: >= 3 in window.
		{"fallbacks below min (2)", StateEnabled, Signals{Fallbacks: 2}, HealthHealthy, "", 0},
		{"fallbacks at min (3)", StateEnabled, Signals{Fallbacks: 3}, HealthNeedsAttention, CauseRepeatedFallbacks, 1},

		// elevated denial rate: denials >= 20% AND requests >= 10.
		{"denial rate high but below min requests (9 req)", StateEnabled, Signals{Requests: 9, Denied: 9}, HealthHealthy, "", 0},
		{"denial rate at floor requests but below rate (25% of 8=2)", StateEnabled, Signals{Requests: 10, Denied: 1}, HealthHealthy, "", 0},
		{"denial rate exactly 20% at 10 requests", StateEnabled, Signals{Requests: 10, Denied: 2}, HealthNeedsAttention, CauseElevatedDenialRate, 1},

		// recent failed sessions: >= 1 in 24h.
		{"no failed sessions", StateEnabled, Signals{FailedSessions: 0}, HealthHealthy, "", 0},
		{"one failed session", StateEnabled, Signals{FailedSessions: 1}, HealthNeedsAttention, CauseRecentFailedSessions, 1},

		// invalid config (LKG serving) -> needs attention, first in WHY order.
		{"current config rejected", StateEnabled, Signals{ConfigRejected: true}, HealthNeedsAttention, CauseInvalidConfig, 1},

		// STOPPED: disabled and nothing blocking.
		{"disabled agent is stopped", StateStopped, Signals{}, HealthStopped, "", 1},
		{"disabled agent with attention signal still stopped", StateStopped, Signals{Fallbacks: 9}, HealthStopped, "", 1},

		// BLOCKED (enforce mode): persistent conditions, outrank even STOPPED.
		{"cap exhausted is blocked", StateEnabled, Signals{Enforcing: true, Budgets: monthly(1000, 1000)}, HealthBlocked, CauseBudgetExhausted, 1},
		{"cap over-exhausted is blocked", StateEnabled, Signals{Enforcing: true, Budgets: monthly(1500, 1000)}, HealthBlocked, CauseBudgetExhausted, 1},
		{"policy deny-all is blocked", StateEnabled, Signals{Enforcing: true, PolicyDenyAll: true}, HealthBlocked, CausePolicyDenyAll, 1},
		{"blocked outranks stopped", StateStopped, Signals{Enforcing: true, Budgets: monthly(100, 100)}, HealthBlocked, CauseBudgetExhausted, 1},
		// daily cap exhausted blocks even when monthly is fine (#283).
		{"daily cap exhausted blocks", StateEnabled, Signals{Enforcing: true, Budgets: []BudgetPeriod{{Name: "daily", Spend: 50, Cap: 50}, {Name: "monthly", Spend: 50, Cap: 1000}}}, HealthBlocked, CauseBudgetExhausted, 1},

		// SHADOW / log_only (Enforcing:false): budget/policy conditions are
		// observed but do not prevent work, so they never render BLOCKED (#270
		// review round 2). Exhausted budget surfaces as a budget WARNING instead.
		{"exhausted cap in shadow is not blocked", StateEnabled, Signals{Enforcing: false, Budgets: monthly(1000, 1000)}, HealthNeedsAttention, CauseBudgetWarning, 1},
		{"policy deny-all in shadow is not blocked", StateEnabled, Signals{Enforcing: false, PolicyDenyAll: true}, HealthHealthy, "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotHealth, gotCauses := Evaluate(tc.state, tc.sig, th(), "EUR")
			if gotHealth != tc.wantHealth {
				t.Fatalf("health = %q, want %q", gotHealth, tc.wantHealth)
			}
			if len(gotCauses) != tc.wantCauses {
				t.Fatalf("causes = %d %+v, want %d", len(gotCauses), gotCauses, tc.wantCauses)
			}
			if tc.wantFirst != "" {
				if len(gotCauses) == 0 || gotCauses[0].Kind != tc.wantFirst {
					t.Fatalf("first cause = %+v, want kind %q", gotCauses, tc.wantFirst)
				}
			}
		})
	}
}

// TestEvaluate_WhyOrder asserts that when several NEEDS-ATTENTION causes match,
// they appear in the exact fixed order and WhyString names the first with a
// "+N more" suffix (#270).
func TestEvaluate_WhyOrder(t *testing.T) {
	// All five attention causes fire at once.
	all := Signals{
		ConfigRejected: true,
		Budgets:        monthly(900, 1000), // 90% -> budget warning (not exhausted)
		Fallbacks:      5,
		Requests:       10, Denied: 5, // 50% denial
		FailedSessions: 2,
	}
	health, causes := Evaluate(StateEnabled, all, th(), "EUR")
	if health != HealthNeedsAttention {
		t.Fatalf("health = %q, want needs-attention", health)
	}
	wantOrder := []CauseKind{
		CauseInvalidConfig,
		CauseBudgetWarning,
		CauseRepeatedFallbacks,
		CauseElevatedDenialRate,
		CauseRecentFailedSessions,
	}
	if len(causes) != len(wantOrder) {
		t.Fatalf("got %d causes %+v, want %d", len(causes), causes, len(wantOrder))
	}
	for i, want := range wantOrder {
		if causes[i].Kind != want {
			t.Fatalf("cause[%d] = %q, want %q (order violated)", i, causes[i].Kind, want)
		}
	}
	// WhyString names the first cause and counts the rest.
	why := WhyString(causes)
	if wantPrefix := "current config rejected"; why[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("WhyString = %q, want it to start with %q", why, wantPrefix)
	}
	if want := "(+4 more)"; !contains(why, want) {
		t.Fatalf("WhyString = %q, want %q suffix", why, want)
	}
}

// TestEvaluate_Recovery asserts a cause clears the instant its window no longer
// matches — the projection recomputes from live windows every call, so a
// dropped signal drops the cause (#270 recovery rules).
func TestEvaluate_Recovery(t *testing.T) {
	warm := Signals{Fallbacks: 3}
	if h, _ := Evaluate(StateEnabled, warm, th(), "EUR"); h != HealthNeedsAttention {
		t.Fatalf("warm health = %q, want needs-attention", h)
	}
	// One fewer fallback in the window: recovered.
	cool := Signals{Fallbacks: 2}
	if h, c := Evaluate(StateEnabled, cool, th(), "EUR"); h != HealthHealthy || len(c) != 0 {
		t.Fatalf("cool health = %q causes %+v, want healthy/none", h, c)
	}
}

// TestWhyString_Healthy renders an em dash when nothing matched.
func TestWhyString_Healthy(t *testing.T) {
	if got := WhyString(nil); got != "—" {
		t.Fatalf("WhyString(nil) = %q, want em dash", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
