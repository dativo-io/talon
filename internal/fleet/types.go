// Package fleet is the shared read model for the operator attention queue
// (#270): the ONE projection that turns runtime membership + evidence/session
// signals into per-agent STATE/HEALTH/COST/WHY rows. Both the server's
// GET /v1/agents/fleet handler and the `talon agents` CLI call Project — the
// dashboard and the CLI never compute health, budget, or session state
// independently (the #270 parity acceptance criterion).
//
// Two output concepts are kept as DISTINCT types and never conflated:
//   - State  — the CONFIGURED operational state (enabled|stopped), straight
//     from agent.enabled.
//   - Health — the EVALUATED status (healthy|needs-attention|stopped|blocked),
//     derived from State plus runtime signals by the pure evaluate() in
//     health.go.
package fleet

import "time"

// State is an agent's configured operational state (the STATE column). It is
// exactly agent.enabled projected to a label — never derived from runtime
// signals.
type State string

const (
	// StateEnabled means agent.enabled is true (or absent, defaulting true).
	StateEnabled State = "enabled"
	// StateStopped means agent.enabled is false — an operator kill switch.
	StateStopped State = "stopped"
)

// Health is an agent's evaluated status (the HEALTH column). It is derived from
// State plus runtime signals; priority is BLOCKED > STOPPED > NEEDS ATTENTION >
// HEALTHY (#270).
type Health string

const (
	// HealthHealthy — no attention cause matched and the agent is enabled.
	HealthHealthy Health = "healthy"
	// HealthNeedsAttention — at least one explicit attention cause matched.
	HealthNeedsAttention Health = "needs-attention"
	// HealthStopped — the agent is disabled (and not BLOCKED).
	HealthStopped Health = "stopped"
	// HealthBlocked — a PERSISTENT condition prevents all normal new work
	// (period cap exhausted, or agent-wide policy invalidity). A single
	// request-specific denial NEVER produces this (#270).
	HealthBlocked Health = "blocked"
)

// CauseKind is the machine label for one health cause. The set is closed: no
// engineer-invented health models, only the causes enumerated in #270.
type CauseKind string

const (
	// CauseInvalidConfig — the agent's current config was rejected by the last
	// reload/scan; the last-known-good config is still serving (#269). A
	// NEVER-valid file is a FleetIssue by path, not this.
	CauseInvalidConfig CauseKind = "invalid_config"
	// CauseBudgetWarning — period spend >= warn ratio of an effective cap.
	CauseBudgetWarning CauseKind = "budget_warning"
	// CauseRepeatedFallbacks — >= FallbackMin fallback dispatches in the window.
	CauseRepeatedFallbacks CauseKind = "repeated_fallbacks"
	// CauseElevatedDenialRate — denials >= DenialRate of requests, over a floor.
	CauseElevatedDenialRate CauseKind = "elevated_denial_rate"
	// CauseRecentFailedSessions — >= FailedSessionMin failed/timed-out sessions.
	CauseRecentFailedSessions CauseKind = "recent_failed_sessions"

	// CauseBudgetExhausted — BLOCKED: a hard cap is exhausted for the current
	// period.
	CauseBudgetExhausted CauseKind = "budget_exhausted"
	// CausePolicyDenyAll — BLOCKED: agent-wide policy invalidity denies all new
	// work.
	CausePolicyDenyAll CauseKind = "policy_deny_all"
)

// Cause is one matched health signal. Kind is stable for machines/JSON; Detail
// is the human string shown in WHY (e.g. "5 fallbacks in 1h").
type Cause struct {
	Kind   CauseKind `json:"kind"`
	Detail string    `json:"detail"`
}

// Thresholds is the ONE configurable place for every health rule's window,
// trigger, and floor (#270 "defaults configurable, one place"). Windows are
// applied by the query layer (projection.go); evaluate() sees pre-windowed
// counts and only compares against the trigger/floor fields.
type Thresholds struct {
	// BudgetWarnRatio: period spend >= ratio*cap raises a budget warning.
	BudgetWarnRatio float64
	// FallbackWindow / FallbackMin: >= FallbackMin fallback dispatches within
	// FallbackWindow raises repeated-fallbacks.
	FallbackWindow time.Duration
	FallbackMin    int
	// DenialWindow / DenialRate / DenialMinRequests: within DenialWindow, when
	// requests >= DenialMinRequests and denied >= DenialRate*requests, raise
	// elevated-denial-rate.
	DenialWindow      time.Duration
	DenialRate        float64
	DenialMinRequests int
	// FailedSessionWindow / FailedSessionMin: >= FailedSessionMin failed or
	// timed-out asserted sessions within the window raises recent-failed-
	// sessions.
	FailedSessionWindow time.Duration
	FailedSessionMin    int
}

// DefaultThresholds returns the #270 defaults. This is the single source of the
// numbers; callers override individual fields, never re-derive them.
func DefaultThresholds() Thresholds {
	return Thresholds{
		BudgetWarnRatio:     0.80,
		FallbackWindow:      time.Hour,
		FallbackMin:         3,
		DenialWindow:        time.Hour,
		DenialRate:          0.20,
		DenialMinRequests:   10,
		FailedSessionWindow: 24 * time.Hour,
		FailedSessionMin:    1,
	}
}

// BudgetPeriod is one spend-vs-cap window for an agent (e.g. daily, monthly).
// A zero Cap means uncapped — budget rules never fire against it. #270 evaluates
// budget against "an effective cap" over "the current budget period"; because an
// agent can have both a daily (#283) and a monthly cap, evaluate() checks every
// period and reports against the most-utilized one.
type BudgetPeriod struct {
	Name  string
	Spend float64
	Cap   float64
}

// Signals carries the pre-windowed runtime counters for ONE agent that
// evaluate() consumes. projection.go fills this from the store/session queries
// using the windows in Thresholds; evaluate() itself does no time math and no
// I/O, so it is exhaustively table-testable.
type Signals struct {
	// Requests / Denied — request-class rows within DenialWindow.
	Requests int
	Denied   int
	// Fallbacks — fallback dispatches within FallbackWindow.
	Fallbacks int
	// FailedSessions — failed/timed-out asserted sessions within
	// FailedSessionWindow.
	FailedSessions int
	// Budgets — every spend-vs-cap period for the agent (daily, monthly).
	// evaluate() blocks if any is exhausted and warns on the most-utilized one.
	Budgets []BudgetPeriod
	// ConfigRejected — the agent's current config was rejected by the last
	// reload/scan and last-known-good is serving (#269): needs-attention, not
	// blocked, because the agent still serves.
	ConfigRejected bool
	// PolicyDenyAll — the agent's ACTIVE policy denies all new work agent-wide:
	// BLOCKED. This is persistent, never a single request-specific denial.
	PolicyDenyAll bool
	// Enforcing is true when the runtime actually blocks on policy/budget: the
	// gateway is in enforce mode, or native execution (which always enforces).
	// In shadow/log_only the gateway OBSERVES violations but forwards traffic,
	// so budget exhaustion and agent-wide policy invalidity do NOT prevent new
	// work and must not render BLOCKED (#270 review round 2). The STOPPED kill
	// switch and the attention causes are unaffected — they hold in every mode.
	Enforcing bool
}

// AgentStatus is the per-agent identity + config-validity + effective-cap input
// to Project. It is assembled the SAME way from two sources so the projection
// is source-agnostic (#270 "same code path"):
//   - server: RuntimeSnapshot membership + Reloader state + effective policy;
//   - CLI offline: a local agents_dir scan + effective policy.
//
// Only VALID or last-known-good identities become an AgentStatus. A never-valid
// file is a FleetIssue by path (handled outside Project), never an AgentStatus.
type AgentStatus struct {
	Name         string
	TenantID     string
	Enabled      bool
	ConfigPath   string
	PolicyDigest string
	// ConfigRejected — the current on-disk config for this agent was rejected by
	// the last reload/scan; the last-known-good is still serving (#269).
	ConfigRejected bool
	ConfigError    string
	// PolicyDenyAll — the ACTIVE policy denies all new work agent-wide (BLOCKED).
	PolicyDenyAll bool
	// DailyCap / MonthlyCap — effective binding caps (0 = uncapped), from
	// EffectivePolicy.BindingDailyCap()/BindingMonthlyCap().
	DailyCap   float64
	MonthlyCap float64
	// Currency the caps and evidence spend are denominated in (ISO-4217).
	Currency string
}

// AgentRow is one projected attention-queue row: the STATE/HEALTH/COST/WHY the
// CLI and dashboard both render. STATE and HEALTH are DISTINCT types (#270): a
// configured State and an evaluated Health — never conflated.
type AgentRow struct {
	Name     string  `json:"name"`
	TenantID string  `json:"tenant_id"`
	State    State   `json:"state"`
	Health   Health  `json:"health"`
	Why      string  `json:"why"`
	Causes   []Cause `json:"causes,omitempty"`
	// COST column inputs: month-to-date spend and its cap (the plan's COST =
	// month-to-date). Daily spend/cap are carried for `show` and daily blocking.
	SpendMonth float64 `json:"spend_month"`
	MonthlyCap float64 `json:"monthly_cap"`
	SpendDay   float64 `json:"spend_day"`
	DailyCap   float64 `json:"daily_cap"`
	Currency   string  `json:"currency"`
	// Window counters behind the health signals (surfaced in `show` / --json).
	Requests       int       `json:"requests"`
	Denied         int       `json:"denied"`
	Fallbacks      int       `json:"fallbacks"`
	FailedSessions int       `json:"failed_sessions"`
	LastRun        time.Time `json:"last_run,omitempty"`
	ConfigPath     string    `json:"config_path"`
	PolicyDigest   string    `json:"policy_digest"`
	ConfigError    string    `json:"config_error,omitempty"`
}

// CostString renders the COST column: month-to-date spend, and "/ cap" when a
// monthly cap is set (0 = uncapped, shown as spend alone).
func (r AgentRow) CostString() string {
	if r.MonthlyCap > 0 {
		return formatMoney(r.Currency, r.SpendMonth) + " / " + formatMoney(r.Currency, r.MonthlyCap)
	}
	return formatMoney(r.Currency, r.SpendMonth)
}
