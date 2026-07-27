package evidence

import (
	"sort"
	"strings"
	"time"
)

// SessionSummary is a rollup over all evidence records sharing a session_id:
// session-level totals plus a per-subagent breakdown. It is pure aggregation
// over already-signed records — no database access, no new tables (#197). The
// same function backs `talon audit --session` / `talon costs --session` and the
// dashboard sessions panel (#199) so the CLI and the dashboard can never drift.
//
// Scoping is the caller's responsibility: pass only the records a reader is
// entitled to see (filter by tenant/agent before calling). Agents lists the
// distinct top-level agent_id values observed so a cross-agent
// session_id collision is visible rather than silently merged.
type SessionSummary struct {
	SessionID     string   `json:"session_id"`
	TenantID      string   `json:"tenant_id"`
	SessionSource string   `json:"session_source,omitempty"` // orchestration session_source (client_asserted|vendor_asserted|synthetic), first seen
	Client        string   `json:"client,omitempty"`         // orchestration client adapter (claude-code|codex|generic), first seen
	AgentIDs      []string `json:"agents,omitempty"`
	Providers     []string `json:"providers,omitempty"`
	Models        []string `json:"models,omitempty"`
	RecordCount   int      `json:"record_count"`
	Allowed       int      `json:"allowed"`
	Denied        int      `json:"denied"`
	Errors        int      `json:"errors"`
	TotalCost     float64  `json:"total_cost"`
	// Currency is the ISO-4217 unit of TotalCost, taken from the records'
	// stamped currency (#216); empty when no record carries one (pre-field
	// records — render as USD, the unit the shipped tables always used).
	Currency         string               `json:"currency,omitempty"`
	InputTokens      int                  `json:"input_tokens"`
	OutputTokens     int                  `json:"output_tokens"`
	CacheReadTokens  int                  `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens int                  `json:"cache_write_tokens,omitempty"`
	FirstSeen        time.Time            `json:"first_seen"`
	LastSeen         time.Time            `json:"last_seen"`
	Subagents        []SessionAgentRollup `json:"subagents,omitempty"`

	// Operational contract (#271). Everything below is derived from the same
	// records as the totals above, so the CLI and dashboard cannot disagree.

	// Requests counts request-class records that are LLM traffic units —
	// provider sub-attempts (RecordClassOf) and intercepted tool actions
	// (IsToolActionType) are split out. RecordCount keeps counting everything.
	Requests int `json:"requests"`
	// DurationMS is the observed traffic window (LastSeen − FirstSeen); zero
	// for a single-record session.
	DurationMS int64 `json:"duration_ms,omitempty"`

	// Reliability facts. Retries counts records echoing a caller-asserted
	// X-Talon-Retry-Attempt; the failover counts mirror the fleet definitions
	// (FallbackCountsByAgent counts fallback_decision dispatches only).
	Retries        int `json:"retries,omitempty"`
	FailedAttempts int `json:"failed_attempts,omitempty"`
	Fallbacks      int `json:"fallbacks,omitempty"`
	FailClosed     int `json:"fail_closed,omitempty"`

	// DeniedByReason buckets denials by machine reason code (DenyReasonCode),
	// so budget denials are distinguishable from PII or egress blocks.
	DeniedByReason map[string]int `json:"denied_by_reason,omitempty"`

	// ProviderPath lists "provider/model" in order of first serving — the path
	// that actually served the session, fallbacks included.
	ProviderPath []string `json:"provider_path,omitempty"`

	// Tool actions visible to Talon: intercepted MCP calls with their
	// decisions. Local actions that bypass Talon are invisible and are not
	// represented here — this is not a complete account of agent activity.
	ToolCalls       int      `json:"tool_calls,omitempty"`
	ToolCallsDenied int      `json:"tool_calls_denied,omitempty"`
	ToolCallsFailed int      `json:"tool_calls_failed,omitempty"`
	ToolNames       []string `json:"tool_names,omitempty"`

	// Policy interventions on LLM requests.
	ToolsFiltered    []string `json:"tools_filtered,omitempty"`
	ToolFilterEvents int      `json:"tool_filter_events,omitempty"`
	PIIRedactions    int      `json:"pii_redactions,omitempty"`
	PIITypes         []string `json:"pii_types,omitempty"`
	ShadowViolations int      `json:"shadow_violation_records,omitempty"`

	// LastFailure is the newest deny or execution failure in the session — the
	// one-line explanation for "why did this fail".
	LastFailure *SessionFailure `json:"last_failure,omitempty"`
}

// SessionFailure is the newest failure observed in a session: a machine code
// (structured failure_reason, deny reason code, or "error") plus a short
// human-readable detail sourced from the record.
type SessionFailure struct {
	At     time.Time `json:"at"`
	Code   string    `json:"code"`
	Detail string    `json:"detail,omitempty"`
}

// SessionAgentRollup is the per-subagent slice of a session. AgentID is the
// client-asserted orchestration agent_id when present, otherwise the top-level
// caller agent_id (so non-orchestrated traffic still rolls up to a single row).
type SessionAgentRollup struct {
	AgentID          string  `json:"agent_id"`
	ParentAgentID    string  `json:"parent_agent_id,omitempty"`
	RecordCount      int     `json:"record_count"`
	TotalCost        float64 `json:"total_cost"`
	InputTokens      int     `json:"input_tokens"`
	OutputTokens     int     `json:"output_tokens"`
	CacheReadTokens  int     `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens int     `json:"cache_write_tokens,omitempty"`
}

// BuildSessionSummary aggregates records (all sharing sessionID) into a
// SessionSummary. Input order does not matter; output ordering is deterministic
// (agents by descending cost then id, string sets sorted). Nil records are
// skipped.
func BuildSessionSummary(sessionID string, records []*Evidence) SessionSummary {
	agg := newSessionAgg(sessionID)
	for _, ev := range records {
		if ev != nil {
			agg.add(ev)
		}
	}
	return agg.finish()
}

// sessionAgg accumulates records into a SessionSummary. Splitting the per-record
// work across small methods keeps each below the cyclomatic-complexity budget.
type sessionAgg struct {
	sum       SessionSummary
	agentIDs  map[string]struct{}
	providers map[string]struct{}
	models    map[string]struct{}
	subagents map[string]*SessionAgentRollup
	// orchAt is the timestamp of the record whose orchestration block
	// currently supplies SessionSource/Client (earliest wins).
	orchAt time.Time
	// pathHops collects (timestamp, provider/model) pairs for records that
	// actually served; ordered into ProviderPath in finish() because input
	// order is not guaranteed.
	pathHops  []pathHop
	toolNames map[string]struct{}
	filtered  map[string]struct{}
	piiTypes  map[string]struct{}
}

type pathHop struct {
	at    time.Time
	label string
}

func newSessionAgg(sessionID string) *sessionAgg {
	return &sessionAgg{
		sum:       SessionSummary{SessionID: sessionID},
		agentIDs:  map[string]struct{}{},
		providers: map[string]struct{}{},
		models:    map[string]struct{}{},
		subagents: map[string]*SessionAgentRollup{},
		toolNames: map[string]struct{}{},
		filtered:  map[string]struct{}{},
		piiTypes:  map[string]struct{}{},
	}
}

func (a *sessionAgg) add(ev *Evidence) {
	a.sum.RecordCount++
	a.addMetadata(ev)
	a.addOutcome(ev)
	a.addTotals(ev)
	a.addWindow(ev.Timestamp)
	a.addClassCounts(ev)
	a.addReliability(ev)
	a.addToolAction(ev)
	a.addInterventions(ev)
	a.addPathHop(ev)
	a.addFailure(ev)
	accumulateAgent(a.subagents, ev)
}

func (a *sessionAgg) addMetadata(ev *Evidence) {
	if a.sum.TenantID == "" {
		a.sum.TenantID = ev.TenantID
	}
	if ev.AgentID != "" {
		a.agentIDs[ev.AgentID] = struct{}{}
	}
	if ev.Execution.ModelUsed != "" {
		a.models[ev.Execution.ModelUsed] = struct{}{}
	}
	if ev.RoutingDecision != nil && ev.RoutingDecision.SelectedProvider != "" {
		a.providers[ev.RoutingDecision.SelectedProvider] = struct{}{}
	}
	if ev.Orchestration != nil {
		// Session source/client come from the EARLIEST orchestrated record —
		// the client that opened the session — independent of input order
		// (ListBySessionID returns newest-first; taking the first iterated
		// record labeled a mostly-claude-code session "codex").
		if a.orchAt.IsZero() || ev.Timestamp.Before(a.orchAt) {
			a.orchAt = ev.Timestamp
			a.sum.SessionSource = ev.Orchestration.SessionSource
			a.sum.Client = ev.Orchestration.Client
		}
	}
}

func (a *sessionAgg) addOutcome(ev *Evidence) {
	if ev.PolicyDecision.Allowed {
		a.sum.Allowed++
	} else {
		a.sum.Denied++
	}
	if ev.Execution.Error != "" {
		a.sum.Errors++
	}
}

func (a *sessionAgg) addTotals(ev *Evidence) {
	if a.sum.Currency == "" && ev.Execution.Currency != "" {
		a.sum.Currency = ev.Execution.Currency
	}
	a.sum.TotalCost += ev.Execution.Cost
	a.sum.InputTokens += ev.Execution.Tokens.Input
	a.sum.OutputTokens += ev.Execution.Tokens.Output
	a.sum.CacheReadTokens += ev.Execution.Tokens.CacheRead
	a.sum.CacheWriteTokens += ev.Execution.Tokens.CacheWrite
}

func (a *sessionAgg) addWindow(t time.Time) {
	if a.sum.FirstSeen.IsZero() || t.Before(a.sum.FirstSeen) {
		a.sum.FirstSeen = t
	}
	if t.After(a.sum.LastSeen) {
		a.sum.LastSeen = t
	}
}

// addClassCounts splits the record stream into LLM requests vs everything
// else: Requests counts only request-class records that are not intercepted
// tool actions.
func (a *sessionAgg) addClassCounts(ev *Evidence) {
	if IsRequestClass(ev.InvocationType) && !IsToolActionType(ev.InvocationType) {
		a.sum.Requests++
	}
	if !ev.PolicyDecision.Allowed {
		if a.sum.DeniedByReason == nil {
			a.sum.DeniedByReason = map[string]int{}
		}
		a.sum.DeniedByReason[DenyReasonCode(ev.PolicyDecision.Reasons)]++
	}
}

func (a *sessionAgg) addReliability(ev *Evidence) {
	if ev.RetryAttempt != "" {
		a.sum.Retries++
	}
	if ev.Failover == nil {
		return
	}
	switch ev.Failover.Role {
	case FailoverRoleFailedAttempt:
		a.sum.FailedAttempts++
	case FailoverRoleFallbackDecision:
		a.sum.Fallbacks++
	case FailoverRoleFailClosed:
		a.sum.FailClosed++
	}
}

// addToolAction rolls up intercepted MCP calls: total, denied, failed
// upstream, and the distinct tool names Talon saw.
func (a *sessionAgg) addToolAction(ev *Evidence) {
	if !IsToolActionType(ev.InvocationType) {
		return
	}
	a.sum.ToolCalls++
	if !ev.PolicyDecision.Allowed {
		a.sum.ToolCallsDenied++
	} else if ev.Execution.Error != "" {
		a.sum.ToolCallsFailed++
	}
	for _, name := range ev.Execution.ToolsCalled {
		if name != "" {
			a.toolNames[name] = struct{}{}
		}
	}
}

func (a *sessionAgg) addInterventions(ev *Evidence) {
	if ev.ToolGovernance != nil {
		if len(ev.ToolGovernance.ToolsFiltered) > 0 {
			a.sum.ToolFilterEvents++
		}
		for _, name := range ev.ToolGovernance.ToolsFiltered {
			a.filtered[name] = struct{}{}
		}
	}
	if ev.Classification.PIIRedacted || ev.Classification.InputPIIRedacted {
		a.sum.PIIRedactions++
	}
	for _, t := range ev.Classification.PIIDetected {
		a.piiTypes[t] = struct{}{}
	}
	for _, t := range ev.Classification.OutputPIITypes {
		a.piiTypes[t] = struct{}{}
	}
	if len(ev.ShadowViolations) > 0 {
		a.sum.ShadowViolations++
	}
}

// addPathHop records what actually served the session: terminal request-class
// records that completed with a model. Failed failover attempts also name a
// model but did not serve — they are counted in FailedAttempts, not the path.
// The provider comes from the routing decision when present, from the
// failover context on fallback dispatches recorded without one.
func (a *sessionAgg) addPathHop(ev *Evidence) {
	if ev.Execution.ModelUsed == "" || ev.Execution.Error != "" {
		return
	}
	if !IsRequestClass(ev.InvocationType) || IsToolActionType(ev.InvocationType) {
		return
	}
	provider := ""
	if ev.RoutingDecision != nil {
		provider = ev.RoutingDecision.SelectedProvider
	}
	if provider == "" && ev.Failover != nil && ev.Failover.Role == FailoverRoleFallbackDecision {
		provider = ev.Failover.Provider
	}
	label := ev.Execution.ModelUsed
	if provider != "" {
		label = provider + "/" + label
	}
	a.pathHops = append(a.pathHops, pathHop{at: ev.Timestamp, label: label})
}

// addFailure keeps the NEWEST deny or execution failure as the session's
// one-line failure explanation.
func (a *sessionAgg) addFailure(ev *Evidence) {
	f := failureOf(ev)
	if f == nil {
		return
	}
	if a.sum.LastFailure == nil || f.At.After(a.sum.LastFailure.At) {
		a.sum.LastFailure = f
	}
}

// maxFailureDetail bounds the human detail line; evidence reasons can embed
// long policy output.
const maxFailureDetail = 200

func failureOf(ev *Evidence) *SessionFailure {
	switch {
	case !ev.PolicyDecision.Allowed:
		detail := ""
		if len(ev.PolicyDecision.Reasons) > 0 {
			detail = ev.PolicyDecision.Reasons[0]
		}
		return &SessionFailure{At: ev.Timestamp, Code: DenyReasonCode(ev.PolicyDecision.Reasons), Detail: truncateDetail(detail)}
	case ev.Execution.Error != "":
		code := ev.FailureReason
		if code == "" {
			code = "error"
		}
		return &SessionFailure{At: ev.Timestamp, Code: code, Detail: truncateDetail(ev.Execution.Error)}
	default:
		return nil
	}
}

func truncateDetail(s string) string {
	if len(s) <= maxFailureDetail {
		return s
	}
	return s[:maxFailureDetail] + "…"
}

func (a *sessionAgg) finish() SessionSummary {
	a.sum.AgentIDs = sortedKeys(a.agentIDs)
	a.sum.Providers = sortedKeys(a.providers)
	a.sum.Models = sortedKeys(a.models)
	a.sum.Subagents = sortedAgents(a.subagents)
	a.sum.ToolNames = sortedKeys(a.toolNames)
	a.sum.ToolsFiltered = sortedKeys(a.filtered)
	a.sum.PIITypes = sortedKeys(a.piiTypes)
	a.sum.ProviderPath = orderedPath(a.pathHops)
	if !a.sum.FirstSeen.IsZero() {
		a.sum.DurationMS = a.sum.LastSeen.Sub(a.sum.FirstSeen).Milliseconds()
	}
	return a.sum
}

// orderedPath sorts hops by time and keeps the first occurrence of each label,
// so a fallback session reads "anthropic/x → openai/y" regardless of input
// order.
func orderedPath(hops []pathHop) []string {
	if len(hops) == 0 {
		return nil
	}
	sort.SliceStable(hops, func(i, j int) bool { return hops[i].at.Before(hops[j].at) })
	seen := map[string]struct{}{}
	out := make([]string, 0, len(hops))
	for _, h := range hops {
		if _, ok := seen[h.label]; ok {
			continue
		}
		seen[h.label] = struct{}{}
		out = append(out, h.label)
	}
	return out
}

// DenyReasonCode classifies a deny by the machine-code prefix convention
// ("session_budget_exceeded: ...", "budget_exceeded: ...", bare egress codes)
// so denials bucket by cause instead of lumping under a generic policy_deny
// (#199). Unrecognized shapes fall back to "policy_deny". Shared by the
// session summary and the dashboard metrics projection — one classifier.
func DenyReasonCode(reasons []string) string {
	if len(reasons) == 0 {
		return "policy_deny"
	}
	code := reasons[0]
	if i := strings.IndexByte(code, ':'); i >= 0 {
		code = code[:i]
	}
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 64 {
		return "policy_deny"
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return "policy_deny"
		}
	}
	return code
}

// accumulateAgent adds ev into the per-subagent rollup keyed by the
// client-asserted orchestration agent_id, falling back to the caller agent_id.
func accumulateAgent(agents map[string]*SessionAgentRollup, ev *Evidence) {
	key := ev.AgentID
	parent := ""
	if ev.Orchestration != nil && ev.Orchestration.AgentID != "" {
		key = ev.Orchestration.AgentID
		parent = ev.Orchestration.ParentAgentID
	}
	r := agents[key]
	if r == nil {
		r = &SessionAgentRollup{AgentID: key, ParentAgentID: parent}
		agents[key] = r
	}
	r.RecordCount++
	r.TotalCost += ev.Execution.Cost
	r.InputTokens += ev.Execution.Tokens.Input
	r.OutputTokens += ev.Execution.Tokens.Output
	r.CacheReadTokens += ev.Execution.Tokens.CacheRead
	r.CacheWriteTokens += ev.Execution.Tokens.CacheWrite
}

func sortedAgents(agents map[string]*SessionAgentRollup) []SessionAgentRollup {
	if len(agents) == 0 {
		return nil
	}
	out := make([]SessionAgentRollup, 0, len(agents))
	for _, r := range agents {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalCost != out[j].TotalCost {
			return out[i].TotalCost > out[j].TotalCost
		}
		return out[i].AgentID < out[j].AgentID
	})
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
