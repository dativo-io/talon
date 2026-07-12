package evidence

import (
	"sort"
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
}

func newSessionAgg(sessionID string) *sessionAgg {
	return &sessionAgg{
		sum:       SessionSummary{SessionID: sessionID},
		agentIDs:  map[string]struct{}{},
		providers: map[string]struct{}{},
		models:    map[string]struct{}{},
		subagents: map[string]*SessionAgentRollup{},
	}
}

func (a *sessionAgg) add(ev *Evidence) {
	a.sum.RecordCount++
	a.addMetadata(ev)
	a.addOutcome(ev)
	a.addTotals(ev)
	a.addWindow(ev.Timestamp)
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

func (a *sessionAgg) finish() SessionSummary {
	a.sum.AgentIDs = sortedKeys(a.agentIDs)
	a.sum.Providers = sortedKeys(a.providers)
	a.sum.Models = sortedKeys(a.models)
	a.sum.Subagents = sortedAgents(a.subagents)
	return a.sum
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
