package evidence

import (
	"sort"
	"strings"
)

// RecordClass buckets an evidence record by its invocation_type so traffic and
// health queries have ONE source of truth for "what counts as a request"
// (#270). Before this, invocation_type was a free-form string and every query
// that wanted to exclude lifecycle/config rows would have to hand-roll its own
// NOT IN list; that drifts. New lifecycle/config/tool invocation types register
// in nonRequestClass below and every request-class query picks up the exclusion
// automatically.
type RecordClass string

const (
	// ClassRequest is a top-level request that produced a policy decision and
	// (usually) a model completion — the actual traffic unit. This is the
	// default: an unknown or empty invocation_type is treated as a request so a
	// forgotten registration over-counts visibly rather than silently dropping
	// real traffic.
	ClassRequest RecordClass = "request"
	// ClassProviderAttempt is a per-provider sub-record of one request (failover
	// attempts, token counts). Counting these as requests would multiply a
	// single user request into several — excluded from traffic.
	ClassProviderAttempt RecordClass = "provider_attempt"
	// ClassOperatorEvent is an operator/control action (enable/disable, mode
	// change, plan review/dispatch, control-plane ops) — not agent traffic.
	ClassOperatorEvent RecordClass = "operator_event"
	// ClassConfigEvent is a configuration lifecycle record (reload activation /
	// rejection) — not agent traffic.
	ClassConfigEvent RecordClass = "config_event"
	// ClassToolEvent is a tool/cache maintenance record (cache eviction /
	// erasure) — not agent traffic.
	ClassToolEvent RecordClass = "tool_event"
)

// nonRequestClass is the closed registry of invocation types that are NOT
// request-class. Everything absent here classifies as ClassRequest. Keep this
// aligned with the invocation_type literals written across the codebase
// (gateway/agent failover, cmd lifecycle, agentcatalog reload, cache events).
var nonRequestClass = map[string]RecordClass{
	// Provider sub-attempts of a single request.
	"gateway_failover_attempt": ClassProviderAttempt,
	"llm_failover_attempt":     ClassProviderAttempt,
	"llm_failover_decision":    ClassProviderAttempt,
	"gateway_count_tokens":     ClassProviderAttempt,

	// Per-request would-deny sub-record of one proxied MCP call (#346): a
	// shadow/passthrough violation is always followed by the call's terminal
	// record (proxy_tool_call or a block), so counting it as a request would
	// multiply one call into several.
	"proxy_shadow_violation": ClassProviderAttempt,

	// Operator / control-plane actions.
	"agent_enabled":        ClassOperatorEvent,
	"agent_disabled":       ClassOperatorEvent,
	"mode_change":          ClassOperatorEvent,
	"plan_review":          ClassOperatorEvent,
	"plan_dispatch":        ClassOperatorEvent,
	"plan_dispatch_manual": ClassOperatorEvent,
	"control_plane":        ClassOperatorEvent,

	// Configuration lifecycle.
	"config_reload": ClassConfigEvent,

	// Tool / cache maintenance.
	CacheEventEviction:      ClassToolEvent,
	CacheEventErasureTenant: ClassToolEvent,
	CacheEventErasureUser:   ClassToolEvent,
}

// RecordClassOf returns the class of an invocation type. Unknown/empty →
// ClassRequest by design (see ClassRequest).
func RecordClassOf(invocationType string) RecordClass {
	if c, ok := nonRequestClass[invocationType]; ok {
		return c
	}
	return ClassRequest
}

// IsRequestClass reports whether an invocation type counts as request traffic.
func IsRequestClass(invocationType string) bool {
	return RecordClassOf(invocationType) == ClassRequest
}

// nonRequestTypesSorted returns the non-request invocation types in a stable
// order so the generated SQL predicate is deterministic (testable, cache-
// friendly).
func nonRequestTypesSorted() []string {
	out := make([]string, 0, len(nonRequestClass))
	for k := range nonRequestClass {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RequestClassSQLPredicate returns a SQL boolean expression over the given
// invocation_type column that selects request-class rows. It is generated from
// nonRequestClass, so request-class queries never hand-roll a NOT IN list — the
// registry above is the single point of change (#270). A NULL invocation_type
// is treated as request-class (SQL NOT IN is NULL-unfriendly, so it is guarded
// explicitly). The values are internal constants, never user input, so inlining
// them is safe.
func RequestClassSQLPredicate(column string) string {
	types := nonRequestTypesSorted()
	quoted := make([]string, len(types))
	for i, t := range types {
		quoted[i] = "'" + strings.ReplaceAll(t, "'", "''") + "'"
	}
	return "(" + column + " IS NULL OR " + column + " NOT IN (" + strings.Join(quoted, ", ") + "))"
}
