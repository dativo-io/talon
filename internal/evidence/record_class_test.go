package evidence

import (
	"strings"
	"testing"
)

// TestRecordClassOf pins every invocation-type literal written across the
// codebase to its class. If a new lifecycle/config/tool invocation type is
// added without registering it here, this test (and the request-class queries)
// will treat it as request traffic — a visible over-count, the intended
// fail-direction (#270).
func TestRecordClassOf(t *testing.T) {
	cases := map[string]RecordClass{
		// Request-class (top-level traffic) — default, incl. empty/unknown.
		"":              ClassRequest,
		"gateway":       ClassRequest,
		"api":           ClassRequest,
		"http":          ClassRequest,
		"mcp":           ClassRequest,
		"manual":        ClassRequest,
		"graph_run":     ClassRequest,
		"totally_new_x": ClassRequest,

		// Provider sub-attempts of one request.
		"gateway_failover_attempt": ClassProviderAttempt,
		"llm_failover_attempt":     ClassProviderAttempt,
		"llm_failover_decision":    ClassProviderAttempt,
		"gateway_count_tokens":     ClassProviderAttempt,

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

		// Tool / cache maintenance (referenced by their exported consts).
		CacheEventEviction:      ClassToolEvent,
		CacheEventErasureTenant: ClassToolEvent,
		CacheEventErasureUser:   ClassToolEvent,
	}
	for it, want := range cases {
		if got := RecordClassOf(it); got != want {
			t.Errorf("RecordClassOf(%q) = %q, want %q", it, got, want)
		}
		if wantReq := want == ClassRequest; IsRequestClass(it) != wantReq {
			t.Errorf("IsRequestClass(%q) = %v, want %v", it, IsRequestClass(it), wantReq)
		}
	}
}

// TestRequestClassSQLPredicate asserts the generated predicate is deterministic,
// excludes every non-request type, and permits NULL/empty (request-class).
func TestRequestClassSQLPredicate(t *testing.T) {
	p := RequestClassSQLPredicate("invocation_type")
	if p != RequestClassSQLPredicate("invocation_type") {
		t.Fatal("predicate is not deterministic")
	}
	if !strings.Contains(p, "invocation_type IS NULL") {
		t.Errorf("predicate must treat NULL as request-class: %q", p)
	}
	if !strings.Contains(p, "NOT IN") {
		t.Errorf("predicate must exclude non-request types: %q", p)
	}
	for it := range nonRequestClass {
		if !strings.Contains(p, "'"+it+"'") {
			t.Errorf("predicate is missing non-request type %q: %q", it, p)
		}
	}
	// A request-class type must NOT be inside the NOT IN list.
	for _, req := range []string{"gateway", "api", "manual"} {
		if strings.Contains(p, "'"+req+"'") {
			t.Errorf("predicate wrongly lists request-class type %q: %q", req, p)
		}
	}
}
