package govcode

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every registered code is unique, lowercase snake_case, carries a class,
// an explanation code and at least one producer; retryability is explicit
// and conservative (denials are never retryable).
func TestRegistry_Shape(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range All() {
		if seen[s.Code] {
			t.Errorf("duplicate code %q", s.Code)
		}
		seen[s.Code] = true
		if problem := specProblem(s); problem != "" {
			t.Errorf("code %q: %s", s.Code, problem)
		}
	}
	if _, ok := Lookup("made_up"); ok {
		t.Error("unregistered code resolved")
	}
	if Retryable("made_up") {
		t.Error("unknown codes must not be retryable")
	}
}

// specProblem names the first shape rule a spec violates, or "".
func specProblem(s Spec) string {
	switch {
	case s.Code != strings.ToLower(s.Code) || strings.ContainsAny(s.Code, " -."):
		return "not lowercase snake_case"
	case s.Class == "" || s.Explanation == "" || s.Summary == "" || len(s.Producers) == 0:
		return "incomplete spec"
	case s.Class == ClassDenied && s.Retryable:
		return "a denial must not be retryable"
	case s.Class == ClassUnknown && s.Retryable:
		return "an unknown outcome must block retry"
	case s.IsTarget() && s.Issue == "":
		return "a target code must name its owning issue"
	case !s.IsTarget() && s.Issue != "":
		return "a shipped code must not carry an issue tag"
	}
	return ""
}

// The #372 minimum vocabulary is present, under its canonical spelling.
func TestRegistry_CoversIssue372Minimum(t *testing.T) {
	for _, code := range []string{
		ActionNotFound, ActionSchemaInvalid, PolicyDenied, EgressDestinationDisallowed, PIIPolicyViolation,
		ApprovalRequired, ApprovalPending, ApprovalRejected, ApprovalExpired, ApprovalCancelled, ApprovalInvalidated, ApprovalBindingStale,
		OperationIDRequired, OperationConflict, OperationAlreadySucceeded, OperationOutcomeUnknown, AttemptNotAuthorized,
		UpstreamAuthUnavailable, UpstreamToolFailed, UpstreamOutcomeUnknown, EvidenceCommitFailed, ApprovalRequiresTasks, UnsupportedRuntimePosture,
	} {
		if _, ok := Lookup(code); !ok {
			t.Errorf("missing %q", code)
		}
	}
	// Codes nothing emits yet stay honestly tagged until their owner ships.
	for _, code := range []string{ApprovalRequiresTasks, ApprovalCancelled, ApprovalInvalidated, UnsupportedRuntimePosture} {
		s, _ := Lookup(code)
		if !s.IsTarget() {
			t.Errorf("%q should be tagged target until its owning issue ships", code)
		}
	}
}

func TestExtension_NewAndMarshal(t *testing.T) {
	e, err := New(PolicyDenied)
	if err != nil {
		t.Fatal(err)
	}
	e.OperationID = "op-1"
	e.Evidence = Committed("act_0123456789abcdef0123")
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"schemaVersion": float64(1), "code": "policy_denied", "decision": "deny", "reasonCode": "ACTION_POLICY_DENIED", "retryable": false, "operationId": "op-1"} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	ev := got["evidence"].(map[string]any)
	if ev["id"] != "act_0123456789abcdef0123" || ev["committed"] != true {
		t.Errorf("evidence = %v", ev)
	}
	if _, err := New("not_a_code"); err == nil {
		t.Error("unregistered code accepted")
	}
	a := Allowed(Committed("req_1"))
	if a.Decision != DecisionAllow || a.Code != "allowed" || a.Evidence.ID != "req_1" {
		t.Errorf("Allowed = %+v", a)
	}
}

// Bounds: an id must never appear without commit, tokens are bounded and
// whitespace-free, remediation is bounded, marshal refuses an invalid object.
func TestExtension_Validate(t *testing.T) {
	ok := Must(ApprovalPending)
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Extension){
		"id without commit":   func(e *Extension) { e.Evidence = &EvidenceRef{ID: "x", Committed: false} },
		"whitespace in id":    func(e *Extension) { e.OperationID = "op 1" },
		"control in id":       func(e *Extension) { e.ApprovalID = "apr\x01" },
		"too long":            func(e *Extension) { e.TaskID = strings.Repeat("a", 300) },
		"bad decision":        func(e *Extension) { e.Decision = "maybe" },
		"unregistered":        func(e *Extension) { e.Code = "nope" },
		"negative retryAfter": func(e *Extension) { e.RetryAfterMs = -1 },
		"remediation too long": func(e *Extension) {
			e.Remediation = strings.Repeat("r", 600)
		},
		"schema version": func(e *Extension) { e.SchemaVersion = 2 },
	}
	for name, mut := range cases {
		e := Must(ApprovalPending)
		mut(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: expected invalid", name)
		}
		if _, err := json.Marshal(e); err == nil {
			t.Errorf("%s: marshal must refuse an invalid extension", name)
		}
	}
	if got := Bounded("a\x00b" + strings.Repeat("x", 600)); len(got) != maxRemediationBytes || strings.ContainsRune(got, 0) {
		t.Errorf("Bounded did not bound/sanitize: len=%d", len(got))
	}
	if NotCommitted().ID != "" || NotCommitted().Committed {
		t.Error("NotCommitted must carry no id")
	}
}

func TestAdvertisement(t *testing.T) {
	adv := Advertisement()
	settings, ok := adv[ExtensionID].(map[string]any)
	if !ok || settings["schemaVersion"] != SchemaVersion {
		t.Fatalf("advertisement = %v", adv)
	}
	if !strings.HasPrefix(ExtensionID, "io.dativo.talon/") {
		t.Error("extension id must be in Talon's reverse-DNS namespace")
	}
}
