package action

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dativo-io/talon/internal/evidence"
)

// Lifecycle verification (#458/#146).
//
// A valid HMAC on each record proves Talon recorded that fact. This
// verifier additionally proves the SET of records describes a possible
// lifecycle: one establishing record, a gap-free sequence, constant
// identity/digests, approval before claim when required, claim before
// dispatch before completion, contiguous attempt ordinals, no attempt
// after a permanently closed or unknown operation, and terminal state
// consistent with the last completion. Individually valid signatures never
// make an impossible lifecycle valid.

// Lifecycle verdicts.
const (
	LifecycleValid      = "valid"
	LifecycleInvalid    = "invalid"
	LifecycleIncomplete = "incomplete" // no violation, but not terminal
)

// Finding is the verifier's result for one operation.
type Finding struct {
	OperationRef string   `json:"operation_ref"`
	OperationID  string   `json:"operation_id,omitempty"`
	Verdict      string   `json:"verdict"`
	Records      int      `json:"records"`
	FinalStatus  string   `json:"final_status,omitempty"`
	Details      []string `json:"details,omitempty"`
	EvidenceIDs  []string `json:"evidence_ids"`
}

// OK reports whether the lifecycle verified without violations.
func (f Finding) OK() bool { return f.Verdict != LifecycleInvalid }

// VerifyLifecycle is pure: records are the evidence chain sharing one
// correlation id; verifySig checks one record's signature.
//
//nolint:gocyclo // the rule list IS the contract; splitting it would hide the order
func VerifyLifecycle(records []*evidence.Evidence, verifySig func(*evidence.Evidence) bool) Finding {
	f := Finding{Verdict: LifecycleValid}
	fail := func(format string, args ...any) {
		f.Verdict = LifecycleInvalid
		f.Details = append(f.Details, fmt.Sprintf(format, args...))
	}

	var chain []*evidence.Evidence
	for _, r := range records {
		if r == nil || r.ActionLifecycle == nil {
			continue
		}
		chain = append(chain, r)
	}
	if len(chain) == 0 {
		return Finding{Verdict: LifecycleInvalid, Details: []string{"no action lifecycle records"}}
	}
	sort.SliceStable(chain, func(i, j int) bool { return chain[i].ActionLifecycle.Sequence < chain[j].ActionLifecycle.Sequence })
	f.Records = len(chain)
	first := chain[0].ActionLifecycle
	f.OperationRef, f.OperationID = first.OperationRef, first.OperationID

	// Rule 0: every record must be intact.
	for _, r := range chain {
		f.EvidenceIDs = append(f.EvidenceIDs, r.ID)
		if verifySig != nil && !verifySig(r) {
			fail("record %s: signature does not verify", r.ID)
		}
	}
	// Rule 1: exactly one establishing record, sequence 1, gap-free.
	if first.Event != evidence.ActionEventOperationEstablished || first.Sequence != 1 {
		fail("chain does not start with operation_established at sequence 1 (got %s@%d)", first.Event, first.Sequence)
	}
	for i, r := range chain {
		l := r.ActionLifecycle
		if l.Sequence != i+1 {
			fail("record %s: sequence %d, expected %d (gap or duplicate)", r.ID, l.Sequence, i+1)
		}
		if i > 0 && l.Event == evidence.ActionEventOperationEstablished {
			fail("record %s: second operation_established", r.ID)
		}
		if r.CorrelationID != first.OperationRef {
			fail("record %s: correlation_id %q is not the operation ref %q", r.ID, r.CorrelationID, first.OperationRef)
		}
		if r.TenantID != chain[0].TenantID || r.AgentID != chain[0].AgentID {
			fail("record %s: tenant/agent differ from the establishing record", r.ID)
		}
		// Rule 2: identity and digests never change.
		if l.OperationRef != first.OperationRef || l.OperationID != first.OperationID || l.Action != first.Action ||
			l.Digest != first.Digest || l.SchemaDigest != first.SchemaDigest || l.PolicyDigest != first.PolicyDigest || l.DefinitionDigest != first.DefinitionDigest ||
			l.ExecutionProfile != first.ExecutionProfile || l.DestinationID != first.DestinationID || l.Verdict != first.Verdict {
			fail("record %s: exact operation identity/digest differs from the establishing record", r.ID)
		}
	}

	// Rule 3+: state machine over events.
	type attemptState struct {
		claimed, armed, completed bool
		status                    string
	}
	attempts := map[string]*attemptState{}
	var ordinals []int
	approvals := map[string]string{} // id → status
	approvedAt := -1
	closed := ""
	terminal := ""
	for i, r := range chain {
		l := r.ActionLifecycle
		switch l.Event {
		case evidence.ActionEventOperationEstablished:
			if l.Verdict == VerdictDeny && l.OperationStatus != OpDenied {
				fail("record %s: DENY verdict must persist a denied operation", r.ID)
			}
		case evidence.ActionEventOperationConflict, evidence.ActionEventAuthorizationRefused:
			// state unchanged
		case evidence.ActionEventApprovalRequested:
			if first.Verdict != VerdictRequireApproval {
				fail("record %s: approval requested for a %s verdict", r.ID, first.Verdict)
			}
			if _, dup := approvals[l.ApprovalID]; dup || l.ApprovalID == "" {
				fail("record %s: approval %q requested twice or empty", r.ID, l.ApprovalID)
			}
			approvals[l.ApprovalID] = ApprovalPending
		case evidence.ActionEventApprovalDecided:
			st, ok := approvals[l.ApprovalID]
			if !ok {
				fail("record %s: decision for approval %q that was never requested", r.ID, l.ApprovalID)
			} else if st != ApprovalPending {
				fail("record %s: approval %q decided twice", r.ID, l.ApprovalID)
			}
			if l.ReviewerPrincipal == "" {
				fail("record %s: decision without an authenticated reviewer principal", r.ID)
			}
			if l.ReviewerPrincipal != "system" && l.ReviewerTenant != r.TenantID {
				fail("record %s: reviewer tenant %q differs from the operation tenant %q", r.ID, l.ReviewerTenant, r.TenantID)
			}
			approvals[l.ApprovalID] = l.ApprovalStatus
			if l.ApprovalStatus == ApprovalApproved {
				approvedAt = i
			}
		case evidence.ActionEventAttemptClaimed:
			if first.Verdict == VerdictDeny {
				fail("record %s: attempt claimed on a denied operation", r.ID)
			}
			if first.Verdict == VerdictRequireApproval && approvedAt < 0 {
				fail("record %s: attempt claimed before any approved decision", r.ID)
			}
			if closed != "" {
				fail("record %s: attempt claimed after the operation was %s", r.ID, closed)
			}
			for id, st := range attempts {
				if !st.completed {
					fail("record %s: attempt claimed while attempt %s is still open", r.ID, id)
				}
			}
			if _, dup := attempts[l.AttemptID]; dup || l.AttemptID == "" {
				fail("record %s: attempt id %q reused or empty", r.ID, l.AttemptID)
			}
			ordinals = append(ordinals, l.AttemptOrdinal)
			attempts[l.AttemptID] = &attemptState{claimed: true}
		case evidence.ActionEventAttemptArmed:
			st, ok := attempts[l.AttemptID]
			if !ok || !st.claimed || st.armed || st.completed {
				fail("record %s: arm marker for attempt %q without a prior open claim", r.ID, l.AttemptID)
			} else {
				st.armed = true
			}
			if !l.DispatchArmed {
				fail("record %s: arm marker must state dispatch_armed", r.ID)
			}
			if l.RequestWritten || l.ResponseObserved {
				fail("record %s: an arm marker is intent only; it must not claim an observed request or response", r.ID)
			}
		case evidence.ActionEventAttemptCompleted:
			st, ok := attempts[l.AttemptID]
			if !ok || !st.claimed || st.completed {
				fail("record %s: completion for attempt %q without a prior open claim", r.ID, l.AttemptID)
				continue
			}
			st.completed, st.status = true, l.AttemptStatus
			if st.armed != l.DispatchArmed {
				fail("record %s: completion dispatch_armed=%t contradicts the chain", r.ID, l.DispatchArmed)
			}
			switch l.AttemptStatus {
			case AttemptSucceeded:
				if !st.armed || !l.RequestWritten || !l.ResponseObserved || l.ResultProvenance != ResultProvenanceObserved {
					fail("record %s: a succeeded attempt requires arm + observed request write + observed response + observed provenance", r.ID)
				}
				closed = l.AttemptStatus
			case AttemptUnknown:
				if !st.armed || l.ResultProvenance != ResultProvenanceUnknown {
					fail("record %s: an unknown attempt requires a prior arm marker and unknown provenance", r.ID)
				}
				closed = l.AttemptStatus
			case AttemptFailed:
				if l.RequestWritten || l.ResultProvenance != ResultProvenanceNotDispatched {
					fail("record %s: a failed attempt is only ever a not_dispatched failure (an observed non-success is unknown, never retryable)", r.ID)
				}
			default:
				fail("record %s: unknown attempt status %q", r.ID, l.AttemptStatus)
			}
		default:
			fail("record %s: unknown lifecycle event %q", r.ID, l.Event)
		}
		terminal = l.OperationStatus
	}
	for i, o := range ordinals {
		if o != i+1 {
			fail("attempt ordinals are not contiguous: %v", ordinals)
			break
		}
	}
	if closed == AttemptSucceeded && terminal != OpSucceeded {
		fail("last completion succeeded but final operation status is %q", terminal)
	}
	if closed == AttemptUnknown && terminal != OpUnknown {
		fail("last completion unknown but final operation status is %q", terminal)
	}
	if closed == "" && terminal == OpSucceeded {
		fail("final status succeeded without a succeeded completion record")
	}
	f.FinalStatus = terminal
	if f.Verdict == LifecycleValid {
		switch terminal {
		case OpSucceeded, OpUnknown, OpDenied, OpCancelled:
		default:
			f.Verdict = LifecycleIncomplete
		}
	}
	return f
}

// Summary renders a one-line human summary.
func (f Finding) Summary() string {
	s := fmt.Sprintf("%s: %s (%d records, final status %s)", f.OperationRef, strings.ToUpper(f.Verdict), f.Records, f.FinalStatus)
	if len(f.Details) > 0 {
		s += "\n  - " + strings.Join(f.Details, "\n  - ")
	}
	return s
}
