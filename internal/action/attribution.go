package action

import (
	"encoding/json"

	"github.com/dativo-io/talon/internal/evidence"
)

// Attribution is client-asserted metadata an adapter links to an operation
// when it establishes it (#431): the MCP client's session id, its own
// correlation id, and the orchestration identity it asserted. Talon
// validated the values' shape (evidence.ValidateOrchValue), not their
// truth: attribution is never authentication, never an input to a verdict
// or the digest, and never creates a Talon session. It joins the
// operation's lifecycle records to the client's session in the existing
// session and evidence projections.
type Attribution struct {
	SessionID     string                         `json:"session_id,omitempty"`
	CorrelationID string                         `json:"correlation_id,omitempty"`
	Orchestration *evidence.OrchestrationContext `json:"orchestration,omitempty"`
}

func (a *Attribution) encode() []byte {
	if a == nil || (a.SessionID == "" && a.CorrelationID == "" && a.Orchestration == nil) {
		return nil
	}
	b, err := json.Marshal(a)
	if err != nil {
		return nil
	}
	return b
}

func decodeAttribution(raw []byte) *Attribution {
	if len(raw) == 0 {
		return nil
	}
	var a Attribution
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil
	}
	return &a
}

// attachAttribution stamps the operation's client-asserted attribution on
// one of its lifecycle records: the session id (joining the record to the
// client's session wherever sessions are projected), the orchestration
// identity, and the client's correlation id as lifecycle metadata. The
// record's own correlation id stays the operation reference, which the
// lifecycle verifier relies on. A verified workload session (the hop)
// takes precedence over a client-asserted one.
func attachAttribution(op *Operation, rec *evidence.Evidence) {
	a := decodeAttribution(op.AttributionJSON)
	if a == nil {
		return
	}
	if rec.SessionID == "" {
		rec.SessionID = a.SessionID
	}
	if a.Orchestration != nil && rec.Orchestration == nil {
		o := *a.Orchestration
		rec.Orchestration = &o
	}
	if rec.ActionLifecycle != nil {
		rec.ActionLifecycle.ClientCorrelationID = a.CorrelationID
	}
}
