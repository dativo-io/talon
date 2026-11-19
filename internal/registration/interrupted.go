// Package registration holds what `talon agents add` and `talon doctor`
// share about use-case registrations: the signed lifecycle record types and
// the detection of a registration that never reached a terminal record.
package registration

import (
	"context"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

// Lifecycle record types of a registration (evidence invocation_type). All
// three are operator events (evidence.ClassOperatorEvent): none of them is
// application traffic.
const (
	// TypeIntent is written first, before anything else is created.
	TypeIntent = "agent_registration_intent"
	// TypeRegistered is the completion record: key stored, file published,
	// fleet validated.
	TypeRegistered = "agent_registered"
	// TypeRolledBack is the terminal record of a registration that did not
	// complete; its reasons say what was removed and what could not be.
	TypeRolledBack = "agent_registration_rolled_back"
)

// Interrupted is a registration whose signed intent has no terminal record
// (neither completed nor rolled back): the process died, or could not write
// its terminal record, somewhere after the intent.
type Interrupted struct {
	Name        string    `json:"name"`
	Tenant      string    `json:"tenant"`
	IntentID    string    `json:"intent_evidence_id"`
	Correlation string    `json:"correlation_id"`
	At          time.Time `json:"at"`
}

// maxIntents bounds how many of the newest intent records one lookup reads.
const maxIntents = 50

// FindInterrupted returns the registrations of name ("" = every use case)
// whose intent has no terminal record, newest first. It reads at most
// maxIntents intent records and, for each, the records of its correlation
// id; it writes nothing.
func FindInterrupted(ctx context.Context, store *evidence.Store, name string) ([]Interrupted, error) {
	intents, err := store.ListIndex(ctx, "", name, time.Time{}, time.Time{}, maxIntents, TypeIntent, "", "")
	if err != nil {
		return nil, err
	}
	var out []Interrupted
	for i := range intents {
		in := &intents[i]
		recs, err := store.ListByCorrelationID(ctx, in.CorrelationID)
		if err != nil {
			return nil, err
		}
		terminal := false
		for _, r := range recs {
			if r.InvocationType == TypeRegistered || r.InvocationType == TypeRolledBack {
				terminal = true
				break
			}
		}
		if !terminal {
			out = append(out, Interrupted{Name: in.AgentID, Tenant: in.TenantID, IntentID: in.ID, Correlation: in.CorrelationID, At: in.Timestamp})
		}
	}
	return out, nil
}
