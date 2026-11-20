// Package registration holds what `talon agents add` and `talon doctor`
// share about use-case registrations: the signed lifecycle record types, the
// installation's registration lock, what a signed intent commits to, and the
// lookup of registrations that never reached a terminal record.
package registration

import (
	"context"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

// Lifecycle record types of a registration (evidence invocation_type). All
// three are operator events (evidence.ClassOperatorEvent): none of them is
// application traffic.
const (
	// TypeIntent is written first, before anything else is created.
	TypeIntent = evidence.InvocationTypeRegistrationIntent
	// TypeRegistered is the completion record: key stored, file published,
	// fleet validated.
	TypeRegistered = evidence.InvocationTypeRegistered
	// TypeRolledBack is the terminal record of a registration that did not
	// complete; its reasons say what was removed and what could not be.
	TypeRolledBack = evidence.InvocationTypeRegistrationRolledBack
)

// What a signed intent commits to, as "<prefix><value>" entries of the
// record's reasons. They are written BEFORE the registration creates
// anything, so that a later process can prove, from the signed intent alone,
// that an artifact it finds is the one this registration created:
//
//   - the vault ownership token of the key version it is about to store (the
//     version's nonce: not secret, stored in clear next to the ciphertext);
//   - the SHA-256 of the agent file it is about to publish.
//
// Neither is derived from the key's value. An intent without them (written
// before they were recorded) proves ownership of nothing.
const (
	reasonSecretName   = "vault secret: "
	reasonKeyOwnership = "vault ownership token: "
	reasonAgentFile    = "config: "
	reasonFileSHA256   = "agent file sha256: "
	reasonMarker       = "registration marker: "
)

// Commitments are the artifacts a registration states, in its signed intent,
// that it is about to create.
type Commitments struct {
	SecretName        string
	KeyOwnershipToken string
	AgentFile         string
	FileSHA256        string
	// Marker is the random, non-secret value this registration wrote into
	// the agent file it generated. The file's content is otherwise the same
	// for every registration of the same name, owner and tenant, so its
	// digest alone would also match a file someone else created; with the
	// marker, the digest is this registration's alone. Empty on an intent
	// written before markers existed: such an intent proves nothing about
	// a file.
	Marker string
}

// Reasons renders the commitments as entries of the intent's reasons.
func (c Commitments) Reasons() []string {
	return []string{
		reasonAgentFile + c.AgentFile,
		reasonFileSHA256 + c.FileSHA256,
		reasonMarker + c.Marker,
		reasonSecretName + c.SecretName,
		reasonKeyOwnership + c.KeyOwnershipToken,
	}
}

func commitmentsOf(reasons []string) Commitments {
	var c Commitments
	for _, r := range reasons {
		switch {
		case strings.HasPrefix(r, reasonKeyOwnership):
			c.KeyOwnershipToken = strings.TrimPrefix(r, reasonKeyOwnership)
		case strings.HasPrefix(r, reasonFileSHA256):
			c.FileSHA256 = strings.TrimPrefix(r, reasonFileSHA256)
		case strings.HasPrefix(r, reasonMarker):
			c.Marker = strings.TrimPrefix(r, reasonMarker)
		case strings.HasPrefix(r, reasonSecretName):
			c.SecretName = strings.TrimPrefix(r, reasonSecretName)
		case strings.HasPrefix(r, reasonAgentFile):
			c.AgentFile = strings.TrimPrefix(r, reasonAgentFile)
		}
	}
	return c
}

// Unresolved is a registration whose signed intent has no terminal record
// (neither completed nor rolled back) in the store. That alone says nothing
// about WHY: the registration may be running right now (the lock tells), its
// process may have died, or its terminal record could not be written.
type Unresolved struct {
	Name        string    `json:"name"`
	Tenant      string    `json:"tenant"`
	IntentID    string    `json:"intent_evidence_id"`
	Correlation string    `json:"correlation_id"`
	At          time.Time `json:"at"`
	// Verified: the intent's signature verifies. An intent that does not
	// verify is listed, and justifies no recovery.
	Verified bool `json:"verified"`
	// Commitments from the signed intent.
	Commitments Commitments `json:"-"`
}

// Lookup is the unresolved registrations a store holds. Complete is false
// when there are more than one lookup reads: the list is then partial, and
// an empty or short list does not mean "none".
type Lookup struct {
	Unresolved []Unresolved
	Complete   bool
}

// maxUnresolved bounds one lookup. Unresolved registrations are rare (each
// is resolved by the next registration of its name); a store with more than
// this many is reported as incomplete rather than read without bound.
const maxUnresolved = 200

// FindUnresolved returns the registrations of name ("" = every use case, in
// every tenant) whose intent has no terminal record, newest first. It asks
// the store for exactly those intents (evidence.UnresolvedRegistrationIntents):
// an old unresolved intent is found however many registrations followed it.
// Each intent's signature is verified; nothing is written.
func FindUnresolved(ctx context.Context, store *evidence.Store, name string) (Lookup, error) {
	recs, complete, err := store.UnresolvedRegistrationIntents(ctx, name, maxUnresolved)
	if err != nil {
		return Lookup{}, err
	}
	out := Lookup{Complete: complete}
	for _, ev := range recs {
		out.Unresolved = append(out.Unresolved, Unresolved{
			Name: ev.AgentID, Tenant: ev.TenantID, IntentID: ev.ID, Correlation: ev.CorrelationID, At: ev.Timestamp,
			Verified: store.VerifyRecord(ev), Commitments: commitmentsOf(ev.PolicyDecision.Reasons),
		})
	}
	return out, nil
}
