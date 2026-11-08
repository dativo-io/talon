package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/dativo-io/talon/internal/evidence"
)

// Detail is the `talon session show` contract and the console's session
// detail (#271, #535): the session-store row when one exists, the ambiguous
// matches when an external id names several rows, and the evidence-derived
// summary built by evidence.BuildSessionSummary — the one pure function
// behind every session rollup, so no two views can disagree.
type Detail struct {
	Session   *Session                `json:"session,omitempty"`
	Ambiguous []*Session              `json:"ambiguous_sessions,omitempty"`
	Summary   evidence.SessionSummary `json:"summary"`
}

// EvidenceKey is the session_id under which the session's evidence is stored:
// the external asserted id when one exists, else the internal id.
func (d *Detail) EvidenceKey(requested string) string {
	if d.Session == nil {
		return requested
	}
	if d.Session.ExternalSessionID != "" {
		return d.Session.ExternalSessionID
	}
	return d.Session.ID
}

// EvidenceSource is the evidence-store surface LoadDetail reads.
// *evidence.Store satisfies it.
type EvidenceSource interface {
	ListBySessionID(ctx context.Context, sessionID string) ([]*evidence.Evidence, error)
}

// ErrDetailNotFound is returned when neither a session row nor any evidence
// record exists for the requested id.
var ErrDetailNotFound = errors.New("session not found (no session row, no evidence records)")

// LoadDetail resolves idOrExternal against both id namespaces (internal
// sess_... primary key, then the external asserted id), scopes to tenant when
// one is given, and joins the row with the session's evidence records. A
// session with evidence but no row (for example one asserted only on the MCP
// proxy path) still gets a summary. When the external id is ambiguous the
// matches are returned with an empty summary and no error; the caller decides
// how to present that.
func LoadDetail(ctx context.Context, store *Store, ev EvidenceSource, idOrExternal, tenant string) (*Detail, error) {
	detail := &Detail{}
	sess, err := store.Get(ctx, idOrExternal, tenant)
	switch {
	case err == nil:
		detail.Session = sess
	case errors.Is(err, ErrSessionNotFound):
		matches, listErr := store.ListByExternalID(ctx, idOrExternal, tenant)
		if listErr != nil {
			return nil, listErr
		}
		switch len(matches) {
		case 0: // evidence-only session, or unknown id — decided below
		case 1:
			detail.Session = matches[0]
		default:
			detail.Ambiguous = matches
			return detail, nil
		}
	default:
		return nil, fmt.Errorf("getting session %s: %w", idOrExternal, err)
	}

	key := detail.EvidenceKey(idOrExternal)
	records, err := ev.ListBySessionID(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("querying session %s: %w", key, err)
	}
	records = ScopeRecords(records, tenant, "")
	if detail.Session == nil && len(records) == 0 {
		return nil, fmt.Errorf("session %s: %w", idOrExternal, ErrDetailNotFound)
	}
	detail.Summary = evidence.BuildSessionSummary(key, records)
	return detail, nil
}

// ScopeRecords drops records that do not match the tenant/agent filters.
// Empty filters match everything. Scoping happens before BuildSessionSummary,
// which by contract summarises only what the reader may see.
func ScopeRecords(records []*evidence.Evidence, tenant, agent string) []*evidence.Evidence {
	if tenant == "" && agent == "" {
		return records
	}
	out := make([]*evidence.Evidence, 0, len(records))
	for _, r := range records {
		if r == nil {
			continue
		}
		if tenant != "" && r.TenantID != tenant {
			continue
		}
		if agent != "" && r.AgentID != agent {
			continue
		}
		out = append(out, r)
	}
	return out
}
