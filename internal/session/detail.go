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
	detail, _, err := resolveDetail(ctx, store, ev, idOrExternal, tenant)
	return detail, err
}

// LoadTimeline is LoadDetail plus the complete timeline (the `talon audit
// list --session --json` shape), built from the same resolved evidence key
// and the same scoped records. The timeline is nil when the external id is
// ambiguous. Bounded consumers use LoadTimelinePage.
func LoadTimeline(ctx context.Context, store *Store, ev EvidenceSource, idOrExternal, tenant string) (*Detail, *Timeline, error) {
	detail, records, err := resolveDetail(ctx, store, ev, idOrExternal, tenant)
	if err != nil || len(detail.Ambiguous) > 0 {
		return detail, nil, err
	}
	tl := BuildTimeline(detail.EvidenceKey(idOrExternal), records)
	return detail, &tl, nil
}

// PagedEvidenceSource is the bounded surface LoadTimelinePage reads.
// *evidence.Store satisfies it.
type PagedEvidenceSource interface {
	EvidenceSource
	ListBySessionIDPage(ctx context.Context, sessionID, tenantID, agentID string, after evidence.TimelineCursor, limit int) ([]*evidence.Evidence, error)
	CountBySessionID(ctx context.Context, sessionID, tenantID, agentID string) (int, error)
}

// LoadTimelinePage is LoadDetail (the complete, accurate summary) plus ONE
// page of the timeline in source-time order, strictly after the cursor, at
// most limit rows, under the same tenant and owner scoping as the summary.
// A long-running session therefore never produces an unbounded response
// (#535 review). The timeline is nil when the external id is ambiguous.
func LoadTimelinePage(ctx context.Context, store *Store, ev PagedEvidenceSource, idOrExternal, tenant string, after evidence.TimelineCursor, limit int) (*Detail, *Timeline, error) {
	detail, _, err := resolveDetail(ctx, store, ev, idOrExternal, tenant)
	if err != nil || len(detail.Ambiguous) > 0 {
		return detail, nil, err
	}
	key, owner := detail.EvidenceKey(idOrExternal), detail.ownerAgent()
	page, err := ev.ListBySessionIDPage(ctx, key, tenant, owner, after, limit)
	if err != nil {
		return nil, nil, err
	}
	total, err := ev.CountBySessionID(ctx, key, tenant, owner)
	if err != nil {
		return nil, nil, err
	}
	tl := &Timeline{Summary: detail.Summary, Records: make([]evidence.Index, 0, len(page)), Total: total, Limit: limit}
	for _, r := range page {
		tl.Records = append(tl.Records, evidence.IndexOf(r))
	}
	if len(page) == limit && len(page) > 0 {
		last := page[len(page)-1]
		tl.NextCursor = &evidence.TimelineCursor{Timestamp: last.Timestamp, ID: last.ID}
	}
	return detail, tl, nil
}

// ownerAgent is the agent whose session row was resolved; "" for an
// evidence-only session, where no row names an owner.
func (d *Detail) ownerAgent() string {
	if d.Session == nil {
		return ""
	}
	return d.Session.AgentID
}

func resolveDetail(ctx context.Context, store *Store, ev EvidenceSource, idOrExternal, tenant string) (*Detail, []*evidence.Evidence, error) {
	detail := &Detail{}
	sess, err := store.Get(ctx, idOrExternal, tenant)
	switch {
	case err == nil:
		detail.Session = sess
	case errors.Is(err, ErrSessionNotFound):
		matches, listErr := store.ListByExternalID(ctx, idOrExternal, tenant)
		if listErr != nil {
			return nil, nil, listErr
		}
		switch len(matches) {
		case 0: // evidence-only session, or unknown id — decided below
		case 1:
			detail.Session = matches[0]
		default:
			detail.Ambiguous = matches
			return detail, nil, nil
		}
	default:
		return nil, nil, fmt.Errorf("getting session %s: %w", idOrExternal, err)
	}

	key := detail.EvidenceKey(idOrExternal)
	records, err := ev.ListBySessionID(ctx, key)
	if err != nil {
		return nil, nil, fmt.Errorf("querying session %s: %w", key, err)
	}
	// Owner isolation (#535 review): when a session row names the agent,
	// only that agent's records belong to the session — two agents asserting
	// the same external id are two sessions. An evidence-only session has no
	// owner row; its summary lists every agent seen so a collision is visible.
	records = ScopeRecords(records, tenant, detail.ownerAgent())
	if detail.Session == nil && len(records) == 0 {
		return nil, nil, fmt.Errorf("session %s: %w", idOrExternal, ErrDetailNotFound)
	}
	detail.Summary = evidence.BuildSessionSummary(key, records)
	return detail, records, nil
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
