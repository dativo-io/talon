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
// *evidence.Store satisfies it. SummarizeSession streams the records through
// the shared accumulator (memory bounded by the summary, not the session);
// ListBySessionID is used only where every record is needed anyway (the
// CLI's complete timeline).
type EvidenceSource interface {
	ListBySessionID(ctx context.Context, sessionID string) ([]*evidence.Evidence, error)
	SummarizeSession(ctx context.Context, sessionID, tenantID, agentID string) (evidence.SessionSummary, error)
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
	detail, err := resolveRow(ctx, store, idOrExternal, tenant)
	if err != nil || len(detail.Ambiguous) > 0 {
		return detail, err
	}
	key := detail.EvidenceKey(idOrExternal)
	sum, err := ev.SummarizeSession(ctx, key, tenant, detail.ownerAgent())
	if err != nil {
		return nil, fmt.Errorf("summarising session %s: %w", key, err)
	}
	if detail.Session == nil && sum.RecordCount == 0 {
		return nil, fmt.Errorf("session %s: %w", idOrExternal, ErrDetailNotFound)
	}
	detail.Summary = sum
	return detail, nil
}

// LoadTimeline is LoadDetail plus the complete timeline (the `talon audit
// list --session --json` shape), built from the same resolved evidence key
// and the same scoped records. The timeline is nil when the external id is
// ambiguous. Bounded consumers use LoadTimelinePage.
func LoadTimeline(ctx context.Context, store *Store, ev EvidenceSource, idOrExternal, tenant string) (*Detail, *Timeline, error) {
	detail, err := resolveRow(ctx, store, idOrExternal, tenant)
	if err != nil || len(detail.Ambiguous) > 0 {
		return detail, nil, err
	}
	key := detail.EvidenceKey(idOrExternal)
	records, err := ev.ListBySessionID(ctx, key)
	if err != nil {
		return nil, nil, fmt.Errorf("querying session %s: %w", key, err)
	}
	records = ScopeRecords(records, tenant, detail.ownerAgent())
	if detail.Session == nil && len(records) == 0 {
		return nil, nil, fmt.Errorf("session %s: %w", idOrExternal, ErrDetailNotFound)
	}
	tl := BuildTimeline(key, records)
	detail.Summary = tl.Summary
	return detail, &tl, nil
}

// PagedEvidenceSource is the bounded surface LoadTimelinePage reads.
// *evidence.Store satisfies it. SessionSnapshotRead returns the streamed
// summary, one page and the total from ONE read transaction.
type PagedEvidenceSource interface {
	EvidenceSource
	SessionSnapshotRead(ctx context.Context, sessionID, tenantID, agentID string, after evidence.TimelineCursor, limit int) (*evidence.SessionSnapshot, error)
}

// LoadTimelinePage is LoadDetail (the complete, accurate summary) plus ONE
// page of the timeline in source-time order, strictly after the cursor, at
// most limit rows, under the same tenant and owner scoping as the summary.
// A long-running session therefore never produces an unbounded response
// (#535 review). The timeline is nil when the external id is ambiguous.
func LoadTimelinePage(ctx context.Context, store *Store, ev PagedEvidenceSource, idOrExternal, tenant string, after evidence.TimelineCursor, limit int) (*Detail, *Timeline, error) {
	detail, err := resolveRow(ctx, store, idOrExternal, tenant)
	if err != nil || len(detail.Ambiguous) > 0 {
		return detail, nil, err
	}
	key, owner := detail.EvidenceKey(idOrExternal), detail.ownerAgent()
	snap, err := ev.SessionSnapshotRead(ctx, key, tenant, owner, after, limit)
	if err != nil {
		return nil, nil, err
	}
	if detail.Session == nil && snap.Total == 0 {
		return nil, nil, fmt.Errorf("session %s: %w", idOrExternal, ErrDetailNotFound)
	}
	detail.Summary = snap.Summary
	tl := &Timeline{Summary: snap.Summary, Records: make([]evidence.Index, 0, len(snap.Page)), Total: snap.Total, Limit: limit}
	for _, r := range snap.Page {
		tl.Records = append(tl.Records, evidence.IndexOf(r))
	}
	if len(snap.Page) == limit && len(snap.Page) > 0 {
		last := snap.Page[len(snap.Page)-1]
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

// resolveRow resolves idOrExternal against the session store only: the
// internal id first, then the external asserted id. It never touches
// evidence; the callers add the summary or timeline they need.
func resolveRow(ctx context.Context, store *Store, idOrExternal, tenant string) (*Detail, error) {
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
		case 0: // evidence-only session, or unknown id — decided by the caller
		case 1:
			detail.Session = matches[0]
		default:
			detail.Ambiguous = matches
		}
	default:
		return nil, fmt.Errorf("getting session %s: %w", idOrExternal, err)
	}
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
