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
	return LoadDetailFor(ctx, store, ev, idOrExternal, tenant, "")
}

// LoadDetailFor is LoadDetail scoped to one agent's share of the session,
// the way an evidence-observed (session id, agent) entry is opened: a row of
// that agent is used when one exists (an external id shared by several
// agents resolves to that agent's row, not to an ambiguity); otherwise the
// evidence under the id is read for that agent only. agent "" is LoadDetail.
func LoadDetailFor(ctx context.Context, store *Store, ev EvidenceSource, idOrExternal, tenant, agent string) (*Detail, error) {
	detail, err := resolveRowFor(ctx, store, idOrExternal, tenant, agent)
	if err != nil || len(detail.Ambiguous) > 0 {
		return detail, err
	}
	key := detail.EvidenceKey(idOrExternal)
	sum, err := ev.SummarizeSession(ctx, key, tenant, detail.scopeAgent(agent))
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
	return LoadTimelinePageFor(ctx, store, ev, idOrExternal, tenant, "", after, limit)
}

// LoadTimelinePageFor is LoadTimelinePage scoped to one agent's share of the
// session (see LoadDetailFor).
func LoadTimelinePageFor(ctx context.Context, store *Store, ev PagedEvidenceSource, idOrExternal, tenant, agent string, after evidence.TimelineCursor, limit int) (*Detail, *Timeline, error) {
	detail, err := resolveRowFor(ctx, store, idOrExternal, tenant, agent)
	if err != nil || len(detail.Ambiguous) > 0 {
		return detail, nil, err
	}
	key, owner := detail.EvidenceKey(idOrExternal), detail.scopeAgent(agent)
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

// scopeAgent is the agent the evidence reads are scoped to: the row's owner
// when a row was resolved, else the requested agent (an evidence-only share).
func (d *Detail) scopeAgent(requested string) string {
	if owner := d.ownerAgent(); owner != "" {
		return owner
	}
	return requested
}

// TimelineOnlySource is the surface LoadTimelineOnly reads.
type TimelineOnlySource interface {
	TimelinePageRead(ctx context.Context, sessionID, tenantID, agentID string, after evidence.TimelineCursor, limit int) (*evidence.TimelinePage, error)
}

// ErrAmbiguousSession is returned by LoadTimelineOnly when an external id
// matches several rows and no agent was named.
var ErrAmbiguousSession = errors.New("external session id matches several sessions; use an internal id or name the agent")

// LoadTimelineOnly returns one timeline page and the total WITHOUT the
// summary, for a client that already holds the summary and walks a long
// session: each page is one indexed range read, never a scan of the
// session. Scoping is identical to LoadTimelinePageFor. The returned
// Timeline's Summary carries only the session id.
func LoadTimelineOnly(ctx context.Context, store *Store, ev TimelineOnlySource, idOrExternal, tenant, agent string, after evidence.TimelineCursor, limit int) (*Timeline, error) {
	detail, err := resolveRowFor(ctx, store, idOrExternal, tenant, agent)
	if err != nil {
		return nil, err
	}
	if len(detail.Ambiguous) > 0 {
		return nil, fmt.Errorf("session %s: %w", idOrExternal, ErrAmbiguousSession)
	}
	key := detail.EvidenceKey(idOrExternal)
	page, err := ev.TimelinePageRead(ctx, key, tenant, detail.scopeAgent(agent), after, limit)
	if err != nil {
		return nil, err
	}
	if detail.Session == nil && page.Total == 0 {
		return nil, fmt.Errorf("session %s: %w", idOrExternal, ErrDetailNotFound)
	}
	tl := &Timeline{Summary: evidence.SessionSummary{SessionID: key}, Records: make([]evidence.Index, 0, len(page.Page)), Total: page.Total, Limit: limit}
	for _, r := range page.Page {
		tl.Records = append(tl.Records, evidence.IndexOf(r))
	}
	if len(page.Page) == limit && len(page.Page) > 0 {
		last := page.Page[len(page.Page)-1]
		tl.NextCursor = &evidence.TimelineCursor{Timestamp: last.Timestamp, ID: last.ID}
	}
	return tl, nil
}

// resolveRow resolves idOrExternal against the session store only: the
// internal id first, then the external asserted id. It never touches
// evidence; the callers add the summary or timeline they need.
func resolveRow(ctx context.Context, store *Store, idOrExternal, tenant string) (*Detail, error) {
	return resolveRowFor(ctx, store, idOrExternal, tenant, "")
}

// resolveRowFor is resolveRow with an agent: among external-id matches the
// agent's own row is chosen, so a shared external id is not ambiguous for a
// caller who names the agent; a row of ANOTHER agent is not this agent's
// session (its internal id is not found for this agent; its external id
// leaves the agent's share evidence-only).
func resolveRowFor(ctx context.Context, store *Store, idOrExternal, tenant, agent string) (*Detail, error) {
	detail := &Detail{}
	sess, err := store.Get(ctx, idOrExternal, tenant)
	switch {
	case err == nil:
		if agent != "" && sess.AgentID != agent {
			return nil, fmt.Errorf("session %s belongs to agent %q, not %q: %w", idOrExternal, sess.AgentID, agent, ErrDetailNotFound)
		}
		detail.Session = sess
	case errors.Is(err, ErrSessionNotFound):
		matches, listErr := store.ListByExternalID(ctx, idOrExternal, tenant)
		if listErr != nil {
			return nil, listErr
		}
		if agent != "" {
			var own []*Session
			for _, m := range matches {
				if m.AgentID == agent {
					own = append(own, m)
				}
			}
			matches = own
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
