package console

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/dativo-io/talon/internal/evidence"
)

// Search bounds.
const (
	MaxSearchQuery   = 128
	maxSearchResults = 10
)

// SearchResults is a bounded lookup over the facts the console can resolve
// exactly (#539): AI use-case names by prefix, and session, evidence and
// correlation ids by exact match. Explanation-code search is not offered:
// codes live inside the signed record JSON and have no index, so a lookup
// would scan the store. Unsupported says so instead of returning nothing.
type SearchResults struct {
	Meta         Meta             `json:"meta"`
	Query        string           `json:"query"`
	Availability Availability     `json:"availability"`
	UseCases     []SearchUseCase  `json:"use_cases"`
	Sessions     []SearchSession  `json:"sessions"`
	Evidence     []evidence.Index `json:"evidence"`
	Unsupported  []string         `json:"unsupported"`
	Notes        []string         `json:"notes,omitempty"`
}

// SearchUseCase is a matching AI use case.
type SearchUseCase struct {
	Name     string `json:"name"`
	TenantID string `json:"tenant_id"`
	Health   string `json:"health"`
}

// SearchSession is a session id with evidence in scope, per owning agent.
type SearchSession struct {
	SessionID   string `json:"session_id"`
	TenantID    string `json:"tenant_id"`
	Managed     bool   `json:"managed"` // a session-store row exists
	RecordCount int    `json:"record_count"`
}

// Search runs the bounded lookups. An empty or over-long query is
// ErrInvalidArgument.
func (s *Service) Search(ctx context.Context, tenant, q string) (*SearchResults, error) {
	q = strings.TrimSpace(q)
	if q == "" || len(q) > MaxSearchQuery {
		return nil, errors.Join(ErrInvalidArgument, errors.New("q must be 1 to 128 characters"))
	}
	scope := tenant
	if scope == "" {
		scope = "default"
	}
	out := &SearchResults{
		Meta: s.meta(scope), Query: q,
		UseCases: []SearchUseCase{}, Sessions: []SearchSession{}, Evidence: []evidence.Index{},
		Unsupported: []string{"explanation_code"},
	}
	var errs []string
	uc := s.useCases(ctx, tenant)
	if uc.Availability.State == StateUnavailable {
		errs = append(errs, "use cases: "+uc.Availability.Error)
	}
	lq := strings.ToLower(q)
	for i := range uc.Rows {
		r := &uc.Rows[i]
		if strings.HasPrefix(strings.ToLower(r.Name), lq) && len(out.UseCases) < maxSearchResults {
			out.UseCases = append(out.UseCases, SearchUseCase{Name: r.Name, TenantID: r.TenantID, Health: string(r.Health)})
		}
	}
	if s.cfg.Evidence == nil {
		errs = append(errs, noStoreMsg)
	} else {
		errs = append(errs, s.searchEvidence(ctx, scope, q, out)...)
	}
	switch {
	case len(errs) > 0 && len(out.UseCases)+len(out.Sessions)+len(out.Evidence) == 0:
		out.Availability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: strings.Join(errs, "; ")}
	case len(errs) > 0:
		out.Availability = Availability{State: StatePartial, Source: SourceEvidenceStore, AsOf: s.now(), Error: strings.Join(errs, "; ")}
	case len(out.UseCases)+len(out.Sessions)+len(out.Evidence) == 0:
		out.Availability = Availability{State: StateEmpty, Source: SourceEvidenceStore, AsOf: s.now()}
	default:
		out.Availability = ok(SourceEvidenceStore, s.now())
	}
	return out, nil
}

func (s *Service) searchEvidence(ctx context.Context, tenant, q string, out *SearchResults) []string {
	var errs []string
	if err := s.searchEvidenceIDs(ctx, tenant, q, out); err != nil {
		errs = append(errs, err...)
	}
	n, err := s.cfg.Evidence.CountBySessionID(ctx, q, tenant, "")
	if err != nil {
		errs = append(errs, "session id: "+err.Error())
	}
	managed := false
	if s.cfg.Sessions != nil {
		if row, gerr := s.cfg.Sessions.Get(ctx, q, tenant); gerr == nil && row != nil {
			managed = true
		}
	}
	if n > 0 || managed {
		out.Sessions = append(out.Sessions, SearchSession{SessionID: q, TenantID: tenant, Managed: managed, RecordCount: n})
	}
	return errs
}

// searchEvidenceIDs resolves q as an exact evidence id, then as an exact
// correlation id (indexed, bounded), in tenant scope, oldest first.
func (s *Service) searchEvidenceIDs(ctx context.Context, tenant, q string, out *SearchResults) []string {
	var errs []string
	seen := map[string]bool{}
	add := func(ev *evidence.Evidence) {
		if ev != nil && ev.TenantID == tenant && !seen[ev.ID] {
			seen[ev.ID] = true
			out.Evidence = append(out.Evidence, evidence.IndexOf(ev))
		}
	}
	d, err := s.cfg.Evidence.Detail(ctx, q)
	switch {
	case err == nil:
		add(d.Record)
	case !errors.Is(err, evidence.ErrNotFound):
		errs = append(errs, "evidence id: "+err.Error())
	}
	byCorr, err := s.cfg.Evidence.ListByCorrelationIDLimit(ctx, q, tenant, maxSearchResults)
	if err != nil {
		errs = append(errs, "correlation id: "+err.Error())
	}
	for _, ev := range byCorr {
		add(ev)
	}
	sort.SliceStable(out.Evidence, func(i, j int) bool { return out.Evidence[i].Timestamp.Before(out.Evidence[j].Timestamp) })
	if len(out.Evidence) > maxSearchResults {
		out.Evidence = out.Evidence[:maxSearchResults]
	}
	return errs
}
