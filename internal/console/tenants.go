package console

import (
	"context"
	"errors"
	"sort"

	"github.com/dativo-io/talon/internal/evidence"
)

// Tenants lists the tenant identities this installation knows, for the scope
// selector (#533 PR 1): tenants of configured AI use cases, tenants with
// recorded activity in the evidence store, and tenants with session-store
// rows. It is a discovery aid, not an authorization list: selecting a tenant
// filters what the paired operator already may read, and nothing here
// provisions tenants.
//
// Talon's own installation events (evidence.IsInstallationEvent: reload
// activation/rejection, recovery resume) are recorded under the reserved
// namespace Installation.TenantID; they do not make that namespace a tenant
// (#593). They are listed on the System page. A tenant that is itself named
// like the namespace is listed when it has use cases, sessions or activity
// of its own.
type Tenants struct {
	Meta    Meta          `json:"meta"`
	Tenants []TenantEntry `json:"tenants"`
	// Installation names the reserved namespace of installation events, so
	// a view scoped to it can say what it is instead of "not seen".
	Installation InstallationScope `json:"installation"`
	// Availability is partial when a source did not answer: tenants seen
	// only there are then missing.
	Availability Availability `json:"availability"`
}

// InstallationScope is the reserved tenant_id of installation events.
type InstallationScope struct {
	TenantID string `json:"tenant_id"`
}

// TenantEntry is one tenant identity and where it was seen.
type TenantEntry struct {
	TenantID    string `json:"tenant_id"`
	UseCases    int    `json:"use_cases"`    // configured AI use cases in this tenant
	HasEvidence bool   `json:"has_evidence"` // recorded evidence of its own activity exists (installation events excluded)
	HasSessions bool   `json:"has_sessions"` // session-store rows exist
	Configured  bool   `json:"configured"`   // at least one configured use case
}

// maxTenants bounds the list.
const maxTenants = 500

// Tenants builds the tenant list.
func (s *Service) Tenants(ctx context.Context) *Tenants {
	out := &Tenants{Meta: s.meta(""), Tenants: []TenantEntry{}, Installation: InstallationScope{TenantID: evidence.InstallationTenantID}}
	byID := map[string]*TenantEntry{}
	get := func(id string) *TenantEntry {
		if id == "" {
			id = "default"
		}
		e, ok := byID[id]
		if !ok {
			e = &TenantEntry{TenantID: id}
			byID[id] = e
		}
		return e
	}
	var failed, errs []string
	fail := func(source, err string) { failed, errs = append(failed, source), append(errs, err) }
	uc := s.useCases(ctx, "")
	if uc.Availability.State == StateUnavailable {
		fail("configured_use_cases", uc.Availability.Error)
	}
	for i := range uc.Rows {
		e := get(uc.Rows[i].TenantID)
		e.UseCases++
		e.Configured = true
	}
	if ids, err := s.evidenceTenants(ctx); err != nil {
		fail("evidence", err.Error())
	} else {
		for _, id := range ids {
			get(id).HasEvidence = true
		}
	}
	if ids, err := s.sessionTenants(ctx); err != nil {
		fail("sessions", err.Error())
	} else {
		for _, id := range ids {
			get(id).HasSessions = true
		}
	}
	for _, e := range byID {
		out.Tenants = append(out.Tenants, *e)
	}
	sort.Slice(out.Tenants, func(i, j int) bool { return out.Tenants[i].TenantID < out.Tenants[j].TenantID })
	if len(out.Tenants) > maxTenants {
		out.Tenants = out.Tenants[:maxTenants]
	}
	out.Availability = ok(SourceConfigFiles, s.now())
	switch {
	case len(failed) == 3:
		out.Availability = Availability{State: StateUnavailable, Source: SourceNone, Error: errs[0]}
	case len(failed) > 0:
		out.Availability.State = StatePartial
		out.Availability.Unavailable = failed
		out.Availability.Note = "some sources could not be read, so tenants seen only there are missing"
		out.Availability.Error = errs[0]
	case len(out.Tenants) == 0:
		out.Availability.State = StateEmpty
	}
	return out
}

func (s *Service) evidenceTenants(ctx context.Context) ([]string, error) {
	if s.cfg.Evidence == nil {
		return nil, errors.New(noStoreMsg)
	}
	return s.cfg.Evidence.ListActivityTenantIDs(ctx)
}

func (s *Service) sessionTenants(ctx context.Context) ([]string, error) {
	if s.cfg.Sessions == nil {
		return nil, errors.New("session store is not open")
	}
	pairs, err := s.cfg.Sessions.DistinctAgents(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p[0])
	}
	return out, nil
}
