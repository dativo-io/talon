package console

import (
	"context"
	"sort"
	"time"
)

// Tenants lists the tenant identities this installation knows, for the scope
// selector (#533 PR 1): tenants of configured AI use cases, tenants with
// recorded evidence, and tenants with session-store rows. It is a discovery
// aid, not an authorization list: selecting a tenant filters what the paired
// operator already may read, and nothing here provisions tenants.
type Tenants struct {
	Meta    Meta          `json:"meta"`
	Tenants []TenantEntry `json:"tenants"`
	// Availability is partial when a source did not answer: tenants seen
	// only there are then missing.
	Availability Availability `json:"availability"`
}

// TenantEntry is one tenant identity and where it was seen.
type TenantEntry struct {
	TenantID    string `json:"tenant_id"`
	UseCases    int    `json:"use_cases"`    // configured AI use cases in this tenant
	HasEvidence bool   `json:"has_evidence"` // recorded evidence exists
	HasSessions bool   `json:"has_sessions"` // session-store rows exist
	Configured  bool   `json:"configured"`   // at least one configured use case
}

// maxTenants bounds the list.
const maxTenants = 500

// Tenants builds the tenant list.
func (s *Service) Tenants(ctx context.Context) *Tenants {
	out := &Tenants{Meta: s.meta(""), Tenants: []TenantEntry{}}
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
	var failed []string
	var errs []string
	uc := s.useCases(ctx, "")
	if uc.Availability.State == StateUnavailable {
		failed, errs = append(failed, "configured_use_cases"), append(errs, uc.Availability.Error)
	}
	for i := range uc.Rows {
		e := get(uc.Rows[i].TenantID)
		e.UseCases++
		e.Configured = true
	}
	if s.cfg.Evidence == nil {
		failed, errs = append(failed, "evidence"), append(errs, noStoreMsg)
	} else if ids, err := s.cfg.Evidence.ListTenantIDs(ctx, time.Time{}, time.Time{}); err != nil {
		failed, errs = append(failed, "evidence"), append(errs, err.Error())
	} else {
		for _, id := range ids {
			get(id).HasEvidence = true
		}
	}
	if s.cfg.Sessions == nil {
		failed, errs = append(failed, "sessions"), append(errs, "session store is not open")
	} else if pairs, err := s.cfg.Sessions.DistinctAgents(ctx); err != nil {
		failed, errs = append(failed, "sessions"), append(errs, err.Error())
	} else {
		for _, p := range pairs {
			get(p[0]).HasSessions = true
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
