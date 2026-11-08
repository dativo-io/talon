package console

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/costs"
	"github.com/dativo-io/talon/internal/events"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/session"
)

// Sentinel errors the HTTP layer maps to status codes.
var (
	ErrNotFound        = errors.New("not found")
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrUnavailable: the store could not answer (not a missing record).
	ErrUnavailable = errors.New("store unavailable")
)

// Bounds of the list endpoints.
const (
	DefaultSessionLimit  = 50
	MaxSessionLimit      = 200
	DefaultEventsLimit   = 50
	MaxEventsLimit       = 500
	DefaultTimelineLimit = 200
	MaxTimelineLimit     = evidence.MaxTimelinePage
	DefaultActivitySpan  = 24 * time.Hour
)

// FleetSource yields the attention queue for a tenant ("" = all) and names
// the source it came from (SourceConfigFiles for the offline projection,
// SourceRuntimeProbe once #538 lands).
type FleetSource func(ctx context.Context, tenant string) (*fleetview.Result, string, error)

// Config wires the Service to the shared stores and the projections.
type Config struct {
	Evidence  *evidence.Store // read-only connection expected (evidence.OpenReadOnly)
	Sessions  *session.Store  // read-only connection expected (session.OpenReadOnly)
	StorePath string
	// Currency is the active pricing table's ISO-4217 code. Required: the
	// console never assumes a unit for amounts.
	Currency string
	Fleet    FleetSource
	// Budgets resolves effective caps for the Costs section; nil means no
	// caps are reported (never a zero cap). See FleetCapsBudgets.
	Budgets    costs.BudgetResolver
	BudgetNote string
	Version    string
	Commit     string
	StartedAt  time.Time
	Now        func() time.Time
}

// Service builds the DTOs.
type Service struct{ cfg Config }

// New returns a Service. Evidence and Sessions may be nil: every section then
// reports unavailable with the reason, which is the console's first-run and
// broken-store behaviour, not an error. Currency is required.
func New(cfg Config) (*Service, error) {
	if strings.TrimSpace(cfg.Currency) == "" {
		return nil, errors.New("console: Currency is required (the active pricing table's ISO-4217 code); amounts are never shown in an assumed unit")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = cfg.Now()
	}
	return &Service{cfg: cfg}, nil
}

func (s *Service) now() time.Time { return s.cfg.Now().UTC() }

func (s *Service) meta(tenant string) Meta {
	return Meta{ContractVersion: ContractVersion, GeneratedAt: s.now(), TenantScope: scopeOf(tenant), TenantID: tenant}
}

func scopeOf(tenant string) string {
	if tenant == "" {
		return ScopeAllTenants
	}
	return ScopeTenant
}

func ok(source string, at time.Time) Availability {
	return Availability{State: StateOK, Source: source, AsOf: at}
}

func unavailable(source string, err error) Availability {
	return Availability{State: StateUnavailable, Source: source, Error: err.Error()}
}

func runtimeUnknown() Runtime {
	return Runtime{Availability: Availability{
		State: StateUnknown, Source: SourceNone,
		Note: "active generation, reload state and collector freshness come from the running Talon process; no runtime probe is wired yet (#538)",
	}}
}

const noStoreMsg = "evidence store is not open"

// ---------------------------------------------------------------- overview

// Overview builds the Overview page. tenant "" is the all-tenant view: the
// use-case rows, the day totals and the event feed then all span every
// tenant, and Meta.TenantScope says so. A named tenant scopes all three to
// it. Nothing substitutes "default" for an omitted scope.
func (s *Service) Overview(ctx context.Context, tenant string) *Overview {
	return &Overview{
		Meta:         s.meta(tenant),
		UseCases:     s.useCases(ctx, tenant),
		Today:        s.today(ctx, tenant),
		RecentEvents: s.recentEvents(ctx, tenant, DefaultEventsLimit),
	}
}

func (s *Service) useCases(ctx context.Context, tenant string) UseCases {
	out := UseCases{Rows: []fleet.AgentRow{}, Attention: []fleet.AgentRow{}, Issues: []agentcatalog.FleetIssue{}, Runtime: runtimeUnknown(), HealthBasis: HealthBasisProjected}
	if s.cfg.Fleet == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceNone, Error: "no fleet source configured"}
		return out
	}
	res, source, err := s.cfg.Fleet(ctx, tenant)
	if err != nil {
		out.Availability = unavailable(source, err)
		return out
	}
	out.Availability = ok(source, s.now())
	if source == SourceConfigFiles {
		out.Availability.Note = "health is projected from the agent configuration on disk and the shared stores; it is not a liveness verdict for any process and the running process's generation is unknown until the runtime probe exists (#538)"
	} else {
		out.HealthBasis = HealthBasisRuntime
	}
	if res.Rows != nil {
		out.Rows = res.Rows
	}
	if res.Issues != nil {
		out.Issues = res.Issues
	}
	for i := range res.Rows {
		if res.Rows[i].Health != fleet.HealthHealthy {
			out.Attention = append(out.Attention, res.Rows[i])
		}
	}
	if len(res.Rows) == 0 && len(res.Issues) == 0 {
		out.Availability.State = StateEmpty
	}
	return out
}

func (s *Service) today(ctx context.Context, tenant string) Today {
	w := costs.WindowAt(s.now())
	out := Today{
		TenantScope: scopeOf(tenant),
		Window:      costs.WindowBounds{DayStart: w.DayStart, DayEnd: w.DayEnd, MonthStart: w.MonthStart, MonthEnd: w.MonthEnd, WeekStart: w.WeekStart, WeekEnd: w.DayEnd},
		Currency:    s.cfg.Currency,
		Scope:       "requests: request_class; cost: all_record_classes",
	}
	if s.cfg.Evidence == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}
		return out
	}
	// Both store queries treat tenant "" as every tenant.
	traffic, err := s.cfg.Evidence.AgentTrafficStats(ctx, tenant, w.DayStart, w.DayEnd)
	if err != nil {
		out.Availability = unavailable(SourceEvidenceStore, err)
		return out
	}
	for _, t := range traffic {
		out.Requests += t.Requests
		out.Denied += t.Denied
	}
	cost, err := s.cfg.Evidence.CostTotal(ctx, tenant, "", w.DayStart, w.DayEnd)
	if err != nil {
		out.Availability = unavailable(SourceEvidenceStore, err)
		return out
	}
	out.Cost = cost
	out.Availability = ok(SourceEvidenceStore, s.now())
	if out.Requests == 0 && cost == 0 {
		out.Availability.State = StateEmpty
	}
	return out
}

func (s *Service) recentEvents(ctx context.Context, tenant string, limit int) RecentEvents {
	limit = clampLimit(limit, DefaultEventsLimit, MaxEventsLimit)
	out := RecentEvents{TenantScope: scopeOf(tenant), Events: []events.OperationalEvent{}, Limit: limit}
	if s.cfg.Evidence == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}
		return out
	}
	// Same recipe as GET /api/v1/events/recent: over-fetch, project, sort
	// newest first, cut to the limit. tenant "" lists every tenant.
	records, err := s.cfg.Evidence.List(ctx, tenant, "", time.Time{}, s.now(), max(limit*4, 200))
	if err != nil {
		out.Availability = unavailable(SourceEvidenceStore, err)
		return out
	}
	list := make([]events.OperationalEvent, 0, len(records))
	for i := range records {
		list = append(list, events.FromEvidence(&records[i]))
	}
	events.SortDesc(list)
	if len(list) > limit {
		list = list[:limit]
	}
	out.Events = list
	out.Availability = ok(SourceEvidenceStore, s.now())
	if len(list) == 0 {
		out.Availability.State = StateEmpty
	} else {
		out.Cursor = list[0].EventID
	}
	return out
}

// --------------------------------------------------------------- use cases

// UseCases is the AI Use Cases list.
func (s *Service) UseCases(ctx context.Context, tenant string) (Meta, UseCases) {
	return s.meta(tenant), s.useCases(ctx, tenant)
}

// UseCase is one use case with its recent sessions, costs and activity, all
// scoped to the use case's own tenant.
func (s *Service) UseCase(ctx context.Context, tenant, name string) (*UseCaseDetail, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: use case name is required", ErrInvalidArgument)
	}
	uc := s.useCases(ctx, tenant)
	out := &UseCaseDetail{
		Meta:         s.meta(tenant),
		Availability: uc.Availability,
		HealthBasis:  uc.HealthBasis,
		Runtime:      uc.Runtime,
		EffectivePolicy: Availability{
			State:  StateUnknown,
			Source: SourceNone,
			Note:   "effective-policy provenance is owned by #305 and not implemented yet; values are not inferred from YAML",
		},
	}
	if uc.Availability.State == StateUnavailable {
		return out, nil
	}
	var row *fleet.AgentRow
	for i := range uc.Rows {
		if uc.Rows[i].Name == name && (tenant == "" || uc.Rows[i].TenantID == tenant) {
			r := uc.Rows[i]
			row = &r
			break
		}
	}
	if row == nil {
		return nil, fmt.Errorf("%w: use case %q", ErrNotFound, name)
	}
	out.Row = row
	scope := row.TenantID
	out.Meta = s.meta(scope)
	out.RecentSessions = s.Sessions(ctx, scope, name, "", session.Cursor{}, evidence.ObservedCursor{}, 10)
	out.Costs = s.Costs(ctx, scope, name, costs.BreakdownAgents)
	now := s.now()
	out.Activity = s.Activity(ctx, scope, name, now.Add(-DefaultActivitySpan), now, time.Hour)
	return out, nil
}

// ---------------------------------------------------------------- sessions

// Sessions is a bounded page of session-store rows plus a bounded page of
// evidence-observed session ids that have no row, each with its own keyset
// cursor. The underlying queries need one tenant; "" means the
// installation's "default" tenant and Meta names it.
func (s *Service) Sessions(ctx context.Context, tenant, agent string, status session.Status, after session.Cursor, observedAfter evidence.ObservedCursor, limit int) SessionList {
	limit = clampLimit(limit, DefaultSessionLimit, MaxSessionLimit)
	if tenant == "" {
		tenant = "default"
	}
	out := SessionList{Meta: s.meta(tenant), Sessions: []*session.Session{}, Observed: []evidence.ObservedSession{}, Limit: limit}
	if s.cfg.Sessions == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceSessionStore, Error: "session store is not open"}
	} else {
		rows, err := s.cfg.Sessions.ListRecent(ctx, tenant, agent, status, after, limit)
		switch {
		case err != nil:
			out.Availability = unavailable(SourceSessionStore, err)
		default:
			if rows != nil {
				out.Sessions = rows
			}
			out.Availability = ok(SourceSessionStore, s.now())
			if len(rows) == 0 {
				out.Availability.State = StateEmpty
			} else if len(rows) == limit {
				c := session.CursorOf(rows[len(rows)-1])
				out.NextCursor = &c
			}
		}
	}
	s.observedSessions(ctx, tenant, agent, observedAfter, limit, &out)
	return out
}

// observedSessions fills the evidence-only part of a SessionList: the
// (session id, agent) pairs seen in evidence for which no session-store row
// of THAT agent exists (ownership-aware: agent A's row for external id X
// does not hide agent B's evidence under X). When the session store cannot
// answer, the entries are still listed but the section is partial, because
// a row-backed pair cannot be told from an evidence-only one.
func (s *Service) observedSessions(ctx context.Context, tenant, agent string, after evidence.ObservedCursor, limit int, out *SessionList) {
	if s.cfg.Evidence == nil {
		out.ObservedAvailability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}
		return
	}
	observed, err := s.cfg.Evidence.ListObservedSessions(ctx, tenant, agent, after, limit)
	if err != nil {
		out.ObservedAvailability = unavailable(SourceEvidenceStore, err)
		return
	}
	ids := make([]string, 0, len(observed))
	for i := range observed {
		ids = append(ids, observed[i].SessionID)
	}
	owners, ownersErr := s.sessionOwners(ctx, tenant, ids)
	kept := make([]evidence.ObservedSession, 0, len(observed))
	for i := range observed {
		o := &observed[i]
		if ownersErr == nil && owners[o.SessionID][o.AgentID] {
			continue // this agent's share of the session has a row: the rows page owns it
		}
		kept = append(kept, *o)
	}
	out.Observed = kept
	out.ObservedAvailability = ok(SourceEvidenceStore, s.now())
	out.ObservedAvailability.Note = "(session id, agent) pairs seen in evidence without a session-store row of that agent (for example asserted on the MCP proxy path); facts are the records' own, no lifecycle is inferred"
	switch {
	case ownersErr != nil:
		out.ObservedAvailability.State = StatePartial
		out.ObservedAvailability.Unavailable = []string{"row_backed_exclusion"}
		out.ObservedAvailability.Error = ownersErr.Error()
		out.ObservedAvailability.Note = "session store unavailable: entries may also have a session-store row; none was excluded"
	case len(kept) == 0:
		out.ObservedAvailability.State = StateEmpty
	}
	if len(observed) == limit {
		last := observed[len(observed)-1]
		out.ObservedNextCursor = &evidence.ObservedCursor{LastSeen: last.LastSeen, SessionID: last.SessionID, AgentID: last.AgentID}
	}
}

// sessionOwners resolves which agents own a session row for each id, in one
// query. A nil session store is an error, not "no owners".
func (s *Service) sessionOwners(ctx context.Context, tenant string, ids []string) (map[string]map[string]bool, error) {
	if s.cfg.Sessions == nil {
		return nil, errors.New("session store is not open")
	}
	return s.cfg.Sessions.OwnersOf(ctx, tenant, ids)
}

// Session is one session's complete summary plus one timeline page. tenant
// "" is the unscoped operator read, as `talon session show` without
// --tenant. A missing session is ErrNotFound; a failing store is
// ErrUnavailable.
func (s *Service) Session(ctx context.Context, id, tenant string, after evidence.TimelineCursor, limit int) (*SessionDetail, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("%w: session id is required", ErrInvalidArgument)
	}
	limit = clampLimit(limit, DefaultTimelineLimit, MaxTimelineLimit)
	if s.cfg.Sessions == nil || s.cfg.Evidence == nil {
		return nil, fmt.Errorf("%w: session or evidence store is not open", ErrUnavailable)
	}
	detail, tl, err := session.LoadTimelinePage(ctx, s.cfg.Sessions, s.cfg.Evidence, id, tenant, after, limit)
	switch {
	case errors.Is(err, session.ErrDetailNotFound):
		return nil, fmt.Errorf("%w: session %q", ErrNotFound, id)
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	out := &SessionDetail{Meta: s.meta(tenant), Detail: detail, Timeline: tl, Availability: ok(SourceSessionStore, s.now())}
	if len(detail.Ambiguous) > 0 {
		out.Availability.Note = fmt.Sprintf("external session id matches %d sessions; open one by its internal id", len(detail.Ambiguous))
	}
	return out, nil
}

// ---------------------------------------------------------------- evidence

// Evidence is one record with its verification. A record outside tenant is
// not found, never partially shown. A failing store is ErrUnavailable, not
// a missing record.
func (s *Service) Evidence(ctx context.Context, id, tenant string) (*EvidenceDetail, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("%w: evidence id is required", ErrInvalidArgument)
	}
	if s.cfg.Evidence == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, noStoreMsg)
	}
	d, err := s.cfg.Evidence.Detail(ctx, id)
	switch {
	case errors.Is(err, evidence.ErrNotFound):
		return nil, fmt.Errorf("%w: evidence %q", ErrNotFound, id)
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if tenant != "" && d.Record.TenantID != tenant {
		return nil, fmt.Errorf("%w: evidence %q", ErrNotFound, id)
	}
	return &EvidenceDetail{Meta: s.meta(tenant), Availability: ok(SourceEvidenceStore, s.now()), Detail: d}, nil
}

// ------------------------------------------------------------------- costs

// Costs is the shared cost report for the scope. tenant "" is the
// installation's "default" tenant and Meta names it. The section is partial
// when the report names unavailable fields.
func (s *Service) Costs(ctx context.Context, tenant, agent string, breakdown costs.Breakdown) Costs {
	if tenant == "" {
		tenant = "default"
	}
	out := Costs{Meta: s.meta(tenant), BudgetNote: s.cfg.BudgetNote}
	if s.cfg.Evidence == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}
		return out
	}
	if out.BudgetNote == "" && s.cfg.Budgets == nil {
		out.BudgetNote = "no budget resolver configured: caps are not reported"
	}
	report, err := costs.Build(ctx, s.cfg.Evidence, costs.Scope{TenantID: tenant, AgentID: agent, Breakdown: breakdown}, costs.WindowAt(s.now()), s.cfg.Currency, s.cfg.Budgets)
	if err != nil {
		out.Availability = unavailable(SourceEvidenceStore, err)
		return out
	}
	out.Report = report
	out.Availability = ok(SourceEvidenceStore, s.now())
	labelPartial(&out)
	return out
}

// labelPartial turns an ok Costs section into a partial one when its report
// names fields that hold no measurement.
func labelPartial(c *Costs) {
	if c.Report == nil || len(c.Report.UnavailableFields) == 0 {
		return
	}
	c.Availability.State = StatePartial
	c.Availability.Unavailable = append([]string(nil), c.Report.UnavailableFields...)
	c.Availability.Note = strings.Join(c.Report.Warnings, "; ")
}

// ---------------------------------------------------------------- activity

// Activity is the request-class series for the window at bucket. tenant ""
// is the installation's "default" tenant and Meta names it.
func (s *Service) Activity(ctx context.Context, tenant, agent string, from, to time.Time, bucket time.Duration) Activity {
	if tenant == "" {
		tenant = "default"
	}
	out := Activity{Meta: s.meta(tenant)}
	if s.cfg.Evidence == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}
		return out
	}
	series, err := s.cfg.Evidence.ActivityBuckets(ctx, tenant, agent, from, to, bucket)
	if err != nil {
		out.Availability = unavailable(SourceEvidenceStore, err)
		return out
	}
	out.Series = series
	out.Availability = ok(SourceEvidenceStore, s.now())
	return out
}

// ------------------------------------------------------------------ system

// System is the System page.
func (s *Service) System(ctx context.Context) *System {
	out := &System{
		Meta:    s.meta(""),
		Console: Info{Version: s.cfg.Version, Commit: s.cfg.Commit, StartedAt: s.cfg.StartedAt, Currency: s.cfg.Currency},
		Store:   StoreHealth{Path: s.cfg.StorePath},
		Runtime: runtimeUnknown(),
	}
	if s.cfg.Evidence == nil {
		out.Store.Availability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}
		return out
	}
	out.Store.ReadOnly = s.cfg.Evidence.ReadOnly()
	if st, err := os.Stat(s.cfg.StorePath); err == nil {
		out.Store.SizeBytes = st.Size()
	}
	count, newest, err := s.cfg.Evidence.Stats(ctx)
	if err != nil {
		out.Store.Availability = unavailable(SourceEvidenceStore, err)
		return out
	}
	out.Store.RecordCount = count
	if !newest.IsZero() {
		n := newest
		out.Store.NewestRecord = &n
	}
	out.Store.Availability = ok(SourceEvidenceStore, s.now())
	return out
}

// ------------------------------------------------------------- fleet source

// OfflineFleetSource is the FleetSource the console uses until the runtime
// probe exists: it scans the agent configuration (agentsDir, else the
// defaultPolicy file) and the gateway config at gatewayConfigPath on every
// call and projects through fleetview.ProjectOffline over the given stores.
// A missing gateway config yields an agent-only view (as `talon agents`
// does); an invalid one is an error.
func OfflineFleetSource(agentsDir, defaultPolicy, gatewayConfigPath, currency string, ev *evidence.Store, ss *session.Store, now func() time.Time) FleetSource {
	return func(ctx context.Context, tenant string) (*fleetview.Result, string, error) {
		if ev == nil || ss == nil {
			return nil, SourceConfigFiles, errors.New("evidence or session store is not open")
		}
		scan, err := fleetview.Scan(ctx, agentsDir, defaultPolicy)
		if err != nil {
			return nil, SourceConfigFiles, err
		}
		var org gateway.OrganizationPolicy
		var providers map[string]gateway.ProviderConfig
		if gatewayConfigPath != "" {
			gw, loadErr := gateway.LoadGatewayConfig(gatewayConfigPath)
			switch {
			case loadErr == nil:
				org, providers = gw.OrganizationPolicy, gw.Providers
			case errors.Is(loadErr, os.ErrNotExist):
				// agent-only view
			default:
				return nil, SourceConfigFiles, fmt.Errorf("gateway config %s is present but invalid: %w", gatewayConfigPath, loadErr)
			}
		}
		t := time.Now().UTC()
		if now != nil {
			t = now().UTC()
		}
		res, err := fleetview.ProjectOffline(ctx, fleetview.Inputs{
			Scan: scan, Org: org, Providers: providers, Tenant: tenant, Currency: currency,
			Evidence: ev, Sessions: ss, Now: t,
		})
		if err != nil {
			return nil, SourceConfigFiles, err
		}
		return res, SourceConfigFiles, nil
	}
}

// FleetCapsBudgets resolves an agent's effective caps from the same
// fleetview projection the use-case rows come from (gateway.
// ResolveEffectivePolicy over the organization baseline and the agent's
// override), labelled config_effective_cap_offline. A tenant-wide scope has
// no single cap and resolves to none. It is the offline stand-in for the
// running server's /v1/costs/budget answer (#288), which the runtime probe
// (#538) will supply.
type FleetCapsBudgets struct{ Fleet FleetSource }

// Resolve implements costs.BudgetResolver.
func (f FleetCapsBudgets) Resolve(ctx context.Context, tenant, agent string, dailyUsed, monthlyUsed float64) (daily, monthly *costs.BudgetUsage, err error) {
	if agent == "" || f.Fleet == nil {
		return nil, nil, nil
	}
	res, _, err := f.Fleet(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	c, found := res.Caps[agent]
	if !found {
		return nil, nil, nil
	}
	const source = "config_effective_cap_offline"
	return costs.NewBudgetUsage(dailyUsed, c.Daily, source), costs.NewBudgetUsage(monthlyUsed, c.Monthly, source), nil
}

func clampLimit(limit, def, maxLimit int) int {
	if limit <= 0 {
		return def
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}
