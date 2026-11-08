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
)

// Bounds of the list endpoints.
const (
	DefaultSessionLimit = 50
	MaxSessionLimit     = 200
	DefaultEventsLimit  = 50
	MaxEventsLimit      = 500
	DefaultActivitySpan = 24 * time.Hour
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
	Currency  string // the active pricing table's ISO-4217 code
	Fleet     FleetSource
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
// broken-store behaviour, not an error.
func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = cfg.Now()
	}
	if cfg.Currency == "" {
		cfg.Currency = "USD"
	}
	return &Service{cfg: cfg}
}

func (s *Service) now() time.Time { return s.cfg.Now().UTC() }

func (s *Service) meta(tenant string) Meta {
	return Meta{ContractVersion: ContractVersion, GeneratedAt: s.now(), TenantID: tenant}
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

// Overview builds the Overview page for tenant ("" = every tenant for the
// use-case rows; "default" for the day totals and events, which are
// tenant-scoped queries).
func (s *Service) Overview(ctx context.Context, tenant string) *Overview {
	scopeTenant := tenant
	if scopeTenant == "" {
		scopeTenant = "default"
	}
	return &Overview{
		Meta:         s.meta(tenant),
		UseCases:     s.useCases(ctx, tenant),
		Today:        s.today(ctx, scopeTenant),
		RecentEvents: s.recentEvents(ctx, scopeTenant, DefaultEventsLimit),
	}
}

func (s *Service) useCases(ctx context.Context, tenant string) UseCases {
	out := UseCases{Rows: []fleet.AgentRow{}, Attention: []fleet.AgentRow{}, Runtime: runtimeUnknown()}
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
		out.Availability.Note = "projected from the agent configuration on disk and the shared stores; the running process's generation is unknown until the runtime probe exists (#538)"
	}
	if res.Rows != nil {
		out.Rows = res.Rows
	}
	out.Issues = res.Issues
	if out.Issues == nil {
		out.Issues = []agentcatalog.FleetIssue{}
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
		Window:   costs.WindowBounds{DayStart: w.DayStart, DayEnd: w.DayEnd, MonthStart: w.MonthStart, MonthEnd: w.MonthEnd, WeekStart: w.WeekStart, WeekEnd: w.DayEnd},
		Currency: s.cfg.Currency,
		Scope:    "requests: request_class; cost: all_record_classes",
	}
	if s.cfg.Evidence == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}
		return out
	}
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
	out := RecentEvents{Events: []events.OperationalEvent{}, Limit: limit}
	if s.cfg.Evidence == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}
		return out
	}
	// Same recipe as GET /api/v1/events/recent: over-fetch, project, sort
	// newest first, cut to the limit.
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

// UseCase is one use case with its recent sessions, costs and activity.
func (s *Service) UseCase(ctx context.Context, tenant, name string) (*UseCaseDetail, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: use case name is required", ErrInvalidArgument)
	}
	uc := s.useCases(ctx, tenant)
	out := &UseCaseDetail{
		Meta:         s.meta(tenant),
		Availability: uc.Availability,
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
	out.RecentSessions = s.Sessions(ctx, scope, name, "", time.Time{}, 10)
	out.Costs = s.Costs(ctx, scope, name, costs.BreakdownAgents)
	now := s.now()
	out.Activity = s.Activity(ctx, scope, name, now.Add(-DefaultActivitySpan), now, time.Hour)
	return out, nil
}

// ---------------------------------------------------------------- sessions

// Sessions is a bounded page of session rows.
func (s *Service) Sessions(ctx context.Context, tenant, agent string, status session.Status, before time.Time, limit int) SessionList {
	limit = clampLimit(limit, DefaultSessionLimit, MaxSessionLimit)
	if tenant == "" {
		tenant = "default"
	}
	out := SessionList{Meta: s.meta(tenant), Sessions: []*session.Session{}, Limit: limit}
	if s.cfg.Sessions == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceSessionStore, Error: "session store is not open"}
		return out
	}
	rows, err := s.cfg.Sessions.ListRecent(ctx, tenant, agent, status, before, limit)
	if err != nil {
		out.Availability = unavailable(SourceSessionStore, err)
		return out
	}
	if rows != nil {
		out.Sessions = rows
	}
	out.Availability = ok(SourceSessionStore, s.now())
	if len(rows) == 0 {
		out.Availability.State = StateEmpty
	} else if len(rows) == limit {
		last := rows[len(rows)-1].CreatedAt
		out.NextBefore = &last
	}
	return out
}

// Session is one session's detail and timeline. tenant "" is the unscoped
// operator read, as `talon session show` without --tenant.
func (s *Service) Session(ctx context.Context, id, tenant string) (*SessionDetail, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("%w: session id is required", ErrInvalidArgument)
	}
	out := &SessionDetail{Meta: s.meta(tenant)}
	if s.cfg.Sessions == nil || s.cfg.Evidence == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceSessionStore, Error: "session or evidence store is not open"}
		return out, nil
	}
	detail, tl, err := session.LoadTimeline(ctx, s.cfg.Sessions, s.cfg.Evidence, id, tenant)
	switch {
	case errors.Is(err, session.ErrDetailNotFound):
		return nil, fmt.Errorf("%w: session %q", ErrNotFound, id)
	case err != nil:
		out.Availability = unavailable(SourceSessionStore, err)
		return out, nil
	}
	out.Detail = detail
	out.Timeline = tl
	out.Availability = ok(SourceSessionStore, s.now())
	if len(detail.Ambiguous) > 0 {
		out.Availability.Note = fmt.Sprintf("external session id matches %d sessions; open one by its internal id", len(detail.Ambiguous))
	}
	return out, nil
}

// ---------------------------------------------------------------- evidence

// Evidence is one record with its verification. A record outside tenant is
// not found, never partially shown.
func (s *Service) Evidence(ctx context.Context, id, tenant string) (*EvidenceDetail, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("%w: evidence id is required", ErrInvalidArgument)
	}
	out := &EvidenceDetail{Meta: s.meta(tenant)}
	if s.cfg.Evidence == nil {
		out.Availability = Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}
		return out, nil
	}
	d, err := s.cfg.Evidence.Detail(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w: evidence %q", ErrNotFound, id)
	}
	if tenant != "" && d.Record.TenantID != tenant {
		return nil, fmt.Errorf("%w: evidence %q", ErrNotFound, id)
	}
	out.Detail = d
	out.Availability = ok(SourceEvidenceStore, s.now())
	return out, nil
}

// ------------------------------------------------------------------- costs

// Costs is the shared cost report for the scope.
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
	return out
}

// ---------------------------------------------------------------- activity

// Activity is the request-class series for the window at bucket.
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
