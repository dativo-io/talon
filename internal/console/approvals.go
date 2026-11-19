package console

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// Approval visibility in the read-only console (#565).
//
// The console shows that approvals exist, why they are required and what
// happened to them. It decides nothing and shows no argument value: every
// view here is action.BuildApprovalView / action.SummarizeApproval under
// the OPERATIONAL disclosure (argument names only), read through
// action.Reader (SELECTs only, on the console's read-only connection).
// A paired browser is not a reviewer, and the tenant parameter is a filter,
// not an authorization boundary; exact values are read with an approver
// credential through `talon approvals show`.
//
// "The configuration now" is what the current FILES compile to
// (effective.BuildActionConfigs). An approval reads "actionable" only when
// every running `talon serve` is proven to have loaded exactly those
// files; otherwise it reads "potentially actionable (per current files)",
// and "unknown" where the files cannot say. Stored facts (an approval is
// unresolved, its lifetime elapsed) need no configuration and are kept
// apart from those inferences in every count.

// SourceActionStore names the action tables of the evidence database.
const SourceActionStore = "action_store"

// ApprovalCounts separates what the store holds from what is inferred.
type ApprovalCounts struct {
	// Unresolved is the number of approvals pending in the store: a
	// persisted fact, exact, independent of any configuration.
	Unresolved int `json:"unresolved"`
	// Eligibility classifies those approvals against the current
	// configuration files. nil when the classification could not be
	// established for all of them (the counts are then not reported, never
	// reported as zero).
	Eligibility *ApprovalEligibilityCounts `json:"eligibility,omitempty"`
}

// ApprovalEligibilityCounts sum to ApprovalCounts.Unresolved.
type ApprovalEligibilityCounts struct {
	// Actionable: eligible, and every running process is proven to have
	// loaded the files this was computed from.
	Actionable int `json:"actionable"`
	// PotentiallyActionable: eligible according to the current files only.
	PotentiallyActionable int `json:"potentially_actionable"`
	// NotDecidable: lifetime elapsed, or bound to a policy or action
	// definition that changed.
	NotDecidable int `json:"not_decidable"`
	// Unknown: eligibility cannot be established from the files.
	Unknown int `json:"unknown"`
}

// Attention is the number of unresolved approvals that are not known to be
// undecidable.
func (c ApprovalEligibilityCounts) Attention() int {
	return c.Actionable + c.PotentiallyActionable + c.Unknown
}

// UseCaseApprovals are one use case's counts.
type UseCaseApprovals struct {
	TenantID string `json:"tenant_id"`
	UseCase  string `json:"use_case"`
	ApprovalCounts
}

// ApprovalsSummary is the approval section of the Overview and AI Use Cases
// pages, in the DTO's tenant scope.
type ApprovalsSummary struct {
	Availability Availability `json:"availability"`
	// Total is nil when the store could not be read.
	Total    *ApprovalCounts    `json:"total,omitempty"`
	UseCases []UseCaseApprovals `json:"use_cases"`
	// Basis says what the eligibility counts rest on.
	Basis string `json:"basis"`
}

const approvalsBasis = "unresolved counts are read from the store; eligibility is inferred from the current configuration files and is 'actionable' only where every running Talon process is proven to have loaded them"

// ApprovalList is one page of the Approvals page.
type ApprovalList struct {
	Meta         Meta                     `json:"meta"`
	Availability Availability             `json:"availability"`
	State        string                   `json:"state"`
	UseCase      string                   `json:"use_case,omitempty"`
	Items        []action.ApprovalSummary `json:"items"`
	Next         string                   `json:"next,omitempty"`
	Limit        int                      `json:"limit"`
	Disclosure   string                   `json:"disclosure"`
}

// ApprovalDetail is one approval for the console.
type ApprovalDetail struct {
	Meta         Meta                 `json:"meta"`
	Availability Availability         `json:"availability"`
	Approval     *action.ApprovalView `json:"approval"`
	// Lifecycle are the operation's signed evidence records, oldest first
	// (the rows `talon audit list` prints); each links to its evidence page.
	Lifecycle DecisionList `json:"lifecycle"`
	// SessionID is the client-asserted session the operation was
	// established in, when it recorded one.
	SessionID string `json:"session_id,omitempty"`
	// Commands are the CLI commands for an approver, with the complete
	// approval id. The console itself offers no decision.
	Commands ApprovalCommands `json:"commands"`
	// ArgumentsNote states why no value is shown.
	ArgumentsNote string `json:"arguments_note"`
}

// ApprovalCommands are copyable commands; none carries a credential.
type ApprovalCommands struct {
	Show    string `json:"show"`
	Approve string `json:"approve,omitempty"`
	Reject  string `json:"reject,omitempty"`
	Verify  string `json:"verify"`
}

const argumentsNote = "The console shows argument names only. Exact values are read by an approver of the required group with: talon approvals show <approval-id> (credential in TALON_APPROVER_KEY)."

func (s *Service) actionReader() (*action.Reader, *Availability) {
	if s.cfg.Evidence == nil {
		return nil, &Availability{State: StateUnavailable, Source: SourceActionStore, Error: noStoreMsg}
	}
	return action.NewReader(s.cfg.Evidence.DB()), nil
}

// actionConfigs compiles the action configuration of every use case from
// the console's configuration files, with the runtime proof.
func (s *Service) actionConfigs(ctx context.Context, rt Runtime) *effective.ActionConfigs {
	src := s.cfg.ConfigSources
	in := effective.Inputs{AgentsDir: src.AgentsDir, DefaultPolicy: src.DefaultPolicy, GatewayConfig: src.GatewayConfig, Now: s.now()}
	if rt.Availability.State == StateOK || rt.Availability.State == StateUnavailable {
		view := runtimestatus.View{Processes: rt.Processes}
		in.Runtime, in.RuntimeReadable = &view, rt.Availability.State == StateOK
	}
	return effective.BuildActionConfigs(ctx, in)
}

// approvalsSummary counts the unresolved approvals of the tenant scope.
// The stored totals come from one grouped query over all rows; the
// eligibility classes come from a second one grouped by what eligibility
// depends on, classified once per group.
func (s *Service) approvalsSummary(ctx context.Context, tenant string, rt Runtime) ApprovalsSummary {
	out := ApprovalsSummary{UseCases: []UseCaseApprovals{}, Basis: approvalsBasis}
	reader, missing := s.actionReader()
	if missing != nil {
		out.Availability = *missing
		return out
	}
	ready, err := reader.Ready(ctx)
	if err != nil {
		out.Availability = unavailable(SourceActionStore, err)
		return out
	}
	if !ready {
		out.Availability = Availability{State: StateEmpty, Source: SourceActionStore, AsOf: s.now(), Note: "this installation has not established any governed action yet"}
		out.Total = &ApprovalCounts{Eligibility: &ApprovalEligibilityCounts{}}
		return out
	}
	now := s.now()
	stored, err := reader.UnresolvedByUseCase(ctx, tenant)
	if err != nil {
		out.Availability = unavailable(SourceActionStore, err)
		return out
	}
	groups, complete, err := reader.UnresolvedGroups(ctx, tenant, now)
	if err != nil {
		out.Availability = unavailable(SourceActionStore, err)
		return out
	}
	out.Availability = ok(SourceActionStore, now)
	byUC := map[string]*ApprovalEligibilityCounts{}
	if complete {
		cfgs := s.actionConfigs(ctx, rt)
		for _, g := range groups {
			key := g.Tenant + "\x00" + g.UseCase
			c := byUC[key]
			if c == nil {
				c = &ApprovalEligibilityCounts{}
				byUC[key] = c
			}
			c.NotDecidable += g.Expired
			addClass(c, g.Eligibility(cfgs.For(g.Tenant, g.UseCase), now).Class, g.Unresolved-g.Expired)
		}
	} else {
		out.Availability.State = StatePartial
		out.Availability.Unavailable = []string{"total.eligibility", "use_cases[].eligibility"}
		out.Availability.Note = "too many distinct approval bindings to classify in one request; the unresolved counts are exact, the eligibility counts are not reported"
	}
	total := ApprovalCounts{}
	if complete {
		total.Eligibility = &ApprovalEligibilityCounts{}
	}
	for _, u := range stored {
		row := UseCaseApprovals{TenantID: u.Tenant, UseCase: u.UseCase, ApprovalCounts: ApprovalCounts{Unresolved: u.Unresolved}}
		total.Unresolved += u.Unresolved
		if c := byUC[u.Tenant+"\x00"+u.UseCase]; complete && c != nil {
			row.Eligibility = c
			total.Eligibility.Actionable += c.Actionable
			total.Eligibility.PotentiallyActionable += c.PotentiallyActionable
			total.Eligibility.NotDecidable += c.NotDecidable
			total.Eligibility.Unknown += c.Unknown
		}
		out.UseCases = append(out.UseCases, row)
	}
	out.Total = &total
	if total.Unresolved == 0 {
		out.Availability.State = StateEmpty
	}
	return out
}

// useCaseApprovals narrows the tenant's summary to one use case.
func (s *Service) useCaseApprovals(ctx context.Context, tenant, name string, rt Runtime) ApprovalsSummary {
	sum := s.approvalsSummary(ctx, tenant, rt)
	rows := []UseCaseApprovals{}
	var total *ApprovalCounts
	if sum.Total != nil {
		total = &ApprovalCounts{}
		if sum.Total.Eligibility != nil {
			total.Eligibility = &ApprovalEligibilityCounts{}
		}
	}
	for _, u := range sum.UseCases {
		if u.UseCase == name && u.TenantID == tenant {
			rows = append(rows, u)
			c := u.ApprovalCounts
			total = &c
		}
	}
	sum.UseCases, sum.Total = rows, total
	if total != nil && total.Unresolved == 0 && sum.Availability.State == StateOK {
		sum.Availability.State = StateEmpty
	}
	return sum
}

func addClass(c *ApprovalEligibilityCounts, class string, n int) {
	switch class {
	case action.ClassActionable:
		c.Actionable += n
	case action.ClassPotentiallyActionable:
		c.PotentiallyActionable += n
	case action.ClassNotDecidable:
		c.NotDecidable += n
	default:
		c.Unknown += n
	}
}

// approvalFindings: one finding per use case with unresolved approvals
// that are not known to be undecidable. An approval waiting for a person is
// work to do, not a fault: severity info. The wording keeps the stored
// count and the inferred classes apart.
func approvalFindings(sum ApprovalsSummary, now time.Time) []Finding {
	out := []Finding{}
	for _, u := range sum.UseCases {
		if u.Unresolved == 0 {
			continue
		}
		t := now.UTC()
		f := Finding{
			Severity: SeverityInfo, Code: "approvals_unresolved", Scope: FindingUseCase,
			Affected: fmt.Sprintf("AI use case %s (tenant %s)", u.UseCase, u.TenantID),
			Source:   SourceActionStore, ObservedAt: &t,
			Link:     "/approvals?tenant=" + url.QueryEscape(u.TenantID) + "&use_case=" + url.QueryEscape(u.UseCase),
			TenantID: u.TenantID, UseCase: u.UseCase,
		}
		switch e := u.Eligibility; {
		case e == nil:
			f.Title = fmt.Sprintf("%s: %s unresolved", u.UseCase, plural(u.Unresolved, "approval"))
			f.Why = "the store holds unresolved approvals; whether they can still be decided could not be established"
		case e.Attention() == 0:
			continue
		default:
			f.Code = "approvals_awaiting_decision"
			f.Title = fmt.Sprintf("%s: %s may await a decision", u.UseCase, plural(e.Attention(), "approval"))
			if e.Actionable == e.Attention() {
				f.Title = fmt.Sprintf("%s: %s await a decision", u.UseCase, plural(e.Attention(), "approval"))
			}
			f.Why = approvalWhy(u.Unresolved, *e)
		}
		out = append(out, f)
	}
	return out
}

func approvalWhy(unresolved int, e ApprovalEligibilityCounts) string {
	parts := []string{fmt.Sprintf("%d unresolved in the store", unresolved)}
	if e.Actionable > 0 {
		parts = append(parts, fmt.Sprintf("%d can be decided now (the running process loaded the configuration they were established under)", e.Actionable))
	}
	if e.PotentiallyActionable > 0 {
		parts = append(parts, fmt.Sprintf("%d eligible according to the current configuration files (not proven to be what a running process enforces)", e.PotentiallyActionable))
	}
	if e.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d of unknown eligibility", e.Unknown))
	}
	if e.NotDecidable > 0 {
		parts = append(parts, fmt.Sprintf("%d can no longer be decided (expired or stale)", e.NotDecidable))
	}
	return strings.Join(parts, "; ") + ". A decision is taken with an approver credential: talon approvals list"
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// Approvals is one page of approvals in the tenant scope ("" = every
// tenant), optionally of one use case. state is attention (default),
// unresolved or decided (action.Select*).
func (s *Service) Approvals(ctx context.Context, tenant, useCase, state, after string, limit int) (*ApprovalList, error) {
	if state == "" {
		state = action.SelectAttention
	}
	if !action.ValidSelection(state) {
		return nil, fmt.Errorf("%w: state must be attention, unresolved or decided", ErrInvalidArgument)
	}
	limit = clampLimit(limit, 50, action.MaxApprovalList)
	out := &ApprovalList{Meta: s.meta(tenant), State: state, UseCase: useCase, Items: []action.ApprovalSummary{}, Limit: limit, Disclosure: action.DiscloseOperational.String()}
	reader, missing := s.actionReader()
	if missing != nil {
		out.Availability = *missing
		return out, nil
	}
	ready, err := reader.Ready(ctx)
	if err != nil {
		out.Availability = unavailable(SourceActionStore, err)
		return out, nil
	}
	if !ready {
		out.Availability = Availability{State: StateEmpty, Source: SourceActionStore, AsOf: s.now(), Note: "this installation has not established any governed action yet"}
		return out, nil
	}
	cfgs := s.actionConfigs(ctx, s.runtime())
	page, err := reader.ListApprovals(ctx, action.ApprovalListQuery{
		Tenant: tenant, UseCase: useCase, Selection: state, Limit: limit, After: after, Now: s.now(), Config: cfgs.For,
	})
	switch {
	case errors.Is(err, action.ErrInvalidListQuery):
		return nil, fmt.Errorf("%w: the after cursor is not one this listing returned", ErrInvalidArgument)
	case err != nil:
		out.Availability = unavailable(SourceActionStore, err)
		return out, nil
	}
	out.Items, out.Next = page.Items, page.Next
	out.Availability = ok(SourceActionStore, s.now())
	out.Availability.Note = approvalsBasis
	if len(out.Items) == 0 {
		out.Availability.State = StateEmpty
	}
	return out, nil
}

// Approval is one approval under the operational disclosure. tenant "" is
// every tenant; a named tenant narrows the lookup (a filter: a paired
// browser can read every tenant of the installation).
func (s *Service) Approval(ctx context.Context, tenant, id string) (*ApprovalDetail, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("%w: approval id is required", ErrInvalidArgument)
	}
	reader, missing := s.actionReader()
	if missing != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, missing.Error)
	}
	ready, err := reader.Ready(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the action store", ErrUnavailable)
	}
	if !ready {
		return nil, fmt.Errorf("%w: approval", ErrNotFound)
	}
	rec, err := reader.ApprovalRecord(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the action store", ErrUnavailable)
	}
	if rec == nil || (tenant != "" && rec.Operation.TenantID != tenant) {
		return nil, fmt.Errorf("%w: approval", ErrNotFound)
	}
	op := rec.Operation
	cfg := s.actionConfigs(ctx, s.runtime()).For(op.TenantID, op.AgentID)
	view := action.BuildApprovalView(rec, cfg, action.DiscloseOperational, s.now())
	out := &ApprovalDetail{
		Meta: s.meta(op.TenantID), Availability: ok(SourceActionStore, s.now()), Approval: view,
		Lifecycle: s.lifecycle(ctx, op.TenantID, op.Ref), ArgumentsNote: argumentsNote,
		Commands: ApprovalCommands{
			Show:   "talon approvals show " + view.ApprovalID,
			Verify: "talon audit verify --operation " + op.OperationID + " --tenant " + op.TenantID,
		},
	}
	out.Availability.Note = approvalsBasis
	if view.Unresolved && view.Eligibility.NeedsAttention() {
		out.Commands.Approve = "talon approvals approve " + view.ApprovalID + ` --reason "..."`
		out.Commands.Reject = "talon approvals reject " + view.ApprovalID + ` --reason "..."`
	}
	if view.Operation.Origin != nil {
		out.SessionID = view.Operation.Origin["session_id"]
	}
	return out, nil
}

// maxLifecycleRecords bounds the lifecycle list of one approval.
const maxLifecycleRecords = 50

// lifecycle lists the operation's evidence records as index rows, oldest
// first. They are the signed records `talon audit verify --operation`
// checks; a lifecycle record never carries an argument value.
func (s *Service) lifecycle(ctx context.Context, tenant, opRef string) DecisionList {
	out := DecisionList{Records: []evidence.Index{}, Limit: maxLifecycleRecords}
	records, err := s.cfg.Evidence.ListByCorrelationIDLimit(ctx, opRef, tenant, maxLifecycleRecords)
	if err != nil {
		out.Availability = unavailable(SourceEvidenceStore, err)
		return out
	}
	for _, r := range records {
		out.Records = append(out.Records, evidence.IndexOf(r))
	}
	sort.SliceStable(out.Records, func(i, j int) bool {
		if !out.Records[i].Timestamp.Equal(out.Records[j].Timestamp) {
			return out.Records[i].Timestamp.Before(out.Records[j].Timestamp)
		}
		return out.Records[i].ID < out.Records[j].ID
	})
	out.Availability = ok(SourceEvidenceStore, s.now())
	if len(out.Records) == 0 {
		out.Availability.State = StateEmpty
	}
	return out
}
