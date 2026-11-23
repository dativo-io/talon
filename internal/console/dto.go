// Package console is the read model of the OSS operations console (#533,
// #535): typed, versioned, bounded DTOs built from the shared Go projections
// the CLI already uses — fleet.Project (via fleetview), costs.Build,
// session.LoadDetail / LoadTimelinePage, evidence.Store.Detail,
// ActivityBuckets, ListObservedSessions and events.FromEvidence. Nothing here
// computes health, budgets, decisions or session facts; it selects, scopes,
// bounds and labels.
//
// Every section carries an Availability so a consumer can tell a real zero
// from a partial, unavailable or unknown source. Live runtime facts (active
// catalog generation, reload state, collector freshness, process versions)
// are not readable from the shared store; until the runtime probe (#538)
// exists they are reported as unknown, never inferred from evidence or from
// files on disk.
package console

import (
	"time"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/costs"
	"github.com/dativo-io/talon/internal/events"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/session"
)

// ContractVersion is the version of every DTO in this package. Changes are
// additive within a version; a breaking change bumps it.
const ContractVersion = "1"

// Availability states.
const (
	StateOK          = "ok"          // the section was read from its source now
	StatePartial     = "partial"     // read, but some fields hold no measurement (see Availability.Unavailable)
	StateUnavailable = "unavailable" // the source exists but could not be read; Error says why
	StateUnknown     = "unknown"     // no source can answer yet (for example no runtime probe, #538)
	StateEmpty       = "empty"       // the source answered and holds nothing in scope (a real zero)
)

// Sources.
const (
	SourceEvidenceStore = "evidence_store"
	SourceSessionStore  = "session_store"
	SourceConfigFiles   = "config_files"
	SourceRuntimeProbe  = "runtime_probe"
	SourceNone          = "none"
)

// Tenant scopes of a DTO.
const (
	ScopeTenant     = "tenant"      // one tenant, named in Meta.TenantID
	ScopeAllTenants = "all_tenants" // every tenant of the installation
)

// Availability labels one DTO section.
type Availability struct {
	State  string    `json:"state"`
	Source string    `json:"source"`
	AsOf   time.Time `json:"as_of,omitempty"`
	Error  string    `json:"error,omitempty"`
	// Note explains a limitation of an ok/unknown section, for example that
	// the active generation needs the runtime probe.
	Note string `json:"note,omitempty"`
	// Unavailable names the fields of a partial section that hold no
	// measurement (machine-readable; the human reasons are in the section).
	Unavailable []string `json:"unavailable,omitempty"`
}

// Meta heads every top-level DTO. TenantScope says whether the whole DTO
// describes one tenant (TenantID) or every tenant; it is never implied.
type Meta struct {
	ContractVersion string    `json:"contract_version"`
	GeneratedAt     time.Time `json:"generated_at"`
	TenantScope     string    `json:"tenant_scope"`
	TenantID        string    `json:"tenant_id,omitempty"`
}

// Runtime is the live-process section (#538): the data-plane processes of
// this installation as assessed from their own runtime records (heartbeat,
// version, active catalog generation, reload rejection). Nothing in it is
// ever derived from evidence; history in the store is independent of it.
type Runtime struct {
	Availability     Availability `json:"availability"`
	ActiveGeneration string       `json:"active_generation,omitempty"`
	ActivatedAt      *time.Time   `json:"activated_at,omitempty"`
	ReadAt           time.Time    `json:"read_at,omitempty"`
	// Roles: mcp_proxy and gateway (and native when served), each running |
	// stale | offline | not_configured | unknown with the reason.
	Roles     []runtimestatus.RoleStatus `json:"roles"`
	Processes []runtimestatus.Process    `json:"processes"`
	// Rejected lists records not combined (another installation, malformed).
	Rejected []runtimestatus.Rejected `json:"rejected,omitempty"`
}

// Health bases of the attention queue.
const (
	// HealthBasisProjected: health was evaluated from persisted evidence and
	// the configuration on disk (fleet.Project). It is not a liveness verdict
	// for any process and can read HEALTHY while the data plane is down; the
	// Runtime section says what is known about the process.
	HealthBasisProjected = "projected_from_store"
	// HealthBasisRuntime: health came from the running process (#538).
	HealthBasisRuntime = "runtime"
)

// UseCases is the attention queue: fleet.AgentRow unchanged, in the CLI's
// order (health rank, then name).
type UseCases struct {
	Availability Availability              `json:"availability"`
	HealthBasis  string                    `json:"health_basis"`
	Rows         []fleet.AgentRow          `json:"rows"`
	Issues       []agentcatalog.FleetIssue `json:"issues"`
	// Attention is the subset of Rows whose health is not healthy, same order.
	Attention []fleet.AgentRow `json:"attention"`
	Runtime   Runtime          `json:"runtime"`
	// CounterWindows are the rolling windows of the row counters (requests,
	// denied, fallbacks, failed_sessions); spend_* use UTC day and month.
	CounterWindows CounterWindows `json:"counter_windows"`
	// Approvals are the per-use-case approval counts on the AI Use Cases
	// page (#565). Kept apart from Rows: fleet health is not redefined by
	// an approval waiting for a person. Empty on the embedded copy inside
	// Overview, which carries its own Approvals section.
	Approvals ApprovalsSummary `json:"approvals"`
}

// CounterWindows are Go duration strings ("1h0m0s").
type CounterWindows struct {
	RequestsDenied string `json:"requests_denied"`
	Fallbacks      string `json:"fallbacks"`
	FailedSessions string `json:"failed_sessions"`
}

// Today is the UTC-day traffic and spend of the DTO's tenant scope.
type Today struct {
	Availability Availability       `json:"availability"`
	TenantScope  string             `json:"tenant_scope"`
	Window       costs.WindowBounds `json:"window"`
	// Requests/Denied count request-class records (the fleet denominator).
	Requests int `json:"requests"`
	Denied   int `json:"denied"`
	// Cost sums execution.cost over every record class (the costs/status
	// denominator) in Currency.
	Cost     float64 `json:"cost"`
	Currency string  `json:"currency"`
	Scope    string  `json:"scope"` // "requests: request_class; cost: all_record_classes"
}

// RecentEvents is the bounded operational-event feed (events.FromEvidence),
// newest first, with the cursor of the newest event.
type RecentEvents struct {
	Availability Availability              `json:"availability"`
	TenantScope  string                    `json:"tenant_scope"`
	Events       []events.OperationalEvent `json:"events"`
	Cursor       string                    `json:"cursor,omitempty"`
	Limit        int                       `json:"limit"`
}

// Overview is the Overview page. UseCases, Today and RecentEvents share
// Meta's tenant scope; Readiness is installation-wide (Readiness.Scope) and
// no tenant scope filters it, so a tenant view never hides a shared outage.
type Overview struct {
	Meta         Meta         `json:"meta"`
	Readiness    Readiness    `json:"readiness"`
	UseCases     UseCases     `json:"use_cases"`
	Today        Today        `json:"today"`
	RecentEvents RecentEvents `json:"recent_events"`
	// Approvals counts the unresolved Action Gateway approvals of Meta's
	// tenant scope (#565): stored counts and inferred eligibility, apart.
	Approvals ApprovalsSummary `json:"approvals"`
	// Findings are the installation findings, the canonical fleet rows that
	// are not healthy and the use cases with approvals that may await a
	// decision (in Meta's tenant scope), most urgent first.
	Findings []Finding `json:"findings"`
}

// UseCaseDetail is one AI use case.
type UseCaseDetail struct {
	Meta           Meta            `json:"meta"`
	Row            *fleet.AgentRow `json:"row"`
	Availability   Availability    `json:"availability"`
	HealthBasis    string          `json:"health_basis"`
	CounterWindows CounterWindows  `json:"counter_windows"`
	Runtime        Runtime         `json:"runtime"`
	RecentSessions SessionList     `json:"recent_sessions"`
	Costs          Costs           `json:"costs"`
	Activity       Activity        `json:"activity"`
	// EffectivePolicy points at the per-use-case effective-policy report
	// (#305, /console/v1/use-cases/{name}/effective-policy).
	EffectivePolicy Availability `json:"effective_policy"`
	// Readiness is the installation's (#533): it applies to this use case
	// as to every other. Findings are the installation findings plus this
	// use case's own canonical fleet finding, most urgent first.
	Readiness Readiness `json:"readiness"`
	Findings  []Finding `json:"findings"`
	// Approvals are this use case's approval counts (#565).
	Approvals ApprovalsSummary `json:"approvals"`
	// RecentDecisions are this use case's newest records with their outcome.
	RecentDecisions DecisionList `json:"recent_decisions"`
	// Issues are configuration issues the catalog attributes to this name
	// (for example a duplicated name).
	Issues []agentcatalog.FleetIssue `json:"issues"`
}

// DecisionList is a bounded list of evidence index rows (evidence.IndexOf,
// each with evidence.OutcomeOf), newest first.
type DecisionList struct {
	Availability Availability     `json:"availability"`
	Records      []evidence.Index `json:"records"`
	Limit        int              `json:"limit"`
	// Truncated: more records exist than Limit; Records is a part of them
	// (Availability says which part and how to read all of them).
	Truncated bool `json:"truncated,omitempty"`
}

// SessionList is a bounded page of sessions from two sources, each with its
// own keyset cursor: session-store rows (lifecycle state Talon tracks) and
// evidence-observed session ids that have no row (for example asserted on
// the MCP proxy path). Observed entries carry only what their records say;
// no lifecycle is fabricated for them.
type SessionList struct {
	Meta         Meta               `json:"meta"`
	Availability Availability       `json:"availability"`
	Sessions     []*session.Session `json:"sessions"`
	Limit        int                `json:"limit"`
	NextCursor   *session.Cursor    `json:"next_cursor,omitempty"`

	ObservedAvailability Availability               `json:"observed_availability"`
	Observed             []evidence.ObservedSession `json:"observed"`
	ObservedNextCursor   *evidence.ObservedCursor   `json:"observed_next_cursor,omitempty"`
}

// SessionDetail is session.Detail (complete summary) plus ONE page of the
// timeline (session.LoadTimelinePage), as `talon session show --json` and
// `talon audit list --session --json` emit them.
type SessionDetail struct {
	Meta         Meta              `json:"meta"`
	Availability Availability      `json:"availability"`
	Detail       *session.Detail   `json:"detail,omitempty"`
	Timeline     *session.Timeline `json:"timeline,omitempty"`
}

// EvidenceDetail is evidence.RecordDetail under the console's operational
// disclosure: the record and the verification performed for this read.
type EvidenceDetail struct {
	Meta         Meta                  `json:"meta"`
	Availability Availability          `json:"availability"`
	Detail       *EvidenceRecordDetail `json:"detail,omitempty"`
}

// EvidenceRecordDetail is the stored record as the console returns it. The
// verification is the one performed over the COMPLETE stored record. The
// record itself is complete except for the fields listed in Withheld (#565):
// a paired browser is not a reviewer, and the one free text a person writes
// into signed evidence, an approval decision's reason, can quote the exact
// arguments. The signed record is never modified; `talon audit show` on the
// installation's host and the reviewer API return the complete record.
type EvidenceRecordDetail struct {
	*evidence.RecordDetail
	Withheld []WithheldField `json:"withheld,omitempty"`
	// InstallationEvent marks Talon's own installation-level record
	// (evidence.IsInstallationEvent): its agent_id names a Talon process,
	// not an AI use case, and its tenant_id is the reserved installation
	// namespace, not a tenant (#593).
	InstallationEvent bool `json:"installation_event,omitempty"`
}

// WithheldField names one field of the stored record that this view does
// not return, why, and how an authorized reader reads it.
type WithheldField struct {
	Field    string `json:"field"`
	Why      string `json:"why"`
	ReadWith string `json:"read_with,omitempty"`
}

// Costs is costs.Report with its availability: partial when the report names
// unavailable fields. Budgets inside the report are resolved by the
// Service's BudgetResolver; BudgetNote states what resolved them.
type Costs struct {
	Meta         Meta          `json:"meta"`
	Availability Availability  `json:"availability"`
	Report       *costs.Report `json:"report,omitempty"`
	BudgetNote   string        `json:"budget_note,omitempty"`
}

// Activity is evidence.ActivitySeries with its availability.
type Activity struct {
	Meta         Meta                     `json:"meta"`
	Availability Availability             `json:"availability"`
	Series       *evidence.ActivitySeries `json:"series,omitempty"`
}

// StoreHealth describes the shared store as the console sees it: facts the
// file itself yields, never the writer process's in-memory write status.
type StoreHealth struct {
	Availability Availability `json:"availability"`
	Path         string       `json:"path"`
	ReadOnly     bool         `json:"read_only"`
	SizeBytes    int64        `json:"size_bytes"`
	RecordCount  int          `json:"record_count"`
	NewestRecord *time.Time   `json:"newest_record,omitempty"`
}

// System is the System page.
type System struct {
	Meta      Meta        `json:"meta"`
	Console   Info        `json:"console"`
	Store     StoreHealth `json:"store"`
	Runtime   Runtime     `json:"runtime"`
	Readiness Readiness   `json:"readiness"`
	// InstallationActivity lists Talon's own installation events (#593).
	InstallationActivity InstallationActivity `json:"installation_activity"`
}

// InstallationActivity is the newest installation events, newest first:
// configuration reloads activated or rejected by talon serve, recovery
// resumes by talon backup, and legacy talon enforce mode changes. Each links
// its signed record. They are installation-wide: no tenant scope applies,
// and none of them is AI use case traffic.
type InstallationActivity struct {
	Availability Availability        `json:"availability"`
	Events       []InstallationEvent `json:"events"`
	Limit        int                 `json:"limit"`
}

// InstallationEvent is one installation event as its signed record states
// it. Reasons are the record's own policy_decision.reasons, written by Talon
// (reload causes, the backups a resume covered) — not the request-oriented
// explanations of an AI use case decision.
type InstallationEvent struct {
	EvidenceID     string    `json:"evidence_id"`
	Timestamp      time.Time `json:"timestamp"`
	InvocationType string    `json:"invocation_type"`
	// RecordedBy is the record's agent_id: the Talon process that wrote it
	// (talon-serve, talon-backup, talon-cli), never an AI use case.
	RecordedBy string   `json:"recorded_by"`
	Allowed    bool     `json:"allowed"`
	Reasons    []string `json:"reasons,omitempty"`
}

// Info identifies the console process itself.
type Info struct {
	Version   string    `json:"version"`
	Commit    string    `json:"commit,omitempty"`
	StartedAt time.Time `json:"started_at"`
	Currency  string    `json:"currency"`
}
