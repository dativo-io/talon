// Package console is the read model of the OSS operations console (#533,
// #535): typed, versioned, bounded DTOs built from the shared Go projections
// the CLI already uses — fleet.Project (via fleetview), costs.Build,
// session.LoadDetail / BuildTimeline, evidence.Store.Detail, ActivityBuckets
// and events.FromEvidence. Nothing here computes health, budgets, decisions
// or session facts; it selects, scopes, bounds and labels.
//
// Every section carries an Availability so a consumer can tell a real zero
// from an unavailable or unknown source. Live runtime facts (active catalog
// generation, reload state, collector freshness, process versions) are not
// readable from the shared store; until the runtime probe (#538) exists they
// are reported as unknown, never inferred from evidence or from files on disk.
package console

import (
	"time"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/costs"
	"github.com/dativo-io/talon/internal/events"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/session"
)

// ContractVersion is the version of every DTO in this package. Changes are
// additive within a version; a breaking change bumps it.
const ContractVersion = "1"

// Availability states.
const (
	StateOK          = "ok"          // the section was read from its source now
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

// Availability labels one DTO section.
type Availability struct {
	State  string    `json:"state"`
	Source string    `json:"source"`
	AsOf   time.Time `json:"as_of,omitempty"`
	Error  string    `json:"error,omitempty"`
	// Note explains a limitation of an ok/unknown section, for example that
	// the active generation needs the runtime probe.
	Note string `json:"note,omitempty"`
}

// Meta heads every top-level DTO.
type Meta struct {
	ContractVersion string    `json:"contract_version"`
	GeneratedAt     time.Time `json:"generated_at"`
	TenantID        string    `json:"tenant_id,omitempty"`
}

// Runtime is the live-process section (#538). Until a probe exists it is
// StateUnknown with a note; nothing in it is ever derived from evidence.
type Runtime struct {
	Availability     Availability `json:"availability"`
	ActiveGeneration string       `json:"active_generation,omitempty"`
	ActivatedAt      *time.Time   `json:"activated_at,omitempty"`
}

// UseCases is the attention queue: fleet.AgentRow unchanged, in the CLI's
// order (health rank, then name).
type UseCases struct {
	Availability Availability              `json:"availability"`
	Rows         []fleet.AgentRow          `json:"rows"`
	Issues       []agentcatalog.FleetIssue `json:"issues"`
	// Attention is the subset of Rows whose health is not healthy, same order.
	Attention []fleet.AgentRow `json:"attention"`
	Runtime   Runtime          `json:"runtime"`
}

// Today is the UTC-day traffic and spend of the tenant.
type Today struct {
	Availability Availability       `json:"availability"`
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
	Events       []events.OperationalEvent `json:"events"`
	Cursor       string                    `json:"cursor,omitempty"`
	Limit        int                       `json:"limit"`
}

// Overview is the Overview page.
type Overview struct {
	Meta         Meta         `json:"meta"`
	UseCases     UseCases     `json:"use_cases"`
	Today        Today        `json:"today"`
	RecentEvents RecentEvents `json:"recent_events"`
}

// UseCaseDetail is one AI use case.
type UseCaseDetail struct {
	Meta           Meta            `json:"meta"`
	Row            *fleet.AgentRow `json:"row"`
	Availability   Availability    `json:"availability"`
	Runtime        Runtime         `json:"runtime"`
	RecentSessions SessionList     `json:"recent_sessions"`
	Costs          Costs           `json:"costs"`
	Activity       Activity        `json:"activity"`
	// EffectivePolicy is reserved for the provenance contract owned by #305.
	// It stays unknown until that implementation lands; nothing here infers
	// provenance from YAML.
	EffectivePolicy Availability `json:"effective_policy"`
}

// SessionList is a bounded page of session rows (session.Store.ListRecent):
// newest first by created_at; NextBefore pages further back.
type SessionList struct {
	Meta         Meta               `json:"meta"`
	Availability Availability       `json:"availability"`
	Sessions     []*session.Session `json:"sessions"`
	Limit        int                `json:"limit"`
	NextBefore   *time.Time         `json:"next_before,omitempty"`
}

// SessionDetail is session.Detail plus the timeline, as `talon session show
// --json` and `talon audit list --session --json` emit them.
type SessionDetail struct {
	Meta         Meta              `json:"meta"`
	Availability Availability      `json:"availability"`
	Detail       *session.Detail   `json:"detail,omitempty"`
	Timeline     *session.Timeline `json:"timeline,omitempty"`
}

// EvidenceDetail is evidence.RecordDetail: the record and the verification
// performed for this read.
type EvidenceDetail struct {
	Meta         Meta                   `json:"meta"`
	Availability Availability           `json:"availability"`
	Detail       *evidence.RecordDetail `json:"detail,omitempty"`
}

// Costs is costs.Report with its availability. Budgets inside the report
// are resolved by the Service's BudgetResolver; BudgetNote states what
// resolved them (or that nothing could).
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
	Meta    Meta        `json:"meta"`
	Console Info        `json:"console"`
	Store   StoreHealth `json:"store"`
	Runtime Runtime     `json:"runtime"`
}

// Info identifies the console process itself.
type Info struct {
	Version   string    `json:"version"`
	Commit    string    `json:"commit,omitempty"`
	StartedAt time.Time `json:"started_at"`
	Currency  string    `json:"currency"`
}
