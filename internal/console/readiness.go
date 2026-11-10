package console

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// Operational readiness (#533 PR 1) answers "can this installation serve
// governed traffic now, and how do we know?" from the sources that can
// actually say so: the processes' own runtime records, the configuration
// digests they report, the agent keys they report holding, and whether the
// console can read the stores. It is INSTALLATION-WIDE: a tenant scope never
// filters it. It is kept apart from canonical fleet health (fleet.Evaluate,
// unchanged), which judges use cases from budgets, policy and recorded
// traffic; neither is folded into the other. Historical evidence never
// proves availability, and a heartbeat never proves that authentication
// works.

// Dimension states.
const (
	ReadyOK            = "ok"             // established now by the source named in the dimension
	ReadyDegraded      = "degraded"       // established now, and wrong
	ReadyUnverified    = "unverified"     // the running process does not report what would prove it
	ReadyUnknown       = "unknown"        // no source can answer now
	ReadyNotConfigured = "not_configured" // intentionally not part of this installation
)

// Overall readiness states.
const (
	OverallOperational   = "operational"    // every configured dimension is ok
	OverallDegraded      = "degraded"       // at least one dimension is degraded
	OverallUnknown       = "unknown"        // nothing is degraded, but at least one dimension cannot be assessed
	OverallUnverified    = "unverified"     // nothing is degraded or unknown, but something is only unverified
	OverallNotConfigured = "not_configured" // no data-plane runtime is configured for this console
)

// Dimension keys.
const (
	DimGateway        = "runtime.gateway"
	DimMCPProxy       = "runtime.mcp_proxy"
	DimActivation     = "configuration.activation"
	DimAgentKeys      = "authentication.agent_keys"
	DimEvidenceStore  = "data.evidence_store"
	DimSessionStore   = "data.session_store"
	DimRuntimeRecords = "data.runtime_records"
)

// Finding severities, most urgent first.
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// Finding scopes.
const (
	FindingInstallation = "installation"
	FindingUseCase      = "use_case"
)

// ScopeInstallation labels a section that no tenant scope filters.
const ScopeInstallation = "installation"

// Readiness is the installation's operational readiness.
type Readiness struct {
	// Scope is always "installation".
	Scope      string               `json:"scope"`
	Overall    string               `json:"overall"`
	Summary    string               `json:"summary"`
	AssessedAt time.Time            `json:"assessed_at"`
	Dimensions []ReadinessDimension `json:"dimensions"`
	// Findings are the installation-level findings, most urgent first.
	Findings []Finding `json:"findings"`
}

// ReadinessDimension is one independent fact about the installation.
type ReadinessDimension struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Reason string `json:"reason"`
	Source string `json:"source"`
	// ObservedAt is when the underlying state was last established (a
	// heartbeat, a store read); nil when nothing established it.
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}

// Finding is one actionable item: what is wrong, what it affects, why it is
// reported, when the supporting state was observed and where to look next.
type Finding struct {
	Severity   string     `json:"severity"`
	Code       string     `json:"code"`
	Scope      string     `json:"scope"`
	Title      string     `json:"title"`
	Affected   string     `json:"affected"`
	Why        string     `json:"why"`
	Source     string     `json:"source"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	// Link is a console route (path and query) to continue from.
	Link     string `json:"link"`
	TenantID string `json:"tenant_id,omitempty"`
	UseCase  string `json:"use_case,omitempty"`
}

// readinessInputs are the facts readiness is derived from; assessReadiness
// is a pure function of them.
type readinessInputs struct {
	Runtime Runtime
	// ProxyConfigDigest / GatewayConfigDigest: sha256 of the config files the
	// console reads now ("" when not configured or unreadable).
	ProxyConfigured     bool
	ProxyConfigDigest   string
	GatewayConfigDigest string
	Evidence            StoreFacts
	Sessions            StoreFacts
	Now                 time.Time
}

// StoreFacts is what the console established about one store just now.
type StoreFacts struct {
	Availability Availability
	RecordCount  int
	Newest       *time.Time
}

func (s *Service) readiness(ctx context.Context, rt Runtime) Readiness {
	in := readinessInputs{Runtime: rt, Now: s.now()}
	src := s.cfg.ConfigSources
	if src.ProxyConfig != "" {
		in.ProxyConfigured = true
		in.ProxyConfigDigest = fileDigest(src.ProxyConfig)
	}
	if src.GatewayConfig != "" {
		in.GatewayConfigDigest = fileDigest(src.GatewayConfig)
	}
	in.Evidence = s.evidenceFacts(ctx)
	in.Sessions = s.sessionFacts(ctx)
	return assessReadiness(in)
}

func (s *Service) evidenceFacts(ctx context.Context) StoreFacts {
	if s.cfg.Evidence == nil {
		return StoreFacts{Availability: Availability{State: StateUnavailable, Source: SourceEvidenceStore, Error: noStoreMsg}}
	}
	count, newest, err := s.cfg.Evidence.Stats(ctx)
	if err != nil {
		return StoreFacts{Availability: unavailable(SourceEvidenceStore, err)}
	}
	f := StoreFacts{Availability: ok(SourceEvidenceStore, s.now()), RecordCount: count}
	if !newest.IsZero() {
		n := newest.UTC()
		f.Newest = &n
	}
	return f
}

func (s *Service) sessionFacts(ctx context.Context) StoreFacts {
	if s.cfg.Sessions == nil {
		return StoreFacts{Availability: Availability{State: StateUnavailable, Source: SourceSessionStore, Error: "session store is not open"}}
	}
	if _, err := s.cfg.Sessions.DistinctAgents(ctx); err != nil {
		return StoreFacts{Availability: unavailable(SourceSessionStore, err)}
	}
	return StoreFacts{Availability: ok(SourceSessionStore, s.now())}
}

// assessReadiness derives the dimensions, the installation findings and the
// overall state. Deterministic for the same inputs.
func assessReadiness(in readinessInputs) Readiness {
	r := Readiness{Scope: ScopeInstallation, AssessedAt: in.Now.UTC(), Dimensions: []ReadinessDimension{}, Findings: []Finding{}}
	add := func(d ReadinessDimension, f *Finding) {
		r.Dimensions = append(r.Dimensions, d)
		if f != nil {
			if f.ObservedAt == nil {
				f.ObservedAt = d.ObservedAt
			}
			if f.Source == "" {
				f.Source = d.Source
			}
			f.Scope = FindingInstallation
			r.Findings = append(r.Findings, *f)
		}
	}
	rt := in.Runtime
	readable := rt.Availability.State == StateOK
	gw := roleDimension(rt, runtimestatus.RoleGateway, DimGateway, "LLM gateway")
	add(gw.dim, gw.finding)
	mp := roleDimension(rt, runtimestatus.RoleMCPProxy, DimMCPProxy, "MCP proxy")
	add(mp.dim, mp.finding)
	d, f := activationDimension(in, readable)
	add(d, f)
	d, f = agentKeysDimension(rt, readable)
	add(d, f)
	d, f = storeDimension(in.Evidence, DimEvidenceStore, "Evidence store", "evidence, costs and sessions observed in evidence cannot be read", SeverityCritical)
	add(d, f)
	d, f = storeDimension(in.Sessions, DimSessionStore, "Session store", "managed session lifecycle cannot be read", SeverityWarning)
	add(d, f)
	d, f = runtimeRecordsDimension(rt)
	add(d, f)

	sortFindings(r.Findings)
	r.Overall = overall(r.Dimensions)
	r.Summary = summary(r)
	return r
}

type roleResult struct {
	dim     ReadinessDimension
	finding *Finding
}

func roleDimension(rt Runtime, role, key, label string) roleResult {
	d := ReadinessDimension{Key: key, Label: label, Source: SourceRuntimeRecords}
	if rt.Availability.State != StateOK {
		d.State, d.Source = ReadyUnknown, firstNonEmpty(rt.Availability.Source, SourceNone)
		d.Reason = "runtime records cannot be read, so whether the " + label + " runs is unknown: " + firstNonEmpty(rt.Availability.Error, rt.Availability.Note)
		return roleResult{dim: d}
	}
	var rs *runtimestatus.RoleStatus
	for i := range rt.Roles {
		if rt.Roles[i].Role == role {
			rs = &rt.Roles[i]
		}
	}
	if rs == nil {
		d.State, d.Reason = ReadyNotConfigured, "not part of this installation's configuration"
		return roleResult{dim: d}
	}
	d.Reason, d.ObservedAt = rs.Reason, rs.LastSeen
	switch rs.State {
	case runtimestatus.Running:
		d.State = ReadyOK
		return roleResult{dim: d}
	case runtimestatus.Stale:
		d.State = ReadyDegraded
		return roleResult{dim: d, finding: &Finding{Severity: SeverityWarning, Code: "runtime_stale", Title: label + " heartbeat is stale", Affected: "traffic through the " + label, Why: rs.Reason, Link: "/system"}}
	case runtimestatus.Offline:
		if !rs.Expected {
			// A process served this role earlier, but this installation's
			// configuration does not expect it: history, not an incident.
			d.State, d.Reason = ReadyNotConfigured, "not expected by this installation's configuration; an earlier instance is "+rs.Reason
			return roleResult{dim: d}
		}
		d.State = ReadyDegraded
		code, title := "runtime_offline", label+" is offline"
		if p := currentProcess(rt, rs.InstanceID); p != nil && p.State == runtimestatus.StateFailed {
			code, title = "runtime_failed_to_start", label+" failed to start"
		}
		return roleResult{dim: d, finding: &Finding{Severity: SeverityCritical, Code: code, Title: title, Affected: "every request through the " + label + " (configured for this installation)", Why: rs.Reason, Link: "/system"}}
	case runtimestatus.NotConfigured:
		d.State = ReadyNotConfigured
		return roleResult{dim: d}
	default:
		d.State = ReadyUnknown
		return roleResult{dim: d, finding: &Finding{Severity: SeverityWarning, Code: "runtime_unknown", Title: "Whether the " + label + " should run is unknown", Affected: "the " + label, Why: rs.Reason, Link: "/configuration"}}
	}
}

func currentProcess(rt Runtime, id string) *runtimestatus.Process {
	for i := range rt.Processes {
		if rt.Processes[i].InstanceID == id {
			return &rt.Processes[i]
		}
	}
	return nil
}

// runningDataPlane lists the running processes that serve the gateway or the
// MCP proxy.
func runningDataPlane(rt Runtime) []*runtimestatus.Process {
	var out []*runtimestatus.Process
	for i := range rt.Processes {
		p := &rt.Processes[i]
		if p.Assessed != runtimestatus.Running {
			continue
		}
		for _, r := range p.Roles {
			if r == runtimestatus.RoleGateway || r == runtimestatus.RoleMCPProxy {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func activationDimension(in readinessInputs, readable bool) (ReadinessDimension, *Finding) {
	d := ReadinessDimension{Key: DimActivation, Label: "Configuration activation", Source: SourceRuntimeRecords}
	if !readable {
		d.State, d.Reason = ReadyUnknown, "runtime records cannot be read, so which configuration runs is unknown"
		return d, nil
	}
	// A rejected reload keeps the last-known-good generation serving: the
	// files on disk are not what runs.
	if p := rejectedReload(in.Runtime); p != nil {
		d.State = ReadyDegraded
		d.Reason = fmt.Sprintf("process %s rejected a configuration reload and keeps serving its previous generation", p.InstanceID)
		d.ObservedAt = timePtr(p.WrittenAt)
		why := d.Reason
		if len(p.Catalog.RejectedCauses) > 0 {
			why += ": " + strings.Join(p.Catalog.RejectedCauses, "; ")
		}
		return d, &Finding{Severity: SeverityWarning, Code: "reload_rejected", Title: "A configuration reload was rejected", Affected: "AI use cases whose agent files changed since the active generation", Why: why, Link: "/configuration"}
	}
	view := runtimestatus.View{Processes: in.Runtime.Processes}
	var proofs []configProof
	if in.ProxyConfigured {
		proofs = append(proofs, configProof{"MCP proxy config", runtimestatus.ProveProxy(view, true, in.ProxyConfigDigest)})
	}
	if roleExpected(in.Runtime, runtimestatus.RoleGateway) {
		proofs = append(proofs, configProof{"gateway config", runtimestatus.ProveGatewayConfig(view, true, in.GatewayConfigDigest)})
	}
	if len(proofs) == 0 {
		d.State, d.Reason = ReadyNotConfigured, "no gateway or MCP proxy is configured for this installation"
		return d, nil
	}
	d.State, d.Reason = worstProof(proofs)
	if ps := runningDataPlane(in.Runtime); len(ps) > 0 {
		d.ObservedAt = timePtr(ps[0].WrittenAt)
	}
	if d.State == ReadyDegraded {
		return d, &Finding{Severity: SeverityWarning, Code: "config_not_active", Title: "A running process does not run the configuration on disk", Affected: "decisions of that process until it restarts", Why: d.Reason, Link: "/configuration"}
	}
	return d, nil
}

type configProof struct {
	label string
	l     runtimestatus.Loaded
}

// worstProof combines boundary proofs: any difference is degraded; a
// boundary with no running process is unknown; an unreported digest is
// unverified.
func worstProof(proofs []configProof) (state, reason string) {
	rank := map[string]int{ReadyOK: 0, ReadyUnverified: 1, ReadyUnknown: 2, ReadyDegraded: 3}
	worst := ReadyOK
	var reasons []string
	for _, pr := range proofs {
		reasons = append(reasons, pr.label+": "+pr.l.Reason)
		st := ReadyOK
		switch pr.l.State {
		case runtimestatus.BoundaryDiffers:
			st = ReadyDegraded
		case runtimestatus.BoundaryUnknown:
			st = ReadyUnverified
		case runtimestatus.BoundaryNotRunning:
			st = ReadyUnknown
		}
		if rank[st] > rank[worst] {
			worst = st
		}
	}
	return worst, strings.Join(reasons, "; ")
}

func rejectedReload(rt Runtime) *runtimestatus.Process {
	for _, p := range runningDataPlane(rt) {
		if p.Catalog != nil && p.Catalog.ReloadRejected {
			return p
		}
	}
	return nil
}

func roleExpected(rt Runtime, role string) bool {
	for _, r := range rt.Roles {
		if r.Role == role {
			return r.Expected
		}
	}
	return false
}

// agentKeysDimension reports whether the running data plane holds the agent
// keys its use cases declare, as the processes themselves report it. It is
// never derived from a heartbeat: a process that does not report its keys is
// unverified, and the console never attempts authentication itself.
func agentKeysDimension(rt Runtime, readable bool) (ReadinessDimension, *Finding) {
	d := ReadinessDimension{Key: DimAgentKeys, Label: "Agent authentication", Source: SourceRuntimeRecords}
	if !readable {
		d.State, d.Reason = ReadyUnknown, "runtime records cannot be read, so whether agent keys are loaded is unknown"
		return d, nil
	}
	// Every fact that makes authentication fail is collected: an expected
	// role that failed to start for want of an agent key, and running
	// processes that do not hold a declared key. Neither hides the other.
	problems, affected, at := startupKeyFailures(rt)
	procs := runningDataPlane(rt)
	kf := keyFactsOf(procs)
	if kf.at.After(at) {
		at = kf.at
	}
	declared, unreported := kf.declared, kf.unreported
	if len(kf.missing) > 0 {
		problems = append(problems, "a running process does not hold the agent key of "+strings.Join(kf.missing, ", ")+"; requests presenting that key are refused, although its heartbeat is fresh")
		affected = append(affected, kf.missing...)
	}
	d.ObservedAt = timePtr(at)
	if len(problems) > 0 {
		d.State, d.Reason = ReadyDegraded, strings.Join(problems, "; ")
		return d, &Finding{
			Severity: SeverityCritical, Code: "agent_keys_unavailable", Title: "Agent authentication is not functional", Affected: strings.Join(affected, "; "),
			Why: d.Reason + ". Check the agent key in the vault and TALON_SECRETS_KEY.", Link: "/system",
		}
	}
	switch {
	case len(procs) == 0 && anyExpected(rt):
		d.State, d.Reason = ReadyUnknown, "no gateway or MCP proxy process is running, so no process reports which agent keys it holds"
		return d, nil
	case len(procs) == 0:
		d.State, d.Reason = ReadyNotConfigured, "no gateway or MCP proxy is configured for this installation"
		return d, nil
	case unreported > 0:
		d.State = ReadyUnverified
		d.Reason = fmt.Sprintf("%d running process(es) do not report which agent keys they hold (an older version?); a fresh heartbeat does not prove that authentication works", unreported)
		return d, &Finding{Severity: SeverityInfo, Code: "agent_keys_unverified", Title: "Agent authentication is unverified", Affected: "use cases served by those processes", Why: d.Reason, Link: "/system"}
	case declared == 0:
		d.State = ReadyNotConfigured
		d.Reason = "no AI use case in the running generation declares an agent key: requests are attributed, not authenticated by agent key"
		return d, nil
	}
	d.State = ReadyOK
	d.Reason = "every running gateway and MCP proxy reports holding the keys of all use cases that declare one; the console did not attempt to authenticate"
	return d, nil
}

func startupKeyFailures(rt Runtime) (problems, affected []string, at time.Time) {
	for _, rs := range rt.Roles {
		if !rs.Expected || rs.State != runtimestatus.Offline {
			continue
		}
		p := currentProcess(rt, rs.InstanceID)
		if p == nil || p.StartupFailure == nil || p.StartupFailure.Code != runtimestatus.FailureAgentKeyUnavailable {
			continue
		}
		problems = append(problems, "the "+roleName(rs.Role)+" failed to start: "+p.StartupFailure.Reason)
		affected = append(affected, "every use case authenticating through the "+roleName(rs.Role))
		if p.WrittenAt.After(at) {
			at = p.WrittenAt
		}
	}
	return problems, affected, at
}

type keyFacts struct {
	declared, unreported int
	missing              []string
	at                   time.Time
}

func keyFactsOf(procs []*runtimestatus.Process) keyFacts {
	var k keyFacts
	for _, p := range procs {
		if p.WrittenAt.After(k.at) {
			k.at = p.WrittenAt
		}
		if p.AgentKeys == nil {
			k.unreported++
			continue
		}
		k.declared += p.AgentKeys.Declared
		for _, n := range p.AgentKeys.Unloaded {
			k.missing = append(k.missing, fmt.Sprintf("%s (%s %s)", n, strings.Join(rolesLabel(p.Roles), " + "), p.InstanceID))
		}
	}
	return k
}

func rolesLabel(roles []string) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, roleName(r))
	}
	return out
}

func anyExpected(rt Runtime) bool {
	for _, r := range rt.Roles {
		if r.Expected {
			return true
		}
	}
	return false
}

func roleName(role string) string {
	switch role {
	case runtimestatus.RoleGateway:
		return "LLM gateway"
	case runtimestatus.RoleMCPProxy:
		return "MCP proxy"
	}
	return role
}

func storeDimension(f StoreFacts, key, label, impact, severity string) (ReadinessDimension, *Finding) {
	d := ReadinessDimension{Key: key, Label: label, Source: f.Availability.Source}
	if f.Availability.State != StateOK && f.Availability.State != StateEmpty {
		d.State = ReadyDegraded
		d.Reason = label + " cannot be read: " + firstNonEmpty(f.Availability.Error, f.Availability.Note, f.Availability.State)
		return d, &Finding{Severity: severity, Code: key + "_unavailable", Title: label + " cannot be read", Affected: impact, Why: d.Reason, Link: "/system"}
	}
	d.State, d.ObservedAt = ReadyOK, timePtr(f.Availability.AsOf)
	d.Reason = "readable now"
	if key == DimEvidenceStore {
		d.Reason = fmt.Sprintf("readable now; %d records", f.RecordCount)
		if f.Newest != nil {
			d.Reason += ", newest " + f.Newest.UTC().Format(time.RFC3339) + " (a recent record shows something wrote; it does not show that a process runs now)"
		}
	}
	return d, nil
}

func runtimeRecordsDimension(rt Runtime) (ReadinessDimension, *Finding) {
	d := ReadinessDimension{Key: DimRuntimeRecords, Label: "Runtime records", Source: firstNonEmpty(rt.Availability.Source, SourceNone)}
	switch rt.Availability.State {
	case StateOK:
	case StateUnavailable:
		d.State, d.Reason = ReadyDegraded, firstNonEmpty(rt.Availability.Error, "runtime records cannot be read")
		return d, &Finding{Severity: SeverityWarning, Code: "runtime_records_unavailable", Title: "Runtime state cannot be assessed", Affected: "every runtime, activation and authentication fact on this page (reported as unknown, not healthy)", Why: d.Reason, Link: "/system"}
	default:
		d.State, d.Reason = ReadyUnknown, firstNonEmpty(rt.Availability.Note, rt.Availability.Error, "no runtime source")
		return d, &Finding{Severity: SeverityWarning, Code: "runtime_records_unknown", Title: "Runtime state cannot be assessed", Affected: "every runtime, activation and authentication fact on this page (reported as unknown, not healthy)", Why: d.Reason, Link: "/system"}
	}
	d.ObservedAt = timePtr(rt.ReadAt)
	foreign, malformed := 0, 0
	for _, r := range rt.Rejected {
		if strings.Contains(r.Reason, "different installation") {
			foreign++
		} else {
			malformed++
		}
	}
	if foreign == 0 && malformed == 0 {
		d.State, d.Reason = ReadyOK, fmt.Sprintf("%d record(s) of this installation read", len(rt.Processes))
		return d, nil
	}
	d.State = ReadyDegraded
	var parts []string
	if foreign > 0 {
		parts = append(parts, fmt.Sprintf("%d record(s) carry a different evidence signing key fingerprint and were ignored: a process writing here may sign evidence with another key", foreign))
	}
	if malformed > 0 {
		parts = append(parts, fmt.Sprintf("%d record(s) could not be read or have an unsupported format", malformed))
	}
	d.Reason = strings.Join(parts, "; ")
	code := "runtime_records_rejected"
	title := "Some runtime records were not combined"
	if foreign > 0 {
		code, title = "runtime_records_foreign_key", "Runtime records from another signing key were ignored"
	}
	return d, &Finding{Severity: SeverityWarning, Code: code, Title: title, Affected: "the processes those records describe are not counted for this installation", Why: d.Reason, Link: "/system"}
}

func overall(dims []ReadinessDimension) string {
	has := map[string]bool{}
	runtimeConfigured := false
	for _, d := range dims {
		has[d.State] = true
		if (d.Key == DimGateway || d.Key == DimMCPProxy) && d.State != ReadyNotConfigured {
			runtimeConfigured = true
		}
	}
	switch {
	case has[ReadyDegraded]:
		return OverallDegraded
	case !runtimeConfigured:
		return OverallNotConfigured
	case has[ReadyUnknown]:
		return OverallUnknown
	case has[ReadyUnverified]:
		return OverallUnverified
	}
	return OverallOperational
}

func summary(r Readiness) string {
	switch r.Overall {
	case OverallDegraded:
		if len(r.Findings) > 0 {
			return r.Findings[0].Title + "."
		}
		return "At least one operational dimension is degraded."
	case OverallNotConfigured:
		return "No gateway or MCP proxy is configured for this console; only recorded history can be shown."
	case OverallUnknown:
		return "Nothing is known to be broken, but part of the runtime cannot be assessed."
	case OverallUnverified:
		return "The configured runtimes run, but part of their readiness is not reported, so it is unverified."
	}
	return "Every configured runtime runs, loaded the configuration on disk and reports its agent keys; the stores are readable."
}

var severityRank = map[string]int{SeverityCritical: 0, SeverityWarning: 1, SeverityInfo: 2}

// codeRank puts a runtime that cannot serve ahead of its consequences within
// a severity: the root cause is the most actionable item.
var codeRank = map[string]int{"runtime_failed_to_start": 0, "runtime_offline": 1, "data.evidence_store_unavailable": 2, "agent_keys_unavailable": 3}

func rankOf(code string) int {
	if r, ok := codeRank[code]; ok {
		return r
	}
	return len(codeRank)
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.Scope != b.Scope {
			return a.Scope == FindingInstallation
		}
		if rankOf(a.Code) != rankOf(b.Code) {
			return rankOf(a.Code) < rankOf(b.Code)
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Affected < b.Affected
	})
}

// useCaseFindings turns the canonical fleet rows that are not healthy into
// findings, unchanged in substance: health and why are fleet.Evaluate's. A
// disabled (stopped) use case is a deliberate state and is reported as info.
func useCaseFindings(rows []fleet.AgentRow, now time.Time) []Finding {
	out := []Finding{}
	for i := range rows {
		r := &rows[i]
		sev := SeverityWarning
		switch r.Health {
		case fleet.HealthHealthy:
			continue
		case fleet.HealthBlocked:
			sev = SeverityCritical
		case fleet.HealthStopped:
			sev = SeverityInfo
		}
		t := now.UTC()
		out = append(out, Finding{
			Severity: sev, Code: "fleet_" + strings.ReplaceAll(string(r.Health), "-", "_"), Scope: FindingUseCase,
			Title:    fmt.Sprintf("%s: %s", r.Name, healthLabel(r.Health)),
			Affected: fmt.Sprintf("AI use case %s (tenant %s)", r.Name, r.TenantID),
			Why:      r.Why, Source: SourceConfigFiles, ObservedAt: &t,
			Link:     "/use-cases/" + url.PathEscape(r.Name) + "?tenant=" + url.QueryEscape(r.TenantID),
			TenantID: r.TenantID, UseCase: r.Name,
		})
	}
	return out
}

func healthLabel(h fleet.Health) string {
	switch h {
	case fleet.HealthBlocked:
		return "blocked"
	case fleet.HealthStopped:
		return "stopped (disabled)"
	case fleet.HealthNeedsAttention:
		return "needs attention"
	}
	return string(h)
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
