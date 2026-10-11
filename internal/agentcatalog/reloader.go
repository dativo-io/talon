package agentcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/secrets"
)

// ReloadOutcome is the result of one reload pass — every branch is explicit
// and unit-testable (#269).
type ReloadOutcome int

const (
	// ReloadUnchanged: the scanned bytes match the active generation; no
	// vault I/O, no evidence — the interval tick is free.
	ReloadUnchanged ReloadOutcome = iota
	// ReloadActivated: a new generation validated, swapped, and recorded.
	ReloadActivated
	// ReloadRejected: the scanned set is invalid; last-known-good keeps
	// serving and ONE signed rejection record names the causes.
	ReloadRejected
	// ReloadRejectedDuplicate: the same broken state as the previous pass —
	// no new evidence row (one record per distinct broken state, not per tick).
	ReloadRejectedDuplicate
	// ReloadRecovered: the bytes reverted to the last-known-good generation
	// while a rejection was active — the rejection clears without a swap.
	ReloadRecovered
	// ReloadRolledBack: the new generation was swapped in but its activation
	// record could not be written — the pointer was rolled back (a signed
	// activation record must describe an activation that occurred, #267).
	ReloadRolledBack
)

// EvidenceSink persists one signed reload record. *evidence.Store satisfies
// it; the reloader depends only on this narrow surface so tests can inject
// failures (#269 review — rollback and rejection-retry paths).
type EvidenceSink interface {
	Store(ctx context.Context, ev *evidence.Evidence) error
}

// RegistryBuilder constructs the identity registry for a reloaded generation,
// given the scan and the PREVIOUS generation (for key reuse). It is
// mode-aware — plain (native-only) serve allows a nil/keyless registry while
// gateway mode requires keyed agents — and reuses unchanged key material so a
// reload never depends on re-reading the vault binding it is changing (#269
// review). May return (nil, nil) for a keyless native-only generation.
type RegistryBuilder func(ctx context.Context, scan *ScanResult, previous *RuntimeSnapshot) (*gateway.IdentityRegistry, error)

// ReloadConfig wires the periodic safe reload (#269).
type ReloadConfig struct {
	Source Source
	// Deps are the SHARED process dependencies bundles compile over — the
	// same providers/config serve built at startup, so a reloaded generation
	// is constructed exactly like the boot generation.
	Deps BundleDeps
	// BuildRegistry constructs the generation's identity registry. serve
	// injects a mode-aware builder; when nil, a vault-backed gateway builder
	// is derived from Vault/AdminKey below (tests and simple callers).
	BuildRegistry RegistryBuilder
	Vault         *secrets.SecretStore
	AdminKey      string
	Holder        *RuntimeHolder
	// Evidence sinks the signed config_reload records. *evidence.Store
	// satisfies it; tests inject failing/blocking writers to exercise the
	// rollback and retry paths.
	Evidence EvidenceSink
	// RequireNonEmpty mirrors gateway startup: a scan yielding zero KEYED
	// agents is a REJECTION (keep last-known-good), never an activation of an
	// empty registry that would deny everything by accident. Native-only
	// serve leaves this false (a keyless generation is legitimate).
	RequireNonEmpty bool
	// Clock is the reloader's time source (tests); nil = time.Now UTC.
	Clock func() time.Time
}

// ReloadState is the runtime-status seam (#270 / GET /v1/agents/fleet): the
// active generation, the last activation, and the most recent rejection with
// its per-path causes.
type ReloadState struct {
	ActiveGeneration string       `json:"active_generation"`
	ActivatedAt      time.Time    `json:"activated_at"`
	Rejected         bool         `json:"rejected"`
	RejectedDigest   string       `json:"rejected_digest,omitempty"`
	RejectedAt       time.Time    `json:"rejected_at,omitempty"`
	RejectedCauses   []string     `json:"rejected_causes,omitempty"`
	Issues           []FleetIssue `json:"fleet_issues,omitempty"`
	// SourcesRejected marks a rejection whose config bytes are unchanged:
	// a trusted action source (#427) could not be re-discovered or no
	// longer compiles; last-known-good keeps serving its catalog.
	SourcesRejected bool `json:"action_sources_rejected,omitempty"`
	// NextSourceRefresh is when discovered action sources are next
	// re-read (absent when no agent binds to one).
	NextSourceRefresh *time.Time `json:"next_action_source_refresh,omitempty"`
}

// Reloader re-reads the agent-config source on an interval and activates
// valid changes as ONE atomic generation swap. Invalid edits never take a
// working fleet offline: last-known-good keeps serving and the rejection is
// loudly visible (log + signed evidence + ReloadState).
// maxRecordedDigests caps the dedup set of already-recorded rejection
// digests. Distinct broken states are operator-driven and rare, so this is
// generous; on overflow the set is cleared (a harmless re-record at worst).
const maxRecordedDigests = 256

type Reloader struct {
	cfg ReloadConfig
	now func() time.Time

	mu          sync.Mutex // serializes ReloadOnce: one activation at a time
	lastGood    string     // generation id of the active snapshot
	lastScan    string     // scan digest of the active snapshot (config change detector)
	activatedAt time.Time
	// refreshKnown/refreshAt pace the re-discovery of trusted action
	// sources (#427): due when the earliest upstream freshness hint of the
	// active generation expires (floored/capped), or after a bounded
	// backoff following a failed refresh.
	refreshKnown bool
	refreshAt    time.Time
	rejection    *rejectionState // CURRENT observed broken state (for View); nil when healthy
	// unrecorded holds every DISTINCT broken state observed whose signed
	// rejection could not yet be persisted (#269 review round 4): each is
	// retried on every tick until it lands, so a temporary evidence-store
	// outage never permanently loses a record — even when a second broken
	// edit replaces the first during the outage window.
	unrecorded map[string]*rejectionState
	// recorded is the dedup set of digests whose rejection evidence persisted.
	recorded map[string]struct{}
}

type rejectionState struct {
	// key dedups distinct broken states; digest is the scanned config
	// generation the evidence names (they differ only for a source-only
	// rejection, where the config bytes are unchanged but the causes are
	// what distinguishes one broken state from another).
	key        string
	digest     string
	at         time.Time
	causes     []string
	issues     []FleetIssue
	sourceOnly bool
}

// Source refresh pacing.
const (
	minSourceRefresh   = time.Second
	maxSourceRefresh   = action.MaxSourceTTL
	sourceRetryBackoff = 30 * time.Second
)

// NewReloader seeds the last-known-good generation from the holder's current
// snapshot (the boot generation).
func NewReloader(cfg ReloadConfig) *Reloader {
	if cfg.BuildRegistry == nil {
		// Default: vault-backed gateway builder with key reuse (keeps simple
		// callers and tests working; serve injects a mode-aware builder).
		vault, adminKey := cfg.Vault, cfg.AdminKey
		cfg.BuildRegistry = func(ctx context.Context, scan *ScanResult, previous *RuntimeSnapshot) (*gateway.IdentityRegistry, error) {
			var prior gateway.PriorKeyLookup
			if previous != nil {
				prior = previous.Registry.PriorKeys()
			}
			return gateway.BuildIdentityRegistryWith(ctx, scan.LoadedAgents(), vault, adminKey, gateway.BuildOptions{PriorKeys: prior})
		}
	}
	r := &Reloader{
		cfg:        cfg,
		now:        cfg.Clock,
		unrecorded: make(map[string]*rejectionState),
		recorded:   make(map[string]struct{}),
	}
	if r.now == nil {
		r.now = func() time.Time { return time.Now().UTC() }
	}
	if snap := cfg.Holder.Current(); snap != nil {
		r.lastGood = snap.Generation
		r.lastScan = snap.ScanDigest
		r.activatedAt = snap.BuiltAt
		r.scheduleRefresh(snap)
	}
	return r
}

// scheduleRefresh derives the next action-source refresh from the
// generation's own freshness hints, floored so a zero ttl cannot turn every
// tick into a discovery storm and capped so a huge ttl cannot freeze the
// catalog for the life of the process.
func (r *Reloader) scheduleRefresh(snap *RuntimeSnapshot) {
	at, ok := snap.ActionRefreshAt()
	r.refreshKnown = ok
	if !ok {
		r.refreshAt = time.Time{}
		return
	}
	now := r.now()
	if at.Before(now.Add(minSourceRefresh)) {
		at = now.Add(minSourceRefresh)
	}
	if at.After(now.Add(maxSourceRefresh)) {
		at = now.Add(maxSourceRefresh)
	}
	r.refreshAt = at
}

// Run ticks ReloadOnce every interval until ctx is done.
func (r *Reloader) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.ReloadOnce(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// State returns a copy of the current reload status.
func (r *Reloader) State() ReloadState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stateLocked()
}

func (r *Reloader) stateLocked() ReloadState {
	s := ReloadState{ActiveGeneration: r.lastGood, ActivatedAt: r.activatedAt}
	if r.refreshKnown {
		t := r.refreshAt
		s.NextSourceRefresh = &t
	}
	if r.rejection != nil {
		s.Rejected = true
		s.RejectedDigest = r.rejection.digest
		s.RejectedAt = r.rejection.at
		s.RejectedCauses = append([]string(nil), r.rejection.causes...)
		s.Issues = append([]FleetIssue(nil), r.rejection.issues...)
		s.SourcesRejected = r.rejection.sourceOnly
	}
	return s
}

// FleetView is a single COHERENT read of the runtime status: the active
// snapshot and the reload state captured under the SAME lock, so the fleet
// endpoint can never report a generation that was rolled back mid-read
// (#269 review). Snapshot is nil in keyless/quickstart mode.
type FleetView struct {
	Snapshot *RuntimeSnapshot
	Reload   ReloadState
}

// View returns the active snapshot and reload state atomically — the holder
// is read under the reloader mutex, so an in-progress activation/rollback
// cannot interleave between the two reads.
func (r *Reloader) View() FleetView {
	r.mu.Lock()
	defer r.mu.Unlock()
	return FleetView{Snapshot: r.cfg.Holder.Current(), Reload: r.stateLocked()}
}

// ReloadOnce runs one pass: scan → validate → activate-or-keep-last-known-good.
// Mutex-serialized; readers never take the mutex — they read the holder's
// atomic pointer, so activation is one pointer store and rollback another.
//
// Two triggers lead to a candidate build: changed agent-file bytes, or a
// due refresh of the trusted action sources (#427) with unchanged bytes.
// Either way the COMPLETE candidate (bundles including discovered catalogs,
// registry) is built off to the side; it activates only when its
// generation differs from the active one.
func (r *Reloader) ReloadOnce(ctx context.Context) ReloadOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Retry any previously-observed broken states whose evidence never
	// persisted — including ones already replaced by a newer edit, so no
	// distinct broken state loses its record after an evidence outage.
	r.flushUnrecorded(ctx)

	scan, scanErr := r.cfg.Source.Scan(ctx)
	now := r.now()
	refreshDue := r.refreshKnown && !now.Before(r.refreshAt)

	// Fast path: unchanged bytes and no source refresh due. Clears an
	// active CONFIG rejection when the operator reverted the broken edit
	// (explicit outcome, #267 review); a source-only rejection stays
	// visible until the sources are re-read successfully.
	if scan.Digest == r.lastScan && !refreshDue {
		if r.rejection != nil && !r.rejection.sourceOnly {
			return r.recover()
		}
		return ReloadUnchanged
	}
	sourceOnly := scan.Digest == r.lastScan

	// Rejection paths: invalid scan, empty set under RequireNonEmpty, or a
	// build failure below. Last-known-good keeps serving in every case.
	if scanErr != nil {
		return r.reject(ctx, scan, causesFrom(scan, scanErr), false)
	}
	if r.cfg.RequireNonEmpty && len(scan.Agents) == 0 {
		return r.reject(ctx, scan, []string{fmt.Sprintf("%s: scan found zero agents — an empty set never activates in gateway mode", scan.Source)}, false)
	}

	bundles, err := BuildRuntimeAgents(ctx, scan, r.cfg.Deps)
	if err != nil {
		return r.reject(ctx, scan, []string{err.Error()}, sourceOnly)
	}
	registry, err := r.cfg.BuildRegistry(ctx, scan, r.cfg.Holder.Current())
	if err != nil {
		return r.reject(ctx, scan, []string{err.Error()}, sourceOnly)
	}

	next := NewRuntimeSnapshot(scan, bundles, registry, now)
	r.scheduleRefresh(next)
	if next.Generation == r.lastGood {
		// Same files and the same discovered facts: there is nothing to
		// activate; the refresh only renewed the schedule.
		if r.rejection != nil {
			return r.recover()
		}
		return ReloadUnchanged
	}

	// Activate: ONE pointer swap publishes catalog + bundles + registry
	// together, THEN the signed activation record is written. If the record
	// cannot be written, the pointer rolls back — a signed activation must
	// describe an activation that actually occurred (#267 review). A crash
	// between swap and record leaves an UNRECORDED activation; the next tick
	// IN THE SAME PROCESS self-heals (generation != lastGood →
	// re-activation). Across a process RESTART the on-disk generation
	// becomes the boot generation, seeded directly as lastGood, so no
	// config_reload record is emitted for it — boot generations are not
	// reload events by design.
	old := r.cfg.Holder.Current()
	r.cfg.Holder.Swap(next)
	reason := fmt.Sprintf("activated %d agent(s) from %s", len(scan.Agents), scan.Source)
	if sourceOnly {
		reason += " after trusted action sources changed"
	}
	if err := r.writeReloadEvidence(ctx, next.Generation, true, []string{reason}); err != nil {
		r.cfg.Holder.Swap(old)
		r.scheduleRefresh(old)
		log.Error().Err(err).Str("generation", shortDigest(next.Generation)).Msg("config_reload_activation_evidence_failed_rolled_back")
		// Best-effort rollback record; the critical log above is the floor.
		_ = r.writeReloadEvidence(ctx, next.Generation, false, []string{"activation rolled back: evidence write failed: " + err.Error()})
		r.rejection = &rejectionState{key: next.Generation, digest: next.Generation, at: now, causes: []string{"activation evidence write failed: " + err.Error()}}
		return ReloadRolledBack
	}
	r.lastGood = next.Generation
	r.lastScan = scan.Digest
	r.activatedAt = next.BuiltAt
	r.rejection = nil
	// Activation ENDS any prior broken incident: reset the dedup memory so a
	// broken digest seen before this good generation is recorded afresh if it
	// reoccurs (#300 review round 5, blocker 6). unrecorded is left intact.
	r.recorded = make(map[string]struct{})
	log.Info().Int("agents", len(scan.Agents)).Str("generation", shortDigest(next.Generation)).Str("source", scan.Source).Bool("action_sources_refreshed", sourceOnly).Msg("agent_config_reload_activated")
	return ReloadActivated
}

// recover ends a broken incident without a swap: the observed state is the
// active generation again. The dedup memory resets so the SAME broken
// state, if reintroduced later, is recorded as a NEW incident rather than
// silently deduplicated (#300 review round 5, blocker 6). unrecorded is
// left intact — evidence still owed for any state that never persisted is
// flushed on subsequent ticks.
func (r *Reloader) recover() ReloadOutcome {
	log.Info().Str("generation", shortDigest(r.lastGood)).Bool("action_sources", r.rejection.sourceOnly).Msg("agent_config_recovered_to_last_known_good")
	r.rejection = nil
	r.recorded = make(map[string]struct{})
	return ReloadRecovered
}

// reject keeps last-known-good serving and ensures ONE signed rejection per
// DISTINCT broken state. The current broken state is always tracked for the
// fleet View; a state whose evidence has already persisted is a duplicate,
// and a state whose write fails is queued (unrecorded) for retry on every
// later tick — so no distinct broken state loses its record, even one
// replaced by a newer edit during an evidence outage (#269 review round 4).
//
// A source-only rejection (unchanged config bytes, failed action-source
// refresh) is keyed by its causes — the bytes alone cannot distinguish one
// upstream failure from the next — and schedules a bounded retry.
func (r *Reloader) reject(ctx context.Context, scan *ScanResult, causes []string, sourceOnly bool) ReloadOutcome {
	digest := scan.Digest
	key := digest
	if sourceOnly {
		key = digest + "+sources:" + shortDigest(causesDigest(causes))
		r.refreshAt = r.now().Add(sourceRetryBackoff)
	}
	// Preserve the incident-start time across polls of the SAME continuous broken
	// state: RejectedAt marks WHEN the incident began, not the last poll, so the
	// attention queue can order incidents by onset (#300 review round 6, P2).
	at := r.now()
	if r.rejection != nil && r.rejection.key == key {
		at = r.rejection.at
	}
	rej := &rejectionState{key: key, digest: digest, at: at, causes: causes, issues: append([]FleetIssue(nil), scan.Issues...), sourceOnly: sourceOnly}
	r.rejection = rej // current observed state (for View)

	if _, done := r.recorded[key]; done {
		log.Debug().Str("rejected_digest", shortDigest(digest)).Msg("agent_config_reload_still_rejected")
		return ReloadRejectedDuplicate
	}
	if _, pending := r.unrecorded[key]; pending {
		// Observed before; its retry ran in flushUnrecorded at tick start.
		return ReloadRejected
	}
	// A newly-observed distinct broken state.
	log.Warn().Strs("causes", causes).Str("generation", shortDigest(r.lastGood)).Bool("action_sources", sourceOnly).Msg("agent_config_reload_rejected_keeping_last_known_good")
	if err := r.writeReloadEvidence(ctx, digest, false, causes); err != nil {
		log.Error().Err(err).Msg("config_reload_rejection_evidence_failed_will_retry")
		r.unrecorded[key] = rej
		return ReloadRejected
	}
	r.markRecorded(key)
	return ReloadRejected
}

func causesDigest(causes []string) string {
	h := sha256.New()
	for _, c := range causes {
		fmt.Fprintf(h, "%s\n", c)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// flushUnrecorded retries the signed rejection write for every distinct
// broken state still awaiting persistence; successes move to the recorded
// set. Called at the start of every ReloadOnce.
func (r *Reloader) flushUnrecorded(ctx context.Context) {
	for key, rej := range r.unrecorded {
		if err := r.writeReloadEvidence(ctx, rej.digest, false, rej.causes); err == nil {
			delete(r.unrecorded, key)
			r.markRecorded(key)
		}
	}
}

func (r *Reloader) markRecorded(digest string) {
	if len(r.recorded) >= maxRecordedDigests {
		r.recorded = make(map[string]struct{})
	}
	r.recorded[digest] = struct{}{}
}

// writeReloadEvidence records one config_reload fact. PolicyVersion names the
// exact scanned generation (the dedupe key and the audit reference).
func (r *Reloader) writeReloadEvidence(ctx context.Context, digest string, activated bool, reasons []string) error {
	if r.cfg.Evidence == nil {
		return nil
	}
	id := "cr_" + uuid.New().String()[:12]
	ev := &evidence.Evidence{
		ID:              id,
		CorrelationID:   id,
		Timestamp:       time.Now().UTC(),
		TenantID:        "system",
		AgentID:         "talon-serve",
		InvocationType:  "config_reload",
		RequestSourceID: "reload_loop",
		PolicyDecision: evidence.PolicyDecision{
			Allowed:       activated,
			Action:        map[bool]string{true: "allow", false: "deny"}[activated],
			Reasons:       reasons,
			PolicyVersion: digest,
		},
	}
	if !activated {
		ev.Execution = evidence.Execution{Error: "config_reload_rejected"}
	}
	return r.cfg.Evidence.Store(ctx, ev)
}

// causesFrom flattens per-file issues (capped) or the scan error itself.
func causesFrom(scan *ScanResult, scanErr error) []string {
	const maxCauses = 10
	if len(scan.Issues) == 0 {
		return []string{scanErr.Error()}
	}
	causes := make([]string, 0, maxCauses+1)
	for i, issue := range scan.Issues {
		if i == maxCauses {
			causes = append(causes, fmt.Sprintf("…and %d more", len(scan.Issues)-maxCauses))
			break
		}
		causes = append(causes, issue.Path+": "+issue.Reason)
	}
	return causes
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
