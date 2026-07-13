package metrics

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/rs/zerolog/log"
)

// Snapshot is the complete dashboard state returned by GET /api/v1/metrics.
type Snapshot struct {
	GeneratedAt     time.Time `json:"generated_at"`
	EnforcementMode string    `json:"enforcement_mode"`
	// Currency is the ISO-4217 unit of every cost figure in this snapshot,
	// from the active pricing table (#216). Field/JSON names keep their
	// legacy _eur suffix for consumer compatibility; Currency is the
	// authoritative unit. Empty on snapshots from servers that predate the
	// field (render as USD).
	Currency          string              `json:"currency,omitempty"`
	Uptime            string              `json:"uptime"`
	DroppedEvents     uint64              `json:"dropped_events,omitempty"`
	Summary           Summary             `json:"summary"`
	RequestsTimeline  []TimePoint         `json:"requests_timeline"`
	PIITimeline       []TimePoint         `json:"pii_timeline"`
	CostTimeline      []CostTimePoint     `json:"cost_timeline"`
	AgentStats        []AgentStat         `json:"agent_stats"`
	PIIBreakdown      []PIITypeStat       `json:"pii_breakdown"`
	ToolGovernance    ToolGovernanceStats `json:"tool_governance"`
	ShadowSummary     *ShadowSummary      `json:"shadow_summary,omitempty"`
	ModelBreakdown    []ModelStat         `json:"model_breakdown"`
	ProviderBreakdown []ProviderStat      `json:"provider_breakdown"`
	BudgetStatus      *BudgetStatus       `json:"budget_status,omitempty"`
	CacheStats        *CacheStats         `json:"cache_stats,omitempty"`
	PlanStats         *PlanStats          `json:"plan_stats,omitempty"`
	// Sessions is the orchestration session drill-down (#199): the most
	// recently active client/vendor-asserted sessions, each aggregated by the
	// SAME pure function behind `talon audit --session`
	// (evidence.BuildSessionSummary) over the store's records — the dashboard
	// and the CLI are structurally incapable of disagreeing, and a destructive
	// ReconcileFromStore rebuild cannot change these numbers. Empty (omitted)
	// when no orchestration data exists.
	Sessions []evidence.SessionSummary `json:"sessions,omitempty"`
	// DenialsByReason buckets denied requests by the machine-code prefix of
	// their first policy reason (session_budget_exceeded, budget_exceeded,
	// egress_* ...) so session denials don't lump under policy_deny (#199).
	DenialsByReason []ReasonCount `json:"denials_by_reason,omitempty"`
}

// ReasonCount is one denial-reason bucket, sorted by descending count.
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// Summary holds top-level KPIs.
type Summary struct {
	TotalRequests   int     `json:"total_requests"`
	BlockedRequests int     `json:"blocked_requests"`
	PIIDetections   int     `json:"pii_detections"`
	PIIRedactions   int     `json:"pii_redactions"`
	ToolsFiltered   int     `json:"tools_filtered"`
	TotalCostEUR    float64 `json:"total_cost_eur"`
	AvgLatencyMS    int64   `json:"avg_latency_ms"`
	P99LatencyMS    int64   `json:"p99_latency_ms"`
	ErrorRate       float64 `json:"error_rate"`
	TotalSuccessful int     `json:"total_successful"`
	TotalFailed     int     `json:"total_failed"`
	TotalTimedOut   int     `json:"total_timed_out"`
	TotalDenied     int     `json:"total_denied"`
	SuccessRate     float64 `json:"success_rate"`
	ActiveRuns      int     `json:"active_runs"`
	AvgTTFTMS       int64   `json:"avg_ttft_ms,omitempty"` // average time to first token (streaming)
	AvgTPOTMS       float64 `json:"avg_tpot_ms,omitempty"` // average time per output token (streaming)
	PendingPlans    int     `json:"pending_plans,omitempty"`
	ApprovedPlans   int     `json:"approved_plans,omitempty"`
	RejectedPlans   int     `json:"rejected_plans,omitempty"`
	ModifiedPlans   int     `json:"modified_plans,omitempty"`
	DispatchedPlans int     `json:"dispatched_plans,omitempty"`
	PlanDispatchErr int     `json:"plan_dispatch_errors,omitempty"`
}

// TimePoint is a count at a 5-minute bucket.
type TimePoint struct {
	Time  string `json:"time"`
	Count int    `json:"count"`
}

// CostTimePoint is a cost value at a 5-minute bucket.
type CostTimePoint struct {
	Time    string  `json:"time"`
	CostEUR float64 `json:"cost_eur"`
}

// AgentStat is per-agent aggregated stats.
type AgentStat struct {
	Agent        string  `json:"agent"`
	Requests     int     `json:"requests"`
	PIIDetected  int     `json:"pii_detected"`
	Blocked      int     `json:"blocked"`
	CostEUR      float64 `json:"cost_eur"`
	AvgLatencyMS int64   `json:"avg_latency_ms"`
	Successful   int     `json:"successful"`
	Failed       int     `json:"failed"`
	TimedOut     int     `json:"timed_out"`
	Denied       int     `json:"denied"`
	SuccessRate  float64 `json:"success_rate"`
	// CostPerSuccess uses total successful run cost divided by successful runs.
	CostPerSuccess float64    `json:"cost_per_success"`
	ViolationTrend []DayCount `json:"violation_trend"`
}

// DayCount tracks per-day counts for rolling trends.
type DayCount struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// PIITypeStat is detection count per PII type.
type PIITypeStat struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// ToolGovernanceStats aggregates tool filtering.
type ToolGovernanceStats struct {
	TotalRequested  int              `json:"total_requested"`
	TotalFiltered   int              `json:"total_filtered"`
	TopFiltered     []ToolFilterStat `json:"top_filtered"`
	ByRiskLevel     []RiskLevelStat  `json:"by_risk_level"`
	BulkOperations  int              `json:"bulk_operations"`
	IrreversibleBlk int              `json:"irreversible_blocked"`
	AnomalousAgents []string         `json:"anomalous_agents"`
}

// ToolFilterStat is a filtered tool with count.
type ToolFilterStat struct {
	Tool  string `json:"tool"`
	Count int    `json:"count"`
}

// RiskLevelStat groups by risk classification.
type RiskLevelStat struct {
	Level   string `json:"level"`
	Allowed int    `json:"allowed"`
	Blocked int    `json:"blocked"`
}

// ShadowSummary appears only when enforcement mode is "shadow".
type ShadowSummary struct {
	WouldHaveBlocked  int                 `json:"would_have_blocked"`
	WouldHaveRedacted int                 `json:"would_have_redacted"`
	ViolationsByType  []ViolationTypeStat `json:"violations_by_type"`
}

// ViolationTypeStat is a shadow violation type count.
type ViolationTypeStat struct {
	Type   string `json:"type"`
	Count  int    `json:"count"`
	Action string `json:"action"`
}

// ModelStat is cost and request count per LLM model.
type ModelStat struct {
	Model    string  `json:"model"`
	Requests int     `json:"requests"`
	CostEUR  float64 `json:"cost_eur"`
}

// ProviderStat is cost and request count per provider.
type ProviderStat struct {
	Provider string  `json:"provider"`
	Requests int     `json:"requests"`
	CostEUR  float64 `json:"cost_eur"`
}

// BudgetStatus shows daily/monthly budget utilization.
type BudgetStatus struct {
	DailyUsed      float64 `json:"daily_used"`
	DailyLimit     float64 `json:"daily_limit"`
	DailyPercent   float64 `json:"daily_percent"`
	MonthlyUsed    float64 `json:"monthly_used"`
	MonthlyLimit   float64 `json:"monthly_limit"`
	MonthlyPercent float64 `json:"monthly_percent"`
}

// CacheStats shows semantic cache performance.
type CacheStats struct {
	Hits      int     `json:"hits"`
	CostSaved float64 `json:"cost_saved"`
	HitRate   float64 `json:"hit_rate"`
}

// PlanStats aggregates plan review and dispatch lifecycle counters.
type PlanStats struct {
	Pending          int `json:"pending"`
	Approved         int `json:"approved"`
	Rejected         int `json:"rejected"`
	Modified         int `json:"modified"`
	Dispatched       int `json:"dispatched"`
	DispatchFailures int `json:"dispatch_failures"`
}

// GatewayEvent is the input from the gateway for real-time dashboard aggregation.
type GatewayEvent struct {
	EvidenceID       string
	Timestamp        time.Time
	AgentName        string
	Model            string
	PIIDetected      []string
	PIIAction        string
	ToolsRequested   []string
	ToolsFiltered    []string
	Blocked          bool
	CostEUR          float64
	TokensInput      int
	TokensOutput     int
	LatencyMS        int64
	EnforcementMode  string
	WouldHaveBlocked bool
	ShadowViolations []string
	HasError         bool
	TimedOut         bool
	CacheHit         bool
	CostSaved        float64
	TTFTMS           int64   // time to first token (streaming); 0 when not streaming
	TPOTMS           float64 // time per output token (streaming); 0 when not applicable
	// Session/orchestration projection (#199) — attribution only, from the
	// evidence record's session spine and client-asserted orchestration block.
	SessionID      string
	SessionSource  string // client_asserted | vendor_asserted | synthetic ("" pre-#194 records)
	OrchAgentID    string
	OrchClient     string
	DenyReasonCode string // machine-code prefix of the first deny reason; "" when not blocked

	IntentClassification *IntentClassificationEvent
	IsBulk               bool
	IrreversibleBlocked  bool
	BehavioralAnomaly    bool
	AgentID              string
}

// IntentClassificationEvent carries risk level from intent governance.
type IntentClassificationEvent struct {
	RiskLevel string `json:"risk_level"`
	Allowed   bool   `json:"allowed"`
}

// internal accumulator types

type bucket struct {
	requests int
	pii      int
	costEUR  float64
}

type agentAccum struct {
	requests   int
	pii        int
	blocked    int
	costEUR    float64
	totalLatMS int64

	successful      int
	failed          int
	timedOut        int
	denied          int
	successCostEUR  float64
	violationsByDay map[string]int
}

type shadowViolationAccum struct {
	count  int
	action string
}

type riskLevelAccum struct {
	allowed int
	blocked int
}

const maxLatencySamples = 10000

// Collector aggregates gateway events in memory for dashboard display.
// Real-time metrics (sparklines, PII, tools, latency) are maintained in-memory.
// Aggregate metrics (model breakdown, budget, cache) are delegated to
// MetricsQuerier at Snapshot() time for consistency with CLI commands.
type Collector struct {
	mu                  sync.RWMutex
	startTime           time.Time
	enforcementMode     string
	currency            string // ISO-4217 unit of cost figures, from the pricing table (#216)
	events              chan GatewayEvent
	done                chan struct{}
	buckets             map[string]*bucket
	agentStats          map[string]*agentAccum
	piiCounts           map[string]int
	piiRedactions       int
	toolFiltered        map[string]int
	toolRequested       int
	shadowViolations    map[string]*shadowViolationAccum
	denialsByReason     map[string]int
	byRiskLevel         map[string]*riskLevelAccum
	bulkOperations      int
	irreversibleBlocked int
	anomalousAgents     map[string]bool
	totalRequests       int
	blockedRequests     int
	totalErrors         int
	totalSuccessful     int
	totalFailed         int
	totalTimedOut       int
	totalDenied         int
	totalCostEUR        float64
	totalLatencyMS      int64
	totalTTFTMS         int64   // sum of TTFT for streaming requests (for average)
	ttftCount           int     // number of events with TTFT > 0
	totalTPOTMS         float64 // sum of TPOT for streaming requests (for average)
	tpotCount           int     // number of events with TPOT > 0
	latencyRing         [maxLatencySamples]int64
	latencyRingPos      int
	latencyRingLen      int

	metricsQuerier evidence.MetricsQuerier
	// sessionQuerier feeds the sessions panel (#199); optional — nil hides it.
	sessionQuerier evidence.SessionQuerier
	activeRunsFn   func() int
	budgetDaily    float64
	budgetMonthly  float64
	tenantID       string
	// tenantScopeFn, when set, is consulted on EVERY aggregate query instead
	// of the static tenantID (#289): serve wires it to the identity-registry
	// holder so a reload re-scopes dashboard SQL without a new collector.
	tenantScopeFn func() string
	// budgetLimitsFn, when set, is consulted on every snapshot instead of
	// the static budgetDaily/budgetMonthly (#291 review, P2) — the budget
	// denominators follow a registry reload like the tenant scope does.
	budgetLimitsFn func() (float64, float64)
	planStatsFn    func(context.Context, string) (PlanStats, error)
	droppedEvents  uint64
	reconcileStats ReconcileStats
}

// tenantScope returns the tenant filter for aggregate queries: the live scope
// function when configured (#289), else the static tenantID.
func (c *Collector) tenantScope() string {
	if c.tenantScopeFn != nil {
		return c.tenantScopeFn()
	}
	return c.tenantID
}

// budgetLimits returns the dashboard budget denominators: the live function
// when configured (#291 review, P2), else the static values.
func (c *Collector) budgetLimits() (daily, monthly float64) {
	if c.budgetLimitsFn != nil {
		return c.budgetLimitsFn()
	}
	return c.budgetDaily, c.budgetMonthly
}

// ReconcileStats tracks collector reconciliation health and outcomes.
type ReconcileStats struct {
	Runs            uint64    `json:"runs"`
	RecoveredEvents uint64    `json:"recovered_events"`
	LastRunAt       time.Time `json:"last_run_at,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	LastLagMS       int64     `json:"last_lag_ms,omitempty"`
}

// CollectorOption configures a Collector.
type CollectorOption func(*Collector)

// WithBudgetLimits sets daily/monthly budget limits for utilization gauge.
func WithBudgetLimits(daily, monthly float64) CollectorOption {
	return func(c *Collector) { c.budgetDaily = daily; c.budgetMonthly = monthly }
}

// WithActiveRunsFn sets the callback for current active run count.
func WithActiveRunsFn(fn func() int) CollectorOption {
	return func(c *Collector) { c.activeRunsFn = fn }
}

// WithTenantID scopes aggregate queries to a specific tenant.
func WithTenantID(tenantID string) CollectorOption {
	return func(c *Collector) { c.tenantID = tenantID }
}

// WithTenantScope scopes aggregate queries through a live function read on
// every snapshot (#289): serve derives it from the identity-registry holder
// so a registry reload (#269) re-scopes the dashboard without collector
// reconstruction. Takes precedence over WithTenantID.
func WithTenantScope(fn func() string) CollectorOption {
	return func(c *Collector) { c.tenantScopeFn = fn }
}

// WithBudgetLimitsFn supplies the budget denominators through a live
// function read on every snapshot (#291 review, P2): serve derives them from
// the identity-registry holder (sum of binding effective caps), so a
// registry reload (#269) updates the dashboard's limits together with its
// tenant scope — never spend from the new registry against denominators
// from the old one. Takes precedence over WithBudgetLimits.
func WithBudgetLimitsFn(fn func() (daily, monthly float64)) CollectorOption {
	return func(c *Collector) { c.budgetLimitsFn = fn }
}

// WithCurrency records the ISO-4217 code of the pricing table backing the
// gateway's cost figures so snapshots carry their cost unit (#216).
func WithCurrency(code string) CollectorOption {
	return func(c *Collector) { c.currency = code }
}

// WithPlanStatsFn sets a callback for plan lifecycle counters.
// WithSessionQuerier enables the orchestration sessions panel (#199): at
// snapshot time the collector re-derives session stats from the evidence
// store via evidence.BuildSessionSummary. Optional; nil keeps the panel off.
func WithSessionQuerier(q evidence.SessionQuerier) CollectorOption {
	return func(c *Collector) { c.sessionQuerier = q }
}

func WithPlanStatsFn(fn func(context.Context, string) (PlanStats, error)) CollectorOption {
	return func(c *Collector) { c.planStatsFn = fn }
}

// NewCollector creates a metrics collector. querier may be nil (aggregate
// metrics will be empty). Starts a background goroutine for event consumption.
func NewCollector(enforcementMode string, querier evidence.MetricsQuerier, opts ...CollectorOption) *Collector {
	c := &Collector{
		startTime:        time.Now(),
		enforcementMode:  enforcementMode,
		events:           make(chan GatewayEvent, 1000),
		done:             make(chan struct{}),
		buckets:          make(map[string]*bucket),
		agentStats:       make(map[string]*agentAccum),
		piiCounts:        make(map[string]int),
		toolFiltered:     make(map[string]int),
		shadowViolations: make(map[string]*shadowViolationAccum),
		denialsByReason:  make(map[string]int),
		byRiskLevel:      make(map[string]*riskLevelAccum),
		anomalousAgents:  make(map[string]bool),
		metricsQuerier:   querier,
	}
	for _, opt := range opts {
		opt(c)
	}
	go c.consumeLoop()
	return c
}

// Record sends a gateway event to the collector. Non-blocking: if the
// channel is full the event is silently dropped.
func (c *Collector) Record(e GatewayEvent) {
	select {
	case c.events <- e:
	default:
		dropped := atomic.AddUint64(&c.droppedEvents, 1)
		recordCollectorEventDrop()
		if dropped == 1 || dropped%100 == 0 {
			log.Warn().Uint64("dropped_events", dropped).Msg("metrics_collector_event_dropped")
		}
	}
}

// DroppedEvents returns number of collector events dropped due to backpressure.
func (c *Collector) DroppedEvents() uint64 {
	return atomic.LoadUint64(&c.droppedEvents)
}

// Close stops the background consumer goroutine.
func (c *Collector) Close() {
	close(c.done)
}

func (c *Collector) consumeLoop() {
	for {
		select {
		case <-c.done:
			return
		case e := <-c.events:
			c.mu.Lock()
			c.processEvent(e)
			c.mu.Unlock()
		}
	}
}

// drainEvents discards all buffered events from the channel.
// Must be called while holding c.mu.
func (c *Collector) drainEvents() {
	for {
		select {
		case <-c.events:
		default:
			return
		}
	}
}

func (c *Collector) processEvent(e GatewayEvent) {
	c.totalRequests++
	if e.Blocked {
		c.blockedRequests++
	}
	if e.HasError {
		c.totalErrors++
	}
	switch {
	case e.TimedOut:
		c.totalTimedOut++
		c.totalFailed++
	case e.Blocked:
		c.totalDenied++
		code := e.DenyReasonCode
		if code == "" {
			code = "policy_deny"
		}
		if c.denialsByReason == nil {
			c.denialsByReason = make(map[string]int)
		}
		c.denialsByReason[code]++
	case e.HasError:
		c.totalFailed++
	default:
		c.totalSuccessful++
	}
	c.totalCostEUR += e.CostEUR
	c.totalLatencyMS += e.LatencyMS
	c.latencyRing[c.latencyRingPos] = e.LatencyMS
	c.latencyRingPos = (c.latencyRingPos + 1) % maxLatencySamples
	if c.latencyRingLen < maxLatencySamples {
		c.latencyRingLen++
	}

	if e.TTFTMS > 0 {
		c.totalTTFTMS += e.TTFTMS
		c.ttftCount++
	}
	if e.TPOTMS > 0 {
		c.totalTPOTMS += e.TPOTMS
		c.tpotCount++
	}

	c.updateBucket(e)
	c.updateAgentStats(e)
	c.updateToolStats(e)
	c.updateIntentClassification(e)
	c.updateShadowViolations(e)
}

func (c *Collector) updateBucket(e GatewayEvent) {
	key := e.Timestamp.Truncate(5 * time.Minute).Format(time.RFC3339)
	b, ok := c.buckets[key]
	if !ok {
		b = &bucket{}
		c.buckets[key] = b
	}
	b.requests++
	b.costEUR += e.CostEUR

	for _, piiType := range e.PIIDetected {
		c.piiCounts[piiType]++
		b.pii++
	}
	if e.PIIAction == "redact" {
		c.piiRedactions += len(e.PIIDetected)
	}
}

func (c *Collector) updateAgentStats(e GatewayEvent) {
	if e.AgentName == "" {
		return
	}
	cs, ok := c.agentStats[e.AgentName]
	if !ok {
		cs = &agentAccum{}
		c.agentStats[e.AgentName] = cs
	}
	cs.requests++
	cs.costEUR += e.CostEUR
	cs.totalLatMS += e.LatencyMS
	cs.pii += len(e.PIIDetected)
	if e.Blocked {
		cs.blocked++
	}
	switch {
	case e.TimedOut:
		cs.timedOut++
		cs.failed++
	case e.Blocked:
		cs.denied++
	case e.HasError:
		cs.failed++
	default:
		cs.successful++
		cs.successCostEUR += e.CostEUR
	}

	dayKey := e.Timestamp.Format("2006-01-02")
	if e.Blocked || len(e.PIIDetected) > 0 || len(e.ToolsFiltered) > 0 {
		if cs.violationsByDay == nil {
			cs.violationsByDay = make(map[string]int)
		}
		cs.violationsByDay[dayKey]++
		recordViolationDaily(dayKey, e.AgentName)
	}

	recordTaskOutcome(e.AgentName, e.Model, e.Blocked, e.HasError, e.TimedOut)
	if !e.TimedOut && !e.Blocked && !e.HasError {
		recordCostPerSuccess(e.AgentName, e.Model, e.CostEUR)
	}
}

func (c *Collector) updateToolStats(e GatewayEvent) {
	c.toolRequested += len(e.ToolsRequested)
	for _, tool := range e.ToolsFiltered {
		c.toolFiltered[tool]++
	}
	if e.IsBulk {
		c.bulkOperations++
	}
	if e.IrreversibleBlocked {
		c.irreversibleBlocked++
	}
	if e.BehavioralAnomaly && e.AgentID != "" {
		c.anomalousAgents[e.AgentID] = true
	}
}

func (c *Collector) updateIntentClassification(e GatewayEvent) {
	if e.IntentClassification == nil {
		return
	}
	rl := e.IntentClassification.RiskLevel
	acc, ok := c.byRiskLevel[rl]
	if !ok {
		acc = &riskLevelAccum{}
		c.byRiskLevel[rl] = acc
	}
	if e.IntentClassification.Allowed {
		acc.allowed++
	} else {
		acc.blocked++
	}
}

func (c *Collector) updateShadowViolations(e GatewayEvent) {
	for _, svType := range e.ShadowViolations {
		sv, ok := c.shadowViolations[svType]
		if !ok {
			sv = &shadowViolationAccum{action: "block"}
			c.shadowViolations[svType] = sv
		}
		sv.count++
	}
}

// Snapshot builds the complete dashboard state. In-memory data is read under
// RLock; aggregate metrics (model breakdown, budget, cache) are queried from
// the evidence store via MetricsQuerier after releasing the lock.
func (c *Collector) Snapshot(ctx context.Context) Snapshot {
	c.mu.RLock()
	snap := c.buildInMemorySnapshot()
	c.mu.RUnlock()

	c.fillAggregateMetrics(ctx, &snap)
	return snap
}

// ReconcileStatus returns the latest reconciliation counters and health fields.
func (c *Collector) ReconcileStatus() ReconcileStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.reconcileStats
}

func (c *Collector) resetInMemoryAggregates() {
	c.buckets = make(map[string]*bucket)
	c.agentStats = make(map[string]*agentAccum)
	c.piiCounts = make(map[string]int)
	c.toolFiltered = make(map[string]int)
	c.shadowViolations = make(map[string]*shadowViolationAccum)
	c.denialsByReason = make(map[string]int)
	c.byRiskLevel = make(map[string]*riskLevelAccum)
	c.anomalousAgents = make(map[string]bool)
	c.piiRedactions = 0
	c.toolRequested = 0
	c.bulkOperations = 0
	c.irreversibleBlocked = 0
	c.totalRequests = 0
	c.blockedRequests = 0
	c.totalErrors = 0
	c.totalSuccessful = 0
	c.totalFailed = 0
	c.totalTimedOut = 0
	c.totalDenied = 0
	c.totalCostEUR = 0
	c.totalLatencyMS = 0
	c.totalTTFTMS = 0
	c.ttftCount = 0
	c.totalTPOTMS = 0
	c.tpotCount = 0
	c.latencyRing = [maxLatencySamples]int64{}
	c.latencyRingPos = 0
	c.latencyRingLen = 0
}

func (c *Collector) rebuildFromEvidence(records []evidence.Evidence) {
	c.resetInMemoryAggregates()
	for i := range records {
		ev := GatewayEventFromEvidence(&records[i])
		c.processEvent(ev)
	}
}

func (c *Collector) markReconcileSuccess(recovered int, lag time.Duration) {
	c.reconcileStats.Runs++
	if recovered > 0 {
		c.reconcileStats.RecoveredEvents += uint64(recovered)
	}
	c.reconcileStats.LastRunAt = time.Now().UTC()
	c.reconcileStats.LastError = ""
	if lag > 0 {
		c.reconcileStats.LastLagMS = lag.Milliseconds()
	} else {
		c.reconcileStats.LastLagMS = 0
	}
	recordCollectorReconcileRun(recovered, lag, false)
}

func (c *Collector) markReconcileFailure(err error) {
	c.reconcileStats.Runs++
	c.reconcileStats.LastRunAt = time.Now().UTC()
	c.reconcileStats.LastLagMS = 0
	if err != nil {
		c.reconcileStats.LastError = err.Error()
	}
	recordCollectorReconcileRun(0, 0, true)
}

func (c *Collector) buildInMemorySnapshot() Snapshot {
	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)

	var sortedKeys []string
	for k := range c.buckets {
		t, err := time.Parse(time.RFC3339, k)
		if err != nil || t.Before(cutoff) {
			continue
		}
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	reqTimeline := make([]TimePoint, 0, len(sortedKeys))
	piiTimeline := make([]TimePoint, 0, len(sortedKeys))
	costTimeline := make([]CostTimePoint, 0, len(sortedKeys))
	for _, k := range sortedKeys {
		b := c.buckets[k]
		reqTimeline = append(reqTimeline, TimePoint{Time: k, Count: b.requests})
		piiTimeline = append(piiTimeline, TimePoint{Time: k, Count: b.pii})
		costTimeline = append(costTimeline, CostTimePoint{Time: k, CostEUR: b.costEUR})
	}

	var avgLatency, p99Latency, avgTTFTMS int64
	var errorRate, avgTPOTMS, successRate float64
	if c.totalRequests > 0 {
		avgLatency = c.totalLatencyMS / int64(c.totalRequests)
		errorRate = float64(c.totalErrors) / float64(c.totalRequests)
		successRate = float64(c.totalSuccessful) / float64(c.totalRequests)
	}
	if c.ttftCount > 0 {
		avgTTFTMS = c.totalTTFTMS / int64(c.ttftCount)
	}
	if c.tpotCount > 0 {
		avgTPOTMS = c.totalTPOTMS / float64(c.tpotCount)
	}
	if c.totalRequests > 0 {
		if c.latencyRingLen > 0 {
			sorted := make([]int64, c.latencyRingLen)
			copy(sorted, c.latencyRing[:c.latencyRingLen])
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			idx := int(float64(len(sorted)) * 0.99)
			if idx >= len(sorted) {
				idx = len(sorted) - 1
			}
			p99Latency = sorted[idx]
		}
	}

	callers := make([]AgentStat, 0, len(c.agentStats))
	for caller, cs := range c.agentStats {
		callers = append(callers, c.buildAgentStat(caller, cs))
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i].Requests > callers[j].Requests })

	piiBreakdown := make([]PIITypeStat, 0, len(c.piiCounts))
	totalPII := 0
	for t, cnt := range c.piiCounts {
		piiBreakdown = append(piiBreakdown, PIITypeStat{Type: t, Count: cnt})
		totalPII += cnt
	}
	sort.Slice(piiBreakdown, func(i, j int) bool { return piiBreakdown[i].Count > piiBreakdown[j].Count })

	totalFiltered, toolGov := c.buildToolGovernance()
	shadow := c.buildShadowSummary()

	activeRuns := 0
	if c.activeRunsFn != nil {
		activeRuns = c.activeRunsFn()
	}

	uptime := formatDuration(time.Since(c.startTime))

	return Snapshot{
		GeneratedAt:     now,
		EnforcementMode: c.enforcementMode,
		Currency:        c.currency,
		Uptime:          uptime,
		DroppedEvents:   c.DroppedEvents(),
		Summary: Summary{
			TotalRequests:   c.totalRequests,
			BlockedRequests: c.blockedRequests,
			PIIDetections:   totalPII,
			PIIRedactions:   c.piiRedactions,
			ToolsFiltered:   totalFiltered,
			TotalCostEUR:    c.totalCostEUR,
			AvgLatencyMS:    avgLatency,
			P99LatencyMS:    p99Latency,
			ErrorRate:       errorRate,
			TotalSuccessful: c.totalSuccessful,
			TotalFailed:     c.totalFailed,
			TotalTimedOut:   c.totalTimedOut,
			TotalDenied:     c.totalDenied,
			SuccessRate:     successRate,
			ActiveRuns:      activeRuns,
			AvgTTFTMS:       avgTTFTMS,
			AvgTPOTMS:       avgTPOTMS,
		},
		RequestsTimeline: reqTimeline,
		PIITimeline:      piiTimeline,
		CostTimeline:     costTimeline,
		AgentStats:       callers,
		PIIBreakdown:     piiBreakdown,
		ToolGovernance:   toolGov,
		ShadowSummary:    shadow,
		DenialsByReason:  denialsByReasonSorted(c.denialsByReason),
	}
}

// denialsByReasonSorted flattens the reason counters, highest count first
// (ties by reason for determinism); nil when there are no denials.
func denialsByReasonSorted(m map[string]int) []ReasonCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]ReasonCount, 0, len(m))
	for reason, count := range m {
		out = append(out, ReasonCount{Reason: reason, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

func (c *Collector) buildAgentStat(agent string, cs *agentAccum) AgentStat {
	stat := AgentStat{
		Agent:       agent,
		Requests:    cs.requests,
		PIIDetected: cs.pii,
		Blocked:     cs.blocked,
		CostEUR:     cs.costEUR,
		Successful:  cs.successful,
		Failed:      cs.failed,
		TimedOut:    cs.timedOut,
		Denied:      cs.denied,
	}
	if cs.requests > 0 {
		stat.AvgLatencyMS = cs.totalLatMS / int64(cs.requests)
		stat.SuccessRate = float64(cs.successful) / float64(cs.requests)
	}
	if cs.successful > 0 {
		stat.CostPerSuccess = cs.successCostEUR / float64(cs.successful)
	}
	stat.ViolationTrend = c.buildViolationTrend(cs.violationsByDay)
	return stat
}

func (c *Collector) buildViolationTrend(byDay map[string]int) []DayCount {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	trend := make([]DayCount, 7)
	for i := 6; i >= 0; i-- {
		day := today.AddDate(0, 0, -i)
		key := day.Format("2006-01-02")
		count := 0
		if byDay != nil {
			count = byDay[key]
		}
		trend[6-i] = DayCount{
			Date:  key,
			Count: count,
		}
	}
	return trend
}

func (c *Collector) buildToolGovernance() (totalFiltered int, stats ToolGovernanceStats) {
	topFiltered := make([]ToolFilterStat, 0, len(c.toolFiltered))
	for tool, cnt := range c.toolFiltered {
		topFiltered = append(topFiltered, ToolFilterStat{Tool: tool, Count: cnt})
		totalFiltered += cnt
	}
	sort.Slice(topFiltered, func(i, j int) bool { return topFiltered[i].Count > topFiltered[j].Count })

	riskLevels := make([]RiskLevelStat, 0, len(c.byRiskLevel))
	for level, acc := range c.byRiskLevel {
		riskLevels = append(riskLevels, RiskLevelStat{Level: level, Allowed: acc.allowed, Blocked: acc.blocked})
	}
	sort.Slice(riskLevels, func(i, j int) bool { return riskLevels[i].Level < riskLevels[j].Level })

	anomalous := make([]string, 0, len(c.anomalousAgents))
	for agent := range c.anomalousAgents {
		anomalous = append(anomalous, agent)
	}
	sort.Strings(anomalous)

	return totalFiltered, ToolGovernanceStats{
		TotalRequested:  c.toolRequested,
		TotalFiltered:   totalFiltered,
		TopFiltered:     topFiltered,
		ByRiskLevel:     riskLevels,
		BulkOperations:  c.bulkOperations,
		IrreversibleBlk: c.irreversibleBlocked,
		AnomalousAgents: anomalous,
	}
}

func (c *Collector) buildShadowSummary() *ShadowSummary {
	if c.enforcementMode != "shadow" || len(c.shadowViolations) == 0 {
		return nil
	}
	var wouldBlock, wouldRedact int
	violations := make([]ViolationTypeStat, 0, len(c.shadowViolations))
	for vType, sv := range c.shadowViolations {
		violations = append(violations, ViolationTypeStat{
			Type:   vType,
			Count:  sv.count,
			Action: sv.action,
		})
		switch sv.action {
		case "redact":
			wouldRedact += sv.count
		default:
			wouldBlock += sv.count
		}
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].Count > violations[j].Count })
	return &ShadowSummary{
		WouldHaveBlocked:  wouldBlock,
		WouldHaveRedacted: wouldRedact,
		ViolationsByType:  violations,
	}
}

func (c *Collector) fillAggregateMetrics(ctx context.Context, snap *Snapshot) {
	c.applyPlanStats(ctx, snap)
	// Sessions depend on the session querier only — fill before the
	// metricsQuerier gate so a collector without cost aggregates still
	// serves the sessions panel (#199).
	c.fillSessions(ctx, snap)
	if c.metricsQuerier == nil {
		return
	}

	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)
	last24h := now.Add(-24 * time.Hour)

	c.fillModelBreakdown(ctx, snap, dayStart, dayEnd)
	c.fillProviderBreakdown(ctx, snap, dayStart, dayEnd)
	c.fillBudgetStatus(ctx, snap, dayStart, dayEnd, monthStart, monthEnd)
	c.fillCacheStats(ctx, snap, last24h, now)
}

// maxDashboardSessions bounds the sessions panel to the most recently active
// orchestration sessions (#199).
const maxDashboardSessions = 20

// fillSessions re-derives the orchestration session drill-down from persisted
// evidence on every snapshot: recent asserted session ids, each aggregated by
// evidence.BuildSessionSummary — the same pure function behind
// `talon audit --session` (#192 §3.8, "one aggregation"). Because nothing is
// kept in collector memory, a destructive ReconcileFromStore rebuild cannot
// change these numbers, and there is no state to drift.
func (c *Collector) fillSessions(ctx context.Context, snap *Snapshot) {
	if c.sessionQuerier == nil {
		return
	}
	ids, err := c.sessionQuerier.ListRecentOrchestrationSessionIDs(ctx, maxDashboardSessions)
	if err != nil {
		// A store failure must be distinguishable from "no orchestration
		// data" in logs, even though the panel hides either way.
		log.Warn().Err(err).Msg("dashboard_sessions_query_failed")
		return
	}
	if len(ids) == 0 {
		return
	}
	sessions := make([]evidence.SessionSummary, 0, len(ids))
	for _, id := range ids {
		records, err := c.sessionQuerier.ListBySessionID(ctx, id)
		if err != nil {
			log.Warn().Err(err).Str("session_id", id).Msg("dashboard_session_load_failed")
			continue
		}
		if len(records) == 0 {
			continue
		}
		sessions = append(sessions, evidence.BuildSessionSummary(id, records))
	}
	snap.Sessions = sessions
}

func (c *Collector) applyPlanStats(ctx context.Context, snap *Snapshot) {
	if c.planStatsFn == nil {
		return
	}
	planStats, err := c.planStatsFn(ctx, c.tenantScope())
	if err != nil {
		return
	}
	snap.PlanStats = &planStats
	snap.Summary.PendingPlans = planStats.Pending
	snap.Summary.ApprovedPlans = planStats.Approved
	snap.Summary.RejectedPlans = planStats.Rejected
	snap.Summary.ModifiedPlans = planStats.Modified
	snap.Summary.DispatchedPlans = planStats.Dispatched
	snap.Summary.PlanDispatchErr = planStats.DispatchFailures
}

func (c *Collector) fillModelBreakdown(ctx context.Context, snap *Snapshot, dayStart, dayEnd time.Time) {
	byModel, err := c.metricsQuerier.CostByModel(ctx, c.tenantScope(), "", dayStart, dayEnd)
	if err != nil || len(byModel) == 0 {
		return
	}
	models := make([]ModelStat, 0, len(byModel))
	for model, cost := range byModel {
		models = append(models, ModelStat{Model: model, CostEUR: cost})
	}
	sort.Slice(models, func(i, j int) bool { return models[i].CostEUR > models[j].CostEUR })
	snap.ModelBreakdown = models
}

func (c *Collector) fillProviderBreakdown(ctx context.Context, snap *Snapshot, dayStart, dayEnd time.Time) {
	byProvider, err := c.metricsQuerier.CostByProvider(ctx, c.tenantScope(), "", dayStart, dayEnd)
	if err != nil || len(byProvider) == 0 {
		return
	}
	providers := make([]ProviderStat, 0, len(byProvider))
	for provider, cost := range byProvider {
		providers = append(providers, ProviderStat{Provider: provider, CostEUR: cost})
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].CostEUR > providers[j].CostEUR })
	snap.ProviderBreakdown = providers
}

func (c *Collector) fillBudgetStatus(ctx context.Context, snap *Snapshot, dayStart, dayEnd, monthStart, monthEnd time.Time) {
	daily, monthly := c.budgetLimits()
	if daily <= 0 && monthly <= 0 {
		return
	}
	bs := &BudgetStatus{DailyLimit: daily, MonthlyLimit: monthly}
	if dailyUsed, err := c.metricsQuerier.CostTotal(ctx, c.tenantScope(), "", dayStart, dayEnd); err == nil {
		bs.DailyUsed = dailyUsed
		if daily > 0 {
			bs.DailyPercent = (dailyUsed / daily) * 100
		}
	}
	if monthlyUsed, err := c.metricsQuerier.CostTotal(ctx, c.tenantScope(), "", monthStart, monthEnd); err == nil {
		bs.MonthlyUsed = monthlyUsed
		if monthly > 0 {
			bs.MonthlyPercent = (monthlyUsed / monthly) * 100
		}
	}
	snap.BudgetStatus = bs
}

func (c *Collector) fillCacheStats(ctx context.Context, snap *Snapshot, from, to time.Time) {
	hits, costSaved, err := c.metricsQuerier.CacheSavings(ctx, c.tenantScope(), from, to)
	if err != nil || hits <= 0 {
		return
	}
	hitRate := 0.0
	if snap.Summary.TotalRequests > 0 {
		hitRate = float64(hits) / float64(snap.Summary.TotalRequests)
	}
	snap.CacheStats = &CacheStats{
		Hits:      int(hits),
		CostSaved: costSaved,
		HitRate:   hitRate,
	}
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h >= 24 {
		days := h / 24
		hours := h % 24
		return intToStr(days) + "d " + intToStr(hours) + "h"
	}
	if h > 0 {
		return intToStr(h) + "h " + intToStr(m) + "m"
	}
	return intToStr(m) + "m"
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
