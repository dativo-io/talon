package metrics

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/dativo-io/talon/internal/evidence"
)

// Snapshot is the complete dashboard state returned by GET /api/v1/metrics.
type Snapshot struct {
	GeneratedAt      time.Time           `json:"generated_at"`
	EnforcementMode  string              `json:"enforcement_mode"`
	Uptime           string              `json:"uptime"`
	Summary          Summary             `json:"summary"`
	RequestsTimeline []TimePoint         `json:"requests_timeline"`
	PIITimeline      []TimePoint         `json:"pii_timeline"`
	CostTimeline     []CostTimePoint     `json:"cost_timeline"`
	CallerStats      []CallerStat        `json:"caller_stats"`
	PIIBreakdown     []PIITypeStat       `json:"pii_breakdown"`
	ToolGovernance   ToolGovernanceStats `json:"tool_governance"`
	ShadowSummary    *ShadowSummary      `json:"shadow_summary,omitempty"`
	ModelBreakdown   []ModelStat         `json:"model_breakdown"`
	BudgetStatus     *BudgetStatus       `json:"budget_status,omitempty"`
	CacheStats       *CacheStats         `json:"cache_stats,omitempty"`
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
	ActiveRuns      int     `json:"active_runs"`
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

// CallerStat is per-caller aggregated stats.
type CallerStat struct {
	Caller       string  `json:"caller"`
	Requests     int     `json:"requests"`
	PIIDetected  int     `json:"pii_detected"`
	Blocked      int     `json:"blocked"`
	CostEUR      float64 `json:"cost_eur"`
	AvgLatencyMS int64   `json:"avg_latency_ms"`
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

// GatewayEvent is the input from the gateway for real-time dashboard aggregation.
type GatewayEvent struct {
	Timestamp        time.Time
	CallerID         string
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
	CacheHit         bool
	CostSaved        float64

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

type callerAccum struct {
	requests   int
	pii        int
	blocked    int
	costEUR    float64
	totalLatMS int64
}

type shadowViolationAccum struct {
	count  int
	action string
}

type riskLevelAccum struct {
	allowed int
	blocked int
}

// Collector aggregates gateway events in memory for dashboard display.
// Real-time metrics (sparklines, PII, tools, latency) are maintained in-memory.
// Aggregate metrics (model breakdown, budget, cache) are delegated to
// MetricsQuerier at Snapshot() time for consistency with CLI commands.
type Collector struct {
	mu                  sync.RWMutex
	startTime           time.Time
	enforcementMode     string
	events              chan GatewayEvent
	done                chan struct{}
	buckets             map[string]*bucket
	callerStats         map[string]*callerAccum
	piiCounts           map[string]int
	piiRedactions       int
	toolFiltered        map[string]int
	toolRequested       int
	shadowViolations    map[string]*shadowViolationAccum
	byRiskLevel         map[string]*riskLevelAccum
	bulkOperations      int
	irreversibleBlocked int
	anomalousAgents     map[string]bool
	totalRequests       int
	blockedRequests     int
	totalErrors         int
	totalCostEUR        float64
	totalLatencyMS      int64
	allLatencies        []int64

	metricsQuerier evidence.MetricsQuerier
	activeRunsFn   func() int
	budgetDaily    float64
	budgetMonthly  float64
	tenantID       string
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

// NewCollector creates a metrics collector. querier may be nil (aggregate
// metrics will be empty). Starts a background goroutine for event consumption.
func NewCollector(enforcementMode string, querier evidence.MetricsQuerier, opts ...CollectorOption) *Collector {
	c := &Collector{
		startTime:        time.Now(),
		enforcementMode:  enforcementMode,
		events:           make(chan GatewayEvent, 1000),
		done:             make(chan struct{}),
		buckets:          make(map[string]*bucket),
		callerStats:      make(map[string]*callerAccum),
		piiCounts:        make(map[string]int),
		toolFiltered:     make(map[string]int),
		shadowViolations: make(map[string]*shadowViolationAccum),
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
	}
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

func (c *Collector) processEvent(e GatewayEvent) {
	c.totalRequests++
	if e.Blocked {
		c.blockedRequests++
	}
	if e.HasError {
		c.totalErrors++
	}
	c.totalCostEUR += e.CostEUR
	c.totalLatencyMS += e.LatencyMS
	c.allLatencies = append(c.allLatencies, e.LatencyMS)

	c.updateBucket(e)
	c.updateCallerStats(e)
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

func (c *Collector) updateCallerStats(e GatewayEvent) {
	if e.CallerID == "" {
		return
	}
	cs, ok := c.callerStats[e.CallerID]
	if !ok {
		cs = &callerAccum{}
		c.callerStats[e.CallerID] = cs
	}
	cs.requests++
	cs.costEUR += e.CostEUR
	cs.totalLatMS += e.LatencyMS
	cs.pii += len(e.PIIDetected)
	if e.Blocked {
		cs.blocked++
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

	var avgLatency, p99Latency int64
	var errorRate float64
	if c.totalRequests > 0 {
		avgLatency = c.totalLatencyMS / int64(c.totalRequests)
		errorRate = float64(c.totalErrors) / float64(c.totalRequests)
		if len(c.allLatencies) > 0 {
			sorted := make([]int64, len(c.allLatencies))
			copy(sorted, c.allLatencies)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			idx := int(float64(len(sorted)) * 0.99)
			if idx >= len(sorted) {
				idx = len(sorted) - 1
			}
			p99Latency = sorted[idx]
		}
	}

	callers := make([]CallerStat, 0, len(c.callerStats))
	for caller, cs := range c.callerStats {
		var avg int64
		if cs.requests > 0 {
			avg = cs.totalLatMS / int64(cs.requests)
		}
		callers = append(callers, CallerStat{
			Caller:       caller,
			Requests:     cs.requests,
			PIIDetected:  cs.pii,
			Blocked:      cs.blocked,
			CostEUR:      cs.costEUR,
			AvgLatencyMS: avg,
		})
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
		Uptime:          uptime,
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
			ActiveRuns:      activeRuns,
		},
		RequestsTimeline: reqTimeline,
		PIITimeline:      piiTimeline,
		CostTimeline:     costTimeline,
		CallerStats:      callers,
		PIIBreakdown:     piiBreakdown,
		ToolGovernance:   toolGov,
		ShadowSummary:    shadow,
	}
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
	if c.metricsQuerier == nil {
		return
	}

	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)
	last24h := now.Add(-24 * time.Hour)

	if byModel, err := c.metricsQuerier.CostByModel(ctx, c.tenantID, "", dayStart, dayEnd); err == nil && len(byModel) > 0 {
		models := make([]ModelStat, 0, len(byModel))
		for model, cost := range byModel {
			models = append(models, ModelStat{Model: model, CostEUR: cost})
		}
		sort.Slice(models, func(i, j int) bool { return models[i].CostEUR > models[j].CostEUR })
		snap.ModelBreakdown = models
	}

	if c.budgetDaily > 0 || c.budgetMonthly > 0 {
		bs := &BudgetStatus{DailyLimit: c.budgetDaily, MonthlyLimit: c.budgetMonthly}
		if dailyUsed, err := c.metricsQuerier.CostTotal(ctx, c.tenantID, "", dayStart, dayEnd); err == nil {
			bs.DailyUsed = dailyUsed
			if c.budgetDaily > 0 {
				bs.DailyPercent = (dailyUsed / c.budgetDaily) * 100
			}
		}
		if monthlyUsed, err := c.metricsQuerier.CostTotal(ctx, c.tenantID, "", monthStart, monthEnd); err == nil {
			bs.MonthlyUsed = monthlyUsed
			if c.budgetMonthly > 0 {
				bs.MonthlyPercent = (monthlyUsed / c.budgetMonthly) * 100
			}
		}
		snap.BudgetStatus = bs
	}

	if hits, costSaved, err := c.metricsQuerier.CacheSavings(ctx, c.tenantID, last24h, now); err == nil && hits > 0 {
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
