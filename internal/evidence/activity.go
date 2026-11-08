package evidence

import (
	"context"
	"fmt"
	"time"
)

// ActivityBucket is one server-defined time bucket of request-class traffic:
// the same record class the fleet attention queue counts (AgentTrafficStats),
// so a chart drawn from these buckets and the `talon agents` request/denial
// counters describe the same thing. Request class means every record that is
// not a provider sub-attempt, an operator/config/cache event, an external
// runtime event or an action-lifecycle record (RecordClassOf); intercepted
// tool actions such as proxy_tool_call / proxy_tool_blocked ARE request-class
// and are counted, exactly as the fleet counters count them. Totals that
// include every class live in CountInRange (/v1/status, counts_scope
// all_record_classes).
type ActivityBucket struct {
	Start    time.Time `json:"start"`
	Requests int       `json:"requests"`
	Denied   int       `json:"denied"`
	// Errors counts request-class records whose execution recorded an error
	// (provider failure after an allow), the same predicate as Index.HasError.
	Errors int `json:"errors"`
	// Cost sums execution.cost over the bucket in the records' currency
	// (unpriced and denied records contribute 0, as everywhere else).
	Cost float64 `json:"cost"`
}

// ActivitySeries is a dense, ascending series of ActivityBucket covering
// [From, To) at Bucket resolution; buckets with no traffic are present with
// zero counts so consumers never interpolate.
type ActivitySeries struct {
	TenantID string           `json:"tenant_id"`
	AgentID  string           `json:"agent_id,omitempty"`
	From     time.Time        `json:"from"`
	To       time.Time        `json:"to"`
	Bucket   string           `json:"bucket"` // 5m | 1h | 24h
	Scope    string           `json:"scope"`  // always "request_class"
	Buckets  []ActivityBucket `json:"buckets"`
}

// ActivityBucketSizes are the only resolutions served, all aligned to UTC
// epoch multiples so 24h buckets are UTC calendar days.
var ActivityBucketSizes = map[string]time.Duration{"5m": 5 * time.Minute, "1h": time.Hour, "24h": 24 * time.Hour}

// MaxActivityBuckets bounds one series (7 days of 5-minute buckets).
const MaxActivityBuckets = 2016

// activityWindow validates the request and aligns it to the bucket grid.
func activityWindow(tenantID string, from, to time.Time, bucketSize time.Duration) (label string, fromAligned, toAligned time.Time, n int, err error) {
	for name, d := range ActivityBucketSizes {
		if d == bucketSize {
			label = name
		}
	}
	switch {
	case label == "":
		err = fmt.Errorf("activity buckets: unsupported bucket size %s (5m, 1h or 24h)", bucketSize)
	case tenantID == "":
		err = fmt.Errorf("activity buckets: tenant is required")
	case from.IsZero() || to.IsZero() || !to.After(from):
		err = fmt.Errorf("activity buckets: window [%s, %s) is empty", from.Format(time.RFC3339), to.Format(time.RFC3339))
	}
	if err != nil {
		return "", time.Time{}, time.Time{}, 0, err
	}
	secs := int64(bucketSize / time.Second)
	fromAligned = time.Unix((from.UTC().Unix()/secs)*secs, 0).UTC()
	toAligned = to.UTC()
	if rem := toAligned.Unix() % secs; rem != 0 {
		toAligned = time.Unix(toAligned.Unix()-rem+secs, 0).UTC()
	}
	n = int((toAligned.Unix() - fromAligned.Unix()) / secs)
	if n > MaxActivityBuckets {
		return "", time.Time{}, time.Time{}, 0, fmt.Errorf("activity buckets: %d buckets exceed the bound of %d; widen the bucket or narrow the window", n, MaxActivityBuckets)
	}
	return label, fromAligned, toAligned, n, nil
}

// ActivityBuckets returns request-class traffic bucketed by bucketSize over
// [from, to). from is aligned down and to aligned up to the bucket grid; a
// series longer than MaxActivityBuckets is refused rather than truncated.
// tenantID is required; agentID narrows to one agent.
func (s *Store) ActivityBuckets(ctx context.Context, tenantID, agentID string, from, to time.Time, bucketSize time.Duration) (*ActivitySeries, error) {
	label, fromAligned, toAligned, n, err := activityWindow(tenantID, from, to, bucketSize)
	if err != nil {
		return nil, err
	}
	secs := int64(bucketSize / time.Second)

	//nolint:gosec // G202: RequestClassSQLPredicate is built from internal constants only
	query := `SELECT (CAST(strftime('%s', timestamp) AS INTEGER) / ?) * ? AS bucket_start,
		COUNT(*),
		SUM(CASE WHEN (json_extract(evidence_json, '$.policy_decision.allowed') = 0 OR json_extract(evidence_json, '$.policy_decision.allowed') = 0.0) THEN 1 ELSE 0 END),
		SUM(CASE WHEN COALESCE(json_extract(evidence_json, '$.execution.error'), '') <> '' THEN 1 ELSE 0 END),
		COALESCE(SUM(COALESCE(json_extract(evidence_json, '$.execution.cost'), json_extract(evidence_json, '$.execution.cost_eur'))), 0)
		FROM evidence WHERE ` + RequestClassSQLPredicate("invocation_type") + ` AND tenant_id = ?`
	args := []interface{}{secs, secs, tenantID}
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	query += ` AND timestamp >= ? AND timestamp < ? GROUP BY bucket_start ORDER BY bucket_start`
	args = append(args, fromAligned, toAligned)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying activity buckets: %w", err)
	}
	defer rows.Close()

	byStart := make(map[int64]ActivityBucket, n)
	for rows.Next() {
		var start int64
		var b ActivityBucket
		if err := rows.Scan(&start, &b.Requests, &b.Denied, &b.Errors, &b.Cost); err != nil {
			return nil, fmt.Errorf("scanning activity bucket: %w", err)
		}
		b.Start = time.Unix(start, 0).UTC()
		byStart[start] = b
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating activity buckets: %w", err)
	}

	series := &ActivitySeries{TenantID: tenantID, AgentID: agentID, From: fromAligned, To: toAligned, Bucket: label, Scope: "request_class", Buckets: make([]ActivityBucket, 0, n)}
	for i := 0; i < n; i++ {
		start := fromAligned.Unix() + int64(i)*secs
		if b, ok := byStart[start]; ok {
			series.Buckets = append(series.Buckets, b)
			continue
		}
		series.Buckets = append(series.Buckets, ActivityBucket{Start: time.Unix(start, 0).UTC()})
	}
	return series, nil
}
