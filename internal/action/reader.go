package action

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Reader reads approvals for people. It runs SELECT statements only: no
// schema statement, no migration, no write and no lifecycle transition, so
// it works on a read-only connection (the Operations Console opens the
// store with mode=ro) as well as on the deciding process's own. An approval
// whose lifetime elapsed stays "pending" in the store until the decision
// path touches it; a Reader reports that as it is and never closes it.
type Reader struct {
	db *sql.DB
}

// NewReader returns a reader over the database that holds the action
// tables (the evidence store's database).
func NewReader(db *sql.DB) *Reader { return &Reader{db: db} }

// Ready reports whether the action tables exist. An installation that
// never served the Action Gateway has none: that is "no approvals", not an
// error, and a reader never creates them.
func (r *Reader) Ready(ctx context.Context) (bool, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('action_operations', 'action_approvals', 'action_attempts')`).Scan(&n)
	if err != nil {
		return false, err
	}
	return n == 3, nil
}

// ApprovalRecord reads one approval, its operation and its latest attempt
// in ONE read transaction, so a decision or a claim that commits between
// the statements can never produce a view that mixes two states (#565
// review). (nil, nil) when no such approval exists.
func (r *Reader) ApprovalRecord(ctx context.Context, approvalID string) (*ApprovalRecord, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	ap, err := getApproval(ctx, tx, approvalID)
	if err != nil || ap == nil {
		return nil, err
	}
	op, err := getOperationByRef(ctx, tx, ap.OperationRef)
	if err != nil {
		return nil, err
	}
	if op == nil {
		return nil, fmt.Errorf("approval %s references a missing operation", approvalID)
	}
	at, err := latestAttempt(ctx, tx, op.Ref)
	if err != nil {
		return nil, err
	}
	return &ApprovalRecord{Approval: ap, Operation: op, LatestAttempt: at}, nil
}

// ApprovalScope returns the tenant and approver groups of an approval and
// nothing else, so a caller can authorize before reading the record that
// carries the review values.
func (r *Reader) ApprovalScope(ctx context.Context, approvalID string) (tenant string, groups []string, found bool, err error) {
	var raw string
	err = r.db.QueryRowContext(ctx, `SELECT o.tenant_id, a.groups_json FROM action_approvals a JOIN action_operations o ON o.ref = a.operation_ref WHERE a.id = ?`, approvalID).Scan(&tenant, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	_ = json.Unmarshal([]byte(raw), &groups)
	return tenant, groups, true, nil
}

// Selections of an approval listing.
const (
	// SelectAttention (default): unresolved approvals that can be decided,
	// may be decidable, or whose eligibility is unknown. Oldest first.
	SelectAttention = "attention"
	// SelectUnresolved: every approval still pending in the store, whatever
	// its eligibility. Oldest first.
	SelectUnresolved = "unresolved"
	// SelectDecided: approvals that are no longer pending (approved,
	// rejected, expired, invalidated). Newest first.
	SelectDecided = "decided"
)

// ValidSelection reports whether s names a listing selection.
func ValidSelection(s string) bool {
	return s == SelectAttention || s == SelectUnresolved || s == SelectDecided
}

const (
	// MaxApprovalList bounds one page of an approval listing.
	MaxApprovalList = 100
	// approvalScanBudget bounds the rows one listing request reads. A page
	// that reaches it ends early with a cursor; the listing stays complete
	// across pages.
	approvalScanBudget = 5000
	approvalScanBatch  = 250
	// maxApprovalGroups bounds the distinct (use case, action, binding)
	// combinations one count request reads.
	maxApprovalGroups = 2000
)

// ApprovalListQuery selects a page of approvals.
type ApprovalListQuery struct {
	// Tenant "" spans every tenant. A filter; authorization is the
	// caller's (the reviewer API passes the credential's tenant).
	Tenant  string
	UseCase string
	// Groups, when non-nil, keeps only approvals that name one of them
	// (the reviewer's groups). nil applies no group filter.
	Groups    []string
	Selection string
	Limit     int
	// After is the cursor of the previous page ("" for the first).
	After string
	Now   time.Time
	// Config returns the configuration an approval of one use case is
	// compared with. It is called once per use case and request.
	Config func(tenant, useCase string) CurrentConfig
}

// ApprovalPage is one page. Next is "" when the selection is exhausted.
//
// Order and cursor are the approval's creation time and id, which never
// change. A page therefore never repeats or skips an approval that stays in
// the selection. An approval whose state changes between two requests (it
// is decided, it expires, the configuration changes) is reported with the
// state it has when its position is read, and is absent from pages already
// delivered or from a selection it has left.
type ApprovalPage struct {
	Items []ApprovalSummary
	Next  string
}

// ListApprovals returns one page of the selection.
func (r *Reader) ListApprovals(ctx context.Context, q ApprovalListQuery) (*ApprovalPage, error) {
	if q.Selection == "" {
		q.Selection = SelectAttention
	}
	if !ValidSelection(q.Selection) {
		return nil, fmt.Errorf("%w: unknown selection %q", ErrInvalidListQuery, q.Selection)
	}
	if q.Limit <= 0 || q.Limit > MaxApprovalList {
		q.Limit = MaxApprovalList
	}
	if q.Now.IsZero() {
		q.Now = time.Now().UTC()
	}
	cur, err := decodeApprovalCursor(q.After)
	if err != nil {
		return nil, err
	}
	ls := &approvalLister{q: q, cur: cur, configs: map[string]CurrentConfig{}, page: &ApprovalPage{Items: []ApprovalSummary{}}}
	for scanned := 0; scanned < approvalScanBudget; {
		n, err := ls.batch(ctx, r.db)
		if err != nil {
			return nil, err
		}
		scanned += n
		if ls.full || n < approvalScanBatch {
			break
		}
	}
	if ls.more {
		ls.page.Next = encodeApprovalCursor(ls.cur)
	}
	return ls.page, nil
}

// ErrInvalidListQuery marks a listing request the caller must correct.
var ErrInvalidListQuery = errors.New("invalid approval listing query")

type approvalCursor struct {
	at  time.Time
	id  string
	set bool
}

func encodeApprovalCursor(c approvalCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.at.UTC().Format(time.RFC3339Nano) + "|" + c.id))
}

func decodeApprovalCursor(s string) (approvalCursor, error) {
	if s == "" {
		return approvalCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return approvalCursor{}, fmt.Errorf("%w: malformed cursor", ErrInvalidListQuery)
	}
	at, id, ok := strings.Cut(string(raw), "|")
	t, perr := time.Parse(time.RFC3339Nano, at)
	if !ok || perr != nil || id == "" {
		return approvalCursor{}, fmt.Errorf("%w: malformed cursor", ErrInvalidListQuery)
	}
	return approvalCursor{at: t.UTC(), id: id, set: true}, nil
}

// The listing statements are fixed text; every value is bound. Optional
// filters are switched by a bound flag (0/1) or an empty string.
const listColumnsSQL = `SELECT a.id, a.rule_id, a.groups_json, a.status, a.expires_at, a.created_at, a.decided_at, a.decided_by,
		o.tenant_id, o.agent_id, o.action, o.policy_digest, o.definition_digest, o.rule_id
	FROM action_approvals a JOIN action_operations o ON o.ref = a.operation_ref `

const listFiltersSQL = ` AND (? = 0 OR a.expires_at > ?) AND (? = '' OR o.tenant_id = ?) AND (? = '' OR o.agent_id = ?) `

const (
	listUnresolvedSQL = listColumnsSQL + `WHERE a.status = ?` + listFiltersSQL +
		`AND (? = 0 OR a.created_at > ? OR (a.created_at = ? AND a.id > ?)) ORDER BY a.created_at, a.id LIMIT ?`
	listDecidedSQL = listColumnsSQL + `WHERE a.status != ?` + listFiltersSQL +
		`AND (? = 0 OR a.created_at < ? OR (a.created_at = ? AND a.id < ?)) ORDER BY a.created_at DESC, a.id DESC LIMIT ?`
)

type approvalLister struct {
	q       ApprovalListQuery
	cur     approvalCursor
	configs map[string]CurrentConfig
	page    *ApprovalPage
	full    bool // the page holds Limit items
	more    bool // rows of the selection may exist after cur
}

func (ls *approvalLister) config(tenant, useCase string) CurrentConfig {
	key := tenant + "\x00" + useCase
	cfg, ok := ls.configs[key]
	if !ok {
		cfg = CurrentConfig{Basis: "none", Unavailable: "no configuration source was given"}
		if ls.q.Config != nil {
			cfg = ls.q.Config(tenant, useCase)
		}
		ls.configs[key] = cfg
	}
	return cfg
}

// batch reads the next rows after the cursor and adds the ones of the
// selection. Listing columns only: the stored review values are never
// selected for a listing.
func (ls *approvalLister) batch(ctx context.Context, db *sql.DB) (int, error) {
	q := ls.q
	query, status := listUnresolvedSQL, ApprovalPending
	if q.Selection == SelectDecided {
		query = listDecidedSQL
	}
	// Lifetime needs no configuration: for the attention selection a long
	// tail of expired approvals is never read.
	unexpiredOnly := 0
	if q.Selection == SelectAttention {
		unexpiredOnly = 1
	}
	after := 0
	if ls.cur.set {
		after = 1
	}
	now := q.Now.UTC()
	rows, err := db.QueryContext(ctx, query, status, unexpiredOnly, now, q.Tenant, q.Tenant, q.UseCase, q.UseCase,
		after, ls.cur.at, ls.cur.at, ls.cur.id, approvalScanBatch)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var ap Approval
		var op Operation
		var groups string
		var decided sql.NullTime
		if err := rows.Scan(&ap.ID, &ap.RuleID, &groups, &ap.Status, &ap.ExpiresAt, &ap.CreatedAt, &decided, &ap.DecidedBy,
			&op.TenantID, &op.AgentID, &op.Action, &op.PolicyDigest, &op.DefinitionDigest, &op.RuleID); err != nil {
			return n, err
		}
		if ls.full {
			// One row beyond a full page: the selection continues.
			ls.more = true
			return n, nil
		}
		n++
		_ = json.Unmarshal([]byte(groups), &ap.Groups)
		ap.ExpiresAt, ap.CreatedAt = ap.ExpiresAt.UTC(), ap.CreatedAt.UTC()
		if decided.Valid {
			t := decided.Time.UTC()
			ap.DecidedAt = &t
		}
		ls.cur = approvalCursor{at: ap.CreatedAt, id: ap.ID, set: true}
		ls.add(&ap, &op)
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	// A full batch that did not fill the page: more rows may follow.
	ls.more = n == approvalScanBatch
	return n, nil
}

func (ls *approvalLister) add(ap *Approval, op *Operation) {
	if ls.q.Groups != nil && firstCommon(ls.q.Groups, ap.Groups) == "" {
		return
	}
	sum := SummarizeApproval(ap, op, ls.config(op.TenantID, op.AgentID), ls.q.Now)
	if ls.q.Selection == SelectAttention && !sum.Eligibility.NeedsAttention() {
		return
	}
	ls.page.Items = append(ls.page.Items, sum)
	ls.full = len(ls.page.Items) == ls.q.Limit
}

// ApprovalGroup counts the unresolved approvals that share one use case,
// action and binding: everything eligibility depends on besides lifetime.
type ApprovalGroup struct {
	Tenant           string
	UseCase          string
	Action           string
	PolicyDigest     string
	DefinitionDigest string
	// Unresolved is the number of approvals pending in the store;
	// Expired of them have an elapsed lifetime.
	Unresolved int
	Expired    int
}

// Eligibility classifies the group's approvals whose lifetime has not
// elapsed against a configuration.
func (g ApprovalGroup) Eligibility(cfg CurrentConfig, now time.Time) Eligibility {
	return classifyApproval(bindingFacts{Status: ApprovalPending, ExpiresAt: now.Add(time.Hour), Action: g.Action, PolicyDigest: g.PolicyDigest, DefinitionDigest: g.DefinitionDigest}, cfg, now)
}

// UnresolvedGroups counts every unresolved approval of a tenant ("" =
// every tenant), grouped by what eligibility depends on. The counts are
// computed in SQL over all rows: no page bound can make them wrong.
// complete is false when there are more distinct groups than one request
// reads; the groups returned are then a subset and must not be summed into
// a total (use UnresolvedByUseCase for the stored totals).
func (r *Reader) UnresolvedGroups(ctx context.Context, tenant string, now time.Time) (groups []ApprovalGroup, complete bool, err error) {
	rows, err := r.db.QueryContext(ctx, `SELECT o.tenant_id, o.agent_id, o.action, o.policy_digest, o.definition_digest,
			COUNT(*), SUM(CASE WHEN a.expires_at <= ? THEN 1 ELSE 0 END)
		FROM action_approvals a JOIN action_operations o ON o.ref = a.operation_ref
		WHERE a.status = ? AND (? = '' OR o.tenant_id = ?)
		GROUP BY o.tenant_id, o.agent_id, o.action, o.policy_digest, o.definition_digest
		ORDER BY o.tenant_id, o.agent_id, o.action, o.policy_digest, o.definition_digest LIMIT ?`,
		now.UTC(), ApprovalPending, tenant, tenant, maxApprovalGroups+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var g ApprovalGroup
		if err := rows.Scan(&g.Tenant, &g.UseCase, &g.Action, &g.PolicyDigest, &g.DefinitionDigest, &g.Unresolved, &g.Expired); err != nil {
			return nil, false, err
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(groups) > maxApprovalGroups {
		return groups[:maxApprovalGroups], false, nil
	}
	return groups, true, nil
}

// UseCaseUnresolved is the stored number of unresolved approvals of one
// use case: a persisted fact, independent of any configuration.
type UseCaseUnresolved struct {
	Tenant     string
	UseCase    string
	Unresolved int
}

// UnresolvedByUseCase counts the approvals pending in the store per use
// case of a tenant ("" = every tenant).
func (r *Reader) UnresolvedByUseCase(ctx context.Context, tenant string) ([]UseCaseUnresolved, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT o.tenant_id, o.agent_id, COUNT(*)
		FROM action_approvals a JOIN action_operations o ON o.ref = a.operation_ref
		WHERE a.status = ? AND (? = '' OR o.tenant_id = ?)
		GROUP BY o.tenant_id, o.agent_id ORDER BY o.tenant_id, o.agent_id`, ApprovalPending, tenant, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UseCaseUnresolved
	for rows.Next() {
		var u UseCaseUnresolved
		if err := rows.Scan(&u.Tenant, &u.UseCase, &u.Unresolved); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Reader returns the read side of this repository's database.
func (r *Repository) Reader() *Reader { return NewReader(r.db) }

// Review returns the reviewer view of one approval of this service's
// tenant and agent, compared with the configuration this service decides
// with. An approval of another agent or tenant is not found. A storage
// failure is reported as one, never as "not found" (#565 review).
func (s *Service) Review(ctx context.Context, approvalID string) (*ApprovalView, error) {
	rec, err := s.repo.Reader().ApprovalRecord(ctx, approvalID)
	if err != nil {
		return nil, &Error{Code: CodeStoreUnavailable, Message: "reading approval", Err: err}
	}
	if rec == nil || rec.Operation.TenantID != s.TenantID || rec.Operation.AgentID != s.AgentID {
		return nil, newErr(CodeNotFound, "approval not found")
	}
	return BuildApprovalView(rec, s.CurrentConfig(), DiscloseReviewer, s.now()), nil
}
