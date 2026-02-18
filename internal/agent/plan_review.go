package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var (
	ErrPlanNotFound   = errors.New("execution plan not found")
	ErrPlanNotPending = errors.New("plan is not in pending status")
)

// PlanReviewStore persists execution plans for human review.
type PlanReviewStore struct {
	db *sql.DB
}

// NewPlanReviewStore creates the plan review store with SQLite backend.
func NewPlanReviewStore(db *sql.DB) (*PlanReviewStore, error) {
	_, err := db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS execution_plans (
			id TEXT PRIMARY KEY,
			correlation_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			plan_json TEXT NOT NULL,
			reviewed_by TEXT,
			reviewed_at DATETIME,
			review_reason TEXT,
			annotations_json TEXT,
			created_at DATETIME NOT NULL,
			timeout_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_plans_status ON execution_plans(status);
		CREATE INDEX IF NOT EXISTS idx_plans_tenant ON execution_plans(tenant_id, status);
	`)
	if err != nil {
		return nil, fmt.Errorf("creating execution_plans table: %w", err)
	}
	return &PlanReviewStore{db: db}, nil
}

// Save persists a new execution plan.
func (s *PlanReviewStore) Save(ctx context.Context, plan *ExecutionPlan) error {
	ctx, span := tracer.Start(ctx, "plan_review.save",
		trace.WithAttributes(
			attribute.String("plan_id", plan.ID),
			attribute.String("tenant_id", plan.TenantID),
		))
	defer span.End()

	planJSON, err := json.Marshal(plan)
	if err != nil {
		return fmt.Errorf("marshaling plan: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO execution_plans (id, correlation_id, tenant_id, agent_id, status, plan_json, created_at, timeout_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		plan.ID, plan.CorrelationID, plan.TenantID, plan.AgentID,
		string(plan.Status), string(planJSON), plan.CreatedAt, plan.TimeoutAt,
	)
	return err
}

// GetPending returns all plans awaiting review, optionally filtered by tenant.
func (s *PlanReviewStore) GetPending(ctx context.Context, tenantID string) ([]*ExecutionPlan, error) {
	query := `SELECT plan_json FROM execution_plans WHERE status = 'pending' AND timeout_at > datetime('now')`
	args := []interface{}{}
	if tenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	query += ` ORDER BY created_at ASC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plans []*ExecutionPlan
	for rows.Next() {
		var planJSON string
		if err := rows.Scan(&planJSON); err != nil {
			return nil, err
		}
		var plan ExecutionPlan
		if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
			continue
		}
		plans = append(plans, &plan)
	}
	return plans, nil
}

// Get returns a single plan by ID.
func (s *PlanReviewStore) Get(ctx context.Context, planID string) (*ExecutionPlan, error) {
	var planJSON, status string
	var reviewedBy, reviewReason sql.NullString
	var reviewedAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT plan_json, status, reviewed_by, reviewed_at, review_reason FROM execution_plans WHERE id = ?`, planID,
	).Scan(&planJSON, &status, &reviewedBy, &reviewedAt, &reviewReason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPlanNotFound
	}
	if err != nil {
		return nil, err
	}

	var plan ExecutionPlan
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		return nil, fmt.Errorf("unmarshaling plan: %w", err)
	}

	plan.Status = PlanStatus(status)
	if reviewedBy.Valid {
		plan.ReviewedBy = reviewedBy.String
	}
	if reviewedAt.Valid {
		t := reviewedAt.Time
		plan.ReviewedAt = &t
	}
	if reviewReason.Valid {
		plan.ReviewReason = reviewReason.String
	}
	return &plan, nil
}

// Approve marks a plan as approved by a reviewer.
func (s *PlanReviewStore) Approve(ctx context.Context, planID, reviewedBy string) error {
	return s.updateStatus(ctx, planID, PlanApproved, reviewedBy, "")
}

// Reject marks a plan as rejected with a reason.
func (s *PlanReviewStore) Reject(ctx context.Context, planID, reviewedBy, reason string) error {
	return s.updateStatus(ctx, planID, PlanRejected, reviewedBy, reason)
}

// Modify marks a plan as approved-with-modifications and stores reviewer annotations.
func (s *PlanReviewStore) Modify(ctx context.Context, planID, reviewedBy string, annotations []Annotation) error {
	annotJSON, _ := json.Marshal(annotations)
	now := time.Now()
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_plans SET status = ?, reviewed_by = ?, reviewed_at = ?, annotations_json = ?
		WHERE id = ? AND status = 'pending'`,
		string(PlanModified), reviewedBy, now, string(annotJSON), planID,
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrPlanNotPending
	}

	log.Info().Str("plan_id", planID).Str("reviewed_by", reviewedBy).Msg("plan_modified")
	return nil
}

func (s *PlanReviewStore) updateStatus(ctx context.Context, planID string, status PlanStatus, reviewedBy, reason string) error {
	now := time.Now()
	result, err := s.db.ExecContext(ctx, `
		UPDATE execution_plans SET status = ?, reviewed_by = ?, reviewed_at = ?, review_reason = ?
		WHERE id = ? AND status = 'pending'`,
		string(status), reviewedBy, now, reason, planID,
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrPlanNotPending
	}

	log.Info().Str("plan_id", planID).Str("status", string(status)).Msg("plan_review_completed")
	return nil
}

// PlanReviewConfig from .talon.yaml.
type PlanReviewConfig struct {
	RequireForTools  bool    `yaml:"require_for_tools"`
	RequireForTier   string  `yaml:"require_for_tier"`
	CostThresholdEUR float64 `yaml:"cost_threshold_eur"`
	TimeoutMinutes   int     `yaml:"timeout_minutes"`
	NotifyWebhook    string  `yaml:"notify_webhook"`
}

// RequiresReview checks if the current request needs human review based on policy.
func RequiresReview(humanOversight string, dataTier int, costEstimate float64, hasTools bool, planConfig *PlanReviewConfig) bool {
	if humanOversight == "always" {
		return true
	}
	if humanOversight == "none" || humanOversight == "" {
		return false
	}
	if planConfig == nil {
		return false
	}
	if planConfig.RequireForTools && hasTools {
		return true
	}
	if planConfig.CostThresholdEUR > 0 && costEstimate >= planConfig.CostThresholdEUR {
		return true
	}
	tierThreshold := tierFromString(planConfig.RequireForTier)
	if tierThreshold >= 0 && dataTier >= tierThreshold {
		return true
	}
	return false
}

func tierFromString(s string) int {
	switch s {
	case "tier_0":
		return 0
	case "tier_1":
		return 1
	case "tier_2":
		return 2
	default:
		return -1
	}
}
