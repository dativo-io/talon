package memory

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ConsolidationAction is the AUDN decision for a candidate memory entry (Mem0-style, governed).
type ConsolidationAction string

const (
	ActionAdd        ConsolidationAction = "add"
	ActionUpdate     ConsolidationAction = "update"
	ActionInvalidate ConsolidationAction = "invalidate"
	ActionNoop       ConsolidationAction = "noop"
)

// ConsolidationResult holds the decision and audit metadata.
type ConsolidationResult struct {
	Action     ConsolidationAction `json:"action"`
	TargetID   string              `json:"target_id,omitempty"`
	Reason     string              `json:"reason"`
	Similarity float64             `json:"similarity,omitempty"`
	NewContent string              `json:"new_content,omitempty"`
}

// Consolidator evaluates candidate entries against existing memory and applies AUDN decisions.
type Consolidator struct {
	store *Store
}

// NewConsolidator returns a consolidator backed by the given store.
func NewConsolidator(store *Store) *Consolidator {
	return &Consolidator{store: store}
}

// Evaluate determines the AUDN action for a candidate entry (rule-based similarity).
// dedupWindow is the policy-configured window for input-hash dedup; 0 means disabled
// (no input-hash NOOP). Caller should pass pol.Memory.Governance.DedupWindowMinutes as duration.
//
// Logic: when dedupWindow > 0 and candidate has InputHash, same hash within window → NOOP;
// else similarity >= 0.90 → NOOP; >= 0.60 → trust comparison → INVALIDATE or UPDATE;
// < 0.30 → ADD; 0.30–0.60 → ADD (related but distinct).
func (c *Consolidator) Evaluate(ctx context.Context, candidate *Entry, dedupWindow time.Duration) (*ConsolidationResult, error) {
	ctx, span := tracer.Start(ctx, "memory.consolidate.evaluate",
		trace.WithAttributes(
			attribute.String("memory.agent_id", candidate.AgentID),
			attribute.String("memory.category", candidate.Category),
		))
	defer span.End()

	if dedupWindow > 0 && candidate.InputHash != "" {
		isDup, err := c.store.HasRecentWithInputHash(ctx,
			candidate.TenantID, candidate.AgentID, candidate.InputHash, dedupWindow)
		if err != nil {
			span.SetAttributes(attribute.Bool("memory.consolidation.dedup_check_failed", true))
			// fail-open: continue to similarity logic
		} else if isDup {
			return &ConsolidationResult{Action: ActionNoop, Reason: "duplicate input hash"}, nil
		}
	}

	existing, err := c.store.SearchByCategory(ctx,
		candidate.TenantID, candidate.AgentID, candidate.Category)
	if err != nil {
		span.SetAttributes(attribute.Bool("memory.consolidation.search_failed", true))
		return &ConsolidationResult{Action: ActionAdd, Reason: "search failed, fail-open to add"}, nil
	}

	var bestMatch *Entry
	var bestSimilarity float64

	for i := range existing {
		if existing[i].ConsolidationStatus != "" &&
			existing[i].ConsolidationStatus != "active" {
			continue
		}
		sim := keywordSimilarity(
			candidate.Title+" "+candidate.Content,
			existing[i].Title+" "+existing[i].Content,
		)
		if sim > bestSimilarity {
			bestSimilarity = sim
			bestMatch = &existing[i]
		}
	}

	span.SetAttributes(
		attribute.Float64("memory.consolidation.best_similarity", bestSimilarity),
		attribute.Int("memory.consolidation.candidates_checked", len(existing)),
	)

	switch {
	case bestMatch == nil || bestSimilarity < 0.30:
		return &ConsolidationResult{
			Action:     ActionAdd,
			Reason:     "novel information",
			Similarity: bestSimilarity,
		}, nil

	case bestSimilarity >= 0.90:
		return &ConsolidationResult{
			Action:     ActionNoop,
			TargetID:   bestMatch.ID,
			Reason:     fmt.Sprintf("near-duplicate (similarity: %.2f)", bestSimilarity),
			Similarity: bestSimilarity,
		}, nil

	case bestSimilarity >= 0.60:
		if candidate.TrustScore >= bestMatch.TrustScore {
			return &ConsolidationResult{
				Action:   ActionInvalidate,
				TargetID: bestMatch.ID,
				Reason: fmt.Sprintf("superseded (new trust:%d >= old trust:%d, sim:%.2f)",
					candidate.TrustScore, bestMatch.TrustScore, bestSimilarity),
				Similarity: bestSimilarity,
			}, nil
		}
		return &ConsolidationResult{
			Action:   ActionUpdate,
			TargetID: bestMatch.ID,
			Reason: fmt.Sprintf("augmenting existing (old trust:%d > new trust:%d, sim:%.2f)",
				bestMatch.TrustScore, candidate.TrustScore, bestSimilarity),
			Similarity: bestSimilarity,
		}, nil

	default:
		return &ConsolidationResult{
			Action:     ActionAdd,
			Reason:     fmt.Sprintf("related but distinct (similarity: %.2f)", bestSimilarity),
			Similarity: bestSimilarity,
		}, nil
	}
}

// Apply executes the consolidation decision against the store.
func (c *Consolidator) Apply(ctx context.Context, candidate *Entry, result *ConsolidationResult) error {
	ctx, span := tracer.Start(ctx, "memory.consolidate.apply",
		trace.WithAttributes(attribute.String("action", string(result.Action))))
	defer span.End()

	now := time.Now().UTC()

	switch result.Action {
	case ActionAdd:
		candidate.ConsolidationStatus = "active"
		candidate.CreatedAt = now
		return c.store.Write(ctx, candidate)

	case ActionNoop:
		consolidationNoops.Add(ctx, 1)
		return nil

	case ActionInvalidate:
		prepareEntry(candidate) // set candidate.ID before Invalidate references it
		if err := c.store.Invalidate(ctx, candidate.TenantID, result.TargetID, candidate.ID, now); err != nil {
			return fmt.Errorf("invalidating %s: %w", result.TargetID, err)
		}
		consolidationInvalidations.Add(ctx, 1)
		candidate.ConsolidationStatus = "active"
		candidate.CreatedAt = now
		return c.store.Write(ctx, candidate)

	case ActionUpdate:
		if err := c.store.AppendContent(ctx, candidate.TenantID, result.TargetID, candidate.Content, now); err != nil {
			return fmt.Errorf("updating %s: %w", result.TargetID, err)
		}
		consolidationUpdates.Add(ctx, 1)
		return nil

	default:
		return fmt.Errorf("unknown consolidation action: %s", result.Action)
	}
}
