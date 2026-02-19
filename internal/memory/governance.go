package memory

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/policy"
)

// ErrMemoryConflict is returned when a memory write conflicts with existing entries
// and the conflict resolution policy is "reject".
var ErrMemoryConflict = errors.New("memory entry conflicts with existing entries")

// Governance enforces Constitutional AI rules on memory writes.
type Governance struct {
	store      *Store
	classifier *classifier.Scanner
}

// NewGovernance creates a governance checker backed by the given store and PII scanner.
func NewGovernance(store *Store, cls *classifier.Scanner) *Governance {
	return &Governance{store: store, classifier: cls}
}

// ConflictCandidate describes a potential conflict with an existing memory entry.
type ConflictCandidate struct {
	ExistingEntryID string
	ExistingTitle   string
	Similarity      float64
	Category        string
	TrustScore      int
}

// forbiddenPhrases that indicate an agent attempting to alter its own governance.
var forbiddenPhrases = []string{
	"ignore policy",
	"bypass policy",
	"override policy",
	"disable policy",
	"policy: false",
	"allowed: true",
	"cost_limits: null",
	"budget: infinity",
}

// ValidateWrite runs all five governance checks in order.
// It may mutate the entry (setting TrustScore, ReviewStatus, ConflictsWith).
func (g *Governance) ValidateWrite(ctx context.Context, entry *Entry, pol *policy.Policy) error {
	ctx, span := tracer.Start(ctx, "memory.governance.validate",
		trace.WithAttributes(
			attribute.String("category", entry.Category),
			attribute.String("source_type", entry.SourceType),
		))
	defer span.End()

	// Check 1: Category allowed
	if err := g.checkCategory(entry.Category, pol); err != nil {
		span.SetAttributes(attribute.String("governance.denied_by", "category"))
		return err
	}

	// Check 2: PII scan (Title and Content — both must be free of PII)
	if g.classifier != nil {
		combined := entry.Title + "\n" + entry.Content
		result := g.classifier.Scan(ctx, combined)
		if result.HasPII {
			span.SetAttributes(attribute.String("governance.denied_by", "pii"))
			return fmt.Errorf("memory write contains PII: %w", ErrPIIDetected)
		}
	}

	// Check 3: Policy override detection (Title and Content)
	if err := g.checkPolicyOverride(entry.Title); err != nil {
		span.SetAttributes(attribute.String("governance.denied_by", "policy_override"))
		return err
	}
	if err := g.checkPolicyOverride(entry.Content); err != nil {
		span.SetAttributes(attribute.String("governance.denied_by", "policy_override"))
		return err
	}

	// Check 4: Provenance validation
	if entry.SourceType == "" {
		span.SetAttributes(attribute.String("governance.denied_by", "missing_source"))
		return fmt.Errorf("source_type is required: %w", ErrMemoryWriteDenied)
	}
	entry.TrustScore = DeriveTrustScore(entry.SourceType)

	// Check 5: Conflict detection + resolution
	if err := g.handleConflicts(ctx, entry, pol); err != nil {
		return err
	}

	span.SetAttributes(
		attribute.Int("governance.trust_score", entry.TrustScore),
		attribute.String("governance.review_status", entry.ReviewStatus),
	)
	return nil
}

// checkCategory validates the entry category against policy rules and hardcoded forbidden list.
func (g *Governance) checkCategory(category string, pol *policy.Policy) error {
	if IsForbiddenCategory(category) {
		return fmt.Errorf("category %q is hardcoded forbidden: %w", category, ErrMemoryWriteDenied)
	}

	if pol.Memory == nil {
		return nil
	}

	// Check policy-level forbidden categories
	for _, fc := range pol.Memory.ForbiddenCategories {
		if fc == category {
			return fmt.Errorf("category %q is forbidden by policy: %w", category, ErrMemoryWriteDenied)
		}
	}

	// If AllowedCategories is set, category must be in the list
	if len(pol.Memory.AllowedCategories) > 0 {
		allowed := false
		for _, ac := range pol.Memory.AllowedCategories {
			if ac == category {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("category %q not in allowed list: %w", category, ErrMemoryWriteDenied)
		}
	}

	return nil
}

// checkPolicyOverride scans content for phrases that indicate a policy manipulation attempt.
func (g *Governance) checkPolicyOverride(content string) error {
	lower := strings.ToLower(content)
	for _, phrase := range forbiddenPhrases {
		if strings.Contains(lower, phrase) {
			return fmt.Errorf("memory write attempts policy override (%q): %w", phrase, ErrMemoryWriteDenied)
		}
	}
	return nil
}

// defaultConflictSimilarityThreshold is used when policy does not set conflict_similarity_threshold.
const defaultConflictSimilarityThreshold = 0.6

// handleConflicts detects and resolves conflicts with existing memory entries.
func (g *Governance) handleConflicts(ctx context.Context, entry *Entry, pol *policy.Policy) error {
	threshold := defaultConflictSimilarityThreshold
	if pol.Memory != nil && pol.Memory.Governance != nil && pol.Memory.Governance.ConflictSimilarityThreshold > 0 {
		threshold = pol.Memory.Governance.ConflictSimilarityThreshold
	}
	conflicts, err := g.CheckConflicts(ctx, *entry, threshold)
	if err != nil {
		// Fail-open: log warning but allow write
		log.Warn().Err(err).Str("entry_id", entry.ID).Msg("conflict detection failed, allowing write")
		if entry.ReviewStatus == "" {
			entry.ReviewStatus = "auto_approved"
		}
		return nil
	}

	if len(conflicts) == 0 {
		if entry.ReviewStatus == "" {
			entry.ReviewStatus = "auto_approved"
		}
		return nil
	}

	// Record conflict IDs on the entry
	conflictIDs := make([]string, len(conflicts))
	for i, c := range conflicts {
		conflictIDs[i] = c.ExistingEntryID
	}
	entry.ConflictsWith = conflictIDs

	// Apply conflict resolution policy
	resolution := "auto"
	if pol.Memory != nil && pol.Memory.Governance != nil && pol.Memory.Governance.ConflictResolution != "" {
		resolution = pol.Memory.Governance.ConflictResolution
	}

	switch resolution {
	case "reject":
		return fmt.Errorf("conflicts with %d existing entries: %w", len(conflicts), ErrMemoryConflict)
	case "flag_for_review":
		entry.ReviewStatus = "pending_review"
	default: // "auto"
		g.resolveByTrustScore(entry, conflicts)
	}

	return nil
}

// CheckConflicts finds existing entries that may contradict the new entry.
// similarityThreshold is the minimum keyword-overlap ratio (0..1) to consider two entries in conflict;
// it is typically taken from policy memory.governance.conflict_similarity_threshold (default 0.6).
func (g *Governance) CheckConflicts(ctx context.Context, entry Entry, similarityThreshold float64) ([]ConflictCandidate, error) {
	ctx, span := tracer.Start(ctx, "memory.governance.check_conflicts",
		trace.WithAttributes(attribute.Float64("conflict_similarity_threshold", similarityThreshold)))
	defer span.End()

	var candidates []ConflictCandidate
	seen := make(map[string]bool)

	// Strategy 1: Category overlap -- entries in the same category
	catEntries, err := g.store.SearchByCategory(ctx, entry.TenantID, entry.AgentID, entry.Category)
	if err != nil {
		return nil, fmt.Errorf("searching by category: %w", err)
	}

	for i := range catEntries {
		existing := &catEntries[i]
		if existing.ID == entry.ID {
			continue
		}
		sim := keywordSimilarity(entry.Title+" "+entry.Content, existing.Title+" "+existing.Content)
		if sim >= similarityThreshold {
			candidates = append(candidates, ConflictCandidate{
				ExistingEntryID: existing.ID,
				ExistingTitle:   existing.Title,
				Similarity:      sim,
				Category:        existing.Category,
				TrustScore:      existing.TrustScore,
			})
			seen[existing.ID] = true
		}
	}

	// Strategy 2: FTS5 keyword search on title + content
	keywords := extractKeywords(entry.Title + " " + entry.Content)
	if len(keywords) > 0 {
		ftsQuery := strings.Join(keywords, " OR ")
		indexResults, err := g.store.Search(ctx, entry.TenantID, entry.AgentID, ftsQuery, 20)
		if err != nil {
			log.Warn().Err(err).Msg("FTS5 conflict search failed, continuing with category results")
		} else {
			for _, idx := range indexResults {
				if seen[idx.ID] || idx.ID == entry.ID {
					continue
				}
				candidates = append(candidates, ConflictCandidate{
					ExistingEntryID: idx.ID,
					ExistingTitle:   idx.Title,
					Similarity:      similarityThreshold, // FTS5 matches treated as at least threshold
					Category:        idx.Category,
					TrustScore:      idx.TrustScore,
				})
			}
		}
	}

	span.SetAttributes(attribute.Int("conflicts.count", len(candidates)))
	return candidates, nil
}

// resolveByTrustScore applies trust-based auto-resolution: if the new entry's trust
// is >= the max existing conflict trust, approve; otherwise flag for review.
func (g *Governance) resolveByTrustScore(entry *Entry, conflicts []ConflictCandidate) {
	maxExistingTrust := 0
	for _, c := range conflicts {
		if c.TrustScore > maxExistingTrust {
			maxExistingTrust = c.TrustScore
		}
	}

	if entry.TrustScore >= maxExistingTrust {
		entry.ReviewStatus = "auto_approved"
	} else {
		entry.ReviewStatus = "pending_review"
	}
}

// keywordSimilarity computes a simple keyword overlap ratio between two texts.
func keywordSimilarity(a, b string) float64 {
	wordsA := extractKeywordSet(a)
	wordsB := extractKeywordSet(b)

	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0
	}

	overlap := 0
	for w := range wordsA {
		if wordsB[w] {
			overlap++
		}
	}

	denominator := len(wordsA)
	if len(wordsB) < denominator {
		denominator = len(wordsB)
	}
	return float64(overlap) / float64(denominator)
}

// extractKeywords returns top keywords from text, excluding stop words.
func extractKeywords(text string) []string {
	words := extractKeywordSet(text)
	result := make([]string, 0, len(words))
	for w := range words {
		result = append(result, w)
		if len(result) >= 10 {
			break
		}
	}
	return result
}

// extractKeywordSet returns unique non-stopword tokens.
func extractKeywordSet(text string) map[string]bool {
	words := make(map[string]bool)
	for _, w := range strings.Fields(strings.ToLower(text)) {
		w = strings.Trim(w, ".,;:!?\"'()[]{}|")
		if len(w) >= 3 && !stopWords[w] {
			words[w] = true
		}
	}
	return words
}

var stopWords = map[string]bool{
	"the": true, "and": true, "for": true, "are": true, "but": true,
	"not": true, "you": true, "all": true, "can": true, "had": true,
	"her": true, "was": true, "one": true, "our": true, "out": true,
	"has": true, "have": true, "this": true, "that": true, "with": true,
	"from": true, "they": true, "been": true, "said": true, "each": true,
	"which": true, "their": true, "will": true, "other": true, "about": true,
	"many": true, "then": true, "them": true, "these": true, "some": true,
	"would": true, "make": true, "like": true, "into": true, "time": true,
}

// Domain errors
var (
	ErrPIIDetected       = errors.New("PII detected in content")
	ErrMemoryWriteDenied = errors.New("memory write denied by governance")
)
