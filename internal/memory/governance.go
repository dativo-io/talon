package memory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/policy"
)

// PolicyEvaluator is an optional interface for OPA-based memory governance.
// When set on Governance, ValidateWrite calls OPA in addition to hardcoded checks.
type PolicyEvaluator interface {
	EvaluateMemoryWrite(ctx context.Context, category string, contentSizeBytes int) (*policy.Decision, error)
}

// ErrMemoryConflict is returned when a memory write conflicts with existing entries
// and the conflict resolution policy is "reject".
var ErrMemoryConflict = errors.New("memory entry conflicts with existing entries")

// Governance enforces Constitutional AI rules on memory writes.
// opaMu protects the shared opa field so that SetPolicyEvaluator and
// evalOPAMemoryWrite (when using g.opa) are safe under concurrent Run() calls.
type Governance struct {
	store      *Store
	classifier *classifier.Scanner
	opa        PolicyEvaluator // optional; nil = skip OPA check; guarded by opaMu
	opaMu      sync.RWMutex
}

// NewGovernance creates a governance checker backed by the given store and PII scanner.
func NewGovernance(store *Store, cls *classifier.Scanner) *Governance {
	return &Governance{store: store, classifier: cls}
}

// SetPolicyEvaluator attaches an OPA-based policy evaluator for memory governance.
// When set, ValidateWrite runs OPA rules in addition to hardcoded Go checks (when
// called with a nil per-call eval). Callers running concurrent agent invocations
// (e.g. talon serve webhooks/cron) should prefer passing the per-run engine into
// ValidateWrite instead of setting a shared evaluator here, to avoid sharing mutable
// state across goroutines.
func (g *Governance) SetPolicyEvaluator(eval PolicyEvaluator) {
	g.opaMu.Lock()
	defer g.opaMu.Unlock()
	g.opa = eval
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
// eval is an optional per-call policy evaluator (e.g. the OPA engine for this run).
// When non-nil, it is used for OPA memory governance instead of the shared g.opa,
// avoiding data races when multiple Run() calls execute concurrently.
func (g *Governance) ValidateWrite(ctx context.Context, entry *Entry, pol *policy.Policy, eval PolicyEvaluator) error {
	ctx, span := tracer.Start(ctx, "memory.governance.validate",
		trace.WithAttributes(
			attribute.String("category", entry.Category),
			attribute.String("source_type", entry.SourceType),
		))
	defer span.End()

	deny := func(reason string, err error) error {
		writesDenied.Add(ctx, 1)
		span.SetAttributes(attribute.String("governance.denied_by", reason))
		return err
	}

	// Check 0 (backstop): Hardcoded forbidden categories — always checked first,
	// regardless of OPA availability, as defense-in-depth.
	if IsForbiddenCategory(entry.Category) {
		return deny("hardcoded_forbidden", fmt.Errorf("category %q is hardcoded forbidden: %w", entry.Category, ErrMemoryWriteDenied))
	}

	// Check 0.5: max_entry_size_kb enforcement (Go-level, mirrors the OPA rego rule)
	if err := g.checkMaxEntrySize(entry, pol); err != nil {
		return deny("max_entry_size", err)
	}

	// Check 0.75: OPA policy evaluation (unified governance path)
	if err := g.evalOPAMemoryWrite(ctx, entry, eval); err != nil {
		return deny("opa", err)
	}

	// Check 1: Category allowed (Go-level allow/forbid lists)
	if err := g.checkCategory(entry.Category, pol); err != nil {
		return deny("category", err)
	}

	// Check 2: PII scan (Title and Content — both must be free of PII)
	if g.classifier != nil {
		combined := entry.Title + "\n" + entry.Content
		result := g.classifier.Scan(ctx, combined)
		if result.HasPII {
			return deny("pii", fmt.Errorf("memory write contains PII: %w", ErrPIIDetected))
		}
	}

	// Check 3: Policy override detection (Title and Content)
	if err := g.checkPolicyOverride(entry.Title); err != nil {
		return deny("policy_override", err)
	}
	if err := g.checkPolicyOverride(entry.Content); err != nil {
		return deny("policy_override", err)
	}

	// Check 4: Provenance validation
	if entry.SourceType == "" {
		return deny("missing_source", fmt.Errorf("source_type is required: %w", ErrMemoryWriteDenied))
	}
	entry.TrustScore = DeriveTrustScore(entry.SourceType)

	// Check 5: Conflict detection + resolution (reject mode returns ErrMemoryConflict)
	// Must use deny() so memory.writes.denied and governance.denied_by are recorded.
	if err := g.handleConflicts(ctx, entry, pol); err != nil {
		return deny("conflict", err)
	}

	span.SetAttributes(
		attribute.Int("governance.trust_score", entry.TrustScore),
		attribute.String("governance.review_status", entry.ReviewStatus),
	)
	return nil
}

// checkMaxEntrySize returns an error if the entry exceeds policy max_entry_size_kb.
func (g *Governance) checkMaxEntrySize(entry *Entry, pol *policy.Policy) error {
	if pol.Memory == nil || pol.Memory.MaxEntrySizeKB <= 0 {
		return nil
	}
	contentSize := len(entry.Title) + len(entry.Content)
	maxBytes := pol.Memory.MaxEntrySizeKB * 1024
	if contentSize <= maxBytes {
		return nil
	}
	return fmt.Errorf("entry size %d bytes exceeds max_entry_size_kb (%d KB): %w",
		contentSize, pol.Memory.MaxEntrySizeKB, ErrMemoryWriteDenied)
}

// evalOPAMemoryWrite runs OPA memory governance when an evaluator is available (eval or g.opa).
// Returns nil if no evaluator, OPA is unavailable (logs and continues), or OPA allows; otherwise the denial error.
// When eval is nil, g.opa is read under opaMu to avoid data races with SetPolicyEvaluator.
func (g *Governance) evalOPAMemoryWrite(ctx context.Context, entry *Entry, eval PolicyEvaluator) error {
	opa := eval
	if opa == nil {
		g.opaMu.RLock()
		opa = g.opa
		g.opaMu.RUnlock()
	}
	if opa == nil {
		return nil
	}
	contentSize := len(entry.Title) + len(entry.Content)
	decision, opaErr := opa.EvaluateMemoryWrite(ctx, entry.Category, contentSize)
	if opaErr != nil {
		log.Warn().Err(opaErr).Msg("OPA memory governance unavailable, continuing with Go checks")
		return nil
	}
	if decision.Allowed {
		return nil
	}
	return fmt.Errorf("OPA policy denied memory write: %s: %w",
		strings.Join(decision.Reasons, "; "), ErrMemoryWriteDenied)
}

// checkCategory validates the entry category against policy allow/forbid lists.
// Hardcoded forbidden categories are already checked in ValidateWrite before this is called.
func (g *Governance) checkCategory(category string, pol *policy.Policy) error {
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
		// Fail-closed: flag for review so transient errors (SQLite lock)
		// cannot allow poisoned entries through.
		log.Warn().Err(err).Str("entry_id", entry.ID).Msg("conflict detection failed, flagging for review")
		entry.ReviewStatus = "pending_review"
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
			for i := range indexResults {
				if seen[indexResults[i].ID] || indexResults[i].ID == entry.ID {
					continue
				}
				candidates = append(candidates, ConflictCandidate{
					ExistingEntryID: indexResults[i].ID,
					ExistingTitle:   indexResults[i].Title,
					Similarity:      similarityThreshold, // FTS5 matches treated as at least threshold
					Category:        indexResults[i].Category,
					TrustScore:      indexResults[i].TrustScore,
				})
			}
		}
	}

	span.SetAttributes(attribute.Int("conflicts.count", len(candidates)))
	if len(candidates) > 0 {
		conflictsFound.Add(ctx, int64(len(candidates)))
	}
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

// extractKeywords returns up to 10 keywords from text (excluding stop words),
// in deterministic lexicographic order so FTS5 conflict detection is reproducible.
func extractKeywords(text string) []string {
	words := extractKeywordSet(text)
	if len(words) == 0 {
		return nil
	}
	keys := make([]string, 0, len(words))
	for w := range words {
		keys = append(keys, w)
	}
	sort.Strings(keys)
	const maxKeywords = 10
	if len(keys) > maxKeywords {
		keys = keys[:maxKeywords]
	}
	return keys
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
