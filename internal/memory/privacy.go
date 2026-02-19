package memory

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	privateTagRe    = regexp.MustCompile(`(?s)<private>(.*?)</private>`)
	classifiedTagRe = regexp.MustCompile(`(?s)<classified:tier_(\d+)>(.*?)</classified>`)
)

// PrivacyResult holds the outcome of stripping privacy tags from content.
type PrivacyResult struct {
	CleanContent            string // Content with <private> blocks removed and <classified> tags stripped
	FullContent             string // Original content unchanged
	PrivateSectionsStripped int
	MaxClassifiedTier       int
	HasPrivateContent       bool
}

// StripPrivateTags processes content for privacy:
//   - Removes <private>...</private> sections entirely (GDPR Art. 25)
//   - Extracts max tier from <classified:tier_N>...</classified> tags
//   - Removes classified tags but preserves inner content
func StripPrivateTags(content string) PrivacyResult {
	result := PrivacyResult{
		FullContent: content,
	}

	// Count and strip <private> sections
	privateMatches := privateTagRe.FindAllStringIndex(content, -1)
	result.PrivateSectionsStripped = len(privateMatches)
	result.HasPrivateContent = len(privateMatches) > 0
	clean := privateTagRe.ReplaceAllString(content, "")

	// Extract max classified tier and strip tags (keep inner content)
	classifiedMatches := classifiedTagRe.FindAllStringSubmatch(clean, -1)
	for _, match := range classifiedMatches {
		if tier, err := strconv.Atoi(match[1]); err == nil && tier > result.MaxClassifiedTier {
			result.MaxClassifiedTier = tier
		}
	}
	clean = classifiedTagRe.ReplaceAllString(clean, "$2")

	// Collapse multiple blank lines left by stripping
	for strings.Contains(clean, "\n\n\n") {
		clean = strings.ReplaceAll(clean, "\n\n\n", "\n\n")
	}
	result.CleanContent = strings.TrimSpace(clean)

	return result
}
