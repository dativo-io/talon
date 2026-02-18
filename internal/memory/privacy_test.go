package memory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripPrivateTags_RemovesPrivateContent(t *testing.T) {
	content := "Public info <private>secret data</private> more public"
	result := StripPrivateTags(content)
	assert.NotContains(t, result.CleanContent, "secret data")
	assert.Contains(t, result.CleanContent, "Public info")
	assert.Contains(t, result.CleanContent, "more public")
}

func TestStripPrivateTags_PreservesFullContent(t *testing.T) {
	content := "Public info <private>secret data</private> more public"
	result := StripPrivateTags(content)
	assert.Contains(t, result.FullContent, "secret data")
	assert.Contains(t, result.FullContent, "<private>")
}

func TestStripPrivateTags_CountsStrippedSections(t *testing.T) {
	content := "<private>first</private> gap <private>second</private> end"
	result := StripPrivateTags(content)
	assert.Equal(t, 2, result.PrivateSectionsStripped)
	assert.True(t, result.HasPrivateContent)
}

func TestStripPrivateTags_ExtractsMaxClassifiedTier(t *testing.T) {
	content := "Data: <classified:tier_2>highly sensitive info</classified>"
	result := StripPrivateTags(content)
	assert.Equal(t, 2, result.MaxClassifiedTier)
	assert.Contains(t, result.CleanContent, "highly sensitive info")
	assert.NotContains(t, result.CleanContent, "<classified")
}

func TestStripPrivateTags_RemovesClassifiedTagsKeepsContent(t *testing.T) {
	content := "Before <classified:tier_1>classified content</classified> after"
	result := StripPrivateTags(content)
	assert.Contains(t, result.CleanContent, "classified content")
	assert.NotContains(t, result.CleanContent, "<classified")
	assert.NotContains(t, result.CleanContent, "</classified>")
}

func TestStripPrivateTags_NoTags(t *testing.T) {
	content := "Just plain text without any tags"
	result := StripPrivateTags(content)
	assert.Equal(t, content, result.CleanContent)
	assert.Equal(t, content, result.FullContent)
	assert.Equal(t, 0, result.PrivateSectionsStripped)
	assert.Equal(t, 0, result.MaxClassifiedTier)
	assert.False(t, result.HasPrivateContent)
}

func TestStripPrivateTags_NestedPrivate(t *testing.T) {
	content := "<private>block1</private><private>block2</private>"
	result := StripPrivateTags(content)
	assert.Equal(t, 2, result.PrivateSectionsStripped)
	assert.NotContains(t, result.CleanContent, "block1")
	assert.NotContains(t, result.CleanContent, "block2")
}

func TestStripPrivateTags_MultipleClassifiedTiers(t *testing.T) {
	content := "<classified:tier_1>low</classified> and <classified:tier_2>high</classified>"
	result := StripPrivateTags(content)
	assert.Equal(t, 2, result.MaxClassifiedTier)
	assert.Contains(t, result.CleanContent, "low")
	assert.Contains(t, result.CleanContent, "high")
}
